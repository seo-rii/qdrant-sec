import base64
import json
import os
import pathlib
import shutil
import stat
import subprocess
import time

import pytest
import requests

from .assertions import assert_http_ok
from .test_resharding import (
    activate_replica,
    commit_read_hashring,
    commit_write_hashring,
    finish_resharding,
    migrate_points,
    start_resharding,
)
from .utils import (
    PROJECT_ROOT,
    get_cluster_info,
    get_collection_cluster_info,
    get_uri,
    init_pytest_log_folder,
    kill_all_processes,
    make_peer_folders,
    processes,
    skip_if_no_feature,
    start_first_peer,
    start_peer,
    wait_for,
    wait_collection_exists_and_active_on_all_peers,
    wait_for_collection_local_shards_count,
    wait_for_collection_resharding_operations_count,
    wait_for_collection_shard_transfers_count,
    wait_for_uniform_cluster_status,
    wait_peer_added,
    wait_for_peer_online,
)


COLLECTION = "docs"
VECTOR = "text"
BASE_EPOCH = 42
NEXT_EPOCH = 43
FIXTURE_EXAMPLE = "private_oram_cluster_fixture"
PLACEHOLDER_COLLECTION_ID = "12345678-90ab-cdef-1234-567890abcdef"
LARGE_FIXTURE_PROFILE = "large"
IDS_VISIBLE_RESULT_PRIVACY = "ids_visible"
RUN_LARGE_BUNDLE_BENCHMARK = "QDRANT_RUN_PRIVATE_ORAM_LARGE_BUNDLE_BENCHMARK"


@pytest.fixture(autouse=True)
def cleanup_private_oram_peers():
    yield
    kill_all_processes()


def _private_oram_fixture(
    collection_id: str,
    profile: str | None = None,
    result_privacy: str | None = None,
) -> dict:
    command = [
        "cargo",
        "run",
        "--quiet",
        "-p",
        "qdrant-sec",
        "--example",
        FIXTURE_EXAMPLE,
        "--",
        collection_id,
    ]
    if profile is not None:
        command.append(profile)
    elif result_privacy is not None:
        command.append("default")
    if result_privacy is not None:
        command.append(result_privacy)
    completed = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
    )
    return json.loads(completed.stdout)


def _write_private_oram_runtime_config(
    peer_dir: pathlib.Path,
    fixture: dict,
    result_signing_key_id: str = "tenant-a/private-result-signing-v1",
) -> None:
    # A paired V2 collection signs its result index with the HNSW owner key, so its tests pass
    # that key's id here.
    hnsw_public_key = fixture["hnsw_public_key"]
    result_public_key = fixture["result_public_key"]
    hnsw_oram = fixture["hnsw"]["manifest"]["oram"]
    hnsw_result_privacy = fixture["hnsw"]["manifest"]["result_privacy"]
    result_oram = fixture["result"]["manifest"]["oram"]
    local_config = f"""
crypto:
  zero_trust_profile: strict
  instances:
    docs_private_hnsw_v1:
      provider: vector/private-hnsw-oram@v1
      materials: {{}}
      options:
        key_id: tenant-a/vector-private-rk
        expected_rk_id: tenant-a/vector-private-rk
        min_rk_epoch: 7
        max_rk_epoch: 7
        search_execution: client_led
        search_mode: private_hnsw_oram
        result_privacy: {hnsw_result_privacy}
        distance: euclid
        dim: 2
        hnsw:
          m: 2
          ef_construction: 4
          max_layers: 3
          fixed_neighbor_slots: 4
        oram:
          kind: path_oram
          bucket_size: 2
          block_size_bytes: {hnsw_oram["block_size_bytes"]}
          tree_height: {hnsw_oram["tree_height"]}
          path_batch_size: 1
        fixed_budget:
          enabled: true
          upper_layer_steps: 1
          base_layer_steps: 3
          paths_per_round: 1
          fixed_result_k: 1
        integrity:
          manifest_signature_required: true
          commit_signature_required: true
          merkle_root_required: true
        signature_public_keys:
          tenant-a/private-hnsw-signing-v1: {hnsw_public_key}
    docs_private_result_oram_v1:
      provider: payload/private-result-oram@v1
      materials: {{}}
      options:
        key_id: tenant-a/vector-private-rk
        expected_rk_id: tenant-a/vector-private-rk
        min_rk_epoch: 7
        max_rk_epoch: 7
        oram:
          kind: path_oram
          bucket_size: 2
          block_size_bytes: {result_oram["block_size_bytes"]}
          tree_height: {result_oram["tree_height"]}
          path_batch_size: 1
        integrity:
          manifest_signature_required: true
          commit_signature_required: true
          merkle_root_required: true
        signature_public_keys:
          {result_signing_key_id}: {result_public_key}
"""
    (peer_dir / "config" / "local.yaml").write_text(local_config)


def _post_result(url: str, body: dict) -> dict:
    response = requests.post(url, json=body, timeout=30)
    assert_http_ok(response)
    return response.json()["result"]


def _collection_uuid(peer_url: str) -> str:
    response = requests.get(
        f"{peer_url}/telemetry", params={"details_level": 2}, timeout=30
    )
    assert_http_ok(response)
    collections = response.json()["result"]["collections"]["collections"]
    collection = next(item for item in collections if item["id"] == COLLECTION)
    return collection["config"]["uuid"]


def _start_private_oram_cluster(
    tmp_path: pathlib.Path,
    peer_count: int,
    replication_factor: int,
    shard_number: int = 1,
    extra_env: dict[str, str] | None = None,
    fixture_profile: str | None = None,
    include_result_oram: bool = True,
    include_public_vector: bool = False,
    write_consistency_factor: int | None = None,
    started_peer_count: int | None = None,
    sharding_method: str = "auto",
    initial_shard_key: str = "tenant-initial",
    initial_shard_key_placement: list[int] | None = None,
) -> tuple[list[str], list[pathlib.Path], dict, int, str]:
    if started_peer_count is None:
        started_peer_count = peer_count
    assert 1 <= started_peer_count <= peer_count
    result_privacy = None if include_result_oram else IDS_VISIBLE_RESULT_PRIVACY
    bootstrap_fixture = _private_oram_fixture(
        PLACEHOLDER_COLLECTION_ID, fixture_profile, result_privacy
    )
    peer_dirs = make_peer_folders(tmp_path, peer_count)
    for peer_dir in peer_dirs:
        _write_private_oram_runtime_config(peer_dir, bootstrap_fixture)

    bootstrap_api, bootstrap_uri = start_first_peer(
        peer_dirs[0], "private_oram_peer_0.log", extra_env=extra_env
    )
    leader = wait_peer_added(bootstrap_api)
    peer_urls = [bootstrap_api]
    for peer_index, peer_dir in enumerate(
        peer_dirs[1:started_peer_count], start=1
    ):
        peer_urls.append(
            start_peer(
                peer_dir,
                f"private_oram_peer_{peer_index}.log",
                bootstrap_uri,
                extra_env=extra_env,
            )
        )
    wait_for_uniform_cluster_status(peer_urls, leader)
    # Shard transfers and resharding of an encrypted collection need every peer's crypto runtime
    # capability metadata, which a peer proposes only once its Raft node has been idle for a few
    # ticks; on a slow host that can lag cluster formation.
    _wait_for_crypto_runtime_capability_metadata(
        peer_dirs[:started_peer_count], started_peer_count, wait_for_timeout=90
    )

    vectors = {VECTOR: {"size": 2, "distance": "Euclid"}}
    if include_public_vector:
        vectors["public"] = {"size": 2, "distance": "Euclid"}
    encryption_rules = [
        {
            "id": "text_private_hnsw",
            "selector": {"kind": "vector_names", "names": [VECTOR]},
            "instance": "docs_private_hnsw_v1",
            "binding": "private-hnsw-oram/v1",
        }
    ]
    if include_result_oram:
        encryption_rules.append(
            {
                "id": "payload_private_result_oram",
                "selector": {"kind": "payload_paths", "paths": ["body"]},
                "instance": "docs_private_result_oram_v1",
                "binding": "private-result-oram/v1",
            }
        )
    create = requests.put(
        f"{bootstrap_api}/collections/{COLLECTION}",
        json={
            "vectors": vectors,
            "shard_number": shard_number,
            "replication_factor": replication_factor,
            "sharding_method": sharding_method,
            "write_consistency_factor": (
                replication_factor
                if write_consistency_factor is None
                else write_consistency_factor
            ),
            "encryption": {
                "version": 1,
                "key_id": "tenant-a/vector-private-rk",
                "crypto_schema_version": 1,
                "encryption_epoch": 7,
                "migration_state": "active",
                "rules": encryption_rules,
            },
        },
        timeout=30,
    )
    assert_http_ok(create)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)

    if sharding_method == "custom":
        peer_ids = [get_cluster_info(peer_url)["peer_id"] for peer_url in peer_urls]
        placement_indices = (
            list(range(started_peer_count))
            if initial_shard_key_placement is None
            else initial_shard_key_placement
        )
        initial_shard = requests.put(
            f"{bootstrap_api}/collections/{COLLECTION}/shards?timeout=60",
            json={
                "shard_key": initial_shard_key,
                "shards_number": shard_number,
                "replication_factor": replication_factor,
                "placement": [peer_ids[index] for index in placement_indices],
            },
            timeout=60,
        )
        assert_http_ok(initial_shard)
        wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)

    fixture = _private_oram_fixture(
        _collection_uuid(bootstrap_api), fixture_profile, result_privacy
    )
    assert fixture["hnsw_public_key"] == bootstrap_fixture["hnsw_public_key"]
    assert fixture["result_public_key"] == bootstrap_fixture["result_public_key"]
    return peer_urls, peer_dirs, fixture, leader, bootstrap_uri


def _upload_hnsw(peer_url: str, fixture: dict) -> None:
    hnsw = fixture["hnsw"]
    _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/manifest",
        {
            "manifest": hnsw["manifest"],
            "signature": hnsw["manifest_signature"],
        },
    )
    _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/buckets",
        {
            "index_epoch": BASE_EPOCH,
            "root_hash": hnsw["manifest"]["root_hash"],
            "buckets": hnsw["buckets"],
        },
    )


def _open_hnsw_owner_session(
    peer_url: str,
    desired_epoch: int,
    result_privacy: str = "private_payload_oram_required",
) -> dict:
    return _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session",
        {
            "client_id": "tenant-a/multi-peer-hnsw-sdk",
            "desired_epoch": desired_epoch,
            "fixed_budget": True,
            "result_privacy": result_privacy,
        },
    )


def _read_hnsw_owner_session(peer_url: str, fixture: dict, session: dict) -> None:
    hnsw = fixture["hnsw"]
    read = _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/oram/read_paths",
        {
            "session_id": session["session_id"],
            "index_epoch": BASE_EPOCH,
            "root_hash": session["root_hash"],
            "paths": hnsw["read"]["paths"],
            "padding": {"requested_paths": 1, "dummy_paths_included": True},
            "client_signature": hnsw["read"]["signature"],
        },
    )
    assert read["index_epoch"] == BASE_EPOCH
    assert read["root_hash"] == session["root_hash"]
    assert len(read["buckets"]) == hnsw["manifest"]["oram"]["tree_height"] + 1


def _exercise_hnsw_owner_session(peer_url: str, fixture: dict) -> None:
    hnsw = fixture["hnsw"]
    session = _open_hnsw_owner_session(
        peer_url, BASE_EPOCH, hnsw["manifest"]["result_privacy"]
    )
    _read_hnsw_owner_session(peer_url, fixture, session)

    commit = hnsw["commit"]
    committed = _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/oram/commit",
        {
            "session_id": session["session_id"],
            "old_epoch": commit["old_epoch"],
            "new_epoch": commit["new_epoch"],
            "old_root_hash": commit["old_root_hash"],
            "new_root_hash": commit["new_root_hash"],
            "updated_buckets": commit["updated_buckets"],
            "commit_signature": commit["signature"],
        },
    )
    assert committed["index_epoch"] == NEXT_EPOCH
    assert committed["root_hash"] == commit["new_root_hash"]

    closed = _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session/{session['session_id']}/close",
        {},
    )
    assert closed is True


def _upload_result_oram(peer_url: str, fixture: dict) -> None:
    result = fixture["result"]
    _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-result-oram/manifest",
        {
            "manifest": result["manifest"],
            "signature": result["manifest_signature"],
        },
    )
    _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-result-oram/buckets",
        {
            "index_epoch": BASE_EPOCH,
            "root_hash": result["manifest"]["root_hash"],
            "buckets": result["buckets"],
        },
    )


def _open_result_owner_session(peer_url: str, desired_epoch: int) -> dict:
    return _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-result-oram/session",
        {
            "client_id": "tenant-a/multi-peer-result-sdk",
            "desired_epoch": desired_epoch,
            "fixed_budget": True,
        },
    )


def _read_result_owner_session(peer_url: str, fixture: dict, session: dict) -> None:
    result = fixture["result"]
    read = _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-result-oram/oram/read_buckets",
        {
            "session_id": session["session_id"],
            "index_epoch": BASE_EPOCH,
            "root_hash": session["root_hash"],
            "bucket_ids": result["read"]["bucket_ids"],
            "read_signature": result["read"]["signature"],
        },
    )
    assert read["index_epoch"] == BASE_EPOCH
    assert read["root_hash"] == session["root_hash"]
    assert len(read["buckets"]) == len(result["read"]["bucket_ids"])


def _exercise_result_owner_session(peer_url: str, fixture: dict) -> None:
    result = fixture["result"]
    session = _open_result_owner_session(peer_url, BASE_EPOCH)
    _read_result_owner_session(peer_url, fixture, session)

    commit = result["commit"]
    committed = _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-result-oram/oram/commit",
        {
            "session_id": session["session_id"],
            "old_epoch": commit["old_epoch"],
            "new_epoch": commit["new_epoch"],
            "old_root_hash": commit["old_root_hash"],
            "new_root_hash": commit["new_root_hash"],
            "updated_buckets": commit["updated_buckets"],
            "commit_signature": commit["signature"],
        },
    )
    assert committed["index_epoch"] == NEXT_EPOCH
    assert committed["root_hash"] == commit["new_root_hash"]

    closed = _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-result-oram/session/{session['session_id']}/close",
        {},
    )
    assert closed is True


def _assert_replica_can_open_current_sessions(peer_url: str) -> None:
    for endpoint, body in [
        (
            f"private-hnsw/{VECTOR}",
            {
                "client_id": "tenant-a/replica-hnsw-sdk",
                "desired_epoch": NEXT_EPOCH,
                "fixed_budget": True,
                "result_privacy": "private_payload_oram_required",
            },
        ),
        (
            "private-result-oram",
            {
                "client_id": "tenant-a/replica-result-sdk",
                "desired_epoch": NEXT_EPOCH,
                "fixed_budget": True,
            },
        ),
    ]:
        session = _post_result(
            f"{peer_url}/collections/{COLLECTION}/{endpoint}/session", body
        )
        assert session["index_epoch"] == NEXT_EPOCH
        close_endpoint = (
            f"private-hnsw/{VECTOR}"
            if endpoint.startswith("private-hnsw")
            else "private-result-oram"
        )
        assert (
            _post_result(
                f"{peer_url}/collections/{COLLECTION}/{close_endpoint}/session/{session['session_id']}/close",
                {},
            )
            is True
        )


def test_private_oram_sessions_replicate_through_public_routes(tmp_path: pathlib.Path):
    peer_urls, _, fixture, _, _ = _start_private_oram_cluster(tmp_path, 2, 2)
    bootstrap_api, replica_api = peer_urls

    _upload_hnsw(bootstrap_api, fixture)
    _exercise_hnsw_owner_session(bootstrap_api, fixture)
    _upload_result_oram(bootstrap_api, fixture)
    _exercise_result_owner_session(bootstrap_api, fixture)
    _assert_replica_can_open_current_sessions(replica_api)


def test_private_oram_replica_removal_requires_idle_index_and_retains_owner(
    tmp_path: pathlib.Path,
):
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(tmp_path, 2, 2)
    coordinator_url, removed_url = peer_urls
    coordinator_info = get_collection_cluster_info(coordinator_url, COLLECTION)
    removed_peer_id = get_cluster_info(removed_url)["peer_id"]
    shard_id = coordinator_info["local_shards"][0]["shard_id"]

    _upload_hnsw(coordinator_url, fixture)
    _exercise_hnsw_owner_session(coordinator_url, fixture)
    _upload_result_oram(coordinator_url, fixture)
    _exercise_result_owner_session(coordinator_url, fixture)

    active_session = _open_hnsw_owner_session(coordinator_url, NEXT_EPOCH)
    drop_body = {
        "drop_replica": {
            "shard_id": shard_id,
            "peer_id": removed_peer_id,
        }
    }
    blocked = requests.post(
        f"{coordinator_url}/collections/{COLLECTION}/cluster",
        json=drop_body,
        timeout=60,
    )
    assert 400 <= blocked.status_code < 600
    for secret in [active_session["session_id"], active_session["root_hash"]]:
        assert secret not in blocked.text

    assert (
        _post_result(
            f"{coordinator_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session/{active_session['session_id']}/close",
            {},
        )
        is True
    )

    removed = requests.post(
        f"{coordinator_url}/collections/{COLLECTION}/cluster",
        json=drop_body,
        timeout=60,
    )
    assert_http_ok(removed)
    wait_for_collection_local_shards_count(removed_url, COLLECTION, 0)
    wait_for_collection_local_shards_count(coordinator_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(coordinator_url, COLLECTION, 0)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)

    assert _private_oram_buckets_dir(peer_dirs[1], "hnsw").is_dir()
    assert _private_oram_buckets_dir(peer_dirs[1], "result").is_dir()
    _assert_replica_can_open_current_sessions(coordinator_url)

    rejected_sessions = [
        (
            f"private-hnsw/{VECTOR}",
            {
                "client_id": "tenant-a/removed-hnsw-sdk",
                "desired_epoch": NEXT_EPOCH,
                "fixed_budget": True,
                "result_privacy": "private_payload_oram_required",
            },
        ),
        (
            "private-result-oram",
            {
                "client_id": "tenant-a/removed-result-sdk",
                "desired_epoch": NEXT_EPOCH,
                "fixed_budget": True,
            },
        ),
    ]
    for endpoint, body in rejected_sessions:
        response = requests.post(
            f"{removed_url}/collections/{COLLECTION}/{endpoint}/session",
            json=body,
            timeout=30,
        )
        assert 400 <= response.status_code < 600
        for secret in [
            fixture["hnsw"]["commit"]["new_root_hash"],
            fixture["result"]["commit"]["new_root_hash"],
        ]:
            assert secret not in response.text


def test_private_oram_custom_shard_key_layout_mutation_is_consensus_bound(
    tmp_path: pathlib.Path,
):
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(
        tmp_path,
        3,
        2,
        sharding_method="custom",
        initial_shard_key="tenant-drop",
        initial_shard_key_placement=[0, 1],
    )
    coordinator_url, removed_owner_url, new_owner_url = peer_urls
    peer_ids = [get_cluster_info(peer_url)["peer_id"] for peer_url in peer_urls]

    _upload_hnsw(coordinator_url, fixture)
    _exercise_hnsw_owner_session(coordinator_url, fixture)
    _upload_result_oram(coordinator_url, fixture)
    _exercise_result_owner_session(coordinator_url, fixture)
    assert all(_private_oram_layout_state(peer_dir) is None for peer_dir in peer_dirs)

    create_retained = requests.put(
        f"{coordinator_url}/collections/{COLLECTION}/shards?timeout=60",
        json={
            "shard_key": "tenant-retained",
            "shards_number": 1,
            "replication_factor": 1,
            "placement": [peer_ids[0]],
        },
        timeout=60,
    )
    assert_http_ok(create_retained)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    wait_for_collection_local_shards_count(coordinator_url, COLLECTION, 2)
    wait_for_collection_local_shards_count(removed_owner_url, COLLECTION, 1)
    wait_for_collection_local_shards_count(new_owner_url, COLLECTION, 0)
    _wait_for_private_oram_layout(peer_dirs, 2, peer_ids[:2])
    _assert_replica_can_open_current_sessions(removed_owner_url)

    new_owner_request = {
        "shard_key": "tenant-new-owner",
        "shards_number": 1,
        "replication_factor": 1,
        "placement": [peer_ids[2]],
    }
    malformed_store = (
        peer_dirs[2]
        / "storage"
        / "collections"
        / COLLECTION
        / "private_result_oram"
    )
    malformed_epochs = malformed_store / "epochs"
    malformed_epochs.mkdir(parents=True)
    (malformed_epochs / "current.json").write_text("{}")
    try:
        failed_new_owner = requests.put(
            f"{coordinator_url}/collections/{COLLECTION}/shards?timeout=60",
            json=new_owner_request,
            timeout=60,
        )
    finally:
        shutil.rmtree(malformed_store)
    assert 400 <= failed_new_owner.status_code < 600
    for secret in [
        fixture["hnsw"]["commit"]["new_root_hash"],
        fixture["result"]["commit"]["new_root_hash"],
    ]:
        assert secret not in failed_new_owner.text
    wait_for_collection_local_shards_count(new_owner_url, COLLECTION, 0)
    _wait_for_private_oram_layout(peer_dirs, 2, peer_ids[:2])
    assert _private_oram_buckets_dir(peer_dirs[2], "hnsw").is_dir()

    create_new_owner = requests.put(
        f"{coordinator_url}/collections/{COLLECTION}/shards?timeout=60",
        json=new_owner_request,
        timeout=60,
    )
    assert_http_ok(create_new_owner)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    wait_for_collection_local_shards_count(coordinator_url, COLLECTION, 2)
    wait_for_collection_local_shards_count(removed_owner_url, COLLECTION, 1)
    wait_for_collection_local_shards_count(new_owner_url, COLLECTION, 1)
    _wait_for_private_oram_layout(peer_dirs, 3, peer_ids)
    assert _private_oram_buckets_dir(peer_dirs[2], "hnsw").is_dir()
    assert _private_oram_buckets_dir(peer_dirs[2], "result").is_dir()
    _assert_replica_can_open_current_sessions(new_owner_url)

    drop_initial = requests.post(
        f"{coordinator_url}/collections/{COLLECTION}/shards/delete?timeout=60",
        json={"shard_key": "tenant-drop"},
        timeout=60,
    )
    assert_http_ok(drop_initial)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    wait_for_collection_local_shards_count(coordinator_url, COLLECTION, 1)
    wait_for_collection_local_shards_count(removed_owner_url, COLLECTION, 0)
    wait_for_collection_local_shards_count(new_owner_url, COLLECTION, 1)
    _wait_for_private_oram_layout(peer_dirs, 4, [peer_ids[0], peer_ids[2]])
    _assert_replica_can_open_current_sessions(coordinator_url)
    _assert_replica_can_open_current_sessions(new_owner_url)

    assert _private_oram_buckets_dir(peer_dirs[1], "hnsw").is_dir()
    assert _private_oram_buckets_dir(peer_dirs[1], "result").is_dir()
    removed_owner_session = requests.post(
        f"{removed_owner_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session",
        json={
            "client_id": "tenant-a/removed-shard-key-owner",
            "desired_epoch": NEXT_EPOCH,
            "fixed_budget": True,
            "result_privacy": "private_payload_oram_required",
        },
        timeout=30,
    )
    assert 400 <= removed_owner_session.status_code < 600

    drop_new_owner = requests.post(
        f"{coordinator_url}/collections/{COLLECTION}/shards/delete?timeout=60",
        json={"shard_key": "tenant-new-owner"},
        timeout=60,
    )
    assert_http_ok(drop_new_owner)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    wait_for_collection_local_shards_count(coordinator_url, COLLECTION, 1)
    wait_for_collection_local_shards_count(removed_owner_url, COLLECTION, 0)
    wait_for_collection_local_shards_count(new_owner_url, COLLECTION, 0)
    _wait_for_private_oram_layout(peer_dirs, 5, [peer_ids[0]])
    assert _private_oram_buckets_dir(peer_dirs[2], "hnsw").is_dir()
    assert _private_oram_buckets_dir(peer_dirs[2], "result").is_dir()
    removed_new_owner_session = requests.post(
        f"{new_owner_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session",
        json={
            "client_id": "tenant-a/removed-new-shard-key-owner",
            "desired_epoch": NEXT_EPOCH,
            "fixed_budget": True,
            "result_privacy": "private_payload_oram_required",
        },
        timeout=30,
    )
    assert 400 <= removed_new_owner_session.status_code < 600

    final_drop = requests.post(
        f"{coordinator_url}/collections/{COLLECTION}/shards/delete?timeout=60",
        json={"shard_key": "tenant-retained"},
        timeout=60,
    )
    assert 400 <= final_drop.status_code < 600
    _wait_for_private_oram_layout(peer_dirs, 5, [peer_ids[0]])


def test_private_oram_existing_layout_advances_after_replica_removal_and_transfer(
    tmp_path: pathlib.Path,
):
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(
        tmp_path, 3, 3
    )
    coordinator_url = peer_urls[0]
    removed_index = 1
    removed_url = peer_urls[removed_index]
    peer_ids = [get_cluster_info(peer_url)["peer_id"] for peer_url in peer_urls]
    coordinator_info = get_collection_cluster_info(coordinator_url, COLLECTION)
    shard_id = coordinator_info["local_shards"][0]["shard_id"]

    _upload_hnsw(coordinator_url, fixture)
    _exercise_hnsw_owner_session(coordinator_url, fixture)
    _upload_result_oram(coordinator_url, fixture)
    _exercise_result_owner_session(coordinator_url, fixture)

    removed = requests.post(
        f"{coordinator_url}/collections/{COLLECTION}/cluster",
        json={
            "drop_replica": {
                "shard_id": shard_id,
                "peer_id": peer_ids[removed_index],
            }
        },
        timeout=60,
    )
    assert_http_ok(removed)
    wait_for_collection_local_shards_count(removed_url, COLLECTION, 0)
    wait_for_collection_shard_transfers_count(coordinator_url, COLLECTION, 0)
    remaining_peer_ids = [
        peer_id for index, peer_id in enumerate(peer_ids) if index != removed_index
    ]
    _wait_for_private_oram_layout(peer_dirs, 2, remaining_peer_ids)

    replicated = _request_private_oram_shard_transfer(
        coordinator_url,
        "replicate_shard",
        shard_id,
        peer_ids[0],
        peer_ids[removed_index],
    )
    assert_http_ok(replicated)
    wait_for_collection_local_shards_count(removed_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(coordinator_url, COLLECTION, 0)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    _assert_replica_can_open_current_sessions(removed_url)
    _wait_for_private_oram_layout(peer_dirs, 3, peer_ids)


def test_private_oram_dead_replica_automatically_recovers_from_source(
    tmp_path: pathlib.Path,
):
    peer_urls, peer_dirs, fixture, leader, _ = _start_private_oram_cluster(
        tmp_path,
        3,
        2,
        shard_number=2,
        include_result_oram=False,
        include_public_vector=True,
        write_consistency_factor=1,
    )
    peer_ids = [get_cluster_info(peer_url)["peer_id"] for peer_url in peer_urls]
    cluster_infos = [
        get_collection_cluster_info(peer_url, COLLECTION) for peer_url in peer_urls
    ]
    replica_indices = [
        index for index, info in enumerate(cluster_infos) if info["local_shards"]
    ]
    assert len(replica_indices) >= 2
    target_index = next(
        index for index in replica_indices if peer_ids[index] != leader
    )
    source_index = next(index for index in replica_indices if index != target_index)
    source_url = peer_urls[source_index]
    target_url = peer_urls[target_index]
    target_peer_id = peer_ids[target_index]
    shard_id = cluster_infos[target_index]["local_shards"][0]["shard_id"]

    _upload_hnsw(source_url, fixture)
    _exercise_hnsw_owner_session(source_url, fixture)
    # The source's lease release reaches the target through consensus, so the target can
    # refuse a session for a moment after the source's close returned.
    replicated_session = {}

    def replicated_session_opens() -> bool:
        try:
            replicated_session.update(
                _open_hnsw_owner_session(target_url, NEXT_EPOCH, IDS_VISIBLE_RESULT_PRIVACY)
            )
        except Exception:  # noqa: BLE001 - HTTP helpers raise plain Exception
            return False
        return True

    wait_for(replicated_session_opens, wait_for_timeout=30)
    assert replicated_session["root_hash"] == fixture["hnsw"]["commit"][
        "new_root_hash"
    ]
    assert (
        _post_result(
            f"{target_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session/{replicated_session['session_id']}/close",
            {},
        )
        is True
    )

    initial_write = requests.put(
        f"{source_url}/collections/{COLLECTION}/points?wait=true",
        json={"points": [{"id": 1, "vector": {"public": [1.0, 0.0]}}]},
        timeout=30,
    )
    assert_http_ok(initial_write)

    target_port = processes[target_index].p2p_port
    restart_bootstrap_uri = get_uri(processes[source_index].p2p_port)
    processes.pop(target_index).kill()

    dead_replica_write = requests.put(
        f"{source_url}/collections/{COLLECTION}/points?wait=true",
        json={
            "points": [
                {"id": point_id, "vector": {"public": [float(point_id), 1.0]}}
                for point_id in range(2, 10)
            ]
        },
        timeout=30,
    )
    assert_http_ok(dead_replica_write)

    def target_replica_is_dead() -> bool:
        info = get_collection_cluster_info(source_url, COLLECTION)
        return any(
            shard["shard_id"] == shard_id
            and shard.get("peer_id") == target_peer_id
            and shard["state"] == "Dead"
            for shard in info["remote_shards"]
        )

    wait_for(target_replica_is_dead, wait_for_timeout=60)

    target_hnsw_store = _private_oram_buckets_dir(
        peer_dirs[target_index], "hnsw"
    ).parents[1]
    shutil.rmtree(target_hnsw_store)

    restarted_url = start_peer(
        peer_dirs[target_index],
        "private_oram_peer_automatic_recovery.log",
        restart_bootstrap_uri,
        port=target_port,
    )
    peer_urls[target_index] = restarted_url
    wait_for_peer_online(restarted_url, path="/cluster")
    wait_for_uniform_cluster_status(peer_urls, leader)
    wait_for(
        lambda: target_hnsw_store.is_dir(),
        wait_for_timeout=60,
    )
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)

    recovered_session = _open_hnsw_owner_session(
        restarted_url,
        NEXT_EPOCH,
        IDS_VISIBLE_RESULT_PRIVACY,
    )
    assert recovered_session["root_hash"] == fixture["hnsw"]["commit"][
        "new_root_hash"
    ]
    assert (
        _post_result(
            f"{restarted_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session/{recovered_session['session_id']}/close",
            {},
        )
        is True
    )
    active_owner_peer_ids = [
        peer_ids[index]
        for index, peer_url in enumerate(peer_urls)
        if get_collection_cluster_info(peer_url, COLLECTION)["local_shards"]
    ]
    # The first recovery transfer records layout generation 1 and every finished one advances
    # it; placement decides whether the target held one shard or both.
    recovered_shard_count = len(cluster_infos[target_index]["local_shards"])
    _wait_for_private_oram_layout(
        peer_dirs, 1 + recovered_shard_count, active_owner_peer_ids
    )


def _private_oram_transfer_peers(
    peer_urls: list[str],
) -> tuple[int, int, str, str, dict, dict]:
    cluster_infos = [
        get_collection_cluster_info(peer_url, COLLECTION) for peer_url in peer_urls
    ]
    source_indices = [
        index for index, info in enumerate(cluster_infos) if info["local_shards"]
    ]
    assert len(source_indices) == 1
    source_index = source_indices[0]
    target_index = next(
        index for index in range(len(peer_urls)) if index != source_index
    )
    return (
        source_index,
        target_index,
        peer_urls[source_index],
        peer_urls[target_index],
        cluster_infos[source_index],
        cluster_infos[target_index],
    )


def _request_private_oram_shard_transfer(
    source_url: str,
    transfer_operation: str,
    shard_id: int,
    source_peer_id: int,
    target_peer_id: int,
) -> requests.Response:
    return requests.post(
        f"{source_url}/collections/{COLLECTION}/cluster",
        json={
            transfer_operation: {
                "shard_id": shard_id,
                "from_peer_id": source_peer_id,
                "to_peer_id": target_peer_id,
                "method": "stream_records",
            }
        },
        timeout=60,
    )


def _request_private_oram_resharding_transfer(
    source_url: str,
    transfer_operation: str,
    source_shard_id: int,
    target_shard_id: int,
    source_peer_id: int,
    target_peer_id: int,
) -> requests.Response:
    return requests.post(
        f"{source_url}/collections/{COLLECTION}/cluster",
        json={
            transfer_operation: {
                "shard_id": source_shard_id,
                "to_shard_id": target_shard_id,
                "from_peer_id": source_peer_id,
                "to_peer_id": target_peer_id,
                "method": "resharding_stream_records",
            }
        },
        timeout=60,
    )


def _private_oram_layout_state(peer_dir: pathlib.Path) -> dict | None:
    try:
        with open(peer_dir / "storage" / "raft_state.json") as state_file:
            layouts = json.load(state_file).get("private_oram_layouts", {})
    except (OSError, json.JSONDecodeError):
        return None
    if len(layouts) != 1:
        return None
    return next(iter(layouts.values()))


def _wait_for_private_oram_layout(
    peer_dirs: list[pathlib.Path], generation: int, owner_peer_ids: list[int]
) -> None:
    expected_owners = sorted(owner_peer_ids)
    observed = {}

    def layouts_match() -> bool:
        for peer_dir in peer_dirs:
            observed[peer_dir.name] = _private_oram_layout_state(peer_dir)
        return all(
            state is not None
            and state["generation"] == generation
            and state["owner_peer_ids"] == expected_owners
            for state in observed.values()
        )

    try:
        wait_for(layouts_match, wait_for_timeout=30)
    except Exception as error:  # noqa: BLE001 - wait_for raises plain Exception
        raise AssertionError(
            f"private ORAM layout is not generation {generation} with owners "
            f"{expected_owners} on every peer; last seen: {observed}"
        ) from error


def _wait_for_private_oram_epochs(
    peer_dirs: list[pathlib.Path], index_epoch: int, expected_count: int
) -> None:
    def epochs_match(peer_dir: pathlib.Path) -> bool:
        try:
            with open(peer_dir / "storage" / "raft_state.json") as state_file:
                epochs = json.load(state_file).get("private_oram_epochs", {})
        except (OSError, json.JSONDecodeError):
            return False
        return len(epochs) == expected_count and all(
            epoch["index_epoch"] == index_epoch for epoch in epochs.values()
        )

    wait_for(
        lambda: all(epochs_match(peer_dir) for peer_dir in peer_dirs),
        wait_for_timeout=30,
    )


def _wait_for_private_oram_session_leases_released(peer_dirs: list[pathlib.Path]) -> None:
    """Shard transfers and resharding of an encrypted collection take its session lease, which
    each peer checks against its own consensus state; a release proposed by another peer (an
    upload's or a closed session's) reaches it a moment later."""

    def released(peer_dir: pathlib.Path) -> bool:
        try:
            with open(peer_dir / "storage" / "raft_state.json") as state_file:
                leases = json.load(state_file).get("private_oram_session_leases", {})
        except (OSError, json.JSONDecodeError):
            return False
        return not leases

    wait_for(
        lambda: all(released(peer_dir) for peer_dir in peer_dirs),
        wait_for_timeout=30,
    )


def _wait_for_crypto_runtime_capability_metadata(
    peer_dirs: list[pathlib.Path], expected_count: int, wait_for_timeout: int = 30
) -> None:
    def metadata_match(peer_dir: pathlib.Path) -> bool:
        try:
            with open(peer_dir / "storage" / "raft_state.json") as state_file:
                metadata = json.load(state_file).get("peer_metadata_by_id", {})
        except (OSError, json.JSONDecodeError):
            return False
        return len(metadata) == expected_count and all(
            peer_metadata.get("crypto_runtime_capability_fingerprint")
            for peer_metadata in metadata.values()
        )

    wait_for(
        lambda: all(metadata_match(peer_dir) for peer_dir in peer_dirs),
        wait_for_timeout=wait_for_timeout,
    )


def _assert_private_oram_sessions_blocked_during_resharding(
    peer_url: str, fixture: dict, include_result_oram: bool
) -> None:
    hnsw = requests.post(
        f"{peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session",
        json={
            "client_id": "tenant-a/resharding-blocked-hnsw-sdk",
            "desired_epoch": NEXT_EPOCH,
            "fixed_budget": True,
            "result_privacy": fixture["hnsw"]["manifest"]["result_privacy"],
        },
        timeout=30,
    )
    assert 400 <= hnsw.status_code < 600
    assert "stable shard topology" in hnsw.text
    assert fixture["hnsw"]["commit"]["new_root_hash"] not in hnsw.text

    if include_result_oram:
        result = requests.post(
            f"{peer_url}/collections/{COLLECTION}/private-result-oram/session",
            json={
                "client_id": "tenant-a/resharding-blocked-result-sdk",
                "desired_epoch": NEXT_EPOCH,
                "fixed_budget": True,
            },
            timeout=30,
        )
        assert 400 <= result.status_code < 600
        assert "stable shard topology" in result.text
        assert fixture["result"]["commit"]["new_root_hash"] not in result.text


def _open_when_lease_free(open_session) -> dict:
    """Opens a session once the collection's session lease is free. A lease released by another
    peer reaches this one through consensus, so an open right after that close can still be
    refused for a moment."""
    opened = {}

    def opens() -> bool:
        try:
            opened.update(open_session())
        except Exception:  # noqa: BLE001 - HTTP helpers raise plain Exception
            return False
        return True

    wait_for(opens, wait_for_timeout=30)
    return opened


def _assert_private_oram_owner_sessions(
    peer_url: str, fixture: dict, include_result_oram: bool
) -> None:
    hnsw = _open_when_lease_free(
        lambda: _open_hnsw_owner_session(
            peer_url,
            NEXT_EPOCH,
            fixture["hnsw"]["manifest"]["result_privacy"],
        )
    )
    assert hnsw["root_hash"] == fixture["hnsw"]["commit"]["new_root_hash"]
    assert (
        _post_result(
            f"{peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session/{hnsw['session_id']}/close",
            {},
        )
        is True
    )

    if include_result_oram:
        result = _open_when_lease_free(lambda: _open_result_owner_session(peer_url, NEXT_EPOCH))
        assert result["root_hash"] == fixture["result"]["commit"]["new_root_hash"]
        assert (
            _post_result(
                f"{peer_url}/collections/{COLLECTION}/private-result-oram/session/{result['session_id']}/close",
                {},
            )
            is True
        )


@pytest.mark.parametrize(
    "include_result_oram",
    [False, True],
    ids=["hnsw-only", "hnsw-result"],
)
def test_private_oram_scale_up_resharding_preserves_encrypted_store_and_sessions(
    tmp_path: pathlib.Path,
    include_result_oram: bool,
):
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(
        tmp_path,
        2,
        1,
        include_result_oram=include_result_oram,
        include_public_vector=True,
        extra_env={"QDRANT__CLUSTER__RESHARDING_ENABLED": "true"},
    )
    _, _, source_url, target_url, source_info, target_info = (
        _private_oram_transfer_peers(peer_urls)
    )
    source_peer_id = source_info["peer_id"]
    target_peer_id = target_info["peer_id"]
    source_shard_id = source_info["local_shards"][0]["shard_id"]
    target_shard_id = source_shard_id + 1

    if not include_result_oram:
        points = requests.put(
            f"{source_url}/collections/{COLLECTION}/points?wait=true",
            json={
                "points": [
                    {"id": point_id, "vector": {"public": [float(point_id), 1.0]}}
                    for point_id in range(16)
                ]
            },
            timeout=30,
        )
        assert_http_ok(points)

    _upload_hnsw(source_url, fixture)
    _exercise_hnsw_owner_session(source_url, fixture)
    if include_result_oram:
        _upload_result_oram(source_url, fixture)
        _exercise_result_owner_session(source_url, fixture)

    started = start_resharding(
        source_url,
        collection=COLLECTION,
        direction="up",
        peer_id=target_peer_id,
    )
    assert_http_ok(started)
    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 1)

    _assert_private_oram_sessions_blocked_during_resharding(
        source_url, fixture, include_result_oram
    )

    migrate_points(
        source_url,
        source_peer_id,
        source_shard_id,
        target_peer_id,
        target_shard_id,
        "up",
        collection=COLLECTION,
    )
    activate_replica(
        source_url,
        target_peer_id,
        target_shard_id,
        collection=COLLECTION,
    )
    assert_http_ok(commit_read_hashring(source_url, collection=COLLECTION))
    assert_http_ok(commit_write_hashring(source_url, collection=COLLECTION))
    assert_http_ok(finish_resharding(source_url, collection=COLLECTION))

    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 0)
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    _wait_for_private_oram_layout(
        peer_dirs,
        2,
        [source_peer_id, target_peer_id],
    )

    assert _private_oram_buckets_dir(peer_dirs[0], "hnsw").is_dir()
    assert _private_oram_buckets_dir(peer_dirs[1], "hnsw").is_dir()
    if include_result_oram:
        assert _private_oram_buckets_dir(peer_dirs[0], "result").is_dir()
        assert _private_oram_buckets_dir(peer_dirs[1], "result").is_dir()
    for owner_url in [source_url, target_url]:
        _assert_private_oram_owner_sessions(owner_url, fixture, include_result_oram)

    if not include_result_oram:
        retrieved = requests.post(
            f"{source_url}/collections/{COLLECTION}/points",
            json={
                "ids": list(range(16)),
                "with_payload": False,
                "with_vector": False,
            },
            timeout=30,
        )
        assert_http_ok(retrieved)
        assert sorted(point["id"] for point in retrieved.json()["result"]) == list(
            range(16)
        )


@pytest.mark.parametrize(
    "include_result_oram",
    [False, True],
    ids=["hnsw-only", "hnsw-result"],
)
def test_private_oram_scale_down_resharding_preserves_encrypted_store_and_sessions(
    tmp_path: pathlib.Path,
    include_result_oram: bool,
):
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(
        tmp_path,
        2,
        2,
        shard_number=2,
        include_result_oram=include_result_oram,
        include_public_vector=True,
        extra_env={"QDRANT__CLUSTER__RESHARDING_ENABLED": "true"},
    )
    source_url, receiver_url = peer_urls
    source_peer_id = get_cluster_info(source_url)["peer_id"]
    receiver_peer_id = get_cluster_info(receiver_url)["peer_id"]
    source_info = get_collection_cluster_info(source_url, COLLECTION)
    target_shard_id = max(shard["shard_id"] for shard in source_info["local_shards"])
    receiver_shard_id = min(shard["shard_id"] for shard in source_info["local_shards"])

    if not include_result_oram:
        points = requests.put(
            f"{source_url}/collections/{COLLECTION}/points?wait=true",
            json={
                "points": [
                    {"id": point_id, "vector": {"public": [float(point_id), 1.0]}}
                    for point_id in range(16)
                ]
            },
            timeout=30,
        )
        assert_http_ok(points)

    _upload_hnsw(source_url, fixture)
    _exercise_hnsw_owner_session(source_url, fixture)
    if include_result_oram:
        _upload_result_oram(source_url, fixture)
        _exercise_result_owner_session(source_url, fixture)

    started = start_resharding(
        source_url,
        collection=COLLECTION,
        direction="down",
        peer_id=source_peer_id,
    )
    assert_http_ok(started)
    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 1)

    _assert_private_oram_sessions_blocked_during_resharding(
        source_url, fixture, include_result_oram
    )

    for destination_peer_id in [source_peer_id, receiver_peer_id]:
        migrate_points(
            source_url,
            destination_peer_id,
            receiver_shard_id,
            source_peer_id,
            target_shard_id,
            "down",
            collection=COLLECTION,
        )
        activate_replica(
            source_url,
            destination_peer_id,
            receiver_shard_id,
            collection=COLLECTION,
        )
    assert_http_ok(commit_read_hashring(source_url, collection=COLLECTION))
    assert_http_ok(commit_write_hashring(source_url, collection=COLLECTION))
    assert_http_ok(finish_resharding(source_url, collection=COLLECTION))

    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 0)
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    _wait_for_private_oram_layout(
        peer_dirs,
        2,
        [source_peer_id, receiver_peer_id],
    )
    assert _private_oram_buckets_dir(peer_dirs[0], "hnsw").is_dir()
    assert _private_oram_buckets_dir(peer_dirs[1], "hnsw").is_dir()
    if include_result_oram:
        assert _private_oram_buckets_dir(peer_dirs[0], "result").is_dir()
        assert _private_oram_buckets_dir(peer_dirs[1], "result").is_dir()

    for owner_url in [source_url, receiver_url]:
        info = get_collection_cluster_info(owner_url, COLLECTION)
        assert {shard["shard_id"] for shard in info["local_shards"]} == {
            receiver_shard_id
        }
        _assert_private_oram_owner_sessions(owner_url, fixture, include_result_oram)

    if not include_result_oram:
        retrieved = requests.post(
            f"{source_url}/collections/{COLLECTION}/points",
            json={
                "ids": list(range(16)),
                "with_payload": False,
                "with_vector": False,
            },
            timeout=30,
        )
        assert_http_ok(retrieved)
        assert sorted(point["id"] for point in retrieved.json()["result"]) == list(
            range(16)
        )


@pytest.mark.parametrize("transfer_operation", ["replicate_shard", "move_shard"])
def test_private_oram_shard_transfer_preinstalls_live_store(
    tmp_path: pathlib.Path, transfer_operation: str
):
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(tmp_path, 2, 1)
    _, _, source_url, target_url, source_info, target_info = (
        _private_oram_transfer_peers(peer_urls)
    )

    assert not target_info["local_shards"]
    shard_id = source_info["local_shards"][0]["shard_id"]

    _upload_hnsw(source_url, fixture)
    _exercise_hnsw_owner_session(source_url, fixture)
    _upload_result_oram(source_url, fixture)
    _exercise_result_owner_session(source_url, fixture)

    transfer = _request_private_oram_shard_transfer(
        source_url,
        transfer_operation,
        shard_id,
        source_info["peer_id"],
        target_info["peer_id"],
    )
    assert_http_ok(transfer)

    wait_for_collection_local_shards_count(target_url, COLLECTION, 1)
    wait_for_collection_local_shards_count(
        source_url,
        COLLECTION,
        1 if transfer_operation == "replicate_shard" else 0,
    )
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    _assert_replica_can_open_current_sessions(target_url)

    expected_owners = (
        [target_info["peer_id"]]
        + (
            [source_info["peer_id"]]
            if transfer_operation == "replicate_shard"
            else []
        )
    )
    _wait_for_private_oram_layout(peer_dirs, 2, expected_owners)


def test_private_oram_multi_shard_union_replication_and_transfer(
    tmp_path: pathlib.Path,
):
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(
        tmp_path,
        3,
        1,
        shard_number=2,
    )
    cluster_infos = [
        get_collection_cluster_info(peer_url, COLLECTION) for peer_url in peer_urls
    ]
    owner_indices = [
        index for index, info in enumerate(cluster_infos) if info["local_shards"]
    ]
    target_indices = [
        index for index, info in enumerate(cluster_infos) if not info["local_shards"]
    ]
    assert len(owner_indices) == 2
    assert len(target_indices) == 1

    source_index, other_owner_index = owner_indices
    target_index = target_indices[0]
    source_url = peer_urls[source_index]
    other_owner_url = peer_urls[other_owner_index]
    target_url = peer_urls[target_index]
    source_info = cluster_infos[source_index]
    target_info = cluster_infos[target_index]
    shard_id = source_info["local_shards"][0]["shard_id"]

    _upload_hnsw(source_url, fixture)
    _exercise_hnsw_owner_session(source_url, fixture)
    _upload_result_oram(source_url, fixture)
    _exercise_result_owner_session(source_url, fixture)
    _assert_replica_can_open_current_sessions(other_owner_url)
    assert not list(
        peer_dirs[target_index].rglob(f"private_hnsw_oram/{VECTOR}/buckets")
    )
    assert not list(peer_dirs[target_index].rglob("private_result_oram/buckets"))

    transfer = _request_private_oram_shard_transfer(
        source_url,
        "replicate_shard",
        shard_id,
        source_info["peer_id"],
        target_info["peer_id"],
    )
    assert_http_ok(transfer)
    wait_for_collection_local_shards_count(target_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    assert _private_oram_buckets_dir(peer_dirs[target_index], "hnsw").is_dir()
    assert _private_oram_buckets_dir(peer_dirs[target_index], "result").is_dir()
    _assert_replica_can_open_current_sessions(target_url)


@pytest.mark.skipif(
    os.environ.get(RUN_LARGE_BUNDLE_BENCHMARK) != "1",
    reason=f"set {RUN_LARGE_BUNDLE_BENCHMARK}=1 to run the large bundle benchmark",
)
def test_private_oram_large_live_bundle_transfer_benchmark(tmp_path: pathlib.Path):
    peer_urls, _, fixture, _, _ = _start_private_oram_cluster(
        tmp_path,
        2,
        1,
        fixture_profile=LARGE_FIXTURE_PROFILE,
    )
    _, _, source_url, target_url, source_info, target_info = (
        _private_oram_transfer_peers(peer_urls)
    )
    shard_id = source_info["local_shards"][0]["shard_id"]
    mib = 1024 * 1024
    hnsw_ciphertext_base64_bytes = sum(
        len(bucket["ciphertext"].encode("ascii"))
        for bucket in fixture["hnsw"]["buckets"]
    )
    result_ciphertext_base64_bytes = sum(
        len(bucket["ciphertext"].encode("ascii"))
        for bucket in fixture["result"]["buckets"]
    )
    assert hnsw_ciphertext_base64_bytes >= 10 * mib
    assert result_ciphertext_base64_bytes >= 5 * mib

    hnsw_started = time.perf_counter()
    _upload_hnsw(source_url, fixture)
    _exercise_hnsw_owner_session(source_url, fixture)
    hnsw_seconds = time.perf_counter() - hnsw_started

    result_started = time.perf_counter()
    _upload_result_oram(source_url, fixture)
    _exercise_result_owner_session(source_url, fixture)
    result_seconds = time.perf_counter() - result_started

    log_folder = pathlib.Path(init_pytest_log_folder())
    log_paths = [
        log_folder / "private_oram_peer_0.log",
        log_folder / "private_oram_peer_1.log",
    ]
    log_offsets = {path: path.stat().st_size for path in log_paths}
    transfer_started = time.perf_counter()
    transfer = _request_private_oram_shard_transfer(
        source_url,
        "replicate_shard",
        shard_id,
        source_info["peer_id"],
        target_info["peer_id"],
    )
    preinstall_seconds = time.perf_counter() - transfer_started
    assert_http_ok(transfer)
    wait_for_collection_local_shards_count(target_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    transfer_seconds = time.perf_counter() - transfer_started
    _assert_replica_can_open_current_sessions(target_url)
    transfer_logs = "".join(
        path.read_bytes()[log_offsets[path] :].decode("utf-8", errors="replace")
        for path in log_paths
    )
    assert "Timeout expired" not in transfer_logs
    assert "Healthcheck timeout" not in transfer_logs
    assert "starting a new election" not in transfer_logs

    print(
        "PRIVATE_ORAM_LARGE_BUNDLE_BENCHMARK "
        + json.dumps(
            {
                "bucket_count": len(fixture["hnsw"]["buckets"]),
                "hnsw_ciphertext_base64_mib": round(
                    hnsw_ciphertext_base64_bytes / mib, 3
                ),
                "result_ciphertext_base64_mib": round(
                    result_ciphertext_base64_bytes / mib, 3
                ),
                "hnsw_upload_commit_seconds": round(hnsw_seconds, 3),
                "result_upload_commit_seconds": round(result_seconds, 3),
                "live_preinstall_submit_seconds": round(preinstall_seconds, 3),
                "replicate_active_seconds": round(transfer_seconds, 3),
            },
            sort_keys=True,
        )
    )


def test_private_oram_partial_live_preinstall_fails_closed_and_retries(
    tmp_path: pathlib.Path,
):
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(tmp_path, 2, 1)
    _, target_index, source_url, target_url, source_info, target_info = (
        _private_oram_transfer_peers(peer_urls)
    )
    shard_id = source_info["local_shards"][0]["shard_id"]

    _upload_hnsw(source_url, fixture)
    _exercise_hnsw_owner_session(source_url, fixture)
    _upload_result_oram(source_url, fixture)
    _exercise_result_owner_session(source_url, fixture)

    malformed_store = (
        peer_dirs[target_index]
        / "storage"
        / "collections"
        / COLLECTION
        / "private_result_oram"
    )
    malformed_epochs = malformed_store / "epochs"
    malformed_epochs.mkdir(parents=True)
    (malformed_epochs / "current.json").write_text("{}")
    try:
        failed = _request_private_oram_shard_transfer(
            source_url,
            "replicate_shard",
            shard_id,
            source_info["peer_id"],
            target_info["peer_id"],
        )
    finally:
        shutil.rmtree(malformed_store)

    assert 400 <= failed.status_code < 600
    for secret in [
        fixture["hnsw"]["commit"]["new_root_hash"],
        fixture["result"]["commit"]["new_root_hash"],
        fixture["hnsw"]["commit"]["signature"]["sig"],
        fixture["result"]["commit"]["signature"]["sig"],
        fixture["hnsw"]["commit"]["updated_buckets"][0]["ciphertext"],
        fixture["result"]["commit"]["updated_buckets"][0]["ciphertext"],
    ]:
        assert secret not in failed.text

    assert _private_oram_buckets_dir(peer_dirs[target_index], "hnsw").is_dir()
    assert not get_collection_cluster_info(source_url, COLLECTION)["shard_transfers"]
    assert len(get_collection_cluster_info(source_url, COLLECTION)["local_shards"]) == 1
    assert not get_collection_cluster_info(target_url, COLLECTION)["local_shards"]
    _assert_replica_can_open_current_sessions(source_url)

    retried = _request_private_oram_shard_transfer(
        source_url,
        "replicate_shard",
        shard_id,
        source_info["peer_id"],
        target_info["peer_id"],
    )
    assert_http_ok(retried)
    wait_for_collection_local_shards_count(target_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    _assert_replica_can_open_current_sessions(target_url)


def test_private_oram_post_submit_abort_releases_sessions_and_retries(
    tmp_path: pathlib.Path,
):
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(
        tmp_path,
        2,
        1,
        extra_env={"QDRANT_STAGING_SHARD_TRANSFER_DELAY_SEC": "5"},
    )
    skip_if_no_feature(peer_urls[0], "staging")
    _, target_index, source_url, target_url, source_info, target_info = (
        _private_oram_transfer_peers(peer_urls)
    )
    shard_id = source_info["local_shards"][0]["shard_id"]

    _upload_hnsw(source_url, fixture)
    _exercise_hnsw_owner_session(source_url, fixture)
    _upload_result_oram(source_url, fixture)
    _exercise_result_owner_session(source_url, fixture)

    started = _request_private_oram_shard_transfer(
        source_url,
        "replicate_shard",
        shard_id,
        source_info["peer_id"],
        target_info["peer_id"],
    )
    assert_http_ok(started)
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(target_url, COLLECTION, 1)

    blocked_session = requests.post(
        f"{source_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session",
        json={
            "client_id": "tenant-a/blocked-transfer-sdk",
            "desired_epoch": NEXT_EPOCH,
            "fixed_budget": True,
            "result_privacy": "private_payload_oram_required",
        },
        timeout=30,
    )
    assert 400 <= blocked_session.status_code < 600
    for secret in [
        fixture["hnsw"]["commit"]["new_root_hash"],
        fixture["result"]["commit"]["new_root_hash"],
    ]:
        assert secret not in blocked_session.text

    aborted = requests.post(
        f"{source_url}/collections/{COLLECTION}/cluster",
        json={
            "abort_transfer": {
                "shard_id": shard_id,
                "from_peer_id": source_info["peer_id"],
                "to_peer_id": target_info["peer_id"],
            }
        },
        timeout=30,
    )
    assert_http_ok(aborted)
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)
    wait_for_collection_shard_transfers_count(target_url, COLLECTION, 0)
    _wait_for_private_oram_layout(peer_dirs, 1, [source_info["peer_id"]])

    aborted_target = get_collection_cluster_info(target_url, COLLECTION)
    assert len(aborted_target["local_shards"]) == 1
    assert aborted_target["local_shards"][0]["state"] == "Dead"
    assert _private_oram_buckets_dir(peer_dirs[target_index], "hnsw").is_dir()
    assert _private_oram_buckets_dir(peer_dirs[target_index], "result").is_dir()
    _assert_replica_can_open_current_sessions(source_url)

    retried = _request_private_oram_shard_transfer(
        source_url,
        "replicate_shard",
        shard_id,
        source_info["peer_id"],
        target_info["peer_id"],
    )
    assert_http_ok(retried)
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    _assert_replica_can_open_current_sessions(target_url)
    _wait_for_private_oram_layout(
        peer_dirs, 2, [source_info["peer_id"], target_info["peer_id"]]
    )


def test_private_oram_restart_repreinstalls_and_completes(
    tmp_path: pathlib.Path,
):
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(
        tmp_path,
        2,
        1,
        extra_env={"QDRANT_STAGING_SHARD_TRANSFER_DELAY_SEC": "5"},
    )
    skip_if_no_feature(peer_urls[0], "staging")
    _, target_index, source_url, target_url, source_info, target_info = (
        _private_oram_transfer_peers(peer_urls)
    )
    shard_id = source_info["local_shards"][0]["shard_id"]

    _upload_hnsw(source_url, fixture)
    _exercise_hnsw_owner_session(source_url, fixture)
    _upload_result_oram(source_url, fixture)
    _exercise_result_owner_session(source_url, fixture)

    started = _request_private_oram_shard_transfer(
        source_url,
        "replicate_shard",
        shard_id,
        source_info["peer_id"],
        target_info["peer_id"],
    )
    assert_http_ok(started)
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(target_url, COLLECTION, 1)
    _wait_for_private_oram_layout(peer_dirs, 1, [source_info["peer_id"]])

    collection_path = (
        peer_dirs[target_index] / "storage" / "collections" / COLLECTION
    )
    hnsw_store = collection_path / "private_hnsw_oram"
    result_store = collection_path / "private_result_oram"
    assert (hnsw_store / VECTOR / "buckets").is_dir()
    assert result_store.is_dir()
    shutil.rmtree(hnsw_store)
    shutil.rmtree(result_store)

    restarted = _request_private_oram_shard_transfer(
        source_url,
        "restart_transfer",
        shard_id,
        source_info["peer_id"],
        target_info["peer_id"],
    )
    assert_http_ok(restarted)
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(target_url, COLLECTION, 1)
    assert (hnsw_store / VECTOR / "buckets").is_dir()
    assert (result_store / "buckets").is_dir()
    _wait_for_private_oram_layout(peer_dirs, 1, [source_info["peer_id"]])

    blocked_session = requests.post(
        f"{source_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session",
        json={
            "client_id": "tenant-a/blocked-restart-sdk",
            "desired_epoch": NEXT_EPOCH,
            "fixed_budget": True,
            "result_privacy": "private_payload_oram_required",
        },
        timeout=30,
    )
    assert 400 <= blocked_session.status_code < 600
    for secret in [
        fixture["hnsw"]["commit"]["new_root_hash"],
        fixture["result"]["commit"]["new_root_hash"],
    ]:
        assert secret not in blocked_session.text

    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)
    wait_for_collection_shard_transfers_count(target_url, COLLECTION, 0)
    wait_for_collection_local_shards_count(target_url, COLLECTION, 1)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    _assert_replica_can_open_current_sessions(target_url)
    _wait_for_private_oram_layout(
        peer_dirs, 2, [source_info["peer_id"], target_info["peer_id"]]
    )


def _prepare_private_oram_active_transfer_snapshot_wiped_target(
    tmp_path: pathlib.Path,
    wipe_mode: str,
    extra_env: dict[str, str],
) -> dict:
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(
        tmp_path,
        3,
        1,
        extra_env=extra_env,
    )
    skip_if_no_feature(peer_urls[0], "staging")
    source_index, target_index, source_url, target_url, source_info, target_info = (
        _private_oram_transfer_peers(peer_urls)
    )
    remaining_index = next(
        index
        for index in range(len(peer_urls))
        if index not in {source_index, target_index}
    )
    shard_id = source_info["local_shards"][0]["shard_id"]

    _upload_hnsw(source_url, fixture)
    _exercise_hnsw_owner_session(source_url, fixture)
    _upload_result_oram(source_url, fixture)
    _exercise_result_owner_session(source_url, fixture)
    _wait_for_private_oram_epochs(peer_dirs, NEXT_EPOCH, 2)
    started = _request_private_oram_shard_transfer(
        source_url,
        "replicate_shard",
        shard_id,
        source_info["peer_id"],
        target_info["peer_id"],
    )
    assert_http_ok(started)
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(target_url, COLLECTION, 1)

    target_process = processes[target_index]
    source_process = processes[source_index]
    remaining_process = processes[remaining_index]
    target_port = target_process.p2p_port
    restart_bootstrap_uri = get_uri(remaining_process.p2p_port)
    target_process.kill()
    processes.remove(target_process)
    surviving_urls = [source_url, peer_urls[remaining_index]]
    surviving_peer_ids = {
        get_cluster_info(url)["peer_id"] for url in surviving_urls
    }
    wait_for(
        lambda: (
            (leader := get_cluster_info(source_url)["raft_info"]["leader"]) is not None
            and leader in surviving_peer_ids
            and get_cluster_info(peer_urls[remaining_index])["raft_info"]["leader"]
            == leader
        ),
        wait_for_timeout=60,
    )
    leader_peer_id = get_cluster_info(source_url)["raft_info"]["leader"]
    metadata_url = next(
        url
        for url in surviving_urls
        if get_cluster_info(url)["peer_id"] == leader_peer_id
    )
    for index in range(8):
        response = requests.put(
            f"{metadata_url}/cluster/metadata/keys/private-oram-fixed-transfer-snapshot-{index}?wait=true",
            json=index,
            timeout=30,
        )
        assert_http_ok(response)
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 1)

    target_collection_path = (
        peer_dirs[target_index] / "storage" / "collections" / COLLECTION
    )
    if wipe_mode == "collection":
        shutil.rmtree(target_collection_path)
    else:
        shutil.rmtree(target_collection_path / "private_hnsw_oram")
        shutil.rmtree(target_collection_path / "private_result_oram")

    return {
        "peer_urls": peer_urls,
        "peer_dirs": peer_dirs,
        "fixture": fixture,
        "source_index": source_index,
        "target_index": target_index,
        "remaining_index": remaining_index,
        "source_url": source_url,
        "source_info": source_info,
        "target_info": target_info,
        "source_process": source_process,
        "remaining_process": remaining_process,
        "target_port": target_port,
        "restart_bootstrap_uri": restart_bootstrap_uri,
        "target_collection_path": target_collection_path,
    }


@pytest.mark.parametrize("wipe_mode", ["collection", "stores"])
def test_private_oram_active_transfer_snapshot_fresh_preinstalls_wiped_target(
    tmp_path: pathlib.Path, wipe_mode: str,
):
    extra_env = {
        "QDRANT__CLUSTER__CONSENSUS__COMPACT_WAL_ENTRIES": "1",
        "QDRANT_STAGING_SHARD_TRANSFER_DELAY_SEC": "20",
    }
    context = _prepare_private_oram_active_transfer_snapshot_wiped_target(
        tmp_path,
        wipe_mode,
        extra_env,
    )
    peer_urls = context["peer_urls"]
    peer_dirs = context["peer_dirs"]
    fixture = context["fixture"]
    source_index = context["source_index"]
    target_index = context["target_index"]
    source_url = context["source_url"]
    source_info = context["source_info"]
    target_info = context["target_info"]
    target_port = context["target_port"]
    restart_bootstrap_uri = context["restart_bootstrap_uri"]
    target_collection_path = context["target_collection_path"]

    target_log = f"private_oram_fixed_transfer_snapshot_wiped_target_{wipe_mode}.log"
    restarted_url = start_peer(
        peer_dirs[target_index],
        target_log,
        restart_bootstrap_uri,
        port=target_port,
        extra_env=extra_env,
    )
    peer_urls[target_index] = restarted_url
    wait_for_peer_online(restarted_url, path="/cluster")

    target_log_path = pathlib.Path(init_pytest_log_folder()) / target_log
    wait_for(
        lambda: target_log_path.exists()
        and "Requesting fresh-preinstall resume for a private ORAM active fixed-layout transfer"
        in target_log_path.read_text(),
        wait_for_timeout=60,
    )
    blocked_hnsw = requests.post(
        f"{restarted_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session",
        json={
            "client_id": "tenant-a/snapshot-marker-blocked-hnsw-sdk",
            "desired_epoch": NEXT_EPOCH,
            "fixed_budget": True,
            "result_privacy": fixture["hnsw"]["manifest"]["result_privacy"],
        },
        timeout=30,
    )
    assert 400 <= blocked_hnsw.status_code < 600
    assert "snapshot recovery is pending" in blocked_hnsw.text
    assert fixture["hnsw"]["commit"]["new_root_hash"] not in blocked_hnsw.text

    blocked_result = requests.post(
        f"{restarted_url}/collections/{COLLECTION}/private-result-oram/session",
        json={
            "client_id": "tenant-a/snapshot-marker-blocked-result-sdk",
            "desired_epoch": NEXT_EPOCH,
            "fixed_budget": True,
        },
        timeout=30,
    )
    assert 400 <= blocked_result.status_code < 600
    assert "snapshot recovery is pending" in blocked_result.text
    assert fixture["result"]["commit"]["new_root_hash"] not in blocked_result.text

    wait_for(
        lambda: (target_collection_path / "private_hnsw_oram" / VECTOR / "buckets").is_dir()
        and (target_collection_path / "private_result_oram" / "buckets").is_dir(),
        wait_for_timeout=60,
    )
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)
    wait_for_collection_shard_transfers_count(restarted_url, COLLECTION, 0)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    _wait_for_private_oram_layout(
        peer_dirs,
        2,
        [source_info["peer_id"], target_info["peer_id"]],
    )
    wait_for(
        lambda: not (
            target_collection_path / "private_oram_snapshot_recovery.json"
        ).exists(),
        wait_for_timeout=60,
    )
    _assert_replica_can_open_current_sessions(restarted_url)

    all_peer_log_text = "\n".join(
        path.read_text()
        for path in pathlib.Path(init_pytest_log_folder()).glob("*.log")
    )
    for secret in [
        fixture["hnsw"]["manifest"]["root_hash"],
        fixture["hnsw"]["commit"]["new_root_hash"],
        fixture["hnsw"]["manifest_signature"]["sig"],
        fixture["hnsw"]["buckets"][0]["ciphertext"],
        fixture["result"]["manifest"]["root_hash"],
        fixture["result"]["commit"]["new_root_hash"],
        fixture["result"]["manifest_signature"]["sig"],
        fixture["result"]["buckets"][0]["ciphertext"],
    ]:
        assert secret not in all_peer_log_text


@pytest.mark.parametrize(
    "fault",
    [
        "pause_after_reservation",
        "pause_after_first_index",
        "pause_after_install",
        "pause_after_restart_apply",
        "stale_root",
        "stale_signature",
    ],
)
def test_private_oram_active_transfer_snapshot_source_preinstall_fault_matrix(
    tmp_path: pathlib.Path,
    fault: str,
):
    extra_env = {
        "QDRANT__CLUSTER__CONSENSUS__COMPACT_WAL_ENTRIES": "1",
        "QDRANT_STAGING_SHARD_TRANSFER_DELAY_SEC": "20",
    }
    fault_env = {
        **extra_env,
        "QDRANT_STAGING_PRIVATE_ORAM_PREINSTALL_FAULT": fault,
    }
    context = _prepare_private_oram_active_transfer_snapshot_wiped_target(
        tmp_path,
        "stores",
        fault_env,
    )
    peer_urls = context["peer_urls"]
    peer_dirs = context["peer_dirs"]
    fixture = context["fixture"]
    source_index = context["source_index"]
    target_index = context["target_index"]
    remaining_index = context["remaining_index"]
    source_info = context["source_info"]
    target_info = context["target_info"]
    source_process = context["source_process"]
    remaining_process = context["remaining_process"]
    source_port = source_process.p2p_port
    target_port = context["target_port"]
    restart_bootstrap_uri = context["restart_bootstrap_uri"]
    target_collection_path = context["target_collection_path"]
    source_collection_path = (
        peer_dirs[source_index] / "storage" / "collections" / COLLECTION
    )
    source_intent = source_collection_path / "private_oram_source_preinstall.json"
    source_log = f"private_oram_peer_{source_index}.log"
    faulted_source_url = context["source_url"]
    faulted_source_process = source_process

    target_log = f"private_oram_preinstall_fault_target_{fault}.log"
    restarted_target_url = start_peer(
        peer_dirs[target_index],
        target_log,
        restart_bootstrap_uri,
        port=target_port,
        extra_env=fault_env,
    )
    peer_urls[target_index] = restarted_target_url
    wait_for_peer_online(restarted_target_url, path="/cluster")

    log_folder = pathlib.Path(init_pytest_log_folder())
    source_log_path = log_folder / source_log
    target_log_path = log_folder / target_log
    if fault.startswith("pause_"):
        wait_for(
            lambda: source_log_path.exists()
            and f"Private ORAM staging preinstall pause reached: {fault}"
            in source_log_path.read_text(),
            wait_for_timeout=60,
        )
    else:
        wait_for(
            lambda: source_log_path.exists()
            and f"Private ORAM staging preinstall wire fault injected: {fault}"
            in source_log_path.read_text()
            and target_log_path.exists()
            and "Failed to request private ORAM active fixed-layout transfer resume"
            in target_log_path.read_text(),
            wait_for_timeout=60,
        )

    hnsw_current = (
        target_collection_path
        / "private_hnsw_oram"
        / VECTOR
        / "epochs"
        / "current.json"
    )
    result_current = (
        target_collection_path / "private_result_oram" / "epochs" / "current.json"
    )
    expected_installed = {
        "pause_after_reservation": (False, False),
        "pause_after_first_index": (True, False),
        "pause_after_install": (True, True),
        "pause_after_restart_apply": (True, True),
        "stale_root": (False, False),
        "stale_signature": (True, False),
    }[fault]
    assert hnsw_current.exists() is expected_installed[0]
    assert result_current.exists() is expected_installed[1]
    wait_for_collection_shard_transfers_count(
        faulted_source_url,
        COLLECTION,
        1,
    )
    wait_for_collection_shard_transfers_count(
        restarted_target_url,
        COLLECTION,
        1,
    )
    _wait_for_private_oram_layout(
        peer_dirs,
        1,
        [source_info["peer_id"]],
    )
    recovery_marker = target_collection_path / "private_oram_snapshot_recovery.json"
    assert recovery_marker.is_file()
    assert source_intent.is_file()
    if os.name != "nt":
        assert stat.S_IMODE(source_intent.stat().st_mode) == 0o600
    source_intent_data = json.loads(source_intent.read_text())
    assert source_intent_data["version"] == 1
    reservation_lease_id_hash = source_intent_data["reservation_lease_id_hash"]
    decoded_reservation_lease_id_hash = base64.urlsafe_b64decode(
        reservation_lease_id_hash + "=" * (-len(reservation_lease_id_hash) % 4)
    )
    assert len(decoded_reservation_lease_id_hash) == 32
    assert (
        base64.urlsafe_b64encode(decoded_reservation_lease_id_hash)
        .decode()
        .rstrip("=")
        == reservation_lease_id_hash
    )

    blocked_hnsw = requests.post(
        f"{restarted_target_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session",
        json={
            "client_id": f"tenant-a/{fault}-blocked-hnsw-sdk",
            "desired_epoch": NEXT_EPOCH,
            "fixed_budget": True,
            "result_privacy": fixture["hnsw"]["manifest"]["result_privacy"],
        },
        timeout=30,
    )
    assert 400 <= blocked_hnsw.status_code < 600
    assert "snapshot recovery is pending" in blocked_hnsw.text
    blocked_result = requests.post(
        f"{restarted_target_url}/collections/{COLLECTION}/private-result-oram/session",
        json={
            "client_id": f"tenant-a/{fault}-blocked-result-sdk",
            "desired_epoch": NEXT_EPOCH,
            "fixed_budget": True,
        },
        timeout=30,
    )
    assert 400 <= blocked_result.status_code < 600
    assert "snapshot recovery is pending" in blocked_result.text

    faulted_source_process.kill()
    processes.remove(faulted_source_process)
    clean_source_log = f"private_oram_preinstall_recovered_source_{fault}.log"
    clean_source_url = start_peer(
        peer_dirs[source_index],
        clean_source_log,
        get_uri(remaining_process.p2p_port),
        port=source_port,
        extra_env=extra_env,
    )
    peer_urls[source_index] = clean_source_url
    wait_for_peer_online(clean_source_url, path="/cluster")

    wait_for(
        lambda: hnsw_current.is_file() and result_current.is_file(),
        wait_for_timeout=60,
    )
    wait_for_collection_shard_transfers_count(clean_source_url, COLLECTION, 0)
    wait_for_collection_shard_transfers_count(restarted_target_url, COLLECTION, 0)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    _wait_for_private_oram_layout(
        peer_dirs,
        2,
        [source_info["peer_id"], target_info["peer_id"]],
    )
    wait_for(lambda: not recovery_marker.exists(), wait_for_timeout=60)
    wait_for(lambda: not source_intent.exists(), wait_for_timeout=60)
    _assert_replica_can_open_current_sessions(restarted_target_url)

    all_peer_log_text = "\n".join(path.read_text() for path in log_folder.glob("*.log"))
    sensitive_values = [
        fixture["hnsw"]["manifest"]["root_hash"],
        fixture["hnsw"]["commit"]["new_root_hash"],
        fixture["hnsw"]["manifest_signature"]["sig"],
        fixture["hnsw"]["buckets"][0]["ciphertext"],
        fixture["result"]["manifest"]["root_hash"],
        fixture["result"]["commit"]["new_root_hash"],
        fixture["result"]["manifest_signature"]["sig"],
        fixture["result"]["buckets"][0]["ciphertext"],
    ]
    for encoded in [
        fixture["hnsw"]["manifest"]["root_hash"],
        fixture["hnsw"]["commit"]["new_root_hash"],
        fixture["hnsw"]["manifest_signature"]["sig"],
        fixture["result"]["manifest"]["root_hash"],
        fixture["result"]["commit"]["new_root_hash"],
        fixture["result"]["manifest_signature"]["sig"],
    ]:
        decoded = bytearray(
            base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        )
        decoded[0] ^= 1
        sensitive_values.append(
            base64.urlsafe_b64encode(decoded).decode().rstrip("=")
        )
    for secret in sensitive_values:
        assert secret not in all_peer_log_text
        assert secret not in blocked_hnsw.text
        assert secret not in blocked_result.text


def test_private_oram_source_preinstall_intent_clears_on_terminal_abort(
    tmp_path: pathlib.Path,
):
    extra_env = {
        "QDRANT__CLUSTER__CONSENSUS__COMPACT_WAL_ENTRIES": "1",
        "QDRANT_STAGING_SHARD_TRANSFER_DELAY_SEC": "20",
        "QDRANT_STAGING_PRIVATE_ORAM_PREINSTALL_FAULT": "stale_root",
    }
    context = _prepare_private_oram_active_transfer_snapshot_wiped_target(
        tmp_path,
        "stores",
        extra_env,
    )
    peer_urls = context["peer_urls"]
    peer_dirs = context["peer_dirs"]
    source_index = context["source_index"]
    target_index = context["target_index"]
    source_info = context["source_info"]
    target_info = context["target_info"]
    source_url = context["source_url"]
    target_log = "private_oram_source_preinstall_terminal_abort_target.log"
    target_url = start_peer(
        peer_dirs[target_index],
        target_log,
        context["restart_bootstrap_uri"],
        port=context["target_port"],
        extra_env=extra_env,
    )
    peer_urls[target_index] = target_url
    wait_for_peer_online(target_url, path="/cluster")

    source_intent = (
        peer_dirs[source_index]
        / "storage"
        / "collections"
        / COLLECTION
        / "private_oram_source_preinstall.json"
    )
    target_log_path = pathlib.Path(init_pytest_log_folder()) / target_log
    wait_for(
        lambda: source_intent.is_file()
        and target_log_path.is_file()
        and "Failed to request private ORAM active fixed-layout transfer resume"
        in target_log_path.read_text(),
        wait_for_timeout=60,
    )

    shard_id = source_info["local_shards"][0]["shard_id"]
    aborted = requests.post(
        f"{source_url}/collections/{COLLECTION}/cluster",
        json={
            "abort_transfer": {
                "shard_id": shard_id,
                "from_peer_id": source_info["peer_id"],
                "to_peer_id": target_info["peer_id"],
            }
        },
        timeout=30,
    )
    assert_http_ok(aborted)
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)
    wait_for_collection_shard_transfers_count(target_url, COLLECTION, 0)
    wait_for(lambda: not source_intent.exists(), wait_for_timeout=60)
    _wait_for_private_oram_layout(peer_dirs, 1, [source_info["peer_id"]])


def test_private_oram_active_transfer_snapshot_recovers_wiped_redundant_owner(
    tmp_path: pathlib.Path,
):
    extra_env = {
        "QDRANT__CLUSTER__CONSENSUS__COMPACT_WAL_ENTRIES": "1",
        "QDRANT_STAGING_SHARD_TRANSFER_DELAY_SEC": "10",
    }
    peer_urls, peer_dirs, fixture, leader, _ = _start_private_oram_cluster(
        tmp_path,
        4,
        2,
        extra_env=extra_env,
    )
    skip_if_no_feature(peer_urls[0], "staging")
    peer_ids = [get_cluster_info(peer_url)["peer_id"] for peer_url in peer_urls]
    cluster_infos = [
        get_collection_cluster_info(peer_url, COLLECTION) for peer_url in peer_urls
    ]
    owner_indices = [
        index for index, info in enumerate(cluster_infos) if info["local_shards"]
    ]
    assert len(owner_indices) == 2
    wiped_owner_index = next(
        index for index in owner_indices if peer_ids[index] != leader
    )
    source_index = next(
        index for index in owner_indices if index != wiped_owner_index
    )
    non_owner_indices = [
        index for index in range(len(peer_urls)) if index not in owner_indices
    ]
    target_index = next(
        index for index in non_owner_indices if peer_ids[index] != leader
    )

    source_url = peer_urls[source_index]
    target_url = peer_urls[target_index]
    source_peer_id = peer_ids[source_index]
    wiped_owner_peer_id = peer_ids[wiped_owner_index]
    target_peer_id = peer_ids[target_index]
    shard_id = cluster_infos[source_index]["local_shards"][0]["shard_id"]

    _upload_hnsw(source_url, fixture)
    _exercise_hnsw_owner_session(source_url, fixture)
    _upload_result_oram(source_url, fixture)
    _exercise_result_owner_session(source_url, fixture)
    _wait_for_private_oram_epochs(peer_dirs, NEXT_EPOCH, 2)
    assert_http_ok(
        _request_private_oram_shard_transfer(
            source_url,
            "replicate_shard",
            shard_id,
            source_peer_id,
            target_peer_id,
        )
    )
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(target_url, COLLECTION, 1)

    wiped_process = processes[wiped_owner_index]
    wiped_port = wiped_process.p2p_port
    restart_bootstrap_uri = get_uri(processes[source_index].p2p_port)
    wiped_process.kill()
    processes.remove(wiped_process)

    leader_url = peer_urls[peer_ids.index(leader)]
    for index in range(8):
        assert_http_ok(
            requests.put(
                f"{leader_url}/cluster/metadata/keys/private-oram-fixed-owner-recovery-{index}?wait=true",
                json=index,
                timeout=30,
            )
        )
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 1)

    wiped_collection_path = (
        peer_dirs[wiped_owner_index] / "storage" / "collections" / COLLECTION
    )
    shutil.rmtree(wiped_collection_path)
    restarted_log = "private_oram_fixed_transfer_owner_snapshot_recovery.log"
    restarted_url = start_peer(
        peer_dirs[wiped_owner_index],
        restarted_log,
        restart_bootstrap_uri,
        port=wiped_port,
        extra_env=extra_env,
    )
    peer_urls[wiped_owner_index] = restarted_url
    wait_for_peer_online(restarted_url, path="/cluster")
    wait_for_uniform_cluster_status(peer_urls, leader)

    restarted_log_path = pathlib.Path(init_pytest_log_folder()) / restarted_log
    wait_for(
        lambda: restarted_log_path.exists()
        and "Applying snapshot" in restarted_log_path.read_text()
        and "Requesting private ORAM active shard transfer rollback for snapshot replica recovery"
        in restarted_log_path.read_text(),
        wait_for_timeout=60,
    )
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)
    wait_for_collection_shard_transfers_count(restarted_url, COLLECTION, 0)
    wait_for(
        lambda: (
            (info := get_collection_cluster_info(restarted_url, COLLECTION))[
                "local_shards"
            ]
            and info["local_shards"][0]["state"] == "Active"
        ),
        wait_for_timeout=60,
    )
    assert not (
        wiped_collection_path / "private_oram_snapshot_recovery.json"
    ).exists()
    assert _private_oram_buckets_dir(peer_dirs[wiped_owner_index], "hnsw").is_dir()
    assert _private_oram_buckets_dir(peer_dirs[wiped_owner_index], "result").is_dir()
    _wait_for_private_oram_layout(
        peer_dirs,
        3,
        sorted([source_peer_id, wiped_owner_peer_id, target_peer_id]),
    )
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)
    wait_for_collection_shard_transfers_count(restarted_url, COLLECTION, 0)
    _assert_private_oram_owner_sessions(restarted_url, fixture, True)
    restarted_log_text = restarted_log_path.read_text()
    for secret in [
        fixture["hnsw"]["commit"]["new_root_hash"],
        fixture["result"]["commit"]["new_root_hash"],
        fixture["hnsw"]["manifest_signature"]["sig"],
        fixture["result"]["manifest_signature"]["sig"],
    ]:
        assert secret not in restarted_log_text


def test_private_oram_resharding_restart_repreinstalls_and_completes(
    tmp_path: pathlib.Path,
):
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(
        tmp_path,
        2,
        1,
        include_public_vector=True,
        extra_env={
            "QDRANT__CLUSTER__RESHARDING_ENABLED": "true",
            "QDRANT_STAGING_SHARD_TRANSFER_DELAY_SEC": "5",
        },
    )
    skip_if_no_feature(peer_urls[0], "staging")
    _, target_index, source_url, target_url, source_info, target_info = (
        _private_oram_transfer_peers(peer_urls)
    )
    source_peer_id = source_info["peer_id"]
    target_peer_id = target_info["peer_id"]
    source_shard_id = source_info["local_shards"][0]["shard_id"]
    target_shard_id = source_shard_id + 1

    _upload_hnsw(source_url, fixture)
    _exercise_hnsw_owner_session(source_url, fixture)
    _upload_result_oram(source_url, fixture)
    _exercise_result_owner_session(source_url, fixture)

    started_resharding = start_resharding(
        source_url,
        collection=COLLECTION,
        direction="up",
        peer_id=target_peer_id,
    )
    assert_http_ok(started_resharding)
    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 1)

    started_transfer = _request_private_oram_resharding_transfer(
        source_url,
        "replicate_shard",
        source_shard_id,
        target_shard_id,
        source_peer_id,
        target_peer_id,
    )
    assert_http_ok(started_transfer)
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(target_url, COLLECTION, 1)
    _wait_for_private_oram_layout(peer_dirs, 1, [source_peer_id])

    collection_path = (
        peer_dirs[target_index] / "storage" / "collections" / COLLECTION
    )
    hnsw_store = collection_path / "private_hnsw_oram"
    result_store = collection_path / "private_result_oram"
    assert (hnsw_store / VECTOR / "buckets").is_dir()
    assert (result_store / "buckets").is_dir()
    shutil.rmtree(hnsw_store)
    shutil.rmtree(result_store)

    restarted = _request_private_oram_resharding_transfer(
        source_url,
        "restart_transfer",
        source_shard_id,
        target_shard_id,
        source_peer_id,
        target_peer_id,
    )
    assert_http_ok(restarted)
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(target_url, COLLECTION, 1)
    assert (hnsw_store / VECTOR / "buckets").is_dir()
    assert (result_store / "buckets").is_dir()
    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 1)
    _wait_for_private_oram_layout(peer_dirs, 1, [source_peer_id])
    _assert_private_oram_sessions_blocked_during_resharding(source_url, fixture, True)

    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)
    wait_for_collection_shard_transfers_count(target_url, COLLECTION, 0)
    activate_replica(
        source_url,
        target_peer_id,
        target_shard_id,
        collection=COLLECTION,
    )
    assert_http_ok(commit_read_hashring(source_url, collection=COLLECTION))
    assert_http_ok(commit_write_hashring(source_url, collection=COLLECTION))
    assert_http_ok(finish_resharding(source_url, collection=COLLECTION))

    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 0)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    _wait_for_private_oram_layout(peer_dirs, 2, [source_peer_id, target_peer_id])
    for owner_url in [source_url, target_url]:
        _assert_private_oram_owner_sessions(owner_url, fixture, True)


def test_private_oram_resharding_source_crash_automatically_repreinstalls_and_resumes(
    tmp_path: pathlib.Path,
):
    extra_env = {
        "QDRANT__CLUSTER__RESHARDING_ENABLED": "true",
        "QDRANT_STAGING_SHARD_TRANSFER_DELAY_SEC": "5",
    }
    peer_urls, peer_dirs, fixture, leader, _ = _start_private_oram_cluster(
        tmp_path,
        2,
        1,
        include_public_vector=True,
        extra_env=extra_env,
    )
    skip_if_no_feature(peer_urls[0], "staging")
    source_index, target_index, source_url, target_url, source_info, target_info = (
        _private_oram_transfer_peers(peer_urls)
    )
    source_peer_id = source_info["peer_id"]
    target_peer_id = target_info["peer_id"]
    source_shard_id = source_info["local_shards"][0]["shard_id"]
    target_shard_id = source_shard_id + 1

    _upload_hnsw(source_url, fixture)
    _exercise_hnsw_owner_session(source_url, fixture)
    _upload_result_oram(source_url, fixture)
    _exercise_result_owner_session(source_url, fixture)

    assert_http_ok(
        start_resharding(
            source_url,
            collection=COLLECTION,
            direction="up",
            peer_id=target_peer_id,
        )
    )
    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 1)
    assert_http_ok(
        _request_private_oram_resharding_transfer(
            source_url,
            "replicate_shard",
            source_shard_id,
            target_shard_id,
            source_peer_id,
            target_peer_id,
        )
    )
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(target_url, COLLECTION, 1)

    source_port = processes[source_index].p2p_port
    restart_bootstrap_uri = get_uri(processes[target_index].p2p_port)
    processes.pop(source_index).kill()
    wait_for_collection_resharding_operations_count(target_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(target_url, COLLECTION, 1)

    collection_path = (
        peer_dirs[target_index] / "storage" / "collections" / COLLECTION
    )
    hnsw_store = collection_path / "private_hnsw_oram"
    result_store = collection_path / "private_result_oram"
    shutil.rmtree(hnsw_store)
    shutil.rmtree(result_store)

    restarted_log = "private_oram_resharding_source_restarted.log"
    restarted_url = start_peer(
        peer_dirs[source_index],
        restarted_log,
        restart_bootstrap_uri,
        port=source_port,
        extra_env=extra_env,
    )
    source_url = restarted_url
    peer_urls[source_index] = restarted_url
    wait_for_peer_online(restarted_url, path="/cluster")
    wait_for_uniform_cluster_status(peer_urls, leader)

    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 1)
    restarted_log_path = pathlib.Path(init_pytest_log_folder()) / restarted_log
    wait_for(
        lambda: restarted_log_path.exists()
        and "Automatically restarting a missing private ORAM resharding transfer"
        in restarted_log_path.read_text(),
        wait_for_timeout=30,
    )
    wait_for(
        lambda: (hnsw_store / VECTOR / "buckets").is_dir()
        and (result_store / "buckets").is_dir(),
        wait_for_timeout=30,
    )
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)
    wait_for_collection_shard_transfers_count(target_url, COLLECTION, 0)
    _wait_for_private_oram_layout(peer_dirs, 1, [source_peer_id])
    _assert_private_oram_sessions_blocked_during_resharding(source_url, fixture, True)

    activate_replica(
        source_url,
        target_peer_id,
        target_shard_id,
        collection=COLLECTION,
    )
    assert_http_ok(commit_read_hashring(source_url, collection=COLLECTION))
    assert_http_ok(commit_write_hashring(source_url, collection=COLLECTION))
    assert_http_ok(finish_resharding(source_url, collection=COLLECTION))

    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 0)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    _wait_for_private_oram_layout(peer_dirs, 2, [source_peer_id, target_peer_id])
    for owner_url in [source_url, target_url]:
        _assert_private_oram_owner_sessions(owner_url, fixture, True)


def test_private_oram_active_reshard_recovers_from_raft_snapshot(
    tmp_path: pathlib.Path,
):
    extra_env = {
        "QDRANT__CLUSTER__RESHARDING_ENABLED": "true",
        "QDRANT__CLUSTER__CONSENSUS__COMPACT_WAL_ENTRIES": "1",
        "QDRANT_STAGING_SHARD_TRANSFER_DELAY_SEC": "5",
    }
    peer_urls, peer_dirs, fixture, leader, _ = _start_private_oram_cluster(
        tmp_path,
        3,
        1,
        include_public_vector=True,
        extra_env=extra_env,
    )
    skip_if_no_feature(peer_urls[0], "staging")
    peer_ids = [get_cluster_info(peer_url)["peer_id"] for peer_url in peer_urls]
    cluster_infos = [
        get_collection_cluster_info(peer_url, COLLECTION) for peer_url in peer_urls
    ]
    source_index = next(
        index for index, info in enumerate(cluster_infos) if info["local_shards"]
    )
    non_source_indices = [
        index for index in range(len(peer_urls)) if index != source_index
    ]
    lagging_index = next(
        index for index in non_source_indices if peer_ids[index] != leader
    )
    target_index = next(
        index for index in non_source_indices if index != lagging_index
    )
    source_url = peer_urls[source_index]
    target_url = peer_urls[target_index]
    source_peer_id = peer_ids[source_index]
    target_peer_id = peer_ids[target_index]
    source_shard_id = cluster_infos[source_index]["local_shards"][0]["shard_id"]
    target_shard_id = source_shard_id + 1

    _upload_hnsw(source_url, fixture)
    _exercise_hnsw_owner_session(source_url, fixture)
    _upload_result_oram(source_url, fixture)
    _exercise_result_owner_session(source_url, fixture)
    _wait_for_private_oram_epochs(peer_dirs, NEXT_EPOCH, 2)
    _wait_for_crypto_runtime_capability_metadata(peer_dirs, len(peer_urls))

    lagging_port = processes[lagging_index].p2p_port
    restart_bootstrap_uri = get_uri(processes[source_index].p2p_port)
    processes.pop(lagging_index).kill()

    assert_http_ok(
        start_resharding(
            source_url,
            collection=COLLECTION,
            direction="up",
            peer_id=target_peer_id,
        )
    )
    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 1)
    assert_http_ok(
        _request_private_oram_resharding_transfer(
            source_url,
            "replicate_shard",
            source_shard_id,
            target_shard_id,
            source_peer_id,
            target_peer_id,
        )
    )
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)
    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 1)
    _wait_for_private_oram_layout(
        [peer_dir for index, peer_dir in enumerate(peer_dirs) if index != lagging_index],
        1,
        [source_peer_id],
    )

    for index in range(8):
        response = requests.put(
            f"{source_url}/cluster/metadata/keys/private-oram-snapshot-{index}?wait=true",
            json=index,
            timeout=30,
        )
        assert_http_ok(response)

    restarted_log = "private_oram_active_reshard_snapshot_restarted.log"
    restarted_url = start_peer(
        peer_dirs[lagging_index],
        restarted_log,
        restart_bootstrap_uri,
        port=lagging_port,
        extra_env=extra_env,
    )
    peer_urls[lagging_index] = restarted_url
    wait_for_peer_online(restarted_url, path="/cluster")
    current_leader = get_cluster_info(source_url)["raft_info"]["leader"]
    wait_for_uniform_cluster_status(peer_urls, current_leader)
    wait_for_collection_resharding_operations_count(restarted_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(restarted_url, COLLECTION, 0)
    _assert_private_oram_sessions_blocked_during_resharding(
        restarted_url, fixture, True
    )
    restarted_log_path = pathlib.Path(init_pytest_log_folder()) / restarted_log
    wait_for(
        lambda: restarted_log_path.exists()
        and "Applying snapshot" in restarted_log_path.read_text(),
        wait_for_timeout=30,
    )

    restarted_info = get_collection_cluster_info(restarted_url, COLLECTION)
    target_replicas = [
        shard
        for shard in restarted_info["remote_shards"]
        if shard["shard_id"] == target_shard_id
        and shard.get("peer_id") == target_peer_id
    ]
    assert len(target_replicas) == 1
    assert target_replicas[0]["state"] == "Resharding"

    activate_replica(
        source_url,
        target_peer_id,
        target_shard_id,
        collection=COLLECTION,
    )
    assert_http_ok(commit_read_hashring(source_url, collection=COLLECTION))
    assert_http_ok(commit_write_hashring(source_url, collection=COLLECTION))
    assert_http_ok(finish_resharding(source_url, collection=COLLECTION))

    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 0)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    _wait_for_private_oram_layout(peer_dirs, 2, [source_peer_id, target_peer_id])
    for owner_url in [source_url, target_url]:
        _assert_private_oram_owner_sessions(owner_url, fixture, True)


def test_private_oram_active_reshard_snapshot_bootstraps_new_non_owner_peer(
    tmp_path: pathlib.Path,
):
    extra_env = {
        "QDRANT__CLUSTER__RESHARDING_ENABLED": "true",
        "QDRANT__CLUSTER__CONSENSUS__COMPACT_WAL_ENTRIES": "1",
        "QDRANT_STAGING_SHARD_TRANSFER_DELAY_SEC": "5",
    }
    peer_urls, peer_dirs, fixture, _, bootstrap_uri = (
        _start_private_oram_cluster(
            tmp_path,
            3,
            1,
            include_public_vector=True,
            extra_env=extra_env,
            started_peer_count=2,
        )
    )
    skip_if_no_feature(peer_urls[0], "staging")
    _, _, source_url, target_url, source_info, target_info = (
        _private_oram_transfer_peers(peer_urls)
    )
    source_peer_id = source_info["peer_id"]
    target_peer_id = target_info["peer_id"]
    source_shard_id = source_info["local_shards"][0]["shard_id"]
    target_shard_id = source_shard_id + 1

    _upload_hnsw(source_url, fixture)
    _exercise_hnsw_owner_session(source_url, fixture)
    _upload_result_oram(source_url, fixture)
    _exercise_result_owner_session(source_url, fixture)
    _wait_for_private_oram_epochs(peer_dirs[:2], NEXT_EPOCH, 2)
    _wait_for_crypto_runtime_capability_metadata(peer_dirs[:2], len(peer_urls))

    assert_http_ok(
        start_resharding(
            source_url,
            collection=COLLECTION,
            direction="up",
            peer_id=target_peer_id,
        )
    )
    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 1)
    assert_http_ok(
        _request_private_oram_resharding_transfer(
            source_url,
            "replicate_shard",
            source_shard_id,
            target_shard_id,
            source_peer_id,
            target_peer_id,
        )
    )
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)
    _wait_for_private_oram_layout(peer_dirs[:2], 1, [source_peer_id])

    for index in range(8):
        response = requests.put(
            f"{source_url}/cluster/metadata/keys/private-oram-new-peer-snapshot-{index}?wait=true",
            json=index,
            timeout=30,
        )
        assert_http_ok(response)

    new_peer_log = "private_oram_active_reshard_snapshot_new_peer.log"
    new_peer_url = start_peer(
        peer_dirs[2],
        new_peer_log,
        bootstrap_uri,
        extra_env=extra_env,
    )
    peer_urls.append(new_peer_url)
    wait_for_peer_online(new_peer_url, path="/cluster")
    current_leader = get_cluster_info(source_url)["raft_info"]["leader"]
    wait_for_uniform_cluster_status(peer_urls, current_leader)
    wait_for_collection_resharding_operations_count(new_peer_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(new_peer_url, COLLECTION, 0)
    _wait_for_private_oram_epochs(peer_dirs, NEXT_EPOCH, 2)
    _wait_for_private_oram_layout(peer_dirs, 1, [source_peer_id])
    _wait_for_crypto_runtime_capability_metadata(peer_dirs, len(peer_urls))
    _assert_private_oram_sessions_blocked_during_resharding(
        new_peer_url, fixture, True
    )

    new_peer_info = get_collection_cluster_info(new_peer_url, COLLECTION)
    assert new_peer_info["local_shards"] == []
    assert not list(peer_dirs[2].rglob("private_hnsw_oram"))
    assert not list(peer_dirs[2].rglob("private_result_oram"))
    new_peer_log_path = pathlib.Path(init_pytest_log_folder()) / new_peer_log
    wait_for(
        lambda: new_peer_log_path.exists()
        and "Applying snapshot" in new_peer_log_path.read_text(),
        wait_for_timeout=30,
    )

    activate_replica(
        source_url,
        target_peer_id,
        target_shard_id,
        collection=COLLECTION,
    )
    assert_http_ok(commit_read_hashring(source_url, collection=COLLECTION))
    assert_http_ok(commit_write_hashring(source_url, collection=COLLECTION))
    assert_http_ok(finish_resharding(source_url, collection=COLLECTION))

    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 0)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    _wait_for_private_oram_layout(
        peer_dirs,
        2,
        [source_peer_id, target_peer_id],
    )
    for owner_url in [source_url, target_url]:
        _assert_private_oram_owner_sessions(owner_url, fixture, True)

    non_owner_session = requests.post(
        f"{new_peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session",
        json={
            "client_id": "tenant-a/new-non-owner-sdk",
            "desired_epoch": NEXT_EPOCH,
            "fixed_budget": True,
            "result_privacy": fixture["hnsw"]["manifest"]["result_privacy"],
        },
        timeout=30,
    )
    assert 400 <= non_owner_session.status_code < 600
    assert "must own an active shard replica" in non_owner_session.text
    assert not list(peer_dirs[2].rglob("private_hnsw_oram"))
    assert not list(peer_dirs[2].rglob("private_result_oram"))


def test_private_oram_active_reshard_snapshot_bootstraps_wiped_scale_up_target(
    tmp_path: pathlib.Path,
):
    extra_env = {
        "QDRANT__CLUSTER__RESHARDING_ENABLED": "true",
        "QDRANT__CLUSTER__CONSENSUS__COMPACT_WAL_ENTRIES": "1",
        "QDRANT_STAGING_SHARD_TRANSFER_DELAY_SEC": "20",
    }
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(
        tmp_path,
        3,
        1,
        include_public_vector=True,
        extra_env=extra_env,
    )
    skip_if_no_feature(peer_urls[0], "staging")
    source_index, target_index, source_url, target_url, source_info, target_info = (
        _private_oram_transfer_peers(peer_urls)
    )
    remaining_index = next(
        index
        for index in range(len(peer_urls))
        if index not in {source_index, target_index}
    )
    source_peer_id = source_info["peer_id"]
    target_peer_id = target_info["peer_id"]
    source_shard_id = source_info["local_shards"][0]["shard_id"]
    target_shard_id = source_shard_id + 1

    _upload_hnsw(source_url, fixture)
    _exercise_hnsw_owner_session(source_url, fixture)
    _upload_result_oram(source_url, fixture)
    _exercise_result_owner_session(source_url, fixture)
    _wait_for_private_oram_epochs(peer_dirs, NEXT_EPOCH, 2)

    assert_http_ok(
        start_resharding(
            source_url,
            collection=COLLECTION,
            direction="up",
            peer_id=target_peer_id,
        )
    )
    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 1)
    assert_http_ok(
        _request_private_oram_resharding_transfer(
            source_url,
            "replicate_shard",
            source_shard_id,
            target_shard_id,
            source_peer_id,
            target_peer_id,
        )
    )
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(target_url, COLLECTION, 1)

    source_process = processes[source_index]
    target_process = processes[target_index]
    remaining_process = processes[remaining_index]
    source_port = source_process.p2p_port
    target_port = target_process.p2p_port
    restart_bootstrap_uri = get_uri(remaining_process.p2p_port)
    target_process.kill()
    processes.remove(target_process)

    surviving_urls = [source_url, peer_urls[remaining_index]]
    surviving_peer_ids = {
        get_cluster_info(url)["peer_id"] for url in surviving_urls
    }
    wait_for(
        lambda: (
            (leader := get_cluster_info(source_url)["raft_info"]["leader"])
            is not None
            and leader in surviving_peer_ids
            and get_cluster_info(peer_urls[remaining_index])["raft_info"]["leader"]
            == leader
        ),
        wait_for_timeout=30,
    )
    leader_peer_id = get_cluster_info(source_url)["raft_info"]["leader"]
    metadata_url = next(
        url
        for url in surviving_urls
        if get_cluster_info(url)["peer_id"] == leader_peer_id
    )
    for index in range(8):
        response = requests.put(
            f"{metadata_url}/cluster/metadata/keys/private-oram-target-snapshot-{index}?wait=true",
            json=index,
            timeout=30,
        )
        assert_http_ok(response)

    source_process.kill()
    processes.remove(source_process)
    target_collection_path = (
        peer_dirs[target_index] / "storage" / "collections" / COLLECTION
    )
    shutil.rmtree(target_collection_path)

    target_log = "private_oram_active_reshard_snapshot_wiped_target.log"
    target_url = start_peer(
        peer_dirs[target_index],
        target_log,
        restart_bootstrap_uri,
        port=target_port,
        extra_env=extra_env,
    )
    peer_urls[target_index] = target_url
    wait_for_peer_online(target_url, path="/cluster")
    wait_for(
        lambda: requests.get(
            f"{target_url}/collections/{COLLECTION}/cluster", timeout=5
        ).status_code
        == 200,
        wait_for_timeout=30,
    )
    wait_for_collection_resharding_operations_count(target_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(target_url, COLLECTION, 1)
    target_log_path = pathlib.Path(init_pytest_log_folder()) / target_log
    wait_for(
        lambda: target_log_path.exists()
        and "Applying snapshot" in target_log_path.read_text(),
        wait_for_timeout=30,
    )
    assert not list(target_collection_path.rglob("private_hnsw_oram"))
    assert not list(target_collection_path.rglob("private_result_oram"))

    source_log = "private_oram_active_reshard_snapshot_source_restarted.log"
    source_url = start_peer(
        peer_dirs[source_index],
        source_log,
        restart_bootstrap_uri,
        port=source_port,
        extra_env=extra_env,
    )
    peer_urls[source_index] = source_url
    wait_for_peer_online(source_url, path="/cluster")
    current_leader = get_cluster_info(target_url)["raft_info"]["leader"]
    wait_for_uniform_cluster_status(peer_urls, current_leader)
    source_log_path = pathlib.Path(init_pytest_log_folder()) / source_log
    wait_for(
        lambda: source_log_path.exists()
        and "Automatically restarting a missing private ORAM resharding transfer"
        in source_log_path.read_text(),
        wait_for_timeout=30,
    )
    wait_for(
        lambda: _private_oram_buckets_dir(peer_dirs[target_index], "hnsw").is_dir()
        and _private_oram_buckets_dir(peer_dirs[target_index], "result").is_dir(),
        wait_for_timeout=30,
    )
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)
    wait_for_collection_shard_transfers_count(target_url, COLLECTION, 0)
    _assert_private_oram_sessions_blocked_during_resharding(
        target_url, fixture, True
    )

    activate_replica(
        source_url,
        target_peer_id,
        target_shard_id,
        collection=COLLECTION,
    )
    assert_http_ok(commit_read_hashring(source_url, collection=COLLECTION))
    assert_http_ok(commit_write_hashring(source_url, collection=COLLECTION))
    assert_http_ok(finish_resharding(source_url, collection=COLLECTION))

    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 0)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    _wait_for_private_oram_layout(
        peer_dirs,
        2,
        [source_peer_id, target_peer_id],
    )
    for owner_url in [source_url, target_url]:
        _assert_private_oram_owner_sessions(owner_url, fixture, True)


def test_private_oram_active_reshard_snapshot_rolls_back_for_wiped_redundant_owner(
    tmp_path: pathlib.Path,
):
    extra_env = {
        "QDRANT__CLUSTER__RESHARDING_ENABLED": "true",
        "QDRANT__CLUSTER__CONSENSUS__COMPACT_WAL_ENTRIES": "1",
        "QDRANT_STAGING_SHARD_TRANSFER_DELAY_SEC": "10",
    }
    peer_urls, peer_dirs, fixture, leader, _ = _start_private_oram_cluster(
        tmp_path,
        4,
        2,
        include_public_vector=True,
        extra_env=extra_env,
    )
    skip_if_no_feature(peer_urls[0], "staging")
    peer_ids = [get_cluster_info(peer_url)["peer_id"] for peer_url in peer_urls]
    cluster_infos = [
        get_collection_cluster_info(peer_url, COLLECTION) for peer_url in peer_urls
    ]
    owner_indices = [
        index for index, info in enumerate(cluster_infos) if info["local_shards"]
    ]
    assert len(owner_indices) == 2
    wiped_owner_index = next(
        index for index in owner_indices if peer_ids[index] != leader
    )
    source_index = next(index for index in owner_indices if index != wiped_owner_index)
    non_owner_indices = [
        index for index in range(len(peer_urls)) if index not in owner_indices
    ]
    target_index = non_owner_indices[0]

    source_url = peer_urls[source_index]
    target_url = peer_urls[target_index]
    source_peer_id = peer_ids[source_index]
    target_peer_id = peer_ids[target_index]
    wiped_owner_peer_id = peer_ids[wiped_owner_index]
    source_shard_id = cluster_infos[source_index]["local_shards"][0]["shard_id"]
    target_shard_id = source_shard_id + 1

    _upload_hnsw(source_url, fixture)
    _exercise_hnsw_owner_session(source_url, fixture)
    _upload_result_oram(source_url, fixture)
    _exercise_result_owner_session(source_url, fixture)
    _wait_for_private_oram_epochs(peer_dirs, NEXT_EPOCH, 2)

    assert_http_ok(
        start_resharding(
            source_url,
            collection=COLLECTION,
            direction="up",
            peer_id=target_peer_id,
        )
    )
    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 1)
    assert_http_ok(
        _request_private_oram_resharding_transfer(
            source_url,
            "replicate_shard",
            source_shard_id,
            target_shard_id,
            source_peer_id,
            target_peer_id,
        )
    )
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(target_url, COLLECTION, 1)

    wiped_process = processes[wiped_owner_index]
    wiped_port = wiped_process.p2p_port
    restart_bootstrap_uri = get_uri(processes[source_index].p2p_port)
    wiped_process.kill()
    processes.remove(wiped_process)

    leader_url = peer_urls[peer_ids.index(leader)]
    for index in range(8):
        assert_http_ok(
            requests.put(
                f"{leader_url}/cluster/metadata/keys/private-oram-owner-rollback-{index}?wait=true",
                json=index,
                timeout=30,
            )
        )

    wiped_collection_path = (
        peer_dirs[wiped_owner_index] / "storage" / "collections" / COLLECTION
    )
    shutil.rmtree(wiped_collection_path)
    restarted_log = "private_oram_snapshot_redundant_owner_rollback.log"
    restarted_url = start_peer(
        peer_dirs[wiped_owner_index],
        restarted_log,
        restart_bootstrap_uri,
        port=wiped_port,
        extra_env=extra_env,
    )
    peer_urls[wiped_owner_index] = restarted_url
    wait_for_peer_online(restarted_url, path="/cluster")
    wait_for_uniform_cluster_status(peer_urls, leader)

    restarted_log_path = pathlib.Path(init_pytest_log_folder()) / restarted_log
    wait_for(
        lambda: restarted_log_path.exists()
        and "Applying snapshot" in restarted_log_path.read_text()
        and "Requesting private ORAM active reshard rollback for snapshot replica recovery"
        in restarted_log_path.read_text(),
        wait_for_timeout=30,
    )
    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 0)
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)
    wait_for_collection_shard_transfers_count(restarted_url, COLLECTION, 0)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    _wait_for_private_oram_layout(
        peer_dirs,
        2,
        sorted([source_peer_id, wiped_owner_peer_id]),
    )
    assert not (
        wiped_collection_path / "private_oram_snapshot_recovery.json"
    ).exists()
    assert _private_oram_buckets_dir(peer_dirs[wiped_owner_index], "hnsw").is_dir()
    assert _private_oram_buckets_dir(peer_dirs[wiped_owner_index], "result").is_dir()
    for owner_url in [source_url, restarted_url]:
        _assert_private_oram_owner_sessions(owner_url, fixture, True)


def test_private_oram_active_scale_down_recovers_from_raft_snapshot(
    tmp_path: pathlib.Path,
):
    extra_env = {
        "QDRANT__CLUSTER__RESHARDING_ENABLED": "true",
        "QDRANT__CLUSTER__CONSENSUS__COMPACT_WAL_ENTRIES": "1",
    }
    peer_urls, peer_dirs, fixture, leader, _ = _start_private_oram_cluster(
        tmp_path,
        4,
        3,
        shard_number=2,
        include_public_vector=True,
        extra_env=extra_env,
    )
    peer_ids = [get_cluster_info(peer_url)["peer_id"] for peer_url in peer_urls]
    cluster_infos = [
        get_collection_cluster_info(peer_url, COLLECTION) for peer_url in peer_urls
    ]
    owner_indices_by_shard: dict[int, list[int]] = {}
    for peer_index, info in enumerate(cluster_infos):
        for shard in info["local_shards"]:
            if shard["state"] == "Active":
                owner_indices_by_shard.setdefault(shard["shard_id"], []).append(
                    peer_index
                )
    assert len(owner_indices_by_shard) == 2
    receiver_shard_id = min(owner_indices_by_shard)
    target_shard_id = max(owner_indices_by_shard)
    receiver_indices = owner_indices_by_shard[receiver_shard_id]
    target_indices = owner_indices_by_shard[target_shard_id]
    assert len(receiver_indices) == 3
    assert len(target_indices) == 3

    source_index = next(
        index for index in target_indices if index in receiver_indices
    )
    source_url = peer_urls[source_index]
    source_peer_id = peer_ids[source_index]
    receiver_peer_ids = [peer_ids[index] for index in receiver_indices]
    initial_owner_peer_ids = sorted(
        {
            peer_ids[index]
            for owner_indices in owner_indices_by_shard.values()
            for index in owner_indices
        }
    )

    _upload_hnsw(source_url, fixture)
    _exercise_hnsw_owner_session(source_url, fixture)
    _upload_result_oram(source_url, fixture)
    _exercise_result_owner_session(source_url, fixture)
    _wait_for_private_oram_epochs(peer_dirs, NEXT_EPOCH, 2)
    _wait_for_crypto_runtime_capability_metadata(peer_dirs, len(peer_urls))

    assert_http_ok(
        start_resharding(
            source_url,
            collection=COLLECTION,
            direction="down",
            peer_id=source_peer_id,
        )
    )
    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 1)
    for receiver_peer_id in receiver_peer_ids:
        migrate_points(
            source_url,
            receiver_peer_id,
            receiver_shard_id,
            source_peer_id,
            target_shard_id,
            "down",
            collection=COLLECTION,
        )
        activate_replica(
            source_url,
            receiver_peer_id,
            receiver_shard_id,
            collection=COLLECTION,
        )
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)
    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 1)
    _wait_for_private_oram_layout(
        peer_dirs,
        1,
        initial_owner_peer_ids,
    )

    lagging_index = next(
        index
        for index, peer_id in enumerate(peer_ids)
        if index != source_index and peer_id != leader
    )
    lagging_port = processes[lagging_index].p2p_port
    restart_bootstrap_uri = get_uri(processes[source_index].p2p_port)
    processes.pop(lagging_index).kill()

    for index in range(8):
        assert_http_ok(
            requests.put(
                f"{source_url}/cluster/metadata/keys/private-oram-scale-down-snapshot-{index}?wait=true",
                json=index,
                timeout=30,
            )
        )

    restarted_log = "private_oram_active_scale_down_snapshot_restarted.log"
    restarted_url = start_peer(
        peer_dirs[lagging_index],
        restarted_log,
        restart_bootstrap_uri,
        port=lagging_port,
        extra_env=extra_env,
    )
    peer_urls[lagging_index] = restarted_url
    wait_for_peer_online(restarted_url, path="/cluster")
    wait_for_uniform_cluster_status(peer_urls, leader)
    wait_for_collection_resharding_operations_count(restarted_url, COLLECTION, 1)
    wait_for_collection_shard_transfers_count(restarted_url, COLLECTION, 0)
    _assert_private_oram_sessions_blocked_during_resharding(
        restarted_url, fixture, True
    )
    restarted_log_path = pathlib.Path(init_pytest_log_folder()) / restarted_log
    wait_for(
        lambda: restarted_log_path.exists()
        and "Applying snapshot" in restarted_log_path.read_text(),
        wait_for_timeout=30,
    )

    restarted_info = get_collection_cluster_info(restarted_url, COLLECTION)
    target_states = [
        shard["state"]
        for shard in restarted_info["local_shards"] + restarted_info["remote_shards"]
        if shard["shard_id"] == target_shard_id
    ]
    assert len(target_states) == len(target_indices)
    assert set(target_states) == {"Active"}

    assert_http_ok(commit_read_hashring(source_url, collection=COLLECTION))
    assert_http_ok(commit_write_hashring(source_url, collection=COLLECTION))
    assert_http_ok(finish_resharding(source_url, collection=COLLECTION))

    wait_for_collection_resharding_operations_count(source_url, COLLECTION, 0)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    _wait_for_private_oram_layout(peer_dirs, 2, receiver_peer_ids)
    for receiver_index in receiver_indices:
        _assert_private_oram_owner_sessions(peer_urls[receiver_index], fixture, True)


def test_private_oram_active_scale_down_snapshot_rolls_back_for_wiped_multishard_redundant_endpoint(
    tmp_path: pathlib.Path,
):
    extra_env = {
        "QDRANT__CLUSTER__RESHARDING_ENABLED": "true",
        "QDRANT__CLUSTER__CONSENSUS__COMPACT_WAL_ENTRIES": "1",
    }
    peer_urls, peer_dirs, fixture, leader, _ = _start_private_oram_cluster(
        tmp_path,
        4,
        3,
        shard_number=2,
        include_public_vector=True,
        extra_env=extra_env,
    )
    peer_ids = [get_cluster_info(peer_url)["peer_id"] for peer_url in peer_urls]
    cluster_infos = [
        get_collection_cluster_info(peer_url, COLLECTION) for peer_url in peer_urls
    ]
    owner_indices_by_shard: dict[int, list[int]] = {}
    for peer_index, info in enumerate(cluster_infos):
        for shard in info["local_shards"]:
            if shard["state"] == "Active":
                owner_indices_by_shard.setdefault(shard["shard_id"], []).append(
                    peer_index
                )
    assert len(owner_indices_by_shard) == 2
    receiver_shard_id = min(owner_indices_by_shard)
    target_shard_id = max(owner_indices_by_shard)
    receiver_indices = owner_indices_by_shard[receiver_shard_id]
    target_indices = owner_indices_by_shard[target_shard_id]
    assert len(receiver_indices) == 3
    assert len(target_indices) == 3

    endpoint_index = next(
        index
        for index in set(receiver_indices).intersection(target_indices)
        if peer_ids[index] != leader
    )
    endpoint_url = peer_urls[endpoint_index]
    coordinator_url = endpoint_url
    endpoint_peer_id = peer_ids[endpoint_index]
    receiver_peer_ids = [peer_ids[index] for index in receiver_indices]
    migration_receiver_peer_ids = [
        peer_id for peer_id in receiver_peer_ids if peer_id != endpoint_peer_id
    ]
    initial_owner_indices = sorted(
        {
            index
            for owner_indices in owner_indices_by_shard.values()
            for index in owner_indices
        }
    )
    initial_owner_peer_ids = sorted(peer_ids[index] for index in initial_owner_indices)

    _upload_hnsw(coordinator_url, fixture)
    _exercise_hnsw_owner_session(coordinator_url, fixture)
    _upload_result_oram(coordinator_url, fixture)
    _exercise_result_owner_session(coordinator_url, fixture)
    _wait_for_private_oram_epochs(peer_dirs, NEXT_EPOCH, 2)
    _wait_for_crypto_runtime_capability_metadata(peer_dirs, len(peer_urls))

    assert_http_ok(
        start_resharding(
            coordinator_url,
            collection=COLLECTION,
            direction="down",
            peer_id=endpoint_peer_id,
        )
    )
    wait_for_collection_resharding_operations_count(coordinator_url, COLLECTION, 1)
    for receiver_peer_id in migration_receiver_peer_ids:
        migrate_points(
            endpoint_url,
            receiver_peer_id,
            receiver_shard_id,
            endpoint_peer_id,
            target_shard_id,
            "down",
            collection=COLLECTION,
        )
        activate_replica(
            endpoint_url,
            receiver_peer_id,
            receiver_shard_id,
            collection=COLLECTION,
        )
    wait_for_collection_shard_transfers_count(endpoint_url, COLLECTION, 0)
    wait_for_collection_resharding_operations_count(endpoint_url, COLLECTION, 1)
    _wait_for_private_oram_layout(peer_dirs, 1, initial_owner_peer_ids)

    endpoint_process = processes[endpoint_index]
    endpoint_port = endpoint_process.p2p_port
    leader_index = peer_ids.index(leader)
    leader_url = peer_urls[leader_index]
    restart_bootstrap_uri = get_uri(processes[leader_index].p2p_port)
    endpoint_process.kill()
    processes.remove(endpoint_process)

    for index in range(8):
        assert_http_ok(
            requests.put(
                f"{leader_url}/cluster/metadata/keys/private-oram-scale-down-endpoint-rollback-{index}?wait=true",
                json=index,
                timeout=30,
            )
        )

    wiped_collection_path = (
        peer_dirs[endpoint_index] / "storage" / "collections" / COLLECTION
    )
    shutil.rmtree(wiped_collection_path)
    restarted_log = "private_oram_scale_down_endpoint_rollback.log"
    restarted_url = start_peer(
        peer_dirs[endpoint_index],
        restarted_log,
        restart_bootstrap_uri,
        port=endpoint_port,
        extra_env=extra_env,
    )
    peer_urls[endpoint_index] = restarted_url
    wait_for_peer_online(restarted_url, path="/cluster")
    wait_for_uniform_cluster_status(peer_urls, leader)

    restarted_log_path = pathlib.Path(init_pytest_log_folder()) / restarted_log
    wait_for(
        lambda: restarted_log_path.exists()
        and "Applying snapshot" in restarted_log_path.read_text()
        and "Requesting private ORAM active reshard rollback for snapshot replica recovery"
        in restarted_log_path.read_text(),
        wait_for_timeout=30,
    )
    wait_for_collection_resharding_operations_count(leader_url, COLLECTION, 0)
    wait_for_collection_shard_transfers_count(leader_url, COLLECTION, 0)
    wait_for_collection_shard_transfers_count(restarted_url, COLLECTION, 0)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    _wait_for_private_oram_layout(peer_dirs, 3, initial_owner_peer_ids)
    assert not (
        wiped_collection_path / "private_oram_snapshot_recovery.json"
    ).exists()
    assert _private_oram_buckets_dir(peer_dirs[endpoint_index], "hnsw").is_dir()
    assert _private_oram_buckets_dir(peer_dirs[endpoint_index], "result").is_dir()

    restarted_info = get_collection_cluster_info(restarted_url, COLLECTION)
    assert {
        shard["shard_id"]
        for shard in restarted_info["local_shards"]
        if shard["state"] == "Active"
    } == {receiver_shard_id, target_shard_id}
    for owner_index in initial_owner_indices:
        _assert_private_oram_owner_sessions(peer_urls[owner_index], fixture, True)


def test_private_oram_active_scale_down_snapshot_rejects_wiped_nonredundant_endpoint(
    tmp_path: pathlib.Path,
):
    extra_env = {
        "QDRANT__CLUSTER__RESHARDING_ENABLED": "true",
        "QDRANT__CLUSTER__CONSENSUS__COMPACT_WAL_ENTRIES": "1",
    }
    peer_urls, peer_dirs, fixture, leader, _ = _start_private_oram_cluster(
        tmp_path,
        3,
        1,
        shard_number=2,
        include_public_vector=True,
        extra_env=extra_env,
    )
    peer_ids = [get_cluster_info(peer_url)["peer_id"] for peer_url in peer_urls]
    cluster_infos = [
        get_collection_cluster_info(peer_url, COLLECTION) for peer_url in peer_urls
    ]
    owner_index_by_shard = {
        shard["shard_id"]: peer_index
        for peer_index, info in enumerate(cluster_infos)
        for shard in info["local_shards"]
        if shard["state"] == "Active"
    }
    assert len(owner_index_by_shard) == 2
    target_shard_id = max(owner_index_by_shard)
    receiver_shard_id = min(owner_index_by_shard)
    endpoint_index = owner_index_by_shard[target_shard_id]
    receiver_index = owner_index_by_shard[receiver_shard_id]
    endpoint_url = peer_urls[endpoint_index]
    coordinator_url = peer_urls[receiver_index]
    endpoint_peer_id = peer_ids[endpoint_index]
    receiver_peer_id = peer_ids[receiver_index]

    _upload_hnsw(coordinator_url, fixture)
    _upload_result_oram(coordinator_url, fixture)
    _wait_for_private_oram_epochs(peer_dirs, BASE_EPOCH, 2)
    _wait_for_private_oram_session_leases_released(peer_dirs)
    _wait_for_crypto_runtime_capability_metadata(peer_dirs, len(peer_urls))

    assert_http_ok(
        start_resharding(
            coordinator_url,
            collection=COLLECTION,
            direction="down",
            peer_id=endpoint_peer_id,
        )
    )
    wait_for_collection_resharding_operations_count(coordinator_url, COLLECTION, 1)
    # The resharding start releases the session leases it took on the coordinator; the endpoint
    # refuses the migration until it has applied that release too.
    _wait_for_private_oram_session_leases_released(peer_dirs)
    migrate_points(
        endpoint_url,
        receiver_peer_id,
        receiver_shard_id,
        endpoint_peer_id,
        target_shard_id,
        "down",
        collection=COLLECTION,
    )
    activate_replica(
        endpoint_url,
        receiver_peer_id,
        receiver_shard_id,
        collection=COLLECTION,
    )
    wait_for_collection_shard_transfers_count(endpoint_url, COLLECTION, 0)
    wait_for_collection_resharding_operations_count(endpoint_url, COLLECTION, 1)

    endpoint_process = processes[endpoint_index]
    endpoint_port = endpoint_process.p2p_port
    restart_bootstrap_uri = get_uri(processes[receiver_index].p2p_port)
    endpoint_process.kill()
    processes.remove(endpoint_process)

    surviving_urls = [
        peer_url for index, peer_url in enumerate(peer_urls) if index != endpoint_index
    ]
    surviving_peer_ids = {
        get_cluster_info(peer_url)["peer_id"] for peer_url in surviving_urls
    }
    wait_for(
        lambda: (
            (new_leader := get_cluster_info(surviving_urls[0])["raft_info"]["leader"])
            is not None
            and new_leader in surviving_peer_ids
            and get_cluster_info(surviving_urls[1])["raft_info"]["leader"]
            == new_leader
        ),
        wait_for_timeout=60,
    )
    new_leader = get_cluster_info(surviving_urls[0])["raft_info"]["leader"]
    metadata_url = next(
        peer_url
        for peer_url in surviving_urls
        if get_cluster_info(peer_url)["peer_id"] == new_leader
    )
    for index in range(8):
        assert_http_ok(
            requests.put(
                f"{metadata_url}/cluster/metadata/keys/private-oram-nonredundant-endpoint-{index}?wait=true",
                json=index,
                timeout=30,
            )
        )

    wiped_collection_path = (
        peer_dirs[endpoint_index] / "storage" / "collections" / COLLECTION
    )
    shutil.rmtree(wiped_collection_path)
    restarted_log = "private_oram_nonredundant_endpoint_snapshot_rejected.log"
    restarted_url = start_peer(
        peer_dirs[endpoint_index],
        restarted_log,
        restart_bootstrap_uri,
        port=endpoint_port,
        extra_env=extra_env,
    )
    peer_urls[endpoint_index] = restarted_url
    wait_for_peer_online(restarted_url, path="/cluster")

    restarted_log_path = pathlib.Path(init_pytest_log_folder()) / restarted_log
    wait_for(
        lambda: restarted_log_path.exists()
        and "private ORAM active reshard Raft snapshot state is invalid"
        in restarted_log_path.read_text(),
        wait_for_timeout=60,
    )
    restarted_log_text = restarted_log_path.read_text()
    for secret in [
        fixture["hnsw"]["manifest"]["root_hash"],
        fixture["hnsw"]["commit"]["new_root_hash"],
        fixture["hnsw"]["manifest_signature"]["sig"],
        fixture["hnsw"]["buckets"][0]["ciphertext"],
        fixture["result"]["manifest"]["root_hash"],
        fixture["result"]["commit"]["new_root_hash"],
        fixture["result"]["manifest_signature"]["sig"],
        fixture["result"]["buckets"][0]["ciphertext"],
    ]:
        assert secret not in restarted_log_text
    assert not wiped_collection_path.exists()
    assert not list(peer_dirs[endpoint_index].rglob("private_hnsw_oram"))
    assert not list(peer_dirs[endpoint_index].rglob("private_result_oram"))


@pytest.mark.parametrize("index_kind", ["hnsw", "result"])
def test_private_oram_replica_prepare_failure_preserves_epoch(
    tmp_path: pathlib.Path, index_kind: str
):
    peer_urls, _, fixture, leader, _ = _start_private_oram_cluster(tmp_path, 3, 3)
    peer_ids = [get_cluster_info(peer_url)["peer_id"] for peer_url in peer_urls]
    coordinator_index = peer_ids.index(leader)
    coordinator_url = peer_urls[coordinator_index]
    failed_replica_index = next(
        index for index, peer_id in enumerate(peer_ids) if peer_id != leader
    )

    if index_kind == "hnsw":
        _upload_hnsw(coordinator_url, fixture)
        session = _open_hnsw_owner_session(coordinator_url, BASE_EPOCH)
        _read_hnsw_owner_session(coordinator_url, fixture, session)
        commit = fixture["hnsw"]["commit"]
        commit_url = f"{coordinator_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/oram/commit"
        commit_body = {
            "session_id": session["session_id"],
            "old_epoch": commit["old_epoch"],
            "new_epoch": commit["new_epoch"],
            "old_root_hash": commit["old_root_hash"],
            "new_root_hash": commit["new_root_hash"],
            "updated_buckets": commit["updated_buckets"],
            "commit_signature": commit["signature"],
        }
    else:
        _upload_result_oram(coordinator_url, fixture)
        session = _open_result_owner_session(coordinator_url, BASE_EPOCH)
        _read_result_owner_session(coordinator_url, fixture, session)
        commit = fixture["result"]["commit"]
        commit_url = f"{coordinator_url}/collections/{COLLECTION}/private-result-oram/oram/commit"
        commit_body = {
            "session_id": session["session_id"],
            "old_epoch": commit["old_epoch"],
            "new_epoch": commit["new_epoch"],
            "old_root_hash": commit["old_root_hash"],
            "new_root_hash": commit["new_root_hash"],
            "updated_buckets": commit["updated_buckets"],
            "commit_signature": commit["signature"],
        }

    processes.pop(failed_replica_index).kill()
    response = requests.post(commit_url, json=commit_body, timeout=60)
    assert 500 <= response.status_code < 600
    for secret in [
        session["session_id"],
        commit["old_root_hash"],
        commit["new_root_hash"],
        commit["signature"]["sig"],
        commit["updated_buckets"][0]["ciphertext"],
    ]:
        assert secret not in response.text

    if index_kind == "hnsw":
        _read_hnsw_owner_session(coordinator_url, fixture, session)
        close_url = f"{coordinator_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session/{session['session_id']}/close"
        assert _post_result(close_url, {}) is True
        reopened = _open_hnsw_owner_session(coordinator_url, BASE_EPOCH)
        reopened_close_url = f"{coordinator_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session/{reopened['session_id']}/close"
    else:
        _read_result_owner_session(coordinator_url, fixture, session)
        close_url = f"{coordinator_url}/collections/{COLLECTION}/private-result-oram/session/{session['session_id']}/close"
        assert _post_result(close_url, {}) is True
        reopened = _open_result_owner_session(coordinator_url, BASE_EPOCH)
        reopened_close_url = f"{coordinator_url}/collections/{COLLECTION}/private-result-oram/session/{reopened['session_id']}/close"

    assert reopened["index_epoch"] == BASE_EPOCH
    assert _post_result(reopened_close_url, {}) is True


def _private_oram_buckets_dir(peer_dir: pathlib.Path, index_kind: str) -> pathlib.Path:
    pattern = (
        f"private_hnsw_oram/{VECTOR}/buckets"
        if index_kind == "hnsw"
        else "private_result_oram/buckets"
    )
    matches = list(peer_dir.rglob(pattern))
    assert len(matches) == 1
    return matches[0]


@pytest.mark.parametrize("index_kind", ["hnsw", "result"])
def test_private_oram_partial_finalize_recovers_after_coordinator_restart(
    tmp_path: pathlib.Path, index_kind: str
):
    # The killed coordinator's session lease stays in consensus until it expires; builds with
    # private ORAM crash points honour this shorter test lease.
    lease_env = {"QDRANT_PRIVATE_ORAM_TEST_SESSION_LEASE_SECS": "15"}
    peer_urls, peer_dirs, fixture, leader, _ = _start_private_oram_cluster(
        tmp_path, 3, 2, extra_env=lease_env
    )
    peer_ids = [get_cluster_info(peer_url)["peer_id"] for peer_url in peer_urls]
    replica_indices = [
        index
        for index, peer_url in enumerate(peer_urls)
        if get_collection_cluster_info(peer_url, COLLECTION)["local_shards"]
    ]
    assert len(replica_indices) == 2
    coordinator_index = next(
        index for index in replica_indices if peer_ids[index] != leader
    )
    finalize_failure_index = next(
        index for index in replica_indices if index != coordinator_index
    )
    coordinator_url = peer_urls[coordinator_index]

    if index_kind == "hnsw":
        _upload_hnsw(coordinator_url, fixture)
        session = _open_hnsw_owner_session(coordinator_url, BASE_EPOCH)
        _read_hnsw_owner_session(coordinator_url, fixture, session)
        commit = fixture["hnsw"]["commit"]
        commit_url = f"{coordinator_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/oram/commit"
        commit_body = {
            "session_id": session["session_id"],
            "old_epoch": commit["old_epoch"],
            "new_epoch": commit["new_epoch"],
            "old_root_hash": commit["old_root_hash"],
            "new_root_hash": commit["new_root_hash"],
            "updated_buckets": commit["updated_buckets"],
            "commit_signature": commit["signature"],
        }
    else:
        _upload_result_oram(coordinator_url, fixture)
        session = _open_result_owner_session(coordinator_url, BASE_EPOCH)
        _read_result_owner_session(coordinator_url, fixture, session)
        commit = fixture["result"]["commit"]
        commit_url = f"{coordinator_url}/collections/{COLLECTION}/private-result-oram/oram/commit"
        commit_body = {
            "session_id": session["session_id"],
            "old_epoch": commit["old_epoch"],
            "new_epoch": commit["new_epoch"],
            "old_root_hash": commit["old_root_hash"],
            "new_root_hash": commit["new_root_hash"],
            "updated_buckets": commit["updated_buckets"],
            "commit_signature": commit["signature"],
        }

    buckets_dir = _private_oram_buckets_dir(
        peer_dirs[finalize_failure_index], index_kind
    )
    original_mode = stat.S_IMODE(buckets_dir.stat().st_mode)
    buckets_dir.chmod(0o500)
    try:
        response = requests.post(commit_url, json=commit_body, timeout=60)
    finally:
        buckets_dir.chmod(original_mode)

    assert 500 <= response.status_code < 600
    for secret in [
        session["session_id"],
        commit["old_root_hash"],
        commit["new_root_hash"],
        commit["signature"]["sig"],
        commit["updated_buckets"][0]["ciphertext"],
    ]:
        assert secret not in response.text
    survivor_index = next(
        index for index in range(len(peer_urls)) if index != coordinator_index
    )
    restart_bootstrap_uri = get_uri(processes[survivor_index].p2p_port)
    processes.pop(coordinator_index).kill()
    restarted_url = start_peer(
        peer_dirs[coordinator_index],
        f"private_oram_{index_kind}_coordinator_restarted.log",
        restart_bootstrap_uri,
        extra_env=lease_env,
    )
    peer_urls[coordinator_index] = restarted_url
    wait_for_peer_online(restarted_url, path="/cluster")
    wait_for_uniform_cluster_status(peer_urls, leader)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)

    recovered = {}

    def recovered_session_opens() -> bool:
        try:
            recovered.update(
                _open_hnsw_owner_session(restarted_url, NEXT_EPOCH)
                if index_kind == "hnsw"
                else _open_result_owner_session(restarted_url, NEXT_EPOCH)
            )
        except Exception:  # noqa: BLE001 - HTTP helpers raise plain Exception
            return False
        return True

    # Up to the default 300 s lease when the build ignores the test lease.
    wait_for(recovered_session_opens, wait_for_timeout=330)
    if index_kind == "hnsw":
        recovered_close_url = f"{restarted_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session/{recovered['session_id']}/close"
    else:
        recovered_close_url = f"{restarted_url}/collections/{COLLECTION}/private-result-oram/session/{recovered['session_id']}/close"
    assert recovered["index_epoch"] == NEXT_EPOCH
    assert recovered["root_hash"] == commit["new_root_hash"]
    assert _post_result(recovered_close_url, {}) is True
