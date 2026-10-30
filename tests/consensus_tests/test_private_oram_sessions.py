import base64
import hashlib
import json
import os
import pathlib
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Thread

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
    all_nodes_cluster_info_consistent,
    get_cluster_info,
    get_collection_cluster_info,
    get_collection_info,
    get_port,
    get_qdrant_exec,
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
SECOND_EPOCH = 44
FIXTURE_EXAMPLE = "private_oram_cluster_fixture"
ACTIVATION_FIXTURE_EXAMPLE = "private_oram_activation_fixture"
PLACEHOLDER_COLLECTION_ID = "12345678-90ab-cdef-1234-567890abcdef"
LARGE_FIXTURE_PROFILE = "large"
IDS_VISIBLE_RESULT_PRIVACY = "ids_visible"
RUN_LARGE_BUNDLE_BENCHMARK = "QDRANT_RUN_PRIVATE_ORAM_LARGE_BUNDLE_BENCHMARK"
RUN_PROCESS_ENOSPC_GATE = "QDRANT_RUN_PRIVATE_ORAM_PROCESS_ENOSPC"
PROCESS_ENOSPC_CHILD = "QDRANT_PRIVATE_ORAM_PROCESS_ENOSPC_CHILD"
PRIVATE_ORAM_RECOVERY_SIGNING_KEY_ID = "tenant-a/private-oram-recovery-v1"
PRIVATE_ORAM_RECOVERY_CHUNK_BYTES = 8 * 1024 * 1024
PRIVATE_ORAM_MUTATION_V2_PEER_IDS = (101, 102, 103)


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


def _private_oram_mutation_v2_fixture(
    collection_id: str,
    profile: str = "default",
    logical_capacity: int = 2,
) -> dict:
    completed = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "qdrant-sec",
            "--example",
            FIXTURE_EXAMPLE,
            "--",
            "build-mutation-v2",
            collection_id,
            profile,
            str(logical_capacity),
        ],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
    )
    return json.loads(completed.stdout)


def _sign_private_oram_mutation_v2_genesis(
    context: dict,
    fixture: dict,
) -> dict:
    client_state = {
        "hnsw": fixture["hnsw"]["client_state"],
        "result": fixture["result"]["client_state"],
    }
    client_state_bytes = json.dumps(
        client_state, sort_keys=True, separators=(",", ":")
    ).encode()
    client_state_digest = base64.urlsafe_b64encode(
        hashlib.sha256(client_state_bytes).digest()
    ).decode().rstrip("=")
    request = {
        "collection_id": context["collection_id"],
        "layout_generation": int(context["layout_generation"]),
        "layout_digest": context["layout_digest"],
        "client_state_digest": client_state_digest,
        "hnsw_manifest": fixture["hnsw"]["manifest"],
        "hnsw_manifest_signature": fixture["hnsw"]["manifest_signature"],
        "result_manifest": fixture["result"]["manifest"],
        "result_manifest_signature": fixture["result"]["manifest_signature"],
    }
    completed = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "qdrant-sec",
            "--example",
            FIXTURE_EXAMPLE,
            "--",
            "sign-mutation-v2-genesis",
        ],
        cwd=PROJECT_ROOT,
        input=json.dumps(request, separators=(",", ":")),
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
    )
    return json.loads(completed.stdout)


def _run_private_oram_mutation_v2_fixture_command(
    command: str,
    request: dict,
) -> dict:
    try:
        completed = subprocess.run(
            [
                "cargo",
                "run",
                "--quiet",
                "-p",
                "qdrant-sec",
                "--example",
                FIXTURE_EXAMPLE,
                "--",
                command,
            ],
            cwd=PROJECT_ROOT,
            input=json.dumps(request, separators=(",", ":")),
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except subprocess.CalledProcessError as error:
        diagnostic = (error.stderr or "").strip()[:4096]
        raise AssertionError(
            f"private ORAM fixture command {command!r} failed: {diagnostic}"
        ) from error
    return json.loads(completed.stdout)


def _private_oram_mutation_v2_append_context(
    prepared: dict,
    opened: dict,
    *,
    old_state: dict | None = None,
    client_checkpoint: dict | None = None,
    encrypted_client_checkpoint: dict | None = None,
) -> dict:
    fixture = prepared["fixture"]
    enrolled = prepared["signed_genesis"]["rest_enroll_body"]
    hnsw_client_state = fixture["hnsw"]["client_state"]
    result_client_state = fixture["result"]["client_state"]
    if client_checkpoint is not None:
        hnsw_checkpoint = next(
            index for index in client_checkpoint["indexes"] if index["kind"] == "hnsw"
        )
        result_checkpoint = next(
            index
            for index in client_checkpoint["indexes"]
            if index["kind"] == "result"
        )
        hnsw_client_state = {
            "entry_node_id": hnsw_checkpoint["entry_node_id"],
            "snapshot": hnsw_checkpoint["state"],
            "records": hnsw_checkpoint["records"],
        }
        result_client_state = {
            "snapshot": result_checkpoint["state"],
            "records": result_checkpoint["records"],
        }
    context = {
        "collection_id": fixture["collection_id"],
        "hnsw_manifest": fixture["hnsw"]["manifest"],
        "hnsw_manifest_signature": fixture["hnsw"]["manifest_signature"],
        "result_manifest": fixture["result"]["manifest"],
        "result_manifest_signature": fixture["result"]["manifest_signature"],
        "hnsw_client_state": hnsw_client_state,
        "result_client_state": result_client_state,
        "immutable_manifest": enrolled["immutable_manifest"],
        "old_state": old_state or enrolled["genesis_state"],
        "open_response": opened,
    }
    if encrypted_client_checkpoint is not None:
        context["encrypted_client_checkpoint"] = encrypted_client_checkpoint
    return context


def _private_oram_mutation_v2_journal_root(peer_dir: pathlib.Path) -> pathlib.Path:
    roots = list(
        (peer_dir / "storage" / "collections").glob(
            "*/private_oram_mutations"
        )
    )
    assert len(roots) == 1
    return roots[0]


def _private_oram_mutation_v2_file_tree(root: pathlib.Path) -> dict[str, str]:
    assert root.is_dir()
    return {
        str(path.relative_to(root)): (
            "directory"
            if path.is_dir()
            else hashlib.sha256(path.read_bytes()).hexdigest()
        )
        for path in sorted(root.rglob("*"))
    }


def _assert_private_oram_mutation_v2_archive_chain(
    peer_dir: pathlib.Path,
    generation: int,
) -> tuple[pathlib.Path, pathlib.Path]:
    parent_completed = (
        _private_oram_mutation_v2_journal_root(peer_dir)
        / f"completed-v2-{generation:020d}"
    )
    parent_terminal_path = parent_completed / "terminal_archive_v2.json"
    parent_grant_path = parent_completed / "owner_child_archive_grant_v1.json"
    assert parent_terminal_path.is_file()
    assert parent_grant_path.is_file()

    owner_hnsw_roots = list(
        (peer_dir / "storage" / "collections").glob(
            f"*/private_hnsw_oram/{VECTOR}"
        )
    )
    assert len(owner_hnsw_roots) == 1
    child_completed = (
        owner_hnsw_roots[0]
        / "temp"
        / "private-oram-owner-v2"
        / f"completed-v2-{generation:020d}"
    )
    child_archive_path = child_completed / "owner-terminal-archive-v1.json"
    assert child_archive_path.is_file()

    parent_terminal_bytes = parent_terminal_path.read_bytes()
    parent_terminal = json.loads(parent_terminal_bytes)
    parent_grant = json.loads(parent_grant_path.read_bytes())
    child_archive = json.loads(child_archive_path.read_bytes())
    parent_terminal_sha256 = base64.urlsafe_b64encode(
        hashlib.sha256(parent_terminal_bytes).digest()
    ).decode().rstrip("=")

    assert parent_terminal["generation"] == generation
    assert parent_grant["generation"] == generation
    assert child_archive["generation"] == generation
    assert (
        parent_grant["terminal_archive_format"]
        == "private-oram-mutation-terminal-archive/v2"
    )
    assert parent_grant["terminal_archive_file_len"] == len(parent_terminal_bytes)
    assert parent_grant["terminal_archive_file_sha256"] == parent_terminal_sha256
    assert (
        parent_grant["parent_terminal_record_digest"]
        == parent_terminal["terminal_record_digest"]
        == child_archive["parent_terminal_record_digest"]
    )
    assert (
        parent_grant["parent_archive_record_digest"]
        == parent_terminal["archive_digest"]
        == child_archive["parent_archive_record_digest"]
    )
    assert (
        parent_grant["pending_tombstone_digest"]
        == parent_terminal["tombstone_digest"]
        == child_archive["pending_tombstone_digest"]
    )
    assert (
        parent_grant["clear_receipt_digest"]
        == parent_terminal["clear_receipt_digest"]
        == child_archive["clear_receipt_digest"]
    )
    assert child_archive["archive_authority_digest"] == parent_grant["grant_digest"]
    return parent_completed, child_completed


def _execute_private_oram_mutation_v2_reads(
    peer_url: str,
    context: dict,
) -> tuple[dict, list[dict]]:
    plan = _run_private_oram_mutation_v2_fixture_command(
        "plan-mutation-v2-append",
        {"context": context},
    )
    responses = []
    for planned in plan["rest_read_requests"]:
        read = _post_result(
            f"{peer_url}/collections/{COLLECTION}/private-oram/v2/mutation/read",
            planned["rest_read_body"],
        )
        assert read["kind"] == planned["kind"]
        responses.append(
            {
                "kind": planned["kind"],
                "sequence": planned["sequence"],
                "response": read["response"],
            }
        )
    return plan, responses


def _private_oram_v2_wire_body(value: dict) -> dict:
    u64_fields = {
        "bucket_count",
        "bucket_id",
        "created_at_unix",
        "dummy_count",
        "dummy_node_count",
        "dummy_result_count",
        "expires_at_unix",
        "generation",
        "index_epoch",
        "initial_leaf",
        "issued_at_unix",
        "layout_generation",
        "lease_expires_unix",
        "level_mask",
        "logical_capacity",
        "logical_count",
        "logical_node_count",
        "logical_result_count",
        "mutation_lease_generation",
        "new_epoch",
        "new_leaf",
        "old_epoch",
        "old_leaf",
        "owner_peer_id",
        "reserved_physical_slots",
        "rk_epoch",
        "signed_at_unix",
        "state_sequence",
        "writer_fence",
    }
    u64_array_fields = {"bucket_ids", "owner_peer_ids"}

    def encode(item, field_name: str | None = None):
        if field_name in u64_fields:
            assert isinstance(item, int) and item >= 0
            return str(item)
        if field_name in u64_array_fields:
            assert isinstance(item, list)
            return [str(entry) for entry in item]
        if isinstance(item, dict):
            return {key: encode(entry, key) for key, entry in item.items()}
        if isinstance(item, list):
            return [encode(entry) for entry in item]
        return item

    return encode(value)


def _write_private_oram_runtime_config(
    peer_dir: pathlib.Path,
    fixture: dict,
    result_signing_key_id: str = "tenant-a/private-result-signing-v1",
) -> None:
    # A paired V2 collection signs its result index with the HNSW owner key, so its tests pass
    # that key's id here.
    hnsw_public_key = fixture["hnsw_public_key"]
    result_public_key = fixture["result_public_key"]
    recovery_public_key = fixture.get("recovery_public_key")
    recovery_key_config = (
        f"tenant-a/private-oram-recovery-v1: {recovery_public_key}"
        if recovery_public_key is not None
        else ""
    )
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
          {recovery_key_config}
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
          {recovery_key_config}
"""
    (peer_dir / "config" / "local.yaml").write_text(local_config)


def _write_private_oram_mutation_v2_runtime_config(
    peer_dir: pathlib.Path,
    fixture: dict,
    peer_id: int,
    activation: dict | None = None,
) -> None:
    hnsw = fixture["hnsw"]["manifest"]
    result = fixture["result"]["manifest"]
    owner_key_id = fixture["owner_signing_key_id"]
    owner_public_key = fixture["owner_public_key"]
    recovery_public_key = fixture["recovery_public_key"]
    activation_config = " {}"
    if activation is not None:
        bundle_path = peer_dir / "private-oram-activation-authority.json"
        bundle_path.write_text(activation["bundle_canonical_json"])
        activation_config = f"""
    private_oram_mutation_v2_activation:
      authority: {json.dumps(activation["authority_public_key"], separators=(",", ":"))}
      cluster_identity_digest: {activation["cluster_identity_digest"]}
      cluster_first_voter_peer_id: {activation["cluster_first_voter_peer_id"]}
      authority_bundle_path: {json.dumps(str(bundle_path))}
"""
    local_config = f"""
cluster:
  peer_id: {peer_id}
  consensus:{activation_config}

crypto:
  zero_trust_profile: strict
  instances:
    docs_private_hnsw_v1:
      provider: vector/private-hnsw-oram@v1
      materials: {{}}
      options:
        key_id: {hnsw["key_id"]}
        expected_rk_id: {hnsw["rk_id"]}
        min_rk_epoch: {hnsw["rk_epoch"]}
        max_rk_epoch: {hnsw["rk_epoch"]}
        search_execution: client_led
        search_mode: private_hnsw_oram
        result_privacy: {hnsw["result_privacy"]}
        distance: euclid
        dim: 2
        hnsw:
          m: {hnsw["hnsw"]["m"]}
          ef_construction: {hnsw["hnsw"]["ef_construction"]}
          max_layers: {hnsw["hnsw"]["max_layers"]}
          fixed_neighbor_slots: {hnsw["hnsw"]["fixed_neighbor_slots"]}
        oram:
          kind: path_oram
          bucket_size: {hnsw["oram"]["bucket_size"]}
          block_size_bytes: {hnsw["oram"]["block_size_bytes"]}
          tree_height: {hnsw["oram"]["tree_height"]}
          path_batch_size: {hnsw["oram"]["path_batch_size"]}
        fixed_budget:
          enabled: true
          upper_layer_steps: {hnsw["fixed_budget"]["upper_layer_steps"]}
          base_layer_steps: {hnsw["fixed_budget"]["base_layer_steps"]}
          paths_per_round: {hnsw["fixed_budget"]["paths_per_round"]}
          fixed_result_k: {hnsw["fixed_budget"]["fixed_result_k"]}
        integrity:
          manifest_signature_required: true
          commit_signature_required: true
          merkle_root_required: true
        signature_public_keys:
          {owner_key_id}: {owner_public_key}
          {PRIVATE_ORAM_RECOVERY_SIGNING_KEY_ID}: {recovery_public_key}
    docs_private_result_oram_v1:
      provider: payload/private-result-oram@v1
      materials: {{}}
      options:
        key_id: {result["key_id"]}
        expected_rk_id: {result["rk_id"]}
        min_rk_epoch: {result["rk_epoch"]}
        max_rk_epoch: {result["rk_epoch"]}
        oram:
          kind: path_oram
          bucket_size: {result["oram"]["bucket_size"]}
          block_size_bytes: {result["oram"]["block_size_bytes"]}
          tree_height: {result["oram"]["tree_height"]}
          path_batch_size: {result["oram"]["path_batch_size"]}
        integrity:
          manifest_signature_required: true
          commit_signature_required: true
          merkle_root_required: true
        signature_public_keys:
          {owner_key_id}: {owner_public_key}
          {PRIVATE_ORAM_RECOVERY_SIGNING_KEY_ID}: {recovery_public_key}
"""
    (peer_dir / "config" / "local.yaml").write_text(local_config)


def _bootstrap_private_oram_peer_identity(peer_dir: pathlib.Path) -> dict:
    env = os.environ.copy()
    env["QDRANT__CLUSTER__ENABLED"] = "true"
    completed = subprocess.run(
        [get_qdrant_exec(), "--bootstrap-private-oram-peer-identity"],
        cwd=peer_dir,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    json_line = next(
        line for line in reversed(completed.stdout.splitlines()) if line.startswith("{")
    )
    return json.loads(json_line)


def _private_oram_activation_fixture(
    peer_ids: tuple[int, ...],
    peer_port_bases: list[int],
    identities: list[dict],
) -> dict:
    assert len(peer_ids) == len(peer_port_bases) == len(identities)
    binary_capability_digest = identities[0]["binary_capability_digest"]
    assert all(
        identity["binary_capability_digest"] == binary_capability_digest
        for identity in identities
    )
    request = {
        "cluster_first_voter_peer_id": peer_ids[0],
        "peers": [
            {
                "peer_id": peer_id,
                "p2p_uri": get_uri(port_base),
                "signer": identity["public_key"],
            }
            for peer_id, port_base, identity in zip(
                peer_ids, peer_port_bases, identities, strict=True
            )
        ],
        "required_binary_capability_digest": binary_capability_digest,
    }
    completed = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "qdrant-sec",
            "--example",
            ACTIVATION_FIXTURE_EXAMPLE,
        ],
        cwd=PROJECT_ROOT,
        input=json.dumps(request, separators=(",", ":")),
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
    )
    return json.loads(completed.stdout)


def _available_private_oram_peer_port_bases(peer_count: int) -> list[int]:
    port_bases: list[int] = []
    planned_ports: set[int] = set()
    while len(port_bases) < peer_count:
        port_base = get_port()
        ports = {port_base, port_base + 1, port_base + 2}
        if port_base > 65533 or not ports.isdisjoint(planned_ports):
            continue
        sockets = []
        try:
            for port in sorted(ports):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sockets.append(sock)
                sock.bind(("127.0.0.1", port))
        except OSError:
            continue
        finally:
            for sock in sockets:
                sock.close()
        port_bases.append(port_base)
        planned_ports.update(ports)
    return port_bases


def _post_result(url: str, body: dict) -> dict:
    response = requests.post(url, json=body, timeout=30)
    assert_http_ok(response)
    return response.json()["result"]


def _collection_uuid(peer_url: str, collection_name: str = COLLECTION) -> str:
    response = requests.get(
        f"{peer_url}/telemetry", params={"details_level": 2}, timeout=30
    )
    assert_http_ok(response)
    collections = response.json()["result"]["collections"]["collections"]
    collection = next(item for item in collections if item["id"] == collection_name)
    return collection["config"]["uuid"]


def _private_oram_collection_create_body(
    replication_factor: int,
    shard_number: int = 1,
    include_result_oram: bool = True,
    include_public_vector: bool = False,
    write_consistency_factor: int | None = None,
    sharding_method: str = "auto",
) -> dict:
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
    return {
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
    }


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
    capture_stderr: bool = False,
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
        peer_dirs[0],
        "private_oram_peer_0.log",
        extra_env=extra_env,
        capture_stderr=capture_stderr,
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
                capture_stderr=capture_stderr,
            )
        )
    wait_for_uniform_cluster_status(peer_urls, leader)
    # Shard transfers and resharding of an encrypted collection need every peer's crypto runtime
    # capability metadata, which a peer proposes only once its Raft node has been idle for a few
    # ticks; on a slow host that can lag cluster formation.
    _wait_for_crypto_runtime_capability_metadata(
        peer_dirs[:started_peer_count], started_peer_count, wait_for_timeout=90
    )

    create = requests.put(
        f"{bootstrap_api}/collections/{COLLECTION}",
        json=_private_oram_collection_create_body(
            replication_factor,
            shard_number,
            include_result_oram,
            include_public_vector,
            write_consistency_factor,
            sharding_method,
        ),
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
    assert fixture["recovery_public_key"] == bootstrap_fixture["recovery_public_key"]
    return peer_urls, peer_dirs, fixture, leader, bootstrap_uri


def _start_private_oram_mutation_v2_cluster(
    tmp_path: pathlib.Path,
    extra_env_by_peer: list[dict[str, str]] | None = None,
    create_auto_collection_before_followers: bool = False,
) -> tuple[list[str], list[pathlib.Path], dict, int]:
    peer_ids = PRIVATE_ORAM_MUTATION_V2_PEER_IDS
    if extra_env_by_peer is None:
        extra_env_by_peer = [{} for _ in peer_ids]
    assert len(extra_env_by_peer) == len(peer_ids)
    peer_port_bases = _available_private_oram_peer_port_bases(len(peer_ids))
    bootstrap_fixture = _private_oram_mutation_v2_fixture(PLACEHOLDER_COLLECTION_ID)
    peer_dirs = make_peer_folders(tmp_path, len(peer_ids))
    for peer_dir, peer_id in zip(peer_dirs, peer_ids, strict=True):
        _write_private_oram_mutation_v2_runtime_config(
            peer_dir, bootstrap_fixture, peer_id
        )
    identities = [
        _bootstrap_private_oram_peer_identity(peer_dir) for peer_dir in peer_dirs
    ]
    assert tuple(identity["peer_id"] for identity in identities) == peer_ids
    activation = _private_oram_activation_fixture(
        peer_ids, peer_port_bases, identities
    )
    for peer_dir, peer_id in zip(peer_dirs, peer_ids, strict=True):
        _write_private_oram_mutation_v2_runtime_config(
            peer_dir, bootstrap_fixture, peer_id, activation
        )

    bootstrap_api, bootstrap_uri = start_first_peer(
        peer_dirs[0],
        "private_oram_mutation_v2_peer_0.log",
        port=peer_port_bases[0],
        extra_env=extra_env_by_peer[0],
        capture_stderr=True,
    )
    leader = wait_peer_added(bootstrap_api)
    assert leader == peer_ids[0]
    if create_auto_collection_before_followers:
        create = requests.put(
            f"{bootstrap_api}/collections/{COLLECTION}",
            json=_private_oram_collection_create_body(
                replication_factor=1,
                shard_number=1,
                sharding_method="auto",
            ),
            timeout=30,
        )
        assert_http_ok(create)
        wait_collection_exists_and_active_on_all_peers(COLLECTION, [bootstrap_api])
    peer_urls = [bootstrap_api]
    for index in range(1, len(peer_ids)):
        peer_urls.append(
            start_peer(
                peer_dirs[index],
                f"private_oram_mutation_v2_peer_{index}.log",
                bootstrap_uri,
                port=peer_port_bases[index],
                extra_env=extra_env_by_peer[index],
                capture_stderr=True,
            )
        )
    wait_for_uniform_cluster_status(peer_urls, leader)
    return peer_urls, peer_dirs, bootstrap_fixture, leader


def _upload_hnsw(
    peer_url: str,
    fixture: dict,
    collection_name: str = COLLECTION,
) -> None:
    hnsw = fixture["hnsw"]
    _post_result(
        f"{peer_url}/collections/{collection_name}/private-hnsw/{VECTOR}/manifest",
        {
            "manifest": hnsw["manifest"],
            "signature": hnsw["manifest_signature"],
        },
    )
    _post_result(
        f"{peer_url}/collections/{collection_name}/private-hnsw/{VECTOR}/buckets",
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


def _read_hnsw_owner_session(
    peer_url: str,
    fixture: dict,
    session: dict,
    read_fixture: dict | None = None,
    expected_epoch: int = BASE_EPOCH,
) -> dict:
    hnsw = fixture["hnsw"]
    read_fixture = read_fixture or hnsw["read"]
    read = _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/oram/read_paths",
        {
            "session_id": session["session_id"],
            "index_epoch": expected_epoch,
            "root_hash": session["root_hash"],
            "paths": read_fixture["paths"],
            "padding": {"requested_paths": 1, "dummy_paths_included": True},
            "client_signature": read_fixture["signature"],
        },
    )
    assert read["index_epoch"] == expected_epoch
    assert read["root_hash"] == session["root_hash"]
    assert len(read["buckets"]) == hnsw["manifest"]["oram"]["tree_height"] + 1
    return read


def _commit_hnsw_owner_session(
    peer_url: str,
    session: dict,
    commit: dict,
) -> dict:
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
    assert committed["index_epoch"] == commit["new_epoch"]
    assert committed["root_hash"] == commit["new_root_hash"]
    return committed


def _exercise_hnsw_owner_session(peer_url: str, fixture: dict) -> None:
    hnsw = fixture["hnsw"]
    session = _open_hnsw_owner_session(
        peer_url, BASE_EPOCH, hnsw["manifest"]["result_privacy"]
    )
    _read_hnsw_owner_session(peer_url, fixture, session)

    _commit_hnsw_owner_session(peer_url, session, hnsw["commit"])

    closed = _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session/{session['session_id']}/close",
        {},
    )
    assert closed is True


def _upload_result_oram(
    peer_url: str,
    fixture: dict,
    collection_name: str = COLLECTION,
) -> None:
    result = fixture["result"]
    _post_result(
        f"{peer_url}/collections/{collection_name}/private-result-oram/manifest",
        {
            "manifest": result["manifest"],
            "signature": result["manifest_signature"],
        },
    )
    _post_result(
        f"{peer_url}/collections/{collection_name}/private-result-oram/buckets",
        {
            "index_epoch": BASE_EPOCH,
            "root_hash": result["manifest"]["root_hash"],
            "buckets": result["buckets"],
        },
    )


def _refresh_private_oram_manifests(peer_url: str, fixture: dict) -> None:
    for endpoint, refresh in [
        (
            f"private-hnsw/{VECTOR}",
            fixture["hnsw"]["manifest_refresh"],
        ),
        (
            "private-result-oram",
            fixture["result"]["manifest_refresh"],
        ),
    ]:
        assert refresh["manifest"]["index_epoch"] == NEXT_EPOCH
        _post_result(
            f"{peer_url}/collections/{COLLECTION}/{endpoint}/manifest",
            refresh,
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


def _read_result_owner_session(
    peer_url: str,
    fixture: dict,
    session: dict,
    read_fixture: dict | None = None,
    expected_epoch: int = BASE_EPOCH,
) -> dict:
    result = fixture["result"]
    read_fixture = read_fixture or result["read"]
    read = _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-result-oram/oram/read_buckets",
        {
            "session_id": session["session_id"],
            "index_epoch": expected_epoch,
            "root_hash": session["root_hash"],
            "bucket_ids": read_fixture["bucket_ids"],
            "read_signature": read_fixture["signature"],
        },
    )
    assert read["index_epoch"] == expected_epoch
    assert read["root_hash"] == session["root_hash"]
    assert len(read["buckets"]) == len(read_fixture["bucket_ids"])
    return read


def _commit_result_owner_session(
    peer_url: str,
    session: dict,
    commit: dict,
) -> dict:
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
    assert committed["index_epoch"] == commit["new_epoch"]
    assert committed["root_hash"] == commit["new_root_hash"]
    return committed


def _exercise_result_owner_session(peer_url: str, fixture: dict) -> None:
    result = fixture["result"]
    session = _open_result_owner_session(peer_url, BASE_EPOCH)
    _read_result_owner_session(peer_url, fixture, session)

    _commit_result_owner_session(peer_url, session, result["commit"])

    closed = _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-result-oram/session/{session['session_id']}/close",
        {},
    )
    assert closed is True


def _verify_private_oram_read_proofs(
    fixture: dict,
    hnsw_read: dict,
    result_read: dict,
    expected_epoch: int,
    expected_hnsw_root: str,
    expected_result_root: str,
) -> dict:
    hnsw_read_fixture = fixture["hnsw"][
        "read" if expected_epoch == BASE_EPOCH else "restart_read"
    ]
    result_read_fixture = fixture["result"][
        "read" if expected_epoch == BASE_EPOCH else "restart_read"
    ]
    request = {
        "hnsw": {
            "manifest": fixture["hnsw"]["manifest"],
            "expected_index_epoch": expected_epoch,
            "expected_root_hash": expected_hnsw_root,
            "response_index_epoch": hnsw_read["index_epoch"],
            "response_root_hash": hnsw_read["root_hash"],
            "leaf_labels": hnsw_read_fixture["paths"],
            "bucket_count": fixture["hnsw"]["manifest"]["bucket_count"],
            "proof_value": hnsw_read["proof"]["value"],
            "buckets": hnsw_read["buckets"],
        },
        "result": {
            "expected_index_epoch": expected_epoch,
            "expected_root_hash": expected_result_root,
            "response_index_epoch": result_read["index_epoch"],
            "response_root_hash": result_read["root_hash"],
            "bucket_ids": result_read_fixture["bucket_ids"],
            "bucket_count": fixture["result"]["manifest"]["bucket_count"],
            "proof_value": result_read["proof"]["value"],
            "buckets": result_read["buckets"],
        },
    }
    _run_private_oram_read_proof_verifier(request, expect_success=True)
    return request


def _run_private_oram_read_proof_verifier(
    request: dict,
    expect_success: bool,
    case: str = "untampered",
) -> None:
    completed = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "qdrant-sec",
            "--example",
            FIXTURE_EXAMPLE,
            "--",
            "verify-read-proofs",
        ],
        cwd=PROJECT_ROOT,
        input=json.dumps(request),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if expect_success:
        assert completed.returncode == 0, completed.stderr
        assert json.loads(completed.stdout) == {"verified": True}
    else:
        assert completed.returncode != 0, f"tampered verifier case passed: {case}"


def _sign_private_oram_recovery_checkpoint(
    export: dict,
    fixture: dict,
    intent: dict,
    expect_success: bool = True,
    expected_indexes: list[dict] | None = None,
) -> dict | None:
    if expected_indexes is None:
        expected_indexes = [
            {
                "index_kind": "hnsw",
                "index_name": VECTOR,
                "index_epoch": BASE_EPOCH,
                "root_hash": fixture["hnsw"]["manifest"]["root_hash"],
                "writeback_digest": None,
            },
            {
                "index_kind": "result_payload",
                "index_name": "",
                "index_epoch": BASE_EPOCH,
                "root_hash": fixture["result"]["manifest"]["root_hash"],
                "writeback_digest": None,
            },
        ]
    completed = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "qdrant-sec",
            "--example",
            FIXTURE_EXAMPLE,
            "--",
            "sign-recovery-checkpoint",
        ],
        cwd=PROJECT_ROOT,
        input=json.dumps(
            {
                "checkpoint": export["checkpoint"],
                "index_states": export["index_states"],
                "expected_indexes": expected_indexes,
                "intent": intent,
            }
        ),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if expect_success:
        assert completed.returncode == 0, completed.stderr
        return json.loads(completed.stdout)
    assert completed.returncode != 0
    for binding in export["index_states"]:
        assert binding["state"]["root_hash"] not in completed.stderr
    return None


def _private_oram_recovery_signing_intent(
    peer_url: str,
    export: dict,
    fixture: dict,
    client_recovery_state_digest: str,
    collection_name: str = COLLECTION,
) -> dict:
    peer_id = get_cluster_info(peer_url)["peer_id"]
    collection_info = get_collection_cluster_info(peer_url, collection_name)
    source_shard_ids = sorted(
        shard["shard_id"] for shard in collection_info["local_shards"]
    )
    checkpoint = export["checkpoint"]
    snapshot = export["snapshot"]
    return {
        "expected_collection_id": fixture["hnsw"]["manifest"]["collection_id"],
        "expected_committed_backup_generation": 0,
        "requested_backup_generation": 1,
        "expected_source_peer_id": peer_id,
        "expected_source_shard_ids": source_shard_ids,
        "expected_layout_generation": checkpoint["layout_generation"],
        "expected_layout_digest": checkpoint["layout_digest"],
        "expected_owner_snapshot_authority_digest": checkpoint[
            "owner_snapshot_authority_digest"
        ],
        "expected_snapshot_size_bytes": snapshot["size"],
        "expected_snapshot_sha256": snapshot["checksum"],
        "expected_client_recovery_state_digest": client_recovery_state_digest,
        "expected_owner_signing_key_id": PRIVATE_ORAM_RECOVERY_SIGNING_KEY_ID,
    }


def _export_private_oram_recovery_snapshot(
    peer_url: str,
    tmp_path: pathlib.Path,
    fixture: dict,
    collection_name: str = COLLECTION,
    expected_indexes: list[dict] | None = None,
) -> tuple[pathlib.Path, dict]:
    encoded_client_recovery_state = fixture["result"][
        "client_recovery_state_base64url"
    ]
    client_recovery_state = base64.urlsafe_b64decode(
        encoded_client_recovery_state
        + "=" * (-len(encoded_client_recovery_state) % 4)
    )
    assert json.loads(client_recovery_state) == fixture["result"][
        "encrypted_client_state"
    ]
    client_recovery_state_digest = base64.urlsafe_b64encode(
        hashlib.sha256(client_recovery_state).digest()
    ).rstrip(b"=").decode()
    assert client_recovery_state_digest != fixture["result"][
        "encrypted_client_state"
    ]["ciphertext_sha256"]
    export = _post_result(
        f"{peer_url}/collections/{collection_name}/private-oram/recovery/export-context",
        {
            "expected_committed_backup_generation": 0,
            "backup_generation": 1,
            "client_recovery_state_digest": client_recovery_state_digest,
            "owner_signing_key_id": PRIVATE_ORAM_RECOVERY_SIGNING_KEY_ID,
        },
    )
    checkpoint = export["checkpoint"]
    snapshot = export["snapshot"]
    assert checkpoint["snapshot_size_bytes"] == snapshot["size"]
    assert checkpoint["snapshot_sha256"] == snapshot["checksum"]
    assert checkpoint["client_recovery_state_digest"] == client_recovery_state_digest

    snapshot_path = tmp_path / f"{collection_name}-{snapshot['name']}"
    with requests.get(
        f"{peer_url}/collections/{collection_name}/snapshots/{snapshot['name']}",
        stream=True,
        timeout=60,
    ) as response:
        assert_http_ok(response)
        with snapshot_path.open("wb") as snapshot_file:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                snapshot_file.write(chunk)
    snapshot_digest = hashlib.sha256()
    with snapshot_path.open("rb") as snapshot_file:
        while chunk := snapshot_file.read(1024 * 1024):
            snapshot_digest.update(chunk)
    assert snapshot_path.stat().st_size == snapshot["size"]
    assert snapshot_digest.hexdigest() == snapshot["checksum"]

    intent = _private_oram_recovery_signing_intent(
        peer_url,
        export,
        fixture,
        client_recovery_state_digest,
        collection_name,
    )
    bundle = _sign_private_oram_recovery_checkpoint(
        export,
        fixture,
        intent,
        expected_indexes=expected_indexes,
    )
    assert bundle is not None
    assert bundle["checkpoint"] == checkpoint
    return snapshot_path, bundle


def _begin_and_upload_private_oram_snapshot(
    peer_url: str,
    snapshot_path: pathlib.Path,
    bundle: dict,
    collection_name: str = COLLECTION,
) -> str:
    begin = _post_result(
        f"{peer_url}/collections/{collection_name}/private-oram/recovery/begin",
        bundle,
    )
    operation_token = begin["operation_token"]
    assert begin["status"]["phase"] == "uploading"

    with snapshot_path.open("rb") as snapshot_file:
        chunk_index = 0
        while chunk := snapshot_file.read(PRIVATE_ORAM_RECOVERY_CHUNK_BYTES):
            response = requests.post(
                f"{peer_url}/collections/{collection_name}/private-oram/recovery/upload",
                data={
                    "operation_token": operation_token,
                    "chunk_index": str(chunk_index),
                    "chunk_sha256": hashlib.sha256(chunk).hexdigest(),
                },
                files={"chunk": ("snapshot.chunk", chunk, "application/octet-stream")},
                timeout=60,
            )
            assert_http_ok(response)
            status = response.json()["result"]
            assert status["next_chunk_index"] == chunk_index + 1
            chunk_index += 1
    assert chunk_index > 0
    return operation_token


def _restore_private_oram_snapshot(
    peer_url: str,
    snapshot_path: pathlib.Path,
    bundle: dict,
) -> None:
    operation_token = _begin_and_upload_private_oram_snapshot(
        peer_url,
        snapshot_path,
        bundle,
    )

    verified = _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-oram/recovery/verify",
        {"operation_token": operation_token},
    )
    assert verified["phase"] == "verified"
    assert (
        _post_result(
            f"{peer_url}/collections/{COLLECTION}/private-oram/recovery/commit",
            {"operation_token": operation_token},
        )
        is True
    )
    checkpoint = bundle["checkpoint"]
    stale_export = requests.post(
        f"{peer_url}/collections/{COLLECTION}/private-oram/recovery/export-context",
        json={
            "expected_committed_backup_generation": 0,
            "backup_generation": checkpoint["backup_generation"] + 1,
            "client_recovery_state_digest": checkpoint[
                "client_recovery_state_digest"
            ],
            "owner_signing_key_id": checkpoint["owner_signing_key_id"],
        },
        timeout=30,
    )
    assert 400 <= stale_export.status_code < 500
    for secret in [
        checkpoint["collection_id"],
        checkpoint["layout_digest"],
        checkpoint["index_state_digest"],
        checkpoint["owner_snapshot_authority_digest"],
        checkpoint["client_recovery_state_digest"],
        checkpoint["owner_signing_key_id"],
    ]:
        assert secret not in stale_export.text


def _private_oram_plaintext_sentinel_variants(
    fixture: dict,
) -> list[tuple[str, bytes]]:
    variants = []
    for sentinel in fixture["plaintext_leakage_sentinels"]:
        encoded = sentinel["base64url"]
        padding = "=" * (-len(encoded) % 4)
        raw = base64.urlsafe_b64decode(encoded + padding)
        assert len(raw) >= 8
        encoded_variants = {
            raw,
            encoded.encode(),
            base64.urlsafe_b64encode(raw),
            base64.b64encode(raw),
            base64.b64encode(raw).rstrip(b"="),
            raw.hex().encode(),
            raw.hex().upper().encode(),
            str(list(raw)).encode(),
            json.dumps(list(raw), separators=(",", ":")).encode(),
            json.dumps(list(raw), indent=2).encode(),
        }
        try:
            decoded_json = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
        else:
            encoded_variants.add(json.dumps(decoded_json, indent=2).encode())
        variants.extend(
            (f"{sentinel['name']}:{encoding_index}", value)
            for encoding_index, value in enumerate(encoded_variants)
        )
    return variants


def _assert_private_oram_plaintext_sentinels_absent(
    roots: dict[str, pathlib.Path],
    fixture: dict,
) -> None:
    sentinels = _private_oram_plaintext_sentinel_variants(fixture)
    max_sentinel_len = max(len(value) for _, value in sentinels)
    scanned_files = 0
    for surface, root in roots.items():
        files = [root] if root.is_file() else sorted(root.rglob("*"))
        surface_files = 0
        for path in files:
            if not path.is_file():
                continue
            surface_files += 1
            scanned_files += 1
            overlap = b""
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    window = overlap + chunk
                    for sentinel_name, sentinel in sentinels:
                        assert sentinel not in window, (
                            f"private ORAM plaintext sentinel {sentinel_name} leaked into "
                            f"{surface}: {path}"
                        )
                    overlap = window[-(max_sentinel_len - 1) :]
        assert surface_files > 0, f"no files scanned for {surface}: {root}"
    assert scanned_files > 0


def _assert_private_oram_plaintext_sentinels_absent_from_bytes(
    surfaces: dict[str, bytes],
    fixture: dict,
) -> None:
    sentinels = _private_oram_plaintext_sentinel_variants(fixture)
    assert surfaces
    for surface, content in surfaces.items():
        assert content, f"empty private ORAM leakage surface: {surface}"
        for sentinel_name, sentinel in sentinels:
            assert sentinel not in content, (
                f"private ORAM plaintext sentinel {sentinel_name} leaked into {surface}"
            )


def _assert_private_oram_read_proof_tampering_rejected(request: dict) -> None:
    cases = []

    tampered = json.loads(json.dumps(request))
    value = tampered["hnsw"]["buckets"][0]["ciphertext"]
    tampered["hnsw"]["buckets"][0]["ciphertext"] = (
        ("A" if value[0] != "A" else "B") + value[1:]
    )
    cases.append(("hnsw-ciphertext", tampered))

    tampered = json.loads(json.dumps(request))
    proof = json.loads(tampered["hnsw"]["proof_value"])
    sibling = next(
        sibling
        for leaf in proof["leaves"]
        for sibling in leaf["siblings"]
    )
    value = sibling["hash"]
    sibling["hash"] = ("A" if value[0] != "A" else "B") + value[1:]
    tampered["hnsw"]["proof_value"] = json.dumps(proof)
    cases.append(("hnsw-proof", tampered))

    tampered = json.loads(json.dumps(request))
    value = tampered["hnsw"]["expected_root_hash"]
    tampered["hnsw"]["expected_root_hash"] = (
        ("A" if value[0] != "A" else "B") + value[1:]
    )
    cases.append(("hnsw-trusted-root", tampered))

    tampered = json.loads(json.dumps(request))
    tampered["hnsw"]["expected_index_epoch"] -= 1
    cases.append(("hnsw-trusted-epoch", tampered))

    tampered = json.loads(json.dumps(request))
    value = tampered["hnsw"]["response_root_hash"]
    tampered["hnsw"]["response_root_hash"] = (
        ("A" if value[0] != "A" else "B") + value[1:]
    )
    cases.append(("hnsw-response-root", tampered))

    tampered = json.loads(json.dumps(request))
    tampered["hnsw"]["response_index_epoch"] -= 1
    cases.append(("hnsw-response-epoch", tampered))

    tampered = json.loads(json.dumps(request))
    tampered["hnsw"]["buckets"].pop()
    cases.append(("hnsw-missing-bucket", tampered))

    tampered = json.loads(json.dumps(request))
    tampered["hnsw"]["buckets"].append(tampered["hnsw"]["buckets"][0])
    cases.append(("hnsw-unrequested-duplicate", tampered))

    tampered = json.loads(json.dumps(request))
    tampered["hnsw"]["buckets"] = []
    cases.append(("hnsw-empty-buckets", tampered))

    tampered = json.loads(json.dumps(request))
    value = tampered["result"]["buckets"][0]["ciphertext"]
    tampered["result"]["buckets"][0]["ciphertext"] = (
        ("A" if value[0] != "A" else "B") + value[1:]
    )
    cases.append(("result-ciphertext", tampered))

    for case, tampered_request in cases:
        _run_private_oram_read_proof_verifier(
            tampered_request,
            expect_success=False,
            case=case,
        )


def _assert_replica_can_open_current_sessions(
    peer_url: str,
    desired_epoch: int = NEXT_EPOCH,
    expected_hnsw_root: str | None = None,
    expected_result_root: str | None = None,
) -> None:
    for endpoint, body in [
        (
            f"private-hnsw/{VECTOR}",
            {
                "client_id": "tenant-a/replica-hnsw-sdk",
                "desired_epoch": desired_epoch,
                "fixed_budget": True,
                "result_privacy": "private_payload_oram_required",
            },
        ),
        (
            "private-result-oram",
            {
                "client_id": "tenant-a/replica-result-sdk",
                "desired_epoch": desired_epoch,
                "fixed_budget": True,
            },
        ),
    ]:
        session = _post_result(
            f"{peer_url}/collections/{COLLECTION}/{endpoint}/session", body
        )
        assert session["index_epoch"] == desired_epoch
        expected_root = (
            expected_hnsw_root
            if endpoint.startswith("private-hnsw")
            else expected_result_root
        )
        if expected_root is not None:
            assert session["root_hash"] == expected_root
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


def _activate_private_oram_mutation_v3_for_fixture(leader_url: str) -> dict:
    # These fixtures run only current peers and require the V3 writer floor. Upgrade
    # tests that intentionally retain an old floor use their own activation helper.
    deadline = time.monotonic() + 90
    last_activation = None
    last_status = None
    transient_errors = (
        "private ORAM activation requires a stable voter configuration",
        "private ORAM activation requires a stable local consensus state",
        "private ORAM activation evidence does not match stable local consensus state",
        "private ORAM activation acknowledgement failed on peer ",
        "private ORAM activation timed out",
    )
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining < 1:
            break
        response = requests.post(
            f"{leader_url}/cluster/private-oram/mutation-v2/activate",
            params={"timeout": min(60, int(remaining))},
            timeout=remaining,
        )
        last_activation = (response.status_code, response.text)
        # An arbitrary refusal (including unsupported binary capabilities) is a
        # fixture error. Only consensus-readiness failures can become ready later.
        assert response.status_code == 200 or (
            response.status_code == 500
            and any(error in response.text for error in transient_errors)
        ), f"mutation activation refused: {last_activation}; status: {last_status}"
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        status_response = requests.get(
            f"{leader_url}/cluster/private-oram/mutation-v2/status",
            timeout=min(30, remaining),
        )
        last_status = (status_response.status_code, status_response.text)
        assert status_response.status_code == 200, (
            f"mutation activation status failed: {last_status}; activate: {last_activation}"
        )
        status = status_response.json()["result"]
        if (
            status["status"] == "active"
            and status["reservation_v3_write_floor_active"] is True
        ):
            return status
        assert status["status"] in {"unprepared", "prepared", "active"}, last_status
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(0.5, remaining))
    raise AssertionError(
        "mutation activation did not reach the active V3 writer floor within 90 seconds; "
        f"activate: {last_activation}; status: {last_status}"
    )


def _prepare_private_oram_mutation_v2_collection(
    tmp_path: pathlib.Path,
    extra_env_by_peer: list[dict[str, str]] | None = None,
    fixture_logical_capacity: int = 2,
    sharding_method: str = "custom",
) -> dict:
    peer_urls, peer_dirs, bootstrap_fixture, leader = (
        _start_private_oram_mutation_v2_cluster(
            tmp_path,
            extra_env_by_peer,
            create_auto_collection_before_followers=sharding_method == "auto",
        )
    )
    leader_url = peer_urls[0]
    if sharding_method != "auto":
        create = requests.put(
            f"{leader_url}/collections/{COLLECTION}",
            json=_private_oram_collection_create_body(
                replication_factor=1,
                shard_number=1,
                sharding_method=sharding_method,
            ),
            timeout=30,
        )
        assert_http_ok(create)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    fixture = _private_oram_mutation_v2_fixture(
        _collection_uuid(leader_url),
        logical_capacity=fixture_logical_capacity,
    )
    assert fixture["owner_public_key"] == bootstrap_fixture["owner_public_key"]
    if sharding_method == "custom":
        create_shard = requests.put(
            f"{leader_url}/collections/{COLLECTION}/shards?timeout=60",
            json={
                "shard_key": "tenant-v2",
                "shards_number": 1,
                "replication_factor": 1,
                "placement": [leader],
            },
            timeout=60,
        )
        assert_http_ok(create_shard)
        wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    else:
        assert sharding_method == "auto"
        _wait_for_crypto_runtime_capability_metadata(peer_dirs, len(peer_urls))
        leader_collection = get_collection_cluster_info(leader_url, COLLECTION)
        assert len(leader_collection["local_shards"]) == 1
        assert leader_collection["remote_shards"] == []

    _upload_hnsw(leader_url, fixture)
    _upload_result_oram(leader_url, fixture)

    context_url = (
        f"{leader_url}/collections/{COLLECTION}/private-oram/v2/mutation/"
        f"enrollment-context/{VECTOR}"
    )
    context_deadline = time.monotonic() + 30
    while True:
        context_response = requests.get(context_url, timeout=30)
        if context_response.status_code == 200:
            break
        context_error = context_response.text
        if (
            context_response.status_code != 500
            or "private ORAM mutation genesis enrollment state is incomplete"
            not in context_error
            or time.monotonic() >= context_deadline
        ):
            break
        time.sleep(0.5)
    assert_http_ok(context_response)
    context = context_response.json()["result"]
    assert context["collection_id"] == fixture["collection_id"]
    assert int(context["layout_generation"]) >= 1
    assert context["owner_peer_ids"] == [str(leader)]
    assert context["enrollment_status"] == "open"
    assert context["hnsw_manifest"] == _private_oram_v2_wire_body(
        {
            "manifest": fixture["hnsw"]["manifest"],
            "signature": fixture["hnsw"]["manifest_signature"],
        }
    )
    assert context["result_manifest"] == _private_oram_v2_wire_body(
        {
            "manifest": fixture["result"]["manifest"],
            "signature": fixture["result"]["manifest_signature"],
        }
    )

    signed_genesis = _sign_private_oram_mutation_v2_genesis(context, fixture)
    enroll_body = _private_oram_v2_wire_body(signed_genesis["rest_enroll_body"])
    _activate_private_oram_mutation_v3_for_fixture(leader_url)

    enrolled = _post_result(
        f"{leader_url}/collections/{COLLECTION}/private-oram/v2/mutation/enroll",
        enroll_body,
    )
    assert enrolled["collection_id"] == fixture["collection_id"]
    assert enrolled["layout_generation"] == context["layout_generation"]
    assert enrolled["layout_digest"] == context["layout_digest"]
    assert enrolled["manifest_digest"] == signed_genesis["manifest_digest"]

    replayed = _post_result(
        f"{leader_url}/collections/{COLLECTION}/private-oram/v2/mutation/enroll",
        enroll_body,
    )
    assert replayed == enrolled
    owner = _post_result(
        f"{leader_url}/collections/{COLLECTION}/private-oram/v2/mutation/owner-enroll",
        {},
    )
    assert owner == {
        "collection_id": fixture["collection_id"],
        "owner_peer_id": str(leader),
        "active": True,
    }
    return {
        "peer_urls": peer_urls,
        "peer_dirs": peer_dirs,
        "leader": leader,
        "leader_url": leader_url,
        "fixture": fixture,
        "signed_genesis": signed_genesis,
        "enroll_body": enroll_body,
        "enrolled": enrolled,
    }


def _open_private_oram_mutation_v2_session(
    prepared: dict,
    mutation_label: bytes,
) -> tuple[dict, dict]:
    fixture = prepared["fixture"]
    signed_genesis = prepared["signed_genesis"]
    leader_url = prepared["leader_url"]
    mutation_id = base64.urlsafe_b64encode(
        hashlib.sha256(mutation_label).digest()
    ).decode().rstrip("=")
    open_body = _private_oram_v2_wire_body(
        {
            "client_id": "tenant-a/process-v2-sdk",
            "vector_name": VECTOR,
            "mutation_id": mutation_id,
            "immutable_manifest": signed_genesis["rest_enroll_body"][
                "immutable_manifest"
            ],
            "old_state": signed_genesis["rest_enroll_body"]["genesis_state"],
        }
    )
    opened = _post_result(
        f"{leader_url}/collections/{COLLECTION}/private-oram/v2/mutation/open",
        open_body,
    )
    assert opened["collection_id"] == fixture["collection_id"]
    assert opened["mutation_id"] == mutation_id
    assert opened["mutation_lease_generation"] == "1"
    assert opened["writer_fence"] == "1"
    assert {index["kind"] for index in opened["indexes"]} == {"hnsw", "result"}
    return opened, open_body


def test_private_oram_mutation_v2_production_bootstrap_opens_encrypted_session(
    tmp_path: pathlib.Path,
):
    prepared = _prepare_private_oram_mutation_v2_collection(tmp_path)
    leader_url = prepared["leader_url"]
    opened, _ = _open_private_oram_mutation_v2_session(
        prepared,
        b"private-oram-v2-process-bootstrap-mutation",
    )
    closed = _post_result(
        f"{leader_url}/collections/{COLLECTION}/private-oram/v2/mutation/close",
        {"session_id": opened["session_id"]},
    )
    assert closed is True


def test_private_oram_mutation_v2_append_commits_and_cleans_up(
    tmp_path: pathlib.Path,
):
    prepared = _prepare_private_oram_mutation_v2_collection(tmp_path)
    peer_urls = prepared["peer_urls"]
    peer_dirs = prepared["peer_dirs"]
    leader_url = prepared["leader_url"]
    opened, _ = _open_private_oram_mutation_v2_session(
        prepared,
        b"private-oram-v2-process-commit",
    )
    append_context = _private_oram_mutation_v2_append_context(prepared, opened)
    read_plan, read_responses = _execute_private_oram_mutation_v2_reads(
        leader_url,
        append_context,
    )
    assert read_plan["fixed_read_budget"] == {
        "hnsw_paths": 3,
        "result_paths": 3,
        "paths_per_window": 1,
    }
    finalized = _run_private_oram_mutation_v2_fixture_command(
        "finalize-mutation-v2-append",
        {
            "context": append_context,
            "read_responses": read_responses,
        },
    )
    append_body = finalized["rest_append_body"]
    new_state = append_body["owner_prepare"]["mutation_bundle"]["mutation"][
        "new_state"
    ]["state"]

    accepted = _post_result(
        f"{leader_url}/collections/{COLLECTION}/private-oram/v2/mutation/append",
        append_body,
    )
    assert accepted == {"accepted": True, "phase": "prestage_pending"}

    # The HTTP handler consumed the paired read sessions while detaching this job.
    # Check durable progress: successful cleanup may already have removed the session.
    # Requiring its consumed read sessions for local prestage would prevent this commit.
    _wait_for_private_oram_epochs(peer_dirs, NEXT_EPOCH, 2)

    terminal_projection: dict[str, dict] = {}

    def mutation_is_terminal_and_cleared() -> bool:
        projections = [
            _private_oram_consensus_protocol_projection(peer_dir)
            for peer_dir in peer_dirs
        ]
        if projections[0] is None or any(
            projection != projections[0] for projection in projections[1:]
        ):
            return False
        states = projections[0]["private_oram_mutation_states"]
        slots = projections[0]["private_oram_mutation_lease_slots"]
        if len(states) != 1 or len(slots) != 1:
            return False
        state = next(iter(states.values()))
        authority = next(iter(slots.values()))["authority"]
        if authority.get("mode") != "activated":
            return False
        activated = authority["state"]
        lease_slot = activated["lease_slot"]
        lifecycle = activated["lifecycle"]
        if (
            state["state_sequence"] != 1
            or state["signed_state_digest"] != finalized["new_state_digest"]
            or state["client_state_digest"] != new_state["client_state_digest"]
            or state["last_transition"].get("kind") != "mutation"
            or state["last_transition"]["receipt"]["mutation_id"]
            != finalized["mutation_id"]
            or lease_slot["generation"] != 1
            or lease_slot["active"] is not None
            or lease_slot["last_clear"] is None
            or lifecycle["active"] is not None
            or lifecycle["last_cleared"] is None
        ):
            return False
        terminal_projection["value"] = projections[0]
        return True

    wait_for(mutation_is_terminal_and_cleared, wait_for_timeout=90)
    assert terminal_projection["value"] is not None

    def all_supervisors_are_ready() -> bool:
        for peer_url in peer_urls:
            response = requests.get(
                f"{peer_url}/cluster/private-oram/mutation-v2/status",
                timeout=30,
            )
            assert_http_ok(response)
            status = response.json()["result"]["supervisor"]
            if (
                status["state"] != "ready"
                or status["process_local_pending"] != 0
                or status["owned_elsewhere"] != 0
                or status["awaiting_cleanup"] != 0
                or status["failed"] != 0
            ):
                return False
        return True

    wait_for(all_supervisors_are_ready, wait_for_timeout=60)
    expected_roots = {index["kind"]: index["root_hash"] for index in new_state["indexes"]}
    _assert_replica_can_open_current_sessions(
        leader_url,
        NEXT_EPOCH,
        expected_roots["hnsw"],
        expected_roots["result"],
    )

    replayed: requests.Response | None = None

    def replay_is_rejected_by_current_leader() -> bool:
        nonlocal replayed
        infos = {peer_url: get_cluster_info(peer_url) for peer_url in peer_urls}
        leader_id = infos[peer_urls[0]]["raft_info"]["leader"]
        if leader_id is None or any(
            info["raft_info"]["leader"] != leader_id for info in infos.values()
        ):
            return False
        current_leader_url = next(
            peer_url for peer_url, info in infos.items() if info["peer_id"] == leader_id
        )
        response = requests.post(
            f"{current_leader_url}/collections/{COLLECTION}/private-oram/v2/mutation/append",
            json=append_body,
            timeout=30,
        )
        # Leadership can move again after discovery; only that precondition is retryable.
        if response.status_code == 500 and response.json()["status"]["error"] == (
            "Pre-condition failure: private ORAM mutation must be coordinated by the current leader"
        ):
            return False
        assert 400 <= response.status_code < 500, response.text
        replayed = response
        return True

    wait_for(replay_is_rejected_by_current_leader, wait_for_timeout=30)
    assert replayed is not None
    sensitive_ciphertext = append_body["owner_prepare"]["indexes"][0][
        "ordered_encrypted_buckets"
    ]["buckets"][0]["ciphertext"]
    assert sensitive_ciphertext not in replayed.text


def test_private_oram_mutation_v2_owner_follower_resumes_after_leader_change(
    tmp_path: pathlib.Path,
):
    pause_file = tmp_path / "private-oram-v2-post-admission.pause"
    pause_file.write_text("pause")
    # Large recovery entries can occupy the debug consensus thread for seconds.
    # Keep elections tied to the deliberate owner stop, including after restart.
    consensus_env = {"QDRANT__CLUSTER__CONSENSUS__TICK_PERIOD_MS": "1000"}
    # Separate the surviving voters' 20-40 and 60-120 second election windows.
    # Simultaneous self-votes can otherwise exhaust the failover deadline.
    slow_follower_env = {"QDRANT__CLUSTER__CONSENSUS__TICK_PERIOD_MS": "3000"}
    pause_env = {
        **consensus_env,
        "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_POST_ADMISSION_PAUSE_FILE": str(
            pause_file
        )
    }
    prepared = _prepare_private_oram_mutation_v2_collection(
        tmp_path,
        [pause_env, consensus_env, slow_follower_env],
    )
    peer_urls = prepared["peer_urls"]
    peer_dirs = prepared["peer_dirs"]
    owner_peer_id = prepared["leader"]
    owner_url = prepared["leader_url"]
    opened, open_body = _open_private_oram_mutation_v2_session(
        prepared,
        b"private-oram-v2-owner-follower-resume",
    )
    append_context = _private_oram_mutation_v2_append_context(prepared, opened)
    read_plan, read_responses = _execute_private_oram_mutation_v2_reads(
        owner_url,
        append_context,
    )
    assert read_plan["fixed_read_budget"] == {
        "hnsw_paths": 3,
        "result_paths": 3,
        "paths_per_window": 1,
    }
    finalized = _run_private_oram_mutation_v2_fixture_command(
        "finalize-mutation-v2-append",
        {
            "context": append_context,
            "read_responses": read_responses,
        },
    )
    append_body = finalized["rest_append_body"]
    new_state = append_body["owner_prepare"]["mutation_bundle"]["mutation"][
        "new_state"
    ]["state"]
    assert new_state["state_sequence"] == "1"
    assert all(index["index_epoch"] == str(NEXT_EPOCH) for index in new_state["indexes"])

    initial_projection = _wait_for_private_oram_consensus_protocol_projection(peer_dirs)
    accepted = _post_result(
        f"{owner_url}/collections/{COLLECTION}/private-oram/v2/mutation/append",
        append_body,
    )
    assert accepted == {"accepted": True, "phase": "prestage_pending"}

    owner_log = (
        pathlib.Path(init_pytest_log_folder())
        / "private_oram_mutation_v2_peer_0.log"
    )
    wait_for(
        lambda: owner_log.exists()
        and "Private ORAM staging mutation append post-admission pause reached"
        in owner_log.read_text(errors="replace"),
        wait_for_timeout=60,
    )
    admitted_projection = _wait_for_private_oram_consensus_protocol_projection(peer_dirs)
    assert admitted_projection != initial_projection

    blocked_session_requests = [
        (
            f"private-hnsw/{VECTOR}",
            {
                "client_id": "tenant-a/active-mutation-hnsw-sdk",
                "desired_epoch": BASE_EPOCH,
                "fixed_budget": True,
                "result_privacy": "private_payload_oram_required",
            },
        ),
        (
            "private-result-oram",
            {
                "client_id": "tenant-a/active-mutation-result-sdk",
                "desired_epoch": BASE_EPOCH,
                "fixed_budget": True,
            },
        ),
    ]
    for endpoint, body in blocked_session_requests:
        response = requests.post(
            f"{owner_url}/collections/{COLLECTION}/{endpoint}/session",
            json=body,
            timeout=30,
        )
        assert 400 <= response.status_code < 600, response.text
        for secret in (
            opened["session_id"],
            prepared["fixture"]["hnsw"]["manifest"]["root_hash"],
            prepared["fixture"]["result"]["manifest"]["root_hash"],
        ):
            assert secret not in response.text

    owner_process = next(
        process for process in processes if get_uri(process.http_port) == owner_url
    )
    owner_port = owner_process.p2p_port
    owner_process.kill()
    processes.remove(owner_process)

    surviving_urls = peer_urls[1:]
    surviving_peer_ids = {
        get_cluster_info(peer_url)["peer_id"] for peer_url in surviving_urls
    }
    elected: dict[str, int] = {}

    def surviving_peers_elected_new_leader() -> bool:
        cluster_infos = [get_cluster_info(peer_url) for peer_url in surviving_urls]
        leader_ids = [info["raft_info"]["leader"] for info in cluster_infos]
        if (
            leader_ids[0] is None
            or leader_ids[0] != leader_ids[1]
            or leader_ids[0] not in surviving_peer_ids
        ):
            return False
        elected["leader"] = leader_ids[0]
        return True

    wait_for(surviving_peers_elected_new_leader, wait_for_timeout=60)
    new_leader_peer_id = elected["leader"]
    assert new_leader_peer_id != owner_peer_id
    new_leader_url = next(
        peer_url
        for peer_url in surviving_urls
        if get_cluster_info(peer_url)["peer_id"] == new_leader_peer_id
    )

    def supervisor_status(peer_url: str) -> dict:
        response = requests.get(
            f"{peer_url}/cluster/private-oram/mutation-v2/status",
            timeout=30,
        )
        assert_http_ok(response)
        return response.json()["result"]["supervisor"]

    foreign_status: dict[str, dict] = {}

    def foreign_supervisor_observed_owner() -> bool:
        status = supervisor_status(new_leader_url)
        if (
            status["state"] != "pending"
            or status["owned_elsewhere"] < 1
            or status["process_local_pending"] != 0
            or status["reconciled"] != 0
            or status["immutable_coordinator_unavailable"] != 0
            or status["failed"] != 0
            or status["block_reason"] is not None
        ):
            return False
        foreign_status["value"] = status
        return True

    wait_for(foreign_supervisor_observed_owner, wait_for_timeout=30)
    first_foreign_generation = foreign_status["value"]["generation"]
    wait_for(
        lambda: supervisor_status(new_leader_url)["generation"]
        > first_foreign_generation,
        wait_for_timeout=30,
    )
    assert all(
        _private_oram_consensus_protocol_projection(peer_dir) == admitted_projection
        for peer_dir in peer_dirs[1:]
    )

    stale_requests = [
        requests.post(
            f"{new_leader_url}/collections/{COLLECTION}/private-oram/v2/mutation/open",
            json=open_body,
            timeout=30,
        ),
        requests.post(
            f"{new_leader_url}/collections/{COLLECTION}/private-oram/v2/mutation/read",
            json=read_plan["rest_read_requests"][0]["rest_read_body"],
            timeout=30,
        ),
        requests.post(
            f"{new_leader_url}/collections/{COLLECTION}/private-oram/v2/mutation/append",
            json=append_body,
            timeout=30,
        ),
    ]
    sensitive_ciphertext = append_body["owner_prepare"]["indexes"][0][
        "ordered_encrypted_buckets"
    ]["buckets"][0]["ciphertext"]
    for response in stale_requests:
        assert 400 <= response.status_code < 500
        for secret in (
            opened["session_id"],
            finalized["mutation_digest"],
            sensitive_ciphertext,
        ):
            assert secret not in response.text
    assert all(
        _private_oram_consensus_protocol_projection(peer_dir) == admitted_projection
        for peer_dir in peer_dirs[1:]
    )

    pause_file.unlink()
    restart_bootstrap_uri = get_uri(processes[0].p2p_port)
    restarted_owner_url = start_peer(
        peer_dirs[0],
        "private_oram_mutation_v2_peer_0_restart.log",
        restart_bootstrap_uri,
        port=owner_port,
        extra_env=pause_env,
        capture_stderr=True,
    )
    peer_urls[0] = restarted_owner_url
    wait_for_peer_online(restarted_owner_url, path="/cluster")
    wait_for_uniform_cluster_status(peer_urls, new_leader_peer_id)
    assert all(
        get_cluster_info(peer_url)["raft_info"]["leader"] == new_leader_peer_id
        for peer_url in peer_urls
    )

    _wait_for_private_oram_epochs(peer_dirs, NEXT_EPOCH, 2)
    terminal_projection: dict[str, dict] = {}

    def mutation_reached_terminal_consensus_state() -> bool:
        projections = [
            _private_oram_consensus_protocol_projection(peer_dir)
            for peer_dir in peer_dirs
        ]
        if projections[0] is None or any(
            projection != projections[0] for projection in projections[1:]
        ):
            return False
        states = projections[0]["private_oram_mutation_states"]
        if len(states) != 1:
            return False
        state = next(iter(states.values()))
        if (
            state["state_sequence"] != 1
            or state["signed_state_digest"] != finalized["new_state_digest"]
            or state["client_state_digest"] != new_state["client_state_digest"]
            or state["last_transition"].get("kind") != "mutation"
            or state["last_transition"]["receipt"]["mutation_id"]
            != finalized["mutation_id"]
        ):
            return False
        terminal_projection["value"] = projections[0]
        return True

    wait_for(mutation_reached_terminal_consensus_state, wait_for_timeout=60)
    assert terminal_projection["value"] != admitted_projection

    def all_supervisors_are_ready() -> bool:
        statuses = [supervisor_status(peer_url) for peer_url in peer_urls]
        return all(
            status["state"] == "ready"
            and status["process_local_pending"] == 0
            and status["owned_elsewhere"] == 0
            and status["awaiting_cleanup"] == 0
            and status["failed"] == 0
            for status in statuses
        )

    wait_for(all_supervisors_are_ready, wait_for_timeout=60)
    expected_roots = {index["kind"]: index["root_hash"] for index in new_state["indexes"]}
    _assert_replica_can_open_current_sessions(
        restarted_owner_url,
        NEXT_EPOCH,
        expected_roots["hnsw"],
        expected_roots["result"],
    )

    stale_after_restart = requests.post(
        f"{new_leader_url}/collections/{COLLECTION}/private-oram/v2/mutation/append",
        json=append_body,
        timeout=30,
    )
    assert 400 <= stale_after_restart.status_code < 500, stale_after_restart.text
    assert sensitive_ciphertext not in stale_after_restart.text


def test_private_oram_mutation_v2_terminal_resume_waits_for_owner_execution_guard(
    tmp_path: pathlib.Path,
):
    pause_file = tmp_path / "private-oram-v2-pre-commit-projection.pause"
    supervisor_pause_file = tmp_path / "private-oram-v2-supervisor-scan.pause"
    pause_file.write_text("pause")
    supervisor_pause_file.write_text("pause")
    # Applying the recovery material can exceed the default two-second election
    # floor in debug CI. Keep the owner leader until the deliberate stop below.
    consensus_env = {"QDRANT__CLUSTER__CONSENSUS__TICK_PERIOD_MS": "1000"}
    pause_env = {
        **consensus_env,
        "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_PRE_COMMIT_PROJECTION_PAUSE_FILE": str(
            pause_file
        ),
        "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_SUPERVISOR_SCAN_PAUSE_FILE": str(
            supervisor_pause_file
        ),
        "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_TERMINAL_RESUME_ATTEMPT_LOG": "1",
    }
    prepared = _prepare_private_oram_mutation_v2_collection(
        tmp_path,
        [pause_env, consensus_env, consensus_env],
    )
    peer_urls = prepared["peer_urls"]
    peer_dirs = prepared["peer_dirs"]
    owner_peer_id = prepared["leader"]
    owner_url = prepared["leader_url"]
    owner_log = (
        pathlib.Path(init_pytest_log_folder())
        / "private_oram_mutation_v2_peer_0.log"
    )
    wait_for(
        lambda: owner_log.exists()
        and "Private ORAM staging mutation supervisor scan pause reached"
        in owner_log.read_text(errors="replace"),
        wait_for_timeout=30,
    )
    opened, _ = _open_private_oram_mutation_v2_session(
        prepared,
        b"private-oram-v2-owner-execution-guard",
    )
    append_context = _private_oram_mutation_v2_append_context(prepared, opened)
    _, read_responses = _execute_private_oram_mutation_v2_reads(
        owner_url,
        append_context,
    )
    finalized = _run_private_oram_mutation_v2_fixture_command(
        "finalize-mutation-v2-append",
        {
            "context": append_context,
            "read_responses": read_responses,
        },
    )
    append_body = finalized["rest_append_body"]
    new_state = append_body["owner_prepare"]["mutation_bundle"]["mutation"][
        "new_state"
    ]["state"]
    accepted = _post_result(
        f"{owner_url}/collections/{COLLECTION}/private-oram/v2/mutation/append",
        append_body,
    )
    assert accepted == {"accepted": True, "phase": "prestage_pending"}

    wait_for(
        lambda: owner_log.exists()
        and "Private ORAM staging mutation commit pre-projection pause reached"
        in owner_log.read_text(errors="replace"),
        wait_for_timeout=90,
    )
    _wait_for_private_oram_epochs(peer_dirs, NEXT_EPOCH, 2)
    committed_projection: dict[str, dict] = {}

    def exact_commit_is_uniform_and_still_active() -> bool:
        projections = [
            _private_oram_consensus_protocol_projection(peer_dir)
            for peer_dir in peer_dirs
        ]
        if projections[0] is None or any(
            projection != projections[0] for projection in projections[1:]
        ):
            return False
        states = projections[0]["private_oram_mutation_states"]
        slots = projections[0]["private_oram_mutation_lease_slots"]
        if len(states) != 1 or len(slots) != 1:
            return False
        state = next(iter(states.values()))
        authority = next(iter(slots.values()))["authority"]
        if authority.get("mode") != "activated":
            return False
        lease_slot = authority["state"]["lease_slot"]
        active = lease_slot["active"]
        if (
            state["state_sequence"] != 1
            or state["signed_state_digest"] != finalized["new_state_digest"]
            or active is None
            or not isinstance(active.get("phase"), dict)
            or "consensus_committed" not in active["phase"]
            or lease_slot["last_clear"] is not None
            or "abort_decided" in json.dumps(projections[0])
        ):
            return False
        committed_projection["value"] = projections[0]
        return True

    wait_for(exact_commit_is_uniform_and_still_active, wait_for_timeout=60)
    supervisor_pause_file.unlink()
    wait_for(
        lambda: "Private ORAM staging mutation terminal resume attempt reached"
        in owner_log.read_text(errors="replace"),
        wait_for_timeout=30,
    )
    time.sleep(1)
    assert all(
        _private_oram_consensus_protocol_projection(peer_dir)
        == committed_projection["value"]
        for peer_dir in peer_dirs
    )

    owner_process = next(
        process for process in processes if get_uri(process.http_port) == owner_url
    )
    owner_port = owner_process.p2p_port
    owner_process.kill()
    processes.remove(owner_process)

    surviving_urls = peer_urls[1:]
    surviving_peer_ids = {
        get_cluster_info(peer_url)["peer_id"] for peer_url in surviving_urls
    }
    elected: dict[str, int] = {}

    def surviving_peers_elected_foreign_leader() -> bool:
        infos = [get_cluster_info(peer_url) for peer_url in surviving_urls]
        leader_ids = [info["raft_info"]["leader"] for info in infos]
        if (
            leader_ids[0] is None
            or leader_ids[0] != leader_ids[1]
            or leader_ids[0] not in surviving_peer_ids
        ):
            return False
        elected["leader"] = leader_ids[0]
        return True

    wait_for(surviving_peers_elected_foreign_leader, wait_for_timeout=60)
    assert elected["leader"] != owner_peer_id
    time.sleep(1)
    assert all(
        _private_oram_consensus_protocol_projection(peer_dir)
        == committed_projection["value"]
        for peer_dir in peer_dirs[1:]
    )

    pause_file.unlink()
    restarted_owner_url = start_peer(
        peer_dirs[0],
        "private_oram_mutation_v2_peer_0_post_commit_restart.log",
        get_uri(processes[0].p2p_port),
        port=owner_port,
        extra_env=pause_env,
        capture_stderr=True,
    )
    peer_urls[0] = restarted_owner_url
    wait_for_peer_online(restarted_owner_url, path="/cluster")
    wait_for_uniform_cluster_status(peer_urls, elected["leader"])

    terminal_projection: dict[str, dict] = {}

    def exact_commit_is_cleared_once() -> bool:
        projections = [
            _private_oram_consensus_protocol_projection(peer_dir)
            for peer_dir in peer_dirs
        ]
        if projections[0] is None or any(
            projection != projections[0] for projection in projections[1:]
        ):
            return False
        states = projections[0]["private_oram_mutation_states"]
        slots = projections[0]["private_oram_mutation_lease_slots"]
        if len(states) != 1 or len(slots) != 1:
            return False
        state = next(iter(states.values()))
        authority = next(iter(slots.values()))["authority"]
        if authority.get("mode") != "activated":
            return False
        activated = authority["state"]
        lease_slot = activated["lease_slot"]
        last_clear = lease_slot["last_clear"]
        last_cleared = activated["lifecycle"]["last_cleared"]
        if (
            state["state_sequence"] != 1
            or state["signed_state_digest"] != finalized["new_state_digest"]
            or state["client_state_digest"] != new_state["client_state_digest"]
            or lease_slot["generation"] != 1
            or lease_slot["active"] is not None
            or last_clear is None
            or last_clear["generation"] != 1
            or last_clear["mutation_id"] != finalized["mutation_id"]
            or last_clear["outcome"]
            != "finalized_or_reconciled_after_consensus_commit"
            or activated["lifecycle"]["active"] is not None
            or last_cleared is None
            or last_cleared["generation"] != 1
            or last_cleared["mutation_id"] != finalized["mutation_id"]
            or "abort_decided" in json.dumps(projections[0])
        ):
            return False
        terminal_projection["value"] = projections[0]
        return True

    wait_for(exact_commit_is_cleared_once, wait_for_timeout=90)
    assert terminal_projection["value"] != committed_projection["value"]

    def all_supervisors_are_ready() -> bool:
        for peer_url in peer_urls:
            response = requests.get(
                f"{peer_url}/cluster/private-oram/mutation-v2/status",
                timeout=30,
            )
            assert_http_ok(response)
            status = response.json()["result"]["supervisor"]
            if (
                status["state"] != "ready"
                or status["process_local_pending"] != 0
                or status["owned_elsewhere"] != 0
                or status["awaiting_cleanup"] != 0
                or status["failed"] != 0
            ):
                return False
        return True

    wait_for(all_supervisors_are_ready, wait_for_timeout=60)
    expected_roots = {index["kind"]: index["root_hash"] for index in new_state["indexes"]}
    _assert_replica_can_open_current_sessions(
        restarted_owner_url,
        NEXT_EPOCH,
        expected_roots["hnsw"],
        expected_roots["result"],
    )


def test_private_oram_mutation_v2_stale_preparing_reconcile_revalidates_after_guard(
    tmp_path: pathlib.Path,
):
    fresh_pause_file = tmp_path / "private-oram-v2-fresh-post-admission.pause"
    commit_pause_file = tmp_path / "private-oram-v2-fresh-pre-projection.pause"
    supervisor_pause_file = tmp_path / "private-oram-v2-stale-supervisor-scan.pause"
    for pause_file in (fresh_pause_file, commit_pause_file, supervisor_pause_file):
        pause_file.write_text("pause")
    pause_env = {
        "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_POST_ADMISSION_PAUSE_FILE": str(
            fresh_pause_file
        ),
        "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_PRE_COMMIT_PROJECTION_PAUSE_FILE": str(
            commit_pause_file
        ),
        "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_SUPERVISOR_SCAN_PAUSE_FILE": str(
            supervisor_pause_file
        ),
        "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_ADMITTED_RECONCILE_PROBE": "1",
    }
    prepared = _prepare_private_oram_mutation_v2_collection(
        tmp_path,
        [pause_env, {}, {}],
    )
    peer_urls = prepared["peer_urls"]
    peer_dirs = prepared["peer_dirs"]
    owner_url = prepared["leader_url"]
    owner_log = (
        pathlib.Path(init_pytest_log_folder())
        / "private_oram_mutation_v2_peer_0.log"
    )
    scan_pause_marker = "Private ORAM staging mutation supervisor scan pause reached"
    wait_for(
        lambda: owner_log.exists()
        and scan_pause_marker in owner_log.read_text(errors="replace"),
        wait_for_timeout=30,
    )

    opened, _ = _open_private_oram_mutation_v2_session(
        prepared,
        b"private-oram-v2-stale-preparing-guard",
    )
    append_context = _private_oram_mutation_v2_append_context(prepared, opened)
    _, read_responses = _execute_private_oram_mutation_v2_reads(
        owner_url,
        append_context,
    )
    finalized = _run_private_oram_mutation_v2_fixture_command(
        "finalize-mutation-v2-append",
        {
            "context": append_context,
            "read_responses": read_responses,
        },
    )
    append_body = finalized["rest_append_body"]
    new_state = append_body["owner_prepare"]["mutation_bundle"]["mutation"][
        "new_state"
    ]["state"]
    accepted = _post_result(
        f"{owner_url}/collections/{COLLECTION}/private-oram/v2/mutation/append",
        append_body,
    )
    assert accepted == {"accepted": True, "phase": "prestage_pending"}

    fresh_pause_marker = (
        "Private ORAM staging mutation append post-admission pause reached"
    )
    wait_for(
        lambda: fresh_pause_marker in owner_log.read_text(errors="replace"),
        wait_for_timeout=90,
    )
    admitted_projection = _wait_for_private_oram_consensus_protocol_projection(
        peer_dirs
    )
    admitted_state = next(
        iter(admitted_projection["private_oram_mutation_states"].values())
    )
    admitted_authority = next(
        iter(admitted_projection["private_oram_mutation_lease_slots"].values())
    )["authority"]
    assert admitted_state["state_sequence"] == 0
    assert admitted_authority["mode"] == "activated"
    admitted_slot = admitted_authority["state"]["lease_slot"]
    assert admitted_slot["generation"] == 1
    assert admitted_slot["last_clear"] is None
    assert admitted_slot["active"]["mutation_id"] == finalized["mutation_id"]
    assert admitted_slot["active"]["phase"] == "preparing"
    assert admitted_authority["state"]["lifecycle"]["last_cleared"] is None
    assert "admitted" in admitted_authority["state"]["lifecycle"]["active"]

    admitted_attempt_marker = (
        "Private ORAM staging mutation admitted reconcile attempt reached"
    )
    admitted_failure_marker = (
        "private ORAM mutation supervisor admitted reconcile failed"
    )
    admitted_failure_count = owner_log.read_text(errors="replace").count(
        admitted_failure_marker
    )
    supervisor_pause_file.unlink()
    wait_for(
        lambda: admitted_attempt_marker in owner_log.read_text(errors="replace"),
        wait_for_timeout=30,
    )
    supervisor_pause_file.write_text("pause")
    scan_pause_count_after_attempt = owner_log.read_text(errors="replace").count(
        scan_pause_marker
    )
    assert owner_log.read_text(errors="replace").count(admitted_failure_marker) == (
        admitted_failure_count
    )
    assert all(
        _private_oram_consensus_protocol_projection(peer_dir) == admitted_projection
        for peer_dir in peer_dirs
    )

    fresh_pause_file.unlink()
    commit_pause_marker = (
        "Private ORAM staging mutation commit pre-projection pause reached"
    )
    wait_for(
        lambda: commit_pause_marker in owner_log.read_text(errors="replace"),
        wait_for_timeout=90,
    )
    _wait_for_private_oram_epochs(peer_dirs, NEXT_EPOCH, 2)
    committed_projection: dict[str, dict] = {}

    def exact_commit_is_uniform_and_active() -> bool:
        projections = [
            _private_oram_consensus_protocol_projection(peer_dir)
            for peer_dir in peer_dirs
        ]
        if projections[0] is None or any(
            projection != projections[0] for projection in projections[1:]
        ):
            return False
        states = projections[0]["private_oram_mutation_states"]
        slots = projections[0]["private_oram_mutation_lease_slots"]
        if len(states) != 1 or len(slots) != 1:
            return False
        state = next(iter(states.values()))
        authority = next(iter(slots.values()))["authority"]
        if authority.get("mode") != "activated":
            return False
        lease_slot = authority["state"]["lease_slot"]
        active = lease_slot["active"]
        if (
            state["state_sequence"] != 1
            or state["signed_state_digest"] != finalized["new_state_digest"]
            or state["client_state_digest"] != new_state["client_state_digest"]
            or active is None
            or active["mutation_id"] != finalized["mutation_id"]
            or not isinstance(active["phase"], dict)
            or "consensus_committed" not in active["phase"]
            or lease_slot["last_clear"] is not None
            or "abort_decided" in json.dumps(projections[0])
        ):
            return False
        committed_projection["value"] = projections[0]
        return True

    wait_for(exact_commit_is_uniform_and_active, wait_for_timeout=60)
    journal_root = _private_oram_mutation_v2_journal_root(peer_dirs[0])
    journal_at_commit = _private_oram_mutation_v2_file_tree(journal_root)
    assert journal_at_commit
    journal_state_at_commit = json.loads(
        (journal_root / "active/state.json").read_text()
    )
    assert journal_state_at_commit["phase"] == "point_stage_durable"
    assert owner_log.read_text(errors="replace").count(admitted_failure_marker) == (
        admitted_failure_count
    )

    commit_pause_file.unlink()
    wait_for(
        lambda: owner_log.read_text(errors="replace").count(scan_pause_marker)
        > scan_pause_count_after_attempt,
        wait_for_timeout=30,
    )
    # After acquiring the guard, the stale Preparing attempt sees the committed
    # lease and returns successfully. Terminal resume records that exact decision.
    assert owner_log.read_text(errors="replace").count(admitted_failure_marker) == (
        admitted_failure_count
    )
    assert all(
        _private_oram_consensus_protocol_projection(peer_dir)
        == committed_projection["value"]
        for peer_dir in peer_dirs
    )
    journal_after_reconcile = _private_oram_mutation_v2_file_tree(journal_root)
    next_sequence = journal_state_at_commit["sequence"] + 1
    decision_record = f"active/state_records/{next_sequence:020d}.json"
    assert set(journal_after_reconcile) == set(journal_at_commit) | {decision_record}
    for path, digest in journal_at_commit.items():
        if path != "active/state.json":
            assert journal_after_reconcile[path] == digest, path
    assert journal_after_reconcile["active/state.json"] == (
        journal_after_reconcile[decision_record]
    )
    decision_state = json.loads((journal_root / decision_record).read_text())
    assert decision_state["sequence"] == next_sequence
    assert decision_state["phase"] == "decision_durable"
    assert decision_state["decision"]["kind"] == "exact_new"
    assert decision_state["predecessor"] == {
        "kind": "previous_v2",
        "record": {
            "sequence": journal_state_at_commit["sequence"],
            "phase": journal_state_at_commit["phase"],
            "record_digest": journal_state_at_commit["record_digest"],
        },
    }

    supervisor_pause_file.unlink()
    terminal_projection: dict[str, dict] = {}

    def exact_terminal_state_is_acknowledged() -> bool:
        projections = [
            _private_oram_consensus_protocol_projection(peer_dir)
            for peer_dir in peer_dirs
        ]
        if projections[0] is None or any(
            projection != projections[0] for projection in projections[1:]
        ):
            return False
        states = projections[0]["private_oram_mutation_states"]
        slots = projections[0]["private_oram_mutation_lease_slots"]
        if len(states) != 1 or len(slots) != 1:
            return False
        state = next(iter(states.values()))
        authority = next(iter(slots.values()))["authority"]
        if authority.get("mode") != "activated":
            return False
        activated = authority["state"]
        lease_slot = activated["lease_slot"]
        last_clear = lease_slot["last_clear"]
        last_cleared = activated["lifecycle"]["last_cleared"]
        if (
            state["state_sequence"] != 1
            or state["signed_state_digest"] != finalized["new_state_digest"]
            or state["client_state_digest"] != new_state["client_state_digest"]
            or lease_slot["generation"] != 1
            or lease_slot["active"] is not None
            or last_clear is None
            or last_clear["generation"] != 1
            or last_clear["mutation_id"] != finalized["mutation_id"]
            or last_clear["outcome"]
            != "finalized_or_reconciled_after_consensus_commit"
            or activated["lifecycle"]["active"] is not None
            or last_cleared is None
            or last_cleared["generation"] != 1
            or last_cleared["mutation_id"] != finalized["mutation_id"]
            or not isinstance(last_cleared["resolution"], dict)
            or "acknowledged" not in last_cleared["resolution"]
            or "abort_decided" in json.dumps(projections[0])
        ):
            return False
        terminal_projection["value"] = projections[0]
        return True

    wait_for(exact_terminal_state_is_acknowledged, wait_for_timeout=120)
    assert terminal_projection["value"] != committed_projection["value"]
    assert owner_log.read_text(errors="replace").count(admitted_attempt_marker) == 1
    assert owner_log.read_text(errors="replace").count(admitted_failure_marker) == (
        admitted_failure_count
    )

    def all_supervisors_are_ready() -> bool:
        for peer_url in peer_urls:
            response = requests.get(
                f"{peer_url}/cluster/private-oram/mutation-v2/status",
                timeout=30,
            )
            assert_http_ok(response)
            status = response.json()["result"]["supervisor"]
            if (
                status["state"] != "ready"
                or status["process_local_pending"] != 0
                or status["owned_elsewhere"] != 0
                or status["awaiting_cleanup"] != 0
                or status["failed"] != 0
            ):
                return False
        return True

    wait_for(all_supervisors_are_ready, wait_for_timeout=60)
    expected_roots = {index["kind"]: index["root_hash"] for index in new_state["indexes"]}
    _assert_replica_can_open_current_sessions(
        owner_url,
        NEXT_EPOCH,
        expected_roots["hnsw"],
        expected_roots["result"],
    )


@pytest.mark.parametrize(
    ("pause_env_name", "pause_milestone", "archive_exists_at_pause"),
    [
        (
            "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_PRE_ARCHIVE_PAUSE_FILE",
            "Private ORAM staging mutation post-clear pre-archive pause reached",
            False,
        ),
        (
            "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_POST_ARCHIVE_PAUSE_FILE",
            "Private ORAM staging mutation post-archive pre-acknowledgement pause reached",
            True,
        ),
    ],
    ids=["before-archive", "after-archive"],
)
def test_private_oram_mutation_v2_post_clear_crash_restarts_archive_and_ack(
    tmp_path: pathlib.Path,
    pause_env_name: str,
    pause_milestone: str,
    archive_exists_at_pause: bool,
):
    pause_file = tmp_path / "private-oram-v2-post-clear.pause"
    pause_file.write_text("pause")
    # Reach the archive barrier before testing owner loss. Debug consensus apply
    # can outlast the default election floor while materializing the recovery entry.
    consensus_env = {"QDRANT__CLUSTER__CONSENSUS__TICK_PERIOD_MS": "1000"}
    pause_env = {**consensus_env, pause_env_name: str(pause_file)}
    prepared = _prepare_private_oram_mutation_v2_collection(
        tmp_path,
        [pause_env, consensus_env, consensus_env],
    )
    peer_urls = prepared["peer_urls"]
    peer_dirs = prepared["peer_dirs"]
    owner_peer_id = prepared["leader"]
    owner_url = prepared["leader_url"]
    payload_index_to_drop = "private_oram_ack_fence_drop_probe"
    payload_index_to_create = "private_oram_ack_fence_create_probe"
    if archive_exists_at_pause:
        create_drop_probe = requests.put(
            f"{owner_url}/collections/{COLLECTION}/index?wait=true",
            json={
                "field_name": payload_index_to_drop,
                "field_schema": "keyword",
            },
            timeout=30,
        )
        assert create_drop_probe.status_code == 200, create_drop_probe.text
    opened, _ = _open_private_oram_mutation_v2_session(
        prepared,
        pause_env_name.encode(),
    )
    append_context = _private_oram_mutation_v2_append_context(prepared, opened)
    _, read_responses = _execute_private_oram_mutation_v2_reads(
        owner_url,
        append_context,
    )
    finalized = _run_private_oram_mutation_v2_fixture_command(
        "finalize-mutation-v2-append",
        {
            "context": append_context,
            "read_responses": read_responses,
        },
    )
    append_body = finalized["rest_append_body"]
    new_state = append_body["owner_prepare"]["mutation_bundle"]["mutation"][
        "new_state"
    ]["state"]
    accepted = _post_result(
        f"{owner_url}/collections/{COLLECTION}/private-oram/v2/mutation/append",
        append_body,
    )
    assert accepted == {"accepted": True, "phase": "prestage_pending"}

    owner_log = (
        pathlib.Path(init_pytest_log_folder())
        / "private_oram_mutation_v2_peer_0.log"
    )
    wait_for(
        lambda: owner_log.exists()
        and pause_milestone in owner_log.read_text(errors="replace"),
        wait_for_timeout=300,
    )
    pending_projection: dict[str, dict] = {}
    pending_tombstone: dict[str, str] = {}

    def clear_is_pending_acknowledgement() -> bool:
        projections = [
            _private_oram_consensus_protocol_projection(peer_dir)
            for peer_dir in peer_dirs
        ]
        if projections[0] is None or any(
            projection != projections[0] for projection in projections[1:]
        ):
            return False
        states = projections[0]["private_oram_mutation_states"]
        slots = projections[0]["private_oram_mutation_lease_slots"]
        if len(states) != 1 or len(slots) != 1:
            return False
        state = next(iter(states.values()))
        authority = next(iter(slots.values()))["authority"]
        if authority.get("mode") != "activated":
            return False
        activated = authority["state"]
        lease_slot = activated["lease_slot"]
        last_clear = lease_slot["last_clear"]
        last_cleared = activated["lifecycle"]["last_cleared"]
        if (
            state["state_sequence"] != 1
            or state["signed_state_digest"] != finalized["new_state_digest"]
            or lease_slot["active"] is not None
            or last_clear is None
            or last_clear["generation"] != 1
            or last_clear["outcome"]
            != "finalized_or_reconciled_after_consensus_commit"
            or activated["lifecycle"]["active"] is not None
            or last_cleared is None
            or last_cleared["generation"] != 1
            or last_cleared["mutation_id"] != finalized["mutation_id"]
            or last_cleared["resolution"] != "pending"
        ):
            return False
        pending_projection["value"] = projections[0]
        pending_tombstone["digest"] = last_cleared["tombstone_digest"]
        pending_tombstone["clear_receipt_digest"] = last_cleared[
            "clear_receipt_digest"
        ]
        return True

    wait_for(clear_is_pending_acknowledgement, wait_for_timeout=60)
    journal_roots = list(
        (peer_dirs[0] / "storage" / "collections").glob(
            "*/private_oram_mutations"
        )
    )
    assert len(journal_roots) == 1
    journal_root = journal_roots[0]
    archive_dir = journal_root / "completed-v2-00000000000000000001"
    archive_file = archive_dir / "terminal_archive_v2.json"
    if archive_exists_at_pause:
        assert not (journal_root / "active").exists()
        assert archive_file.is_file()
        with open(archive_file) as source:
            installed_archive = json.load(source)
        assert installed_archive["tombstone_digest"] == pending_tombstone["digest"]
        assert (
            installed_archive["clear_receipt_digest"]
            == pending_tombstone["clear_receipt_digest"]
        )
    else:
        assert (journal_root / "active").is_dir()
        assert not archive_dir.exists()

    owner_process = next(
        process for process in processes if get_uri(process.http_port) == owner_url
    )
    owner_port = owner_process.p2p_port
    owner_process.kill()
    processes.remove(owner_process)

    surviving_urls = peer_urls[1:]
    surviving_peer_ids = {
        get_cluster_info(peer_url)["peer_id"] for peer_url in surviving_urls
    }
    elected: dict[str, int] = {}

    def surviving_peers_elected_foreign_leader() -> bool:
        infos = [get_cluster_info(peer_url) for peer_url in surviving_urls]
        leader_ids = [info["raft_info"]["leader"] for info in infos]
        if (
            leader_ids[0] is None
            or leader_ids[0] != leader_ids[1]
            or leader_ids[0] not in surviving_peer_ids
        ):
            return False
        elected["leader"] = leader_ids[0]
        return True

    wait_for(surviving_peers_elected_foreign_leader, wait_for_timeout=60)
    assert elected["leader"] != owner_peer_id
    foreign_leader_url = next(
        peer_url
        for peer_url in surviving_urls
        if get_cluster_info(peer_url)["peer_id"] == elected["leader"]
    )
    time.sleep(1)
    assert all(
        _private_oram_consensus_protocol_projection(peer_dir)
        == pending_projection["value"]
        for peer_dir in peer_dirs[1:]
    )

    if not archive_exists_at_pause:
        pause_file.unlink()
    restarted_owner_url = start_peer(
        peer_dirs[0],
        f"private_oram_mutation_v2_peer_0_{'post' if archive_exists_at_pause else 'pre'}_archive_restart.log",
        get_uri(processes[0].p2p_port),
        port=owner_port,
        extra_env=pause_env,
        capture_stderr=True,
    )
    peer_urls[0] = restarted_owner_url
    wait_for_peer_online(restarted_owner_url, path="/cluster")
    wait_for_uniform_cluster_status(peer_urls, elected["leader"])
    if archive_exists_at_pause:
        metadata_update = {
            "metadata": {"private_oram_restart_ack_fence_probe": "after-ack"}
        }
        blocked_metadata = requests.patch(
            f"{foreign_leader_url}/collections/{COLLECTION}",
            json=metadata_update,
            timeout=30,
        )
        assert 400 <= blocked_metadata.status_code < 500, blocked_metadata.text
        assert "private ORAM local archive acknowledgement" in blocked_metadata.text
        blocked_crypto = requests.post(
            f"{foreign_leader_url}/collections/{COLLECTION}/crypto/migration/plan",
            json={
                "from": "active",
                "to": "rotating",
                "target_epoch": 8,
                "active_rk_id": "tenant-a/vector-private-rk-v2",
                "retired_rk_id": "tenant-a/vector-private-rk",
                "dry_run": True,
            },
            timeout=30,
        )
        assert 400 <= blocked_crypto.status_code < 500, blocked_crypto.text
        assert "private ORAM local archive acknowledgement" in blocked_crypto.text
        blocked_create_payload_index = requests.put(
            f"{foreign_leader_url}/collections/{COLLECTION}/index?wait=true",
            json={
                "field_name": payload_index_to_create,
                "field_schema": "keyword",
            },
            timeout=30,
        )
        assert 400 <= blocked_create_payload_index.status_code < 500, (
            blocked_create_payload_index.text
        )
        assert (
            "private ORAM local archive acknowledgement"
            in blocked_create_payload_index.text
        )
        blocked_drop_payload_index = requests.delete(
            f"{foreign_leader_url}/collections/{COLLECTION}/index/{payload_index_to_drop}?wait=true",
            timeout=30,
        )
        assert 400 <= blocked_drop_payload_index.status_code < 500, (
            blocked_drop_payload_index.text
        )
        assert (
            "private ORAM local archive acknowledgement"
            in blocked_drop_payload_index.text
        )
        blocked_delete_collection = requests.delete(
            f"{foreign_leader_url}/collections/{COLLECTION}?timeout=30",
            timeout=30,
        )
        assert 400 <= blocked_delete_collection.status_code < 500, (
            blocked_delete_collection.text
        )
        assert (
            "private ORAM local archive acknowledgement"
            in blocked_delete_collection.text
        )
        payload_schema_while_pending = get_collection_info(
            foreign_leader_url, COLLECTION
        )["payload_schema"]
        assert payload_index_to_drop in payload_schema_while_pending
        assert payload_index_to_create not in payload_schema_while_pending
        pause_file.unlink()

    def clear_acknowledgement_is_durable() -> bool:
        projections = [
            _private_oram_consensus_protocol_projection(peer_dir)
            for peer_dir in peer_dirs
        ]
        if projections[0] is None or any(
            projection != projections[0] for projection in projections[1:]
        ):
            return False
        states = projections[0]["private_oram_mutation_states"]
        slots = projections[0]["private_oram_mutation_lease_slots"]
        if len(states) != 1 or len(slots) != 1:
            return False
        state = next(iter(states.values()))
        authority = next(iter(slots.values()))["authority"]
        if authority.get("mode") != "activated":
            return False
        activated = authority["state"]
        lease_slot = activated["lease_slot"]
        last_cleared = activated["lifecycle"]["last_cleared"]
        return (
            state["state_sequence"] == 1
            and state["signed_state_digest"] == finalized["new_state_digest"]
            and state["client_state_digest"] == new_state["client_state_digest"]
            and lease_slot["generation"] == 1
            and lease_slot["active"] is None
            and lease_slot["last_clear"] is not None
            and activated["lifecycle"]["active"] is None
            and last_cleared is not None
            and last_cleared["generation"] == 1
            and last_cleared["mutation_id"] == finalized["mutation_id"]
            and isinstance(last_cleared["resolution"], dict)
            and "acknowledged" in last_cleared["resolution"]
        )

    wait_for(clear_acknowledgement_is_durable, wait_for_timeout=90)
    assert not (journal_root / "active").exists()
    assert archive_file.is_file()
    with open(archive_file) as source:
        installed_archive = json.load(source)
    assert installed_archive["version"] == 1
    assert installed_archive["generation"] == 1
    assert installed_archive["tombstone_digest"] == pending_tombstone["digest"]
    assert (
        installed_archive["clear_receipt_digest"]
        == pending_tombstone["clear_receipt_digest"]
    )
    if archive_exists_at_pause:
        metadata_after_ack = requests.patch(
            f"{foreign_leader_url}/collections/{COLLECTION}",
            json=metadata_update,
            timeout=30,
        )
        assert metadata_after_ack.status_code == 200, metadata_after_ack.text
        create_payload_index_after_ack = requests.put(
            f"{foreign_leader_url}/collections/{COLLECTION}/index?wait=true",
            json={
                "field_name": payload_index_to_create,
                "field_schema": "keyword",
            },
            timeout=30,
        )
        assert create_payload_index_after_ack.status_code == 200, (
            create_payload_index_after_ack.text
        )
        drop_payload_index_after_ack = requests.delete(
            f"{foreign_leader_url}/collections/{COLLECTION}/index/{payload_index_to_drop}?wait=true",
            timeout=30,
        )
        assert drop_payload_index_after_ack.status_code == 200, (
            drop_payload_index_after_ack.text
        )
        payload_schema_after_ack = get_collection_info(
            foreign_leader_url, COLLECTION
        )["payload_schema"]
        assert payload_index_to_create in payload_schema_after_ack
        assert payload_index_to_drop not in payload_schema_after_ack

    def all_supervisors_are_ready() -> bool:
        for peer_url in peer_urls:
            response = requests.get(
                f"{peer_url}/cluster/private-oram/mutation-v2/status",
                timeout=30,
            )
            assert_http_ok(response)
            status = response.json()["result"]["supervisor"]
            if (
                status["state"] != "ready"
                or status["process_local_pending"] != 0
                or status["owned_elsewhere"] != 0
                or status["awaiting_cleanup"] != 0
                or status["failed"] != 0
            ):
                return False
        return True

    wait_for(all_supervisors_are_ready, wait_for_timeout=60)
    expected_roots = {index["kind"]: index["root_hash"] for index in new_state["indexes"]}
    _assert_replica_can_open_current_sessions(
        restarted_owner_url,
        NEXT_EPOCH,
        expected_roots["hnsw"],
        expected_roots["result"],
    )
    if archive_exists_at_pause:
        delete_collection_after_ack = requests.delete(
            f"{foreign_leader_url}/collections/{COLLECTION}?timeout=30",
            timeout=30,
        )
        assert delete_collection_after_ack.status_code == 200, (
            delete_collection_after_ack.text
        )
        assert delete_collection_after_ack.json()["result"] is True
        deleted_collection = requests.get(
            f"{foreign_leader_url}/collections/{COLLECTION}",
            timeout=30,
        )
        assert deleted_collection.status_code == 404, deleted_collection.text


def test_private_oram_mutation_v2_pending_ack_rejects_next_admission_without_overwrite(
    tmp_path: pathlib.Path,
):
    archive_pause_file = tmp_path / "private-oram-v2-next-generation-post-archive.pause"
    archive_pause_file.write_text("pause")
    consensus_env = {
        "QDRANT__CLUSTER__CONSENSUS__TICK_PERIOD_MS": "1000",
    }
    pause_env = {
        **consensus_env,
        "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_POST_ARCHIVE_PAUSE_FILE": str(
            archive_pause_file
        ),
        "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_ADMITTED_RECONCILE_PROBE": "1",
    }
    prepared = _prepare_private_oram_mutation_v2_collection(
        tmp_path,
        [pause_env, consensus_env.copy(), consensus_env.copy()],
        fixture_logical_capacity=4,
    )
    peer_urls = prepared["peer_urls"]
    peer_dirs = prepared["peer_dirs"]
    owner_url = prepared["leader_url"]
    opened, _ = _open_private_oram_mutation_v2_session(
        prepared,
        b"private-oram-v2-pending-ack-generation-one",
    )
    append_context = _private_oram_mutation_v2_append_context(prepared, opened)
    _, read_responses = _execute_private_oram_mutation_v2_reads(
        owner_url,
        append_context,
    )
    finalized = _run_private_oram_mutation_v2_fixture_command(
        "finalize-mutation-v2-append",
        {
            "context": append_context,
            "read_responses": read_responses,
        },
    )
    append_body = finalized["rest_append_body"]
    new_state_bundle = finalized["next_signed_state"]
    new_state = new_state_bundle["state"]
    accepted = _post_result(
        f"{owner_url}/collections/{COLLECTION}/private-oram/v2/mutation/append",
        append_body,
    )
    assert accepted == {"accepted": True, "phase": "prestage_pending"}

    owner_log = (
        pathlib.Path(init_pytest_log_folder())
        / "private_oram_mutation_v2_peer_0.log"
    )
    wait_for(
        lambda: owner_log.exists()
        and "Private ORAM staging mutation post-archive pre-acknowledgement pause reached"
        in owner_log.read_text(errors="replace"),
        wait_for_timeout=300,
    )
    pending_projection: dict[str, dict] = {}
    pending_tombstone: dict[str, str] = {}

    def generation_one_is_cleared_pending_acknowledgement() -> bool:
        projections = [
            _private_oram_consensus_protocol_projection(peer_dir)
            for peer_dir in peer_dirs
        ]
        if projections[0] is None or any(
            projection != projections[0] for projection in projections[1:]
        ):
            return False
        states = projections[0]["private_oram_mutation_states"]
        slots = projections[0]["private_oram_mutation_lease_slots"]
        if len(states) != 1 or len(slots) != 1:
            return False
        state = next(iter(states.values()))
        authority = next(iter(slots.values()))["authority"]
        if authority.get("mode") != "activated":
            return False
        activated = authority["state"]
        lease_slot = activated["lease_slot"]
        last_clear = lease_slot["last_clear"]
        last_cleared = activated["lifecycle"]["last_cleared"]
        if (
            state["state_sequence"] != 1
            or state["signed_state_digest"] != finalized["new_state_digest"]
            or state["client_state_digest"] != new_state["client_state_digest"]
            or lease_slot["generation"] != 1
            or lease_slot["active"] is not None
            or last_clear is None
            or last_clear["generation"] != 1
            or last_clear["mutation_id"] != finalized["mutation_id"]
            or last_clear["outcome"]
            != "finalized_or_reconciled_after_consensus_commit"
            or activated["lifecycle"]["active"] is not None
            or last_cleared is None
            or last_cleared["generation"] != 1
            or last_cleared["mutation_id"] != finalized["mutation_id"]
            or last_cleared["resolution"] != "pending"
            or "abort_decided" in json.dumps(projections[0])
        ):
            return False
        pending_projection["value"] = projections[0]
        pending_tombstone["digest"] = last_cleared["tombstone_digest"]
        pending_tombstone["clear_receipt_digest"] = last_cleared[
            "clear_receipt_digest"
        ]
        return True

    wait_for(
        generation_one_is_cleared_pending_acknowledgement,
        wait_for_timeout=60,
    )
    journal_root = _private_oram_mutation_v2_journal_root(peer_dirs[0])
    archive_dir = journal_root / "completed-v2-00000000000000000001"
    archive_file = archive_dir / "terminal_archive_v2.json"
    assert not (journal_root / "active").exists()
    assert archive_file.is_file()
    installed_archive_before_ack = archive_file.read_bytes()
    pending_journal = _private_oram_mutation_v2_file_tree(journal_root)
    metadata_update = {
        "metadata": {"private_oram_archive_ack_fence_probe": "applied-after-ack"}
    }
    crypto_dry_run = {
        "from": "active",
        "to": "rotating",
        "target_epoch": 8,
        "active_rk_id": "tenant-a/vector-private-rk-v2",
        "retired_rk_id": "tenant-a/vector-private-rk",
        "dry_run": True,
    }
    blocked_metadata = requests.patch(
        f"{owner_url}/collections/{COLLECTION}",
        json=metadata_update,
        timeout=30,
    )
    assert 400 <= blocked_metadata.status_code < 500, blocked_metadata.text
    assert "private ORAM local archive acknowledgement" in blocked_metadata.text
    blocked_crypto = requests.post(
        f"{owner_url}/collections/{COLLECTION}/crypto/migration/plan",
        json=crypto_dry_run,
        timeout=30,
    )
    assert 400 <= blocked_crypto.status_code < 500, blocked_crypto.text
    assert "private ORAM local archive acknowledgement" in blocked_crypto.text

    next_mutation_id = base64.urlsafe_b64encode(
        hashlib.sha256(b"private-oram-v2-generation-two-before-ack").digest()
    ).decode().rstrip("=")
    next_open_body = _private_oram_v2_wire_body(
        {
            "client_id": "tenant-a/process-v2-next-generation-sdk",
            "vector_name": VECTOR,
            "mutation_id": next_mutation_id,
            "immutable_manifest": prepared["signed_genesis"]["rest_enroll_body"][
                "immutable_manifest"
            ],
            "old_state": new_state_bundle,
        }
    )
    next_open = _post_result(
        f"{owner_url}/collections/{COLLECTION}/private-oram/v2/mutation/open",
        next_open_body,
    )
    assert next_open["collection_id"] == prepared["fixture"]["collection_id"]
    assert next_open["mutation_id"] == next_mutation_id
    assert next_open["manifest_digest"] == prepared["signed_genesis"][
        "manifest_digest"
    ]
    assert next_open["old_state_digest"] == finalized["new_state_digest"]
    assert next_open["mutation_lease_generation"] == "2"
    assert next_open["writer_fence"] == "2"
    assert {index["index_epoch"] for index in next_open["indexes"]} == {
        str(NEXT_EPOCH)
    }
    next_append_context = _private_oram_mutation_v2_append_context(
        prepared,
        next_open,
        old_state=new_state_bundle,
        client_checkpoint=finalized["next_client_checkpoint"],
        encrypted_client_checkpoint=finalized["encrypted_client_checkpoint"],
    )
    _, next_read_responses = _execute_private_oram_mutation_v2_reads(
        owner_url,
        next_append_context,
    )
    next_finalize_request = {
        "context": next_append_context,
        "read_responses": next_read_responses,
    }
    next_finalized = _run_private_oram_mutation_v2_fixture_command(
        "finalize-mutation-v2-append",
        next_finalize_request,
    )
    next_append_body = next_finalized["rest_append_body"]
    rejected = requests.post(
        f"{owner_url}/collections/{COLLECTION}/private-oram/v2/mutation/append",
        json=next_append_body,
        timeout=30,
    )
    assert 400 <= rejected.status_code < 500, rejected.text
    assert "clear acknowledgement is pending" in rejected.text
    sensitive_ciphertext = next_append_body["owner_prepare"]["indexes"][0][
        "ordered_encrypted_buckets"
    ]["buckets"][0]["ciphertext"]
    assert sensitive_ciphertext not in rejected.text
    assert all(
        _private_oram_consensus_protocol_projection(peer_dir)
        == pending_projection["value"]
        for peer_dir in peer_dirs
    )
    assert _private_oram_mutation_v2_file_tree(journal_root) == pending_journal
    assert not (journal_root / "active").exists()
    assert archive_file.read_bytes() == installed_archive_before_ack
    closed_next_session = _post_result(
        f"{owner_url}/collections/{COLLECTION}/private-oram/v2/mutation/close",
        {"session_id": next_open["session_id"]},
    )
    assert closed_next_session is True

    archive_pause_file.unlink()
    acknowledged_projection: dict[str, dict] = {}

    def generation_one_archive_and_ack_are_durable() -> bool:
        projections = [
            _private_oram_consensus_protocol_projection(peer_dir)
            for peer_dir in peer_dirs
        ]
        if projections[0] is None or any(
            projection != projections[0] for projection in projections[1:]
        ):
            return False
        states = projections[0]["private_oram_mutation_states"]
        slots = projections[0]["private_oram_mutation_lease_slots"]
        if len(states) != 1 or len(slots) != 1:
            return False
        state = next(iter(states.values()))
        authority = next(iter(slots.values()))["authority"]
        if authority.get("mode") != "activated":
            return False
        activated = authority["state"]
        lease_slot = activated["lease_slot"]
        last_cleared = activated["lifecycle"]["last_cleared"]
        if (
            state["state_sequence"] != 1
            or state["signed_state_digest"] != finalized["new_state_digest"]
            or state["client_state_digest"] != new_state["client_state_digest"]
            or lease_slot["generation"] != 1
            or lease_slot["active"] is not None
            or lease_slot["last_clear"] is None
            or activated["lifecycle"]["active"] is not None
            or last_cleared is None
            or last_cleared["generation"] != 1
            or last_cleared["mutation_id"] != finalized["mutation_id"]
            or last_cleared["tombstone_digest"] == pending_tombstone["digest"]
            or last_cleared["clear_receipt_digest"]
            != pending_tombstone["clear_receipt_digest"]
            or not isinstance(last_cleared["resolution"], dict)
            or "acknowledged" not in last_cleared["resolution"]
            or "abort_decided" in json.dumps(projections[0])
        ):
            return False
        acknowledged_projection["value"] = projections[0]
        return True

    wait_for(generation_one_archive_and_ack_are_durable, wait_for_timeout=90)
    assert not (journal_root / "active").exists()
    assert archive_file.is_file()
    with open(archive_file) as source:
        installed_archive = json.load(source)
    assert installed_archive["version"] == 1
    assert installed_archive["generation"] == 1
    assert installed_archive["tombstone_digest"] == pending_tombstone["digest"]
    assert (
        installed_archive["clear_receipt_digest"]
        == pending_tombstone["clear_receipt_digest"]
    )
    metadata_after_ack = requests.patch(
        f"{owner_url}/collections/{COLLECTION}",
        json=metadata_update,
        timeout=30,
    )
    assert metadata_after_ack.status_code == 200, metadata_after_ack.text
    crypto_after_ack = requests.post(
        f"{owner_url}/collections/{COLLECTION}/crypto/migration/plan",
        json=crypto_dry_run,
        timeout=30,
    )
    assert crypto_after_ack.status_code == 200, crypto_after_ack.text

    next_open = _post_result(
        f"{owner_url}/collections/{COLLECTION}/private-oram/v2/mutation/open",
        next_open_body,
    )
    assert next_open["mutation_lease_generation"] == "2"
    assert next_open["writer_fence"] == "2"
    next_append_context = _private_oram_mutation_v2_append_context(
        prepared,
        next_open,
        old_state=new_state_bundle,
        client_checkpoint=finalized["next_client_checkpoint"],
        encrypted_client_checkpoint=finalized["encrypted_client_checkpoint"],
    )
    _, next_read_responses = _execute_private_oram_mutation_v2_reads(
        owner_url,
        next_append_context,
    )
    next_finalized = _run_private_oram_mutation_v2_fixture_command(
        "finalize-mutation-v2-append",
        {
            "context": next_append_context,
            "read_responses": next_read_responses,
        },
    )
    next_append_body = next_finalized["rest_append_body"]

    accepted_response = requests.post(
        f"{owner_url}/collections/{COLLECTION}/private-oram/v2/mutation/append",
        json=next_append_body,
        timeout=30,
    )
    assert accepted_response.status_code == 200, accepted_response.text
    accepted = accepted_response.json()["result"]
    assert accepted == {"accepted": True, "phase": "prestage_pending"}
    generation_two_projection: dict[str, dict] = {}

    def generation_two_is_acknowledged_without_overwriting_generation_one() -> bool:
        projections = [
            _private_oram_consensus_protocol_projection(peer_dir)
            for peer_dir in peer_dirs
        ]
        if projections[0] is None or any(
            projection != projections[0] for projection in projections[1:]
        ):
            return False
        states = projections[0]["private_oram_mutation_states"]
        slots = projections[0]["private_oram_mutation_lease_slots"]
        if len(states) != 1 or len(slots) != 1:
            return False
        state = next(iter(states.values()))
        authority = next(iter(slots.values()))["authority"]
        if authority.get("mode") != "activated":
            return False
        activated = authority["state"]
        lease_slot = activated["lease_slot"]
        last_clear = lease_slot["last_clear"]
        last_cleared = activated["lifecycle"]["last_cleared"]
        if (
            state["state_sequence"] != 2
            or state["signed_state_digest"] != next_finalized["new_state_digest"]
            or lease_slot["generation"] != 2
            or lease_slot["active"] is not None
            or last_clear is None
            or last_clear["generation"] != 2
            or last_clear["mutation_id"] != next_finalized["mutation_id"]
            or activated["lifecycle"]["active"] is not None
            or last_cleared is None
            or last_cleared["generation"] != 2
            or last_cleared["mutation_id"] != next_finalized["mutation_id"]
            or not isinstance(last_cleared["resolution"], dict)
            or "acknowledged" not in last_cleared["resolution"]
            or "abort_decided" in json.dumps(projections[0])
        ):
            return False
        generation_two_projection["value"] = projections[0]
        return True

    wait_for(
        generation_two_is_acknowledged_without_overwriting_generation_one,
        wait_for_timeout=600,
    )
    generation_two_archive = (
        journal_root
        / "completed-v2-00000000000000000002"
        / "terminal_archive_v2.json"
    )
    assert generation_two_archive.is_file()
    assert archive_file.read_bytes() == installed_archive_before_ack
    assert generation_two_projection["value"] != acknowledged_projection["value"]
    _assert_private_oram_mutation_v2_archive_chain(peer_dirs[0], 1)
    _assert_private_oram_mutation_v2_archive_chain(peer_dirs[0], 2)
    installed_generation_two_archive = generation_two_archive.read_bytes()

    generation_three_state_bundle = next_finalized["next_signed_state"]
    generation_three_mutation_id = base64.urlsafe_b64encode(
        hashlib.sha256(b"private-oram-v2-generation-three").digest()
    ).decode().rstrip("=")
    generation_three_open = _post_result(
        f"{owner_url}/collections/{COLLECTION}/private-oram/v2/mutation/open",
        _private_oram_v2_wire_body(
            {
                "client_id": "tenant-a/process-v2-generation-three-sdk",
                "vector_name": VECTOR,
                "mutation_id": generation_three_mutation_id,
                "immutable_manifest": prepared["signed_genesis"]["rest_enroll_body"][
                    "immutable_manifest"
                ],
                "old_state": generation_three_state_bundle,
            }
        ),
    )
    assert generation_three_open["mutation_lease_generation"] == "3"
    assert generation_three_open["writer_fence"] == "3"
    assert {index["index_epoch"] for index in generation_three_open["indexes"]} == {
        str(NEXT_EPOCH + 1)
    }
    generation_three_context = _private_oram_mutation_v2_append_context(
        prepared,
        generation_three_open,
        old_state=generation_three_state_bundle,
        client_checkpoint=next_finalized["next_client_checkpoint"],
        encrypted_client_checkpoint=next_finalized["encrypted_client_checkpoint"],
    )
    _, generation_three_read_responses = _execute_private_oram_mutation_v2_reads(
        owner_url,
        generation_three_context,
    )
    generation_three_finalized = _run_private_oram_mutation_v2_fixture_command(
        "finalize-mutation-v2-append",
        {
            "context": generation_three_context,
            "read_responses": generation_three_read_responses,
        },
    )
    generation_three_accepted = requests.post(
        f"{owner_url}/collections/{COLLECTION}/private-oram/v2/mutation/append",
        json=generation_three_finalized["rest_append_body"],
        timeout=30,
    )
    assert generation_three_accepted.status_code == 200, generation_three_accepted.text
    assert generation_three_accepted.json()["result"] == {
        "accepted": True,
        "phase": "prestage_pending",
    }

    def generation_three_is_acknowledged_without_overwriting_older_archives() -> bool:
        projections = [
            _private_oram_consensus_protocol_projection(peer_dir)
            for peer_dir in peer_dirs
        ]
        if projections[0] is None or any(
            projection != projections[0] for projection in projections[1:]
        ):
            return False
        states = projections[0]["private_oram_mutation_states"]
        slots = projections[0]["private_oram_mutation_lease_slots"]
        if len(states) != 1 or len(slots) != 1:
            return False
        state = next(iter(states.values()))
        authority = next(iter(slots.values()))["authority"]
        if authority.get("mode") != "activated":
            return False
        activated = authority["state"]
        lease_slot = activated["lease_slot"]
        last_clear = lease_slot["last_clear"]
        last_cleared = activated["lifecycle"]["last_cleared"]
        return (
            state["state_sequence"] == 3
            and state["signed_state_digest"]
            == generation_three_finalized["new_state_digest"]
            and lease_slot["generation"] == 3
            and lease_slot["active"] is None
            and last_clear is not None
            and last_clear["generation"] == 3
            and last_clear["mutation_id"]
            == generation_three_finalized["mutation_id"]
            and activated["lifecycle"]["active"] is None
            and last_cleared is not None
            and last_cleared["generation"] == 3
            and last_cleared["mutation_id"]
            == generation_three_finalized["mutation_id"]
            and isinstance(last_cleared["resolution"], dict)
            and "acknowledged" in last_cleared["resolution"]
            and "abort_decided" not in json.dumps(projections[0])
        )

    wait_for(
        generation_three_is_acknowledged_without_overwriting_older_archives,
        wait_for_timeout=600,
    )
    generation_three_archive = (
        journal_root
        / "completed-v2-00000000000000000003"
        / "terminal_archive_v2.json"
    )
    assert generation_three_archive.is_file()
    assert archive_file.read_bytes() == installed_archive_before_ack
    assert generation_two_archive.read_bytes() == installed_generation_two_archive
    for generation in range(1, 4):
        _assert_private_oram_mutation_v2_archive_chain(peer_dirs[0], generation)

    def all_supervisors_are_ready() -> bool:
        for peer_url in peer_urls:
            response = requests.get(
                f"{peer_url}/cluster/private-oram/mutation-v2/status",
                timeout=30,
            )
            assert_http_ok(response)
            status = response.json()["result"]["supervisor"]
            if (
                status["state"] != "ready"
                or status["process_local_pending"] != 0
                or status["owned_elsewhere"] != 0
                or status["awaiting_cleanup"] != 0
                or status["failed"] != 0
            ):
                return False
        return True

    wait_for(all_supervisors_are_ready, wait_for_timeout=60)
    next_state = generation_three_finalized["next_signed_state"]["state"]
    expected_roots = {
        index["kind"]: index["root_hash"] for index in next_state["indexes"]
    }
    _assert_replica_can_open_current_sessions(
        owner_url,
        NEXT_EPOCH + 2,
        expected_roots["hnsw"],
        expected_roots["result"],
    )


def test_private_oram_mutation_v2_paired_archive_loss_rejects_next_admission_before_raft(
    tmp_path: pathlib.Path,
):
    archive_pause_file = tmp_path / "private-oram-v2-paired-loss-post-archive.pause"
    archive_pause_file.write_text("pause")
    consensus_env = {
        "QDRANT__CLUSTER__CONSENSUS__TICK_PERIOD_MS": "1000",
    }
    pause_env = {
        **consensus_env,
        "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_POST_ARCHIVE_PAUSE_FILE": str(
            archive_pause_file
        ),
    }
    prepared = _prepare_private_oram_mutation_v2_collection(
        tmp_path,
        [pause_env, consensus_env.copy(), consensus_env.copy()],
        fixture_logical_capacity=3,
    )
    peer_dirs = prepared["peer_dirs"]
    owner_url = prepared["leader_url"]
    opened, _ = _open_private_oram_mutation_v2_session(
        prepared,
        b"private-oram-v2-paired-loss-generation-one",
    )
    append_context = _private_oram_mutation_v2_append_context(prepared, opened)
    _, read_responses = _execute_private_oram_mutation_v2_reads(
        owner_url,
        append_context,
    )
    finalized = _run_private_oram_mutation_v2_fixture_command(
        "finalize-mutation-v2-append",
        {
            "context": append_context,
            "read_responses": read_responses,
        },
    )
    accepted = _post_result(
        f"{owner_url}/collections/{COLLECTION}/private-oram/v2/mutation/append",
        finalized["rest_append_body"],
    )
    assert accepted == {"accepted": True, "phase": "prestage_pending"}

    owner_log = (
        pathlib.Path(init_pytest_log_folder())
        / "private_oram_mutation_v2_peer_0.log"
    )
    wait_for(
        lambda: owner_log.exists()
        and "Private ORAM staging mutation post-archive pre-acknowledgement pause reached"
        in owner_log.read_text(errors="replace"),
        wait_for_timeout=300,
    )
    archive_pause_file.unlink()

    acknowledged_projection: dict[str, dict] = {}

    def generation_one_archive_and_ack_are_durable() -> bool:
        projections = [
            _private_oram_consensus_protocol_projection(peer_dir)
            for peer_dir in peer_dirs
        ]
        if projections[0] is None or any(
            projection != projections[0] for projection in projections[1:]
        ):
            return False
        states = projections[0]["private_oram_mutation_states"]
        slots = projections[0]["private_oram_mutation_lease_slots"]
        if len(states) != 1 or len(slots) != 1:
            return False
        state = next(iter(states.values()))
        authority = next(iter(slots.values()))["authority"]
        if authority.get("mode") != "activated":
            return False
        activated = authority["state"]
        lease_slot = activated["lease_slot"]
        last_cleared = activated["lifecycle"]["last_cleared"]
        if (
            state["state_sequence"] != 1
            or state["signed_state_digest"] != finalized["new_state_digest"]
            or lease_slot["generation"] != 1
            or lease_slot["active"] is not None
            or activated["lifecycle"]["active"] is not None
            or last_cleared is None
            or last_cleared["generation"] != 1
            or last_cleared["mutation_id"] != finalized["mutation_id"]
            or not isinstance(last_cleared["resolution"], dict)
            or "acknowledged" not in last_cleared["resolution"]
            or "abort_decided" in json.dumps(projections[0])
        ):
            return False
        acknowledged_projection["value"] = projections[0]
        return True

    wait_for(generation_one_archive_and_ack_are_durable, wait_for_timeout=120)

    _, completed_archive = _assert_private_oram_mutation_v2_archive_chain(
        peer_dirs[0],
        1,
    )
    owner_hnsw_root = completed_archive.parents[2]
    retired_root = (
        owner_hnsw_root
        / "temp"
        / "private-oram-owner-prestage-v2"
        / "retired"
    )
    retired_adopted_intents = list(retired_root.iterdir())
    assert len(retired_adopted_intents) == 1
    retired_adopted_intent = retired_adopted_intents[0]
    assert retired_adopted_intent.is_dir()

    shutil.rmtree(completed_archive)
    shutil.rmtree(retired_adopted_intent)
    assert not completed_archive.exists()
    assert list(retired_root.iterdir()) == []
    assert all(
        _private_oram_consensus_protocol_projection(peer_dir)
        == acknowledged_projection["value"]
        for peer_dir in peer_dirs
    )

    next_state_bundle = finalized["next_signed_state"]
    next_mutation_id = base64.urlsafe_b64encode(
        hashlib.sha256(b"private-oram-v2-paired-loss-generation-two").digest()
    ).decode().rstrip("=")
    next_open = _post_result(
        f"{owner_url}/collections/{COLLECTION}/private-oram/v2/mutation/open",
        _private_oram_v2_wire_body(
            {
                "client_id": "tenant-a/process-v2-paired-loss-sdk",
                "vector_name": VECTOR,
                "mutation_id": next_mutation_id,
                "immutable_manifest": prepared["signed_genesis"]["rest_enroll_body"][
                    "immutable_manifest"
                ],
                "old_state": next_state_bundle,
            }
        ),
    )
    assert next_open["mutation_lease_generation"] == "2"
    assert next_open["writer_fence"] == "2"
    next_append_context = _private_oram_mutation_v2_append_context(
        prepared,
        next_open,
        old_state=next_state_bundle,
        client_checkpoint=finalized["next_client_checkpoint"],
        encrypted_client_checkpoint=finalized["encrypted_client_checkpoint"],
    )
    _, next_read_responses = _execute_private_oram_mutation_v2_reads(
        owner_url,
        next_append_context,
    )
    next_finalized = _run_private_oram_mutation_v2_fixture_command(
        "finalize-mutation-v2-append",
        {
            "context": next_append_context,
            "read_responses": next_read_responses,
        },
    )
    rejected = requests.post(
        f"{owner_url}/collections/{COLLECTION}/private-oram/v2/mutation/append",
        json=next_finalized["rest_append_body"],
        timeout=30,
    )
    assert rejected.status_code == 500, rejected.text
    assert "owner journal is not ready for a new generation" in rejected.text
    sensitive_ciphertext = next_finalized["rest_append_body"]["owner_prepare"][
        "indexes"
    ][0]["ordered_encrypted_buckets"]["buckets"][0]["ciphertext"]
    assert sensitive_ciphertext not in rejected.text

    assert all(
        _private_oram_consensus_protocol_projection(peer_dir)
        == acknowledged_projection["value"]
        for peer_dir in peer_dirs
    )
    state = next(
        iter(
            acknowledged_projection["value"][
                "private_oram_mutation_states"
            ].values()
        )
    )
    slot = next(
        iter(
            acknowledged_projection["value"][
                "private_oram_mutation_lease_slots"
            ].values()
        )
    )["authority"]["state"]["lease_slot"]
    assert state["state_sequence"] == 1
    assert slot["generation"] == 1
    assert slot["active"] is None
    assert not completed_archive.exists()
    assert list(retired_root.iterdir()) == []


def test_private_oram_sessions_replicate_through_public_routes(tmp_path: pathlib.Path):
    peer_urls, _, fixture, _, _ = _start_private_oram_cluster(tmp_path, 2, 2)
    bootstrap_api, replica_api = peer_urls

    _upload_hnsw(bootstrap_api, fixture)
    _exercise_hnsw_owner_session(bootstrap_api, fixture)
    _upload_result_oram(bootstrap_api, fixture)
    _exercise_result_owner_session(bootstrap_api, fixture)
    _assert_replica_can_open_current_sessions(replica_api)


@pytest.mark.parametrize("shard_number", [1, 2], ids=["single-shard", "multi-shard"])
def test_private_oram_rf1_hard_restart_preserves_proof_verified_writeback(
    tmp_path: pathlib.Path,
    shard_number: int,
):
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(
        tmp_path,
        1,
        1,
        shard_number=shard_number,
    )
    owner_url = peer_urls[0]
    _upload_hnsw(owner_url, fixture)
    _exercise_hnsw_owner_session(owner_url, fixture)
    _upload_result_oram(owner_url, fixture)
    _exercise_result_owner_session(owner_url, fixture)

    owner_process = processes.pop()
    owner_port = owner_process.p2p_port
    owner_process.kill()
    restarted_url, _ = start_first_peer(
        peer_dirs[0],
        f"private_oram_rf1_{shard_number}_shard_hard_restart.log",
        port=owner_port,
    )
    restarted_leader = wait_peer_added(restarted_url)
    wait_for_uniform_cluster_status([restarted_url], restarted_leader)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, [restarted_url])

    hnsw = fixture["hnsw"]
    hnsw_session = _open_hnsw_owner_session(
        restarted_url,
        NEXT_EPOCH,
        hnsw["manifest"]["result_privacy"],
    )
    assert hnsw_session["root_hash"] == hnsw["commit"]["new_root_hash"]
    hnsw_read = _read_hnsw_owner_session(
        restarted_url,
        fixture,
        hnsw_session,
        hnsw["restart_read"],
        NEXT_EPOCH,
    )

    result = fixture["result"]
    result_session = _open_result_owner_session(restarted_url, NEXT_EPOCH)
    assert result_session["root_hash"] == result["commit"]["new_root_hash"]
    result_read = _read_result_owner_session(
        restarted_url,
        fixture,
        result_session,
        result["restart_read"],
        NEXT_EPOCH,
    )

    verification_request = _verify_private_oram_read_proofs(
        fixture,
        hnsw_read,
        result_read,
        NEXT_EPOCH,
        hnsw["commit"]["new_root_hash"],
        result["commit"]["new_root_hash"],
    )
    _assert_private_oram_read_proof_tampering_rejected(verification_request)
    _commit_hnsw_owner_session(restarted_url, hnsw_session, hnsw["restart_commit"])
    _commit_result_owner_session(
        restarted_url,
        result_session,
        result["restart_commit"],
    )

    assert (
        _post_result(
            f"{restarted_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session/{hnsw_session['session_id']}/close",
            {},
        )
        is True
    )
    assert (
        _post_result(
            f"{restarted_url}/collections/{COLLECTION}/private-result-oram/session/{result_session['session_id']}/close",
            {},
        )
        is True
    )
    _assert_replica_can_open_current_sessions(
        restarted_url,
        SECOND_EPOCH,
        hnsw["restart_commit"]["new_root_hash"],
        result["restart_commit"]["new_root_hash"],
    )


def test_private_oram_mutation_v2_post_prepare_snapshot_failures_publish_nothing(
    tmp_path: pathlib.Path,
):
    pause_file = tmp_path / "private-oram-snapshot-post-prepare.pause"
    pause_file.write_text("pause")
    prepared = _prepare_private_oram_mutation_v2_collection(
        tmp_path,
        [
            {
                "QDRANT_STAGING_PRIVATE_ORAM_SNAPSHOT_POST_PREPARE_PAUSE_FILE": str(
                    pause_file
                )
            },
            {},
            {},
        ],
        sharding_method="auto",
    )
    owner_url = prepared["leader_url"]
    owner_dir = prepared["peer_dirs"][0]
    owner_log = (
        pathlib.Path(init_pytest_log_folder())
        / "private_oram_mutation_v2_peer_0.log"
    )
    owner_prestage_root = (
        owner_dir
        / "storage"
        / "collections"
        / COLLECTION
        / "private_hnsw_oram"
        / VECTOR
        / "temp"
        / "private-oram-owner-prestage-v2"
    )
    assert owner_prestage_root.is_dir()
    unexpected_entry = owner_prestage_root / "unexpected.snapshot-entry"

    def public_snapshot_state() -> tuple[list[str], list[str], list[str]]:
        full_response = requests.get(f"{owner_url}/snapshots", timeout=30)
        assert_http_ok(full_response)
        collection_response = requests.get(
            f"{owner_url}/collections/{COLLECTION}/snapshots",
            timeout=30,
        )
        assert_http_ok(collection_response)
        public_root = owner_dir / "snapshots"
        public_files = (
            sorted(
                str(path.relative_to(public_root))
                for path in public_root.rglob("*")
                if path.is_file()
            )
            if public_root.exists()
            else []
        )
        return (
            sorted(snapshot["name"] for snapshot in full_response.json()["result"]),
            sorted(
                snapshot["name"]
                for snapshot in collection_response.json()["result"]
            ),
            public_files,
        )

    def staged_snapshot_files() -> list[str]:
        return sorted(
            str(path.relative_to(owner_dir))
            for path in owner_dir.rglob("*")
            if path.is_file()
            and (".staged" in path.name or ".snapshot-arc-" in path.name)
        )

    baseline_public = public_snapshot_state()
    baseline_staged = staged_snapshot_files()

    def assert_post_prepare_failure(scope: str, endpoint: str) -> None:
        marker = f"Private ORAM staging {scope} snapshot post-prepare pause reached"
        wait_for(owner_log.exists, wait_for_timeout=30)
        marker_count = owner_log.read_text(errors="replace").count(marker)
        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    requests.post,
                    endpoint,
                    timeout=180,
                )
                try:
                    wait_for(
                        lambda: owner_log.exists()
                        and owner_log.read_text(errors="replace").count(marker)
                        > marker_count,
                        wait_for_timeout=120,
                    )
                    assert public_snapshot_state() == baseline_public
                    assert staged_snapshot_files() != baseline_staged
                    unexpected_entry.write_bytes(b"unexpected")
                finally:
                    pause_file.unlink(missing_ok=True)
                response = future.result(timeout=180)
            assert response.status_code == 500, response.text
            assert (
                "private ORAM V2 snapshot owner archive chain is not ready"
                in response.text
            )
        finally:
            unexpected_entry.unlink(missing_ok=True)
            pause_file.unlink(missing_ok=True)
        assert public_snapshot_state() == baseline_public
        assert staged_snapshot_files() == baseline_staged

    assert_post_prepare_failure(
        "collection",
        f"{owner_url}/collections/{COLLECTION}/snapshots?wait=true",
    )
    pause_file.write_text("pause")
    assert_post_prepare_failure("full", f"{owner_url}/snapshots?wait=true")


def test_private_oram_mutation_v2_snapshot_waits_for_remote_config_apply(
    tmp_path: pathlib.Path,
):
    snapshot_pause = tmp_path / "private-oram-snapshot-post-prepare.pause"
    apply_pause = tmp_path / "private-oram-snapshot-authority-apply.pause"
    prepared = _prepare_private_oram_mutation_v2_collection(
        tmp_path,
        [
            {
                "QDRANT_STAGING_PRIVATE_ORAM_SNAPSHOT_POST_PREPARE_PAUSE_FILE": str(
                    snapshot_pause
                ),
                "QDRANT_STAGING_PRIVATE_ORAM_SNAPSHOT_AUTHORITY_APPLY_PAUSE_FILE": str(
                    apply_pause
                ),
            },
            {},
            {},
        ],
        sharding_method="auto",
    )
    leader_url = prepared["leader_url"]
    snapshot_url = leader_url
    update_url = prepared["peer_urls"][1]
    snapshot_log = (
        pathlib.Path(init_pytest_log_folder())
        / "private_oram_mutation_v2_peer_0.log"
    )
    def public_snapshots() -> list[str]:
        response = requests.get(
            f"{snapshot_url}/collections/{COLLECTION}/snapshots",
            timeout=30,
        )
        assert_http_ok(response)
        return sorted(snapshot["name"] for snapshot in response.json()["result"])

    baseline = public_snapshots()
    snapshot_pause.write_text("pause")
    apply_pause.write_text("pause")
    snapshot_marker = "Private ORAM staging collection snapshot post-prepare pause reached"
    apply_marker = (
        "Private ORAM staging snapshot authority consensus apply pause reached"
    )
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            snapshot_future = executor.submit(
                requests.post,
                f"{snapshot_url}/collections/{COLLECTION}/snapshots?wait=true",
                timeout=240,
            )
            wait_for(
                lambda: snapshot_log.exists()
                and snapshot_marker in snapshot_log.read_text(errors="replace"),
                wait_for_timeout=120,
            )
            assert public_snapshots() == baseline

            update_future = executor.submit(
                requests.patch,
                f"{update_url}/collections/{COLLECTION}",
                json={"optimizers_config": {"indexing_threshold": 30_000}},
                timeout=240,
            )
            wait_for(
                lambda: snapshot_log.exists()
                and apply_marker in snapshot_log.read_text(errors="replace"),
                wait_for_timeout=120,
            )
            update_response = update_future.result(timeout=120)
            assert_http_ok(update_response)

            snapshot_pause.unlink(missing_ok=True)
            time.sleep(1)
            assert not snapshot_future.done()
            assert public_snapshots() == baseline

            apply_pause.unlink(missing_ok=True)
            snapshot_response = snapshot_future.result(timeout=180)
        assert snapshot_response.status_code == 500, snapshot_response.text
        assert public_snapshots() == baseline
    finally:
        snapshot_pause.unlink(missing_ok=True)
        apply_pause.unlink(missing_ok=True)


def test_private_oram_snapshots_reject_active_external_recovery(
    tmp_path: pathlib.Path,
):
    peer_urls, _, fixture, _, _ = _start_private_oram_cluster(tmp_path, 1, 1)
    owner_url = peer_urls[0]
    _upload_hnsw(owner_url, fixture)
    _upload_result_oram(owner_url, fixture)
    _, checkpoint_bundle = _export_private_oram_recovery_snapshot(
        owner_url,
        tmp_path,
        fixture,
    )

    collection_snapshots_url = f"{owner_url}/collections/{COLLECTION}/snapshots"
    full_snapshots_url = f"{owner_url}/snapshots"

    def snapshot_names(url: str) -> list[str]:
        response = requests.get(url, timeout=30)
        assert_http_ok(response)
        return sorted(snapshot["name"] for snapshot in response.json()["result"])

    baseline_collection = snapshot_names(collection_snapshots_url)
    baseline_full = snapshot_names(full_snapshots_url)
    begin = _post_result(
        f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/begin",
        checkpoint_bundle,
    )
    operation_token = begin["operation_token"]
    assert begin["status"]["phase"] == "uploading"

    for snapshot_url in [collection_snapshots_url, full_snapshots_url]:
        rejected = requests.post(f"{snapshot_url}?wait=true", timeout=60)
        assert 400 <= rejected.status_code < 600, rejected.text
        assert "active external recovery" in rejected.text

    assert snapshot_names(collection_snapshots_url) == baseline_collection
    assert snapshot_names(full_snapshots_url) == baseline_full
    assert (
        _post_result(
            f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/abort",
            {"operation_token": operation_token},
        )
        is True
    )

    # Collection snapshot names use whole-second UTC timestamps. Avoid replacing
    # the checkpoint snapshot when recovery begins and aborts within that second.
    def snapshot_timestamp_is_unused() -> bool:
        suffix = time.strftime("-%Y-%m-%d-%H-%M-%S.snapshot", time.gmtime())
        return not any(name.endswith(suffix) for name in baseline_collection)

    wait_for(snapshot_timestamp_is_unused, wait_for_timeout=30)
    resumed = requests.post(f"{collection_snapshots_url}?wait=true", timeout=60)
    assert_http_ok(resumed)
    assert len(snapshot_names(collection_snapshots_url)) == len(baseline_collection) + 1


def test_private_oram_mutation_v2_acknowledged_snapshot_restore_admits_next_generation(
    tmp_path: pathlib.Path,
):
    consensus_env = {
        "QDRANT__CLUSTER__CONSENSUS__TICK_PERIOD_MS": "1000",
    }
    prepared = _prepare_private_oram_mutation_v2_collection(
        tmp_path,
        [
            {
                **consensus_env,
                "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_ADMITTED_RECONCILE_PROBE": "1"
            },
            consensus_env.copy(),
            consensus_env.copy(),
        ],
        fixture_logical_capacity=4,
        sharding_method="auto",
    )
    owner_url = prepared["leader_url"]
    peer_dirs = prepared["peer_dirs"]
    fixture = prepared["fixture"]

    opened, _ = _open_private_oram_mutation_v2_session(
        prepared,
        b"private-oram-v2-snapshot-generation-one",
    )
    append_context = _private_oram_mutation_v2_append_context(prepared, opened)
    _, read_responses = _execute_private_oram_mutation_v2_reads(
        owner_url,
        append_context,
    )
    finalized = _run_private_oram_mutation_v2_fixture_command(
        "finalize-mutation-v2-append",
        {
            "context": append_context,
            "read_responses": read_responses,
        },
    )
    accepted = _post_result(
        f"{owner_url}/collections/{COLLECTION}/private-oram/v2/mutation/append",
        finalized["rest_append_body"],
    )
    assert accepted == {"accepted": True, "phase": "prestage_pending"}
    generation_one_state = finalized["next_signed_state"]["state"]

    def generation_one_is_acknowledged() -> bool:
        projections = [
            _private_oram_consensus_protocol_projection(peer_dir)
            for peer_dir in peer_dirs
        ]
        if projections[0] is None or any(
            projection != projections[0] for projection in projections[1:]
        ):
            return False
        states = projections[0]["private_oram_mutation_states"]
        slots = projections[0]["private_oram_mutation_lease_slots"]
        if len(states) != 1 or len(slots) != 1:
            return False
        state = next(iter(states.values()))
        authority = next(iter(slots.values()))["authority"]
        if authority.get("mode") != "activated":
            return False
        activated = authority["state"]
        last_cleared = activated["lifecycle"]["last_cleared"]
        return (
            state["state_sequence"] == 1
            and state["signed_state_digest"] == finalized["new_state_digest"]
            and activated["lease_slot"]["generation"] == 1
            and activated["lease_slot"]["active"] is None
            and activated["lifecycle"]["active"] is None
            and last_cleared is not None
            and last_cleared["generation"] == 1
            and isinstance(last_cleared["resolution"], dict)
            and "acknowledged" in last_cleared["resolution"]
        )
    wait_for(generation_one_is_acknowledged, wait_for_timeout=300)
    for endpoint, refresh, expected_kind in [
        (
            f"private-hnsw/{VECTOR}",
            finalized["manifest_refresh"]["hnsw"],
            "hnsw",
        ),
        (
            "private-result-oram",
            finalized["manifest_refresh"]["result"],
            "result",
        ),
    ]:
        refreshed = _post_result(
            f"{owner_url}/collections/{COLLECTION}/{endpoint}/manifest",
            refresh,
        )
        expected_index = next(
            index
            for index in generation_one_state["indexes"]
            if index["kind"] == expected_kind
        )
        assert refreshed == {
            "index_epoch": expected_index["index_epoch"],
            "root_hash": expected_index["root_hash"],
        }
    refreshed_hnsw_manifest = json.loads(
        (
            peer_dirs[0]
            / "storage"
            / "collections"
            / COLLECTION
            / "private_hnsw_oram"
            / VECTOR
            / "manifest.json"
        ).read_text()
    )
    refreshed_result_manifest = json.loads(
        (
            peer_dirs[0]
            / "storage"
            / "collections"
            / COLLECTION
            / "private_result_oram"
            / "manifest.json"
        ).read_text()
    )
    expected_hnsw = next(
        index for index in generation_one_state["indexes"] if index["kind"] == "hnsw"
    )
    expected_result = next(
        index for index in generation_one_state["indexes"] if index["kind"] == "result"
    )
    assert (
        refreshed_hnsw_manifest["logical_node_count"],
        refreshed_hnsw_manifest["dummy_node_count"],
    ) == (expected_hnsw["logical_count"], expected_hnsw["dummy_count"])
    assert (
        refreshed_result_manifest["logical_result_count"],
        refreshed_result_manifest["dummy_result_count"],
    ) == (expected_result["logical_count"], expected_result["dummy_count"])
    parent_archive, child_archive = _assert_private_oram_mutation_v2_archive_chain(
        peer_dirs[0],
        1,
    )
    parent_tree_before = _private_oram_mutation_v2_file_tree(parent_archive.parent)
    child_tree_before = _private_oram_mutation_v2_file_tree(child_archive)

    expected_indexes = [
        {
            "index_kind": (
                "result_payload" if index["kind"] == "result" else index["kind"]
            ),
            "index_name": "" if index["kind"] == "result" else index["index_name"],
            "index_epoch": int(index["index_epoch"]),
            "root_hash": index["root_hash"],
            "writeback_digest": index["last_writeback_digest"],
        }
        for index in generation_one_state["indexes"]
    ]
    snapshot_path, checkpoint_bundle = _export_private_oram_recovery_snapshot(
        owner_url,
        tmp_path,
        fixture,
        expected_indexes=expected_indexes,
    )
    authority_digest = checkpoint_bundle["checkpoint"][
        "owner_snapshot_authority_digest"
    ]
    assert len(authority_digest) == 43
    assert authority_digest != checkpoint_bundle["checkpoint"]["index_state_digest"]
    with tarfile.open(snapshot_path, mode="r:*") as snapshot_archive:
        archived_names = {
            member.name.removeprefix("./").rstrip("/")
            for member in snapshot_archive.getmembers()
        }
    assert any(
        name.endswith(
            "private_oram_mutations/completed-v2-00000000000000000001/"
            "owner_child_archive_grant_v1.json"
        )
        for name in archived_names
    )
    assert any(
        name.endswith(
            f"private_hnsw_oram/{VECTOR}/temp/private-oram-owner-v2/"
            "completed-v2-00000000000000000001/owner-terminal-archive-v1.json"
        )
        for name in archived_names
    )

    _restore_private_oram_snapshot(owner_url, snapshot_path, checkpoint_bundle)
    restored_parent_archive, restored_child_archive = (
        _assert_private_oram_mutation_v2_archive_chain(peer_dirs[0], 1)
    )
    assert (
        _private_oram_mutation_v2_file_tree(restored_parent_archive.parent)
        == parent_tree_before
    )
    assert (
        _private_oram_mutation_v2_file_tree(restored_child_archive)
        == child_tree_before
    )

    next_mutation_id = base64.urlsafe_b64encode(
        hashlib.sha256(b"private-oram-v2-snapshot-generation-two").digest()
    ).decode().rstrip("=")
    next_open = _post_result(
        f"{owner_url}/collections/{COLLECTION}/private-oram/v2/mutation/open",
        _private_oram_v2_wire_body(
            {
                "client_id": "tenant-a/process-v2-snapshot-sdk",
                "vector_name": VECTOR,
                "mutation_id": next_mutation_id,
                "immutable_manifest": prepared["signed_genesis"]["rest_enroll_body"][
                    "immutable_manifest"
                ],
                "old_state": finalized["next_signed_state"],
            }
        ),
    )
    assert next_open["mutation_lease_generation"] == "2"
    assert next_open["writer_fence"] == "2"
    next_context = _private_oram_mutation_v2_append_context(
        prepared,
        next_open,
        old_state=finalized["next_signed_state"],
        client_checkpoint=finalized["next_client_checkpoint"],
        encrypted_client_checkpoint=finalized["encrypted_client_checkpoint"],
    )
    _, next_read_responses = _execute_private_oram_mutation_v2_reads(
        owner_url,
        next_context,
    )
    next_finalized = _run_private_oram_mutation_v2_fixture_command(
        "finalize-mutation-v2-append",
        {
            "context": next_context,
            "read_responses": next_read_responses,
        },
    )
    next_accepted = _post_result(
        f"{owner_url}/collections/{COLLECTION}/private-oram/v2/mutation/append",
        next_finalized["rest_append_body"],
    )
    assert next_accepted == {"accepted": True, "phase": "prestage_pending"}

    def generation_two_is_acknowledged() -> bool:
        projections = [
            _private_oram_consensus_protocol_projection(peer_dir)
            for peer_dir in peer_dirs
        ]
        if projections[0] is None or any(
            projection != projections[0] for projection in projections[1:]
        ):
            return False
        state = next(iter(projections[0]["private_oram_mutation_states"].values()))
        authority = next(
            iter(projections[0]["private_oram_mutation_lease_slots"].values())
        )["authority"]
        if authority.get("mode") != "activated":
            return False
        activated = authority["state"]
        last_cleared = activated["lifecycle"]["last_cleared"]
        return (
            state["state_sequence"] == 2
            and state["signed_state_digest"] == next_finalized["new_state_digest"]
            and activated["lease_slot"]["generation"] == 2
            and activated["lease_slot"]["active"] is None
            and activated["lifecycle"]["active"] is None
            and last_cleared is not None
            and last_cleared["generation"] == 2
            and isinstance(last_cleared["resolution"], dict)
            and "acknowledged" in last_cleared["resolution"]
        )

    wait_for(generation_two_is_acknowledged, wait_for_timeout=300)
    _assert_private_oram_mutation_v2_archive_chain(peer_dirs[0], 1)
    _assert_private_oram_mutation_v2_archive_chain(peer_dirs[0], 2)


@pytest.mark.parametrize("shard_number", [1, 2], ids=["single-shard", "multi-shard"])
def test_private_oram_rf1_external_restore_preserves_proof_verified_writeback(
    tmp_path: pathlib.Path,
    shard_number: int,
):
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(
        tmp_path,
        1,
        1,
        shard_number=shard_number,
    )
    owner_url = peer_urls[0]
    _upload_hnsw(owner_url, fixture)
    _upload_result_oram(owner_url, fixture)

    snapshot_path, checkpoint_bundle = _export_private_oram_recovery_snapshot(
        owner_url,
        tmp_path,
        fixture,
    )
    _restore_private_oram_snapshot(owner_url, snapshot_path, checkpoint_bundle)

    owner_process = processes.pop()
    owner_port = owner_process.p2p_port
    owner_process.kill()
    restarted_url, _ = start_first_peer(
        peer_dirs[0],
        f"private_oram_rf1_external_restore_{shard_number}_shard_restart.log",
        port=owner_port,
    )
    restarted_leader = wait_peer_added(restarted_url)
    wait_for_uniform_cluster_status([restarted_url], restarted_leader)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, [restarted_url])

    hnsw = fixture["hnsw"]
    hnsw_session = _open_hnsw_owner_session(
        restarted_url,
        BASE_EPOCH,
        hnsw["manifest"]["result_privacy"],
    )
    assert hnsw_session["root_hash"] == hnsw["manifest"]["root_hash"]
    hnsw_read = _read_hnsw_owner_session(
        restarted_url,
        fixture,
        hnsw_session,
    )

    result = fixture["result"]
    result_session = _open_result_owner_session(restarted_url, BASE_EPOCH)
    assert result_session["root_hash"] == result["manifest"]["root_hash"]
    result_read = _read_result_owner_session(
        restarted_url,
        fixture,
        result_session,
    )
    _verify_private_oram_read_proofs(
        fixture,
        hnsw_read,
        result_read,
        BASE_EPOCH,
        hnsw["manifest"]["root_hash"],
        result["manifest"]["root_hash"],
    )

    _commit_hnsw_owner_session(restarted_url, hnsw_session, hnsw["commit"])
    _commit_result_owner_session(restarted_url, result_session, result["commit"])
    assert (
        _post_result(
            f"{restarted_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session/{hnsw_session['session_id']}/close",
            {},
        )
        is True
    )
    assert (
        _post_result(
            f"{restarted_url}/collections/{COLLECTION}/private-result-oram/session/{result_session['session_id']}/close",
            {},
        )
        is True
    )
    _assert_replica_can_open_current_sessions(
        restarted_url,
        NEXT_EPOCH,
        hnsw["commit"]["new_root_hash"],
        result["commit"]["new_root_hash"],
    )


@pytest.mark.parametrize(
    "resource_env",
    [
        {
            "QDRANT__STORAGE__PRIVATE_ORAM_EXTERNAL_RECOVERY__MAX_SNAPSHOT_BYTES": "1",
        },
        {
            "QDRANT__STORAGE__PRIVATE_ORAM_EXTERNAL_RECOVERY__MAX_TOTAL_STAGED_BYTES": "2",
            "QDRANT__STORAGE__PRIVATE_ORAM_EXTERNAL_RECOVERY__MAX_UNPACKED_BYTES": "1",
        },
        {
            "QDRANT__STORAGE__PRIVATE_ORAM_EXTERNAL_RECOVERY__MIN_FREE_SPACE_BYTES": str(
                2**64 - 1
            ),
        },
    ],
    ids=["snapshot-limit", "node-staging-quota", "free-space-reserve"],
)
def test_private_oram_external_restore_resource_admission_has_no_staging_side_effects(
    tmp_path: pathlib.Path,
    resource_env: dict[str, str],
):
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(
        tmp_path,
        1,
        1,
        extra_env=resource_env,
    )
    owner_url = peer_urls[0]
    _upload_hnsw(owner_url, fixture)
    _upload_result_oram(owner_url, fixture)
    snapshot_path, checkpoint_bundle = _export_private_oram_recovery_snapshot(
        owner_url,
        tmp_path,
        fixture,
    )

    recovery_root = peer_dirs[0] / "storage" / "private_oram_external_recovery"
    assert not recovery_root.exists()
    rejected = requests.post(
        f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/begin",
        json=checkpoint_bundle,
        timeout=30,
    )
    assert 400 <= rejected.status_code < 500
    assert not recovery_root.exists()
    assert snapshot_path.exists()
    for secret in [
        checkpoint_bundle["checkpoint"]["collection_id"],
        checkpoint_bundle["checkpoint"]["snapshot_sha256"],
        checkpoint_bundle["signature"]["sig"],
    ]:
        assert secret not in rejected.text
    _assert_replica_can_open_current_sessions(owner_url, BASE_EPOCH)


@pytest.mark.parametrize("sync_target", ["verified", "live"])
def test_private_oram_external_restore_retries_install_bulk_sync_enospc(
    tmp_path: pathlib.Path,
    sync_target: str,
):
    fault_selector_path = tmp_path / "private-oram-install-bulk-sync-fault.json"
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(
        tmp_path,
        1,
        1,
        extra_env={
            "QDRANT__STORAGE__PRIVATE_ORAM_EXTERNAL_RECOVERY__MAX_TOTAL_STAGED_BYTES": str(
                3 * 1024 * 1024 * 1024
            ),
            "QDRANT__STORAGE__PRIVATE_ORAM_EXTERNAL_RECOVERY__MAX_UNPACKED_BYTES": str(
                1024 * 1024 * 1024
            ),
            "QDRANT_STAGING_PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_BULK_SYNC_ENOSPC_ONCE_FILE": str(
                fault_selector_path
            ),
        },
        capture_stderr=True,
    )
    owner_url = peer_urls[0]
    _upload_hnsw(owner_url, fixture)
    _upload_result_oram(owner_url, fixture)
    snapshot_path, checkpoint_bundle = _export_private_oram_recovery_snapshot(
        owner_url,
        tmp_path,
        fixture,
    )
    operation_token = _begin_and_upload_private_oram_snapshot(
        owner_url,
        snapshot_path,
        checkpoint_bundle,
    )
    verified = _post_result(
        f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/verify",
        {"operation_token": operation_token},
    )
    assert verified["phase"] == "verified"

    recovery_root = peer_dirs[0] / "storage" / "private_oram_external_recovery"
    state_paths = list(recovery_root.glob("*/*/state.json"))
    assert len(state_paths) == 1
    operation_path = state_paths[0].parent
    collection_recovery_path = operation_path.parent
    live_collection_path = peer_dirs[0] / "storage" / "collections" / COLLECTION
    assert live_collection_path.is_dir()
    assert (operation_path / "verified_collection").is_dir()
    fault_selector_path.write_text(
        json.dumps(
            {
                "operation_id_hash": operation_path.name,
                "tree": sync_target,
            }
        )
    )

    log_path = pathlib.Path(init_pytest_log_folder()) / "private_oram_peer_0.log"
    fault_marker = (
        "Private ORAM staging external recovery install bulk-sync ENOSPC injected: "
        f"{sync_target}"
    )
    second_collection = f"docs-install-{sync_target}-control"
    create = requests.put(
        f"{owner_url}/collections/{second_collection}",
        json=_private_oram_collection_create_body(1),
        timeout=30,
    )
    assert_http_ok(create)
    wait_collection_exists_and_active_on_all_peers(second_collection, [owner_url])
    second_fixture = _private_oram_fixture(
        _collection_uuid(owner_url, second_collection)
    )
    _upload_hnsw(owner_url, second_fixture, second_collection)
    _upload_result_oram(owner_url, second_fixture, second_collection)
    second_snapshot_path, second_checkpoint_bundle = (
        _export_private_oram_recovery_snapshot(
            owner_url,
            tmp_path,
            second_fixture,
            second_collection,
        )
    )
    second_operation_token = _begin_and_upload_private_oram_snapshot(
        owner_url,
        second_snapshot_path,
        second_checkpoint_bundle,
        second_collection,
    )
    second_verified = _post_result(
        f"{owner_url}/collections/{second_collection}/private-oram/recovery/verify",
        {"operation_token": second_operation_token},
    )
    assert second_verified["phase"] == "verified"
    assert (
        _post_result(
            f"{owner_url}/collections/{second_collection}/private-oram/recovery/commit",
            {"operation_token": second_operation_token},
        )
        is True
    )
    assert fault_marker not in log_path.read_text()

    failed_commit = requests.post(
        f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/commit",
        json={"operation_token": operation_token},
        timeout=60,
    )
    assert 400 <= failed_commit.status_code < 600
    for secret in [
        operation_token,
        checkpoint_bundle["checkpoint"]["collection_id"],
        checkpoint_bundle["checkpoint"]["snapshot_sha256"],
        checkpoint_bundle["checkpoint"]["layout_digest"],
        checkpoint_bundle["checkpoint"]["index_state_digest"],
        checkpoint_bundle["signature"]["sig"],
        fixture["hnsw"]["manifest"]["root_hash"],
        fixture["result"]["manifest"]["root_hash"],
    ]:
        assert secret not in failed_commit.text

    status_response = requests.get(
        f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/status",
        headers={"x-qdrant-private-oram-recovery-token": operation_token},
        timeout=30,
    )
    assert_http_ok(status_response)
    recovery_status = status_response.json()["result"]
    assert recovery_status["phase"] == "verified"
    assert recovery_status["backup_generation"] == checkpoint_bundle["checkpoint"][
        "backup_generation"
    ]
    assert json.loads(state_paths[0].read_text())["phase"] == "verified"
    assert not (collection_recovery_path / "install.json").exists()
    assert not (collection_recovery_path / "live_collection.backup").exists()
    assert live_collection_path.is_dir()
    assert (operation_path / "verified_collection").is_dir()
    wait_collection_exists_and_active_on_all_peers(COLLECTION, [owner_url])

    wait_for(
        lambda: log_path.exists() and log_path.read_text().count(fault_marker) == 1,
        wait_for_timeout=30,
    )

    fenced_session = requests.post(
        f"{owner_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session",
        json={
            "client_id": f"tenant-a/install-{sync_target}-enospc-fenced-sdk",
            "desired_epoch": BASE_EPOCH,
            "fixed_budget": True,
            "result_privacy": fixture["hnsw"]["manifest"]["result_privacy"],
        },
        timeout=30,
    )
    assert fenced_session.status_code == 400
    assert "session lease conflicts with active external recovery" in fenced_session.text

    assert (
        _post_result(
            f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/commit",
            {"operation_token": operation_token},
        )
        is True
    )
    assert log_path.read_text().count(fault_marker) == 1
    assert not operation_path.exists()
    assert sorted(path.name for path in collection_recovery_path.iterdir()) == [
        "recovery.lock"
    ]
    _assert_replica_can_open_current_sessions(owner_url, BASE_EPOCH)
    all_log_text = "\n".join(
        path.read_text()
        for path in pathlib.Path(init_pytest_log_folder()).glob("*.log")
    )
    for secret in [
        operation_token,
        checkpoint_bundle["checkpoint"]["collection_id"],
        checkpoint_bundle["checkpoint"]["snapshot_sha256"],
        checkpoint_bundle["checkpoint"]["layout_digest"],
        checkpoint_bundle["checkpoint"]["index_state_digest"],
        checkpoint_bundle["signature"]["sig"],
        fixture["hnsw"]["manifest"]["root_hash"],
        fixture["result"]["manifest"]["root_hash"],
        second_operation_token,
        second_checkpoint_bundle["checkpoint"]["collection_id"],
        second_checkpoint_bundle["checkpoint"]["snapshot_sha256"],
        second_checkpoint_bundle["checkpoint"]["layout_digest"],
        second_checkpoint_bundle["checkpoint"]["index_state_digest"],
        second_checkpoint_bundle["signature"]["sig"],
        second_fixture["hnsw"]["manifest"]["root_hash"],
        second_fixture["result"]["manifest"]["root_hash"],
    ]:
        assert secret not in all_log_text


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux mount namespaces")
@pytest.mark.skipif(
    os.getenv(RUN_PROCESS_ENOSPC_GATE) != "1",
    reason=f"set {RUN_PROCESS_ENOSPC_GATE}=1 to run the isolated ENOSPC gate",
)
def test_private_oram_external_restore_recovers_from_process_enospc(
    tmp_path: pathlib.Path,
):
    if os.getenv(PROCESS_ENOSPC_CHILD) != "1":
        child_env = os.environ.copy()
        child_env[RUN_PROCESS_ENOSPC_GATE] = "1"
        child_env[PROCESS_ENOSPC_CHILD] = "1"
        completed = subprocess.run(
            [
                "unshare",
                "-Ur",
                "-m",
                "--",
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "-s",
                "tests/consensus_tests/test_private_oram_sessions.py::test_private_oram_external_restore_recovers_from_process_enospc",
            ],
            cwd=PROJECT_ROOT,
            env=child_env,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr
        return

    mount_root = tmp_path / "private-oram-process-enospc"
    mount_root.mkdir()
    mounted = subprocess.run(
        [
            "mount",
            "-t",
            "tmpfs",
            "-o",
            "size=256m,nr_inodes=65536,mode=700",
            "qdrant-private-oram-process-enospc",
            str(mount_root),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert mounted.returncode == 0, mounted.stderr

    pause_file = tmp_path / "private-oram-archive-preflight.pause"
    unpack_error_kind_file = tmp_path / "private-oram-unpack-error-kind"
    filler_path = mount_root / "concurrent-disk-consumer"
    try:
        host_artifacts = tmp_path / "host-artifacts"
        host_artifacts.mkdir()
        recovery_limits = {
            "QDRANT__STORAGE__PRIVATE_ORAM_EXTERNAL_RECOVERY__MAX_SNAPSHOT_BYTES": str(
                64 * 1024 * 1024
            ),
            "QDRANT__STORAGE__PRIVATE_ORAM_EXTERNAL_RECOVERY__MAX_TOTAL_STAGED_BYTES": str(
                192 * 1024 * 1024
            ),
            "QDRANT__STORAGE__PRIVATE_ORAM_EXTERNAL_RECOVERY__MAX_UNPACKED_BYTES": str(
                128 * 1024 * 1024
            ),
            "QDRANT__STORAGE__PRIVATE_ORAM_EXTERNAL_RECOVERY__MIN_FREE_SPACE_BYTES": "0",
            "QDRANT_STAGING_PRIVATE_ORAM_EXTERNAL_RECOVERY_ARCHIVE_PREFLIGHT_PAUSE_FILE": str(
                pause_file
            ),
            "QDRANT_STAGING_PRIVATE_ORAM_EXTERNAL_RECOVERY_UNPACK_ERROR_KIND_FILE": str(
                unpack_error_kind_file
            ),
        }
        peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(
            mount_root,
            1,
            1,
            extra_env=recovery_limits,
            fixture_profile=LARGE_FIXTURE_PROFILE,
            capture_stderr=True,
        )
        owner_url = peer_urls[0]
        _upload_hnsw(owner_url, fixture)
        _upload_result_oram(owner_url, fixture)
        snapshot_path, checkpoint_bundle = _export_private_oram_recovery_snapshot(
            owner_url,
            host_artifacts,
            fixture,
        )
        assert not snapshot_path.is_relative_to(mount_root)
        with tarfile.open(snapshot_path, mode="r:*") as snapshot_archive:
            logical_snapshot_bytes = sum(
                member.size for member in snapshot_archive.getmembers() if member.isfile()
            )
        bytes_to_leave = 4 * 1024 * 1024
        assert logical_snapshot_bytes > 2 * bytes_to_leave

        snapshot_name = snapshot_path.name.removeprefix(f"{COLLECTION}-")
        assert snapshot_name != snapshot_path.name
        deleted_snapshot = requests.delete(
            f"{owner_url}/collections/{COLLECTION}/snapshots/{snapshot_name}",
            params={"wait": "true"},
            timeout=30,
        )
        assert_http_ok(deleted_snapshot)

        operation_token = _begin_and_upload_private_oram_snapshot(
            owner_url,
            snapshot_path,
            checkpoint_bundle,
        )
        recovery_root = peer_dirs[0] / "storage" / "private_oram_external_recovery"
        state_paths = list(recovery_root.glob("*/*/state.json"))
        assert len(state_paths) == 1
        operation_path = state_paths[0].parent

        verify_result: dict[str, requests.Response | Exception] = {}

        def verify_while_storage_is_exhausted() -> None:
            try:
                verify_result["response"] = requests.post(
                    f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/verify",
                    json={"operation_token": operation_token},
                    timeout=120,
                )
            except Exception as error:
                verify_result["error"] = error

        pause_file.write_text("pause")
        log_path = pathlib.Path(init_pytest_log_folder()) / "private_oram_peer_0.log"
        pause_marker = (
            "Private ORAM staging external recovery archive-preflight pause reached"
        )
        pause_count_before = log_path.read_text().count(pause_marker)
        verify_thread = Thread(target=verify_while_storage_is_exhausted, daemon=True)
        verify_thread.start()
        wait_for(
            lambda: log_path.exists()
            and log_path.read_text().count(pause_marker) > pause_count_before,
            wait_for_timeout=60,
        )

        available_before_fill = shutil.disk_usage(mount_root).free
        assert available_before_fill > logical_snapshot_bytes + bytes_to_leave
        filler_chunk = b"\xa5" * (1024 * 1024)
        with filler_path.open("wb", buffering=0) as filler:
            while True:
                available = shutil.disk_usage(mount_root).free
                if available <= bytes_to_leave:
                    break
                write_size = min(len(filler_chunk), available - bytes_to_leave)
                filler.write(filler_chunk[:write_size])
            os.fsync(filler.fileno())
        available_after_fill = shutil.disk_usage(mount_root).free
        assert 0 < available_after_fill <= bytes_to_leave + len(filler_chunk)

        pause_file.unlink()
        verify_thread.join(timeout=120)
        assert not verify_thread.is_alive()
        assert "error" not in verify_result, verify_result.get("error")
        failed_verify = verify_result["response"]
        assert isinstance(failed_verify, requests.Response)
        assert 400 <= failed_verify.status_code < 500
        assert unpack_error_kind_file.read_text() == "storage_full\n"
        for secret in [
            checkpoint_bundle["checkpoint"]["collection_id"],
            checkpoint_bundle["checkpoint"]["snapshot_sha256"],
            checkpoint_bundle["signature"]["sig"],
        ]:
            assert secret not in failed_verify.text

        state_after_failure = json.loads(state_paths[0].read_text())
        assert state_after_failure["phase"] == "uploading"
        pending_path = operation_path / "verified_collection.pending"
        verified_path = operation_path / "verified_collection"
        partial_files = [path for path in pending_path.rglob("*") if path.is_file()]
        partial_bytes = sum(path.stat().st_size for path in partial_files)
        assert partial_files
        assert 0 < partial_bytes < logical_snapshot_bytes
        assert not verified_path.exists()

        filler_path.unlink()
        assert shutil.disk_usage(mount_root).free > logical_snapshot_bytes
        unpack_error_kind_file.unlink()
        fenced_session = requests.post(
            f"{owner_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session",
            json={
                "client_id": "tenant-a/process-enospc-fenced-sdk",
                "desired_epoch": BASE_EPOCH,
                "fixed_budget": True,
                "result_privacy": fixture["hnsw"]["manifest"]["result_privacy"],
            },
            timeout=30,
        )
        assert fenced_session.status_code == 400
        assert "session lease conflicts with active external recovery" in fenced_session.text
        verified = _post_result(
            f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/verify",
            {"operation_token": operation_token},
        )
        assert verified["phase"] == "verified"
        assert not unpack_error_kind_file.exists()
        assert (
            _post_result(
                f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/commit",
                {"operation_token": operation_token},
            )
            is True
        )
        _assert_replica_can_open_current_sessions(owner_url, BASE_EPOCH)
    finally:
        if pause_file.exists():
            pause_file.unlink()
        if filler_path.exists():
            filler_path.unlink()
        if unpack_error_kind_file.exists():
            unpack_error_kind_file.unlink()
        kill_all_processes()
        unmounted = subprocess.run(
            ["umount", str(mount_root)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert unmounted.returncode == 0, unmounted.stderr


def test_private_oram_external_restore_status_during_verify_keeps_rest_worker_available(
    tmp_path: pathlib.Path,
):
    pause_file = tmp_path / "private-oram-verify-status.pause"
    peer_urls, _, fixture, _, _ = _start_private_oram_cluster(
        tmp_path,
        1,
        1,
        extra_env={
            "QDRANT__SERVICE__MAX_WORKERS": "1",
            "QDRANT__STORAGE__PRIVATE_ORAM_EXTERNAL_RECOVERY__MAX_TOTAL_STAGED_BYTES": str(
                3 * 1024 * 1024 * 1024
            ),
            "QDRANT__STORAGE__PRIVATE_ORAM_EXTERNAL_RECOVERY__MAX_UNPACKED_BYTES": str(
                1024 * 1024 * 1024
            ),
            "QDRANT_STAGING_PRIVATE_ORAM_EXTERNAL_RECOVERY_ARCHIVE_PREFLIGHT_PAUSE_FILE": str(
                pause_file
            ),
        },
        capture_stderr=True,
    )
    owner_url = peer_urls[0]
    _upload_hnsw(owner_url, fixture)
    _upload_result_oram(owner_url, fixture)
    snapshot_path, checkpoint_bundle = _export_private_oram_recovery_snapshot(
        owner_url,
        tmp_path,
        fixture,
    )
    operation_token = _begin_and_upload_private_oram_snapshot(
        owner_url,
        snapshot_path,
        checkpoint_bundle,
    )

    recovery_url = f"{owner_url}/collections/{COLLECTION}/private-oram/recovery"
    pause_file.write_text("pause")
    log_path = pathlib.Path(init_pytest_log_folder()) / "private_oram_peer_0.log"
    pause_marker = "Private ORAM staging external recovery archive-preflight pause reached"
    with ThreadPoolExecutor(max_workers=2) as requests_in_flight:
        try:
            verify = requests_in_flight.submit(
                requests.post,
                f"{recovery_url}/verify",
                json={"operation_token": operation_token},
                timeout=30,
            )
            wait_for(
                lambda: log_path.exists() and pause_marker in log_path.read_text(),
                wait_for_timeout=10,
            )
            status = requests_in_flight.submit(
                requests.get,
                f"{recovery_url}/status",
                headers={"x-qdrant-private-oram-recovery-token": operation_token},
                timeout=30,
            )
            time.sleep(0.25)
            assert not status.done(), "status must wait for the held verification flock"
            ready = requests.get(f"{owner_url}/readyz", timeout=3)
            assert_http_ok(ready)
        finally:
            pause_file.unlink(missing_ok=True)

        verified = verify.result(timeout=10)
        observed = status.result(timeout=10)
        assert_http_ok(verified)
        assert_http_ok(observed)
        assert verified.json()["result"]["phase"] == "verified"
        assert observed.json()["result"]["phase"] == "verified"
        assert_http_ok(requests.get(f"{owner_url}/readyz", timeout=3))


def test_private_oram_external_restore_worker_limit_is_process_wide(
    tmp_path: pathlib.Path,
):
    pause_file = tmp_path / "private-oram-worker.pause"
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(
        tmp_path,
        1,
        1,
        extra_env={
            "QDRANT__STORAGE__PRIVATE_ORAM_EXTERNAL_RECOVERY__MAX_CONCURRENT_VERIFY_PREPARE": "1",
            "QDRANT__STORAGE__PRIVATE_ORAM_EXTERNAL_RECOVERY__MAX_TOTAL_STAGED_BYTES": str(
                3 * 1024 * 1024 * 1024
            ),
            "QDRANT__STORAGE__PRIVATE_ORAM_EXTERNAL_RECOVERY__MAX_UNPACKED_BYTES": str(
                1024 * 1024 * 1024
            ),
            "QDRANT_STAGING_PRIVATE_ORAM_EXTERNAL_RECOVERY_WORKER_PAUSE_FILE": str(
                pause_file
            ),
        },
    )
    owner_url = peer_urls[0]
    _upload_hnsw(owner_url, fixture)
    _upload_result_oram(owner_url, fixture)
    snapshot_path, checkpoint_bundle = _export_private_oram_recovery_snapshot(
        owner_url,
        tmp_path,
        fixture,
    )

    second_collection = "docs-worker-contention"
    create = requests.put(
        f"{owner_url}/collections/{second_collection}",
        json=_private_oram_collection_create_body(1),
        timeout=30,
    )
    assert_http_ok(create)
    wait_collection_exists_and_active_on_all_peers(second_collection, [owner_url])
    second_fixture = _private_oram_fixture(
        _collection_uuid(owner_url, second_collection)
    )
    _upload_hnsw(owner_url, second_fixture, second_collection)
    _upload_result_oram(owner_url, second_fixture, second_collection)
    second_snapshot_path, second_checkpoint_bundle = (
        _export_private_oram_recovery_snapshot(
            owner_url,
            tmp_path,
            second_fixture,
            second_collection,
        )
    )

    operation_token = _begin_and_upload_private_oram_snapshot(
        owner_url,
        snapshot_path,
        checkpoint_bundle,
    )
    second_operation_token = _begin_and_upload_private_oram_snapshot(
        owner_url,
        second_snapshot_path,
        second_checkpoint_bundle,
        second_collection,
    )
    recovery_root = peer_dirs[0] / "storage" / "private_oram_external_recovery"
    second_state_paths = [
        path
        for path in recovery_root.glob("*/*/state.json")
        if json.loads(path.read_text())["checkpoint_bundle"]["checkpoint"]
        ["collection_id"]
        == second_fixture["hnsw"]["manifest"]["collection_id"]
    ]
    assert len(second_state_paths) == 1
    second_operation_path = second_state_paths[0].parent
    second_before_rejected_verify = {
        str(path.relative_to(second_operation_path)): (
            "directory"
            if path.is_dir()
            else hashlib.sha256(path.read_bytes()).hexdigest()
        )
        for path in second_operation_path.rglob("*")
    }

    first_verify: dict[str, requests.Response | Exception] = {}

    def verify_first_collection() -> None:
        try:
            first_verify["response"] = requests.post(
                f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/verify",
                json={"operation_token": operation_token},
                timeout=120,
            )
        except Exception as error:
            first_verify["error"] = error

    pause_file.write_text("pause")
    verify_thread = Thread(target=verify_first_collection, daemon=True)
    log_path = pathlib.Path(init_pytest_log_folder()) / "private_oram_peer_0.log"
    pause_marker = "Private ORAM staging external recovery worker-acquire pause reached"
    pause_count_before = log_path.read_text().count(pause_marker)
    verify_thread.start()
    try:
        wait_for(
            lambda: log_path.exists()
            and log_path.read_text().count(pause_marker) > pause_count_before,
            wait_for_timeout=30,
        )
        metrics = requests.get(
            f"{owner_url}/metrics",
            params={"anonymize": "false"},
            timeout=30,
        )
        assert_http_ok(metrics)
        assert (
            "private_oram_external_recovery_workers_in_use 1"
            in metrics.text
        )
        assert (
            "private_oram_external_recovery_staging_reservations 2"
            in metrics.text
        )

        rejected = requests.post(
            f"{owner_url}/collections/{second_collection}/private-oram/recovery/verify",
            json={"operation_token": second_operation_token},
            timeout=30,
        )
        assert rejected.status_code == 429
        second_after_rejected_verify = {
            str(path.relative_to(second_operation_path)): (
                "directory"
                if path.is_dir()
                else hashlib.sha256(path.read_bytes()).hexdigest()
            )
            for path in second_operation_path.rglob("*")
        }
        assert second_after_rejected_verify == second_before_rejected_verify
        after_rejection_metrics = requests.get(
            f"{owner_url}/metrics",
            params={"anonymize": "false"},
            timeout=30,
        )
        assert_http_ok(after_rejection_metrics)
        assert (
            "private_oram_external_recovery_workers_in_use 1"
            in after_rejection_metrics.text
        )
        assert (
            "private_oram_external_recovery_staging_reservations 2"
            in after_rejection_metrics.text
        )
        for secret in [
            checkpoint_bundle["checkpoint"]["collection_id"],
            checkpoint_bundle["checkpoint"]["snapshot_sha256"],
            second_checkpoint_bundle["checkpoint"]["collection_id"],
            second_checkpoint_bundle["checkpoint"]["snapshot_sha256"],
        ]:
            assert secret not in rejected.text
    finally:
        pause_file.unlink(missing_ok=True)
        verify_thread.join(timeout=120)

    assert not verify_thread.is_alive()
    assert "error" not in first_verify
    first_response = first_verify["response"]
    assert isinstance(first_response, requests.Response)
    assert_http_ok(first_response)
    assert first_response.json()["result"]["phase"] == "verified"

    second_verified = _post_result(
        f"{owner_url}/collections/{second_collection}/private-oram/recovery/verify",
        {"operation_token": second_operation_token},
    )
    assert second_verified["phase"] == "verified"
    assert (
        _post_result(
            f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/abort",
            {"operation_token": operation_token},
        )
        is True
    )

    operation_token = _begin_and_upload_private_oram_snapshot(
        owner_url,
        snapshot_path,
        checkpoint_bundle,
    )
    second_before_rejected_install = {
        str(path.relative_to(second_operation_path)): (
            "directory"
            if path.is_dir()
            else hashlib.sha256(path.read_bytes()).hexdigest()
        )
        for path in second_operation_path.rglob("*")
    }
    install_contention_verify: dict[str, requests.Response | Exception] = {}

    def verify_first_collection_for_install_contention() -> None:
        try:
            install_contention_verify["response"] = requests.post(
                f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/verify",
                json={"operation_token": operation_token},
                timeout=120,
            )
        except Exception as error:
            install_contention_verify["error"] = error

    pause_file.write_text("pause")
    pause_count_before = log_path.read_text().count(pause_marker)
    verify_thread = Thread(
        target=verify_first_collection_for_install_contention,
        daemon=True,
    )
    verify_thread.start()
    try:
        wait_for(
            lambda: log_path.exists()
            and log_path.read_text().count(pause_marker) > pause_count_before,
            wait_for_timeout=30,
        )
        metrics = requests.get(
            f"{owner_url}/metrics",
            params={"anonymize": "false"},
            timeout=30,
        )
        assert_http_ok(metrics)
        assert (
            "private_oram_external_recovery_workers_in_use 1"
            in metrics.text
        )

        rejected_install = requests.post(
            f"{owner_url}/collections/{second_collection}/private-oram/recovery/commit",
            json={"operation_token": second_operation_token},
            timeout=30,
        )
        assert rejected_install.status_code == 429
        second_after_rejected_install = {
            str(path.relative_to(second_operation_path)): (
                "directory"
                if path.is_dir()
                else hashlib.sha256(path.read_bytes()).hexdigest()
            )
            for path in second_operation_path.rglob("*")
        }
        assert second_after_rejected_install == second_before_rejected_install
        for secret in [
            checkpoint_bundle["checkpoint"]["collection_id"],
            checkpoint_bundle["checkpoint"]["snapshot_sha256"],
            second_checkpoint_bundle["checkpoint"]["collection_id"],
            second_checkpoint_bundle["checkpoint"]["snapshot_sha256"],
        ]:
            assert secret not in rejected_install.text
    finally:
        pause_file.unlink(missing_ok=True)
        verify_thread.join(timeout=120)

    assert not verify_thread.is_alive()
    assert "error" not in install_contention_verify
    install_contention_response = install_contention_verify["response"]
    assert isinstance(install_contention_response, requests.Response)
    assert_http_ok(install_contention_response)
    assert install_contention_response.json()["result"]["phase"] == "verified"
    assert (
        _post_result(
            f"{owner_url}/collections/{second_collection}/private-oram/recovery/commit",
            {"operation_token": second_operation_token},
        )
        is True
    )
    assert (
        _post_result(
            f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/abort",
            {"operation_token": operation_token},
        )
        is True
    )
    metrics = requests.get(
        f"{owner_url}/metrics",
        params={"anonymize": "false"},
        timeout=30,
    )
    assert_http_ok(metrics)
    assert "private_oram_external_recovery_workers_in_use 0" in metrics.text
    assert "private_oram_external_recovery_staging_reservations 0" in metrics.text


@pytest.mark.parametrize(
    "crash_point",
    [
        "verified",
        "prepared",
        "old_moved",
        "new_promoted",
        "load_in_progress",
        "loaded",
        "post_consensus",
        "pre_finalize",
        "post_finalize",
        "post_resource_release",
    ],
)
@pytest.mark.parametrize("shard_number", [1, 2], ids=["single-shard", "multi-shard"])
def test_private_oram_external_restore_recovers_every_process_crash_phase(
    tmp_path: pathlib.Path,
    crash_point: str,
    shard_number: int,
):
    crash_env = {
        "QDRANT_STAGING_PRIVATE_ORAM_EXTERNAL_RECOVERY_CRASH": crash_point,
    }
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(
        tmp_path,
        1,
        1,
        shard_number=shard_number,
        extra_env=crash_env,
    )
    owner_url = peer_urls[0]
    _upload_hnsw(owner_url, fixture)
    _upload_result_oram(owner_url, fixture)
    snapshot_path, checkpoint_bundle = _export_private_oram_recovery_snapshot(
        owner_url,
        tmp_path,
        fixture,
    )
    operation_token = _begin_and_upload_private_oram_snapshot(
        owner_url,
        snapshot_path,
        checkpoint_bundle,
    )

    owner_process = processes[-1]
    request_url = (
        f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/verify"
        if crash_point == "verified"
        else f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/commit"
    )
    if crash_point != "verified":
        verified = _post_result(
            f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/verify",
            {"operation_token": operation_token},
        )
        assert verified["phase"] == "verified"

    response = None
    try:
        response = requests.post(
            request_url,
            json={"operation_token": operation_token},
            timeout=60,
        )
    except requests.RequestException:
        pass
    owner_process.proc.wait(timeout=60)
    assert owner_process.proc.returncode not in (None, 0)
    if response is not None:
        assert response.status_code >= 500

    log_path = (
        pathlib.Path(init_pytest_log_folder()) / "private_oram_peer_0.log"
    )
    wait_for(
        lambda: log_path.exists()
        and f"Private ORAM external recovery staging crash reached: {crash_point}"
        in log_path.read_text(),
        wait_for_timeout=30,
    )

    recovery_root = peer_dirs[0] / "storage" / "private_oram_external_recovery"
    state_paths = list(recovery_root.glob("*/*/state.json"))
    finalized = crash_point in {"post_finalize", "post_resource_release"}
    if finalized:
        assert state_paths == []
    else:
        assert len(state_paths) == 1
        assert json.loads(state_paths[0].read_text())["phase"] == "verified"
    marker_paths = list(recovery_root.glob("*/install.json"))
    expected_marker_phase = {
        "verified": None,
        "prepared": "prepared",
        "old_moved": "old_moved",
        "new_promoted": "new_promoted",
        "load_in_progress": "load_in_progress",
        "loaded": "loaded",
        "post_consensus": "loaded",
        "pre_finalize": "consensus_committed",
        "post_finalize": None,
        "post_resource_release": None,
    }[crash_point]
    if expected_marker_phase is None:
        assert marker_paths == []
    else:
        assert len(marker_paths) == 1
        assert json.loads(marker_paths[0].read_text())["phase"] == expected_marker_phase

    owner_port = owner_process.p2p_port
    assert processes.pop() is owner_process
    owner_process.kill()
    restarted_url, _ = start_first_peer(
        peer_dirs[0],
        f"private_oram_external_recovery_crash_{crash_point}_{shard_number}_shard_restart.log",
        port=owner_port,
    )
    restarted_leader = wait_peer_added(restarted_url)
    wait_for_uniform_cluster_status([restarted_url], restarted_leader)

    if crash_point not in {
        "post_consensus",
        "pre_finalize",
        "post_finalize",
        "post_resource_release",
    }:
        assert (
            _post_result(
                f"{restarted_url}/collections/{COLLECTION}/private-oram/recovery/commit",
                {"operation_token": operation_token},
            )
            is True
        )
    wait_collection_exists_and_active_on_all_peers(COLLECTION, [restarted_url])
    _assert_replica_can_open_current_sessions(
        restarted_url,
        BASE_EPOCH,
        fixture["hnsw"]["manifest"]["root_hash"],
        fixture["result"]["manifest"]["root_hash"],
    )

    all_log_text = "\n".join(
        path.read_text()
        for path in pathlib.Path(init_pytest_log_folder()).glob("*.log")
    )
    for secret in [
        checkpoint_bundle["checkpoint"]["collection_id"],
        checkpoint_bundle["checkpoint"]["layout_digest"],
        checkpoint_bundle["checkpoint"]["index_state_digest"],
        fixture["hnsw"]["manifest"]["root_hash"],
        fixture["result"]["manifest"]["root_hash"],
    ]:
        assert secret not in all_log_text


def test_private_oram_external_restore_commit_serializes_with_abort(
    tmp_path: pathlib.Path,
):
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(tmp_path, 1, 1)
    owner_url = peer_urls[0]
    _upload_hnsw(owner_url, fixture)
    _upload_result_oram(owner_url, fixture)
    snapshot_path, checkpoint_bundle = _export_private_oram_recovery_snapshot(
        owner_url,
        tmp_path,
        fixture,
    )
    operation_token = _begin_and_upload_private_oram_snapshot(
        owner_url,
        snapshot_path,
        checkpoint_bundle,
    )
    recovery_root = peer_dirs[0] / "storage" / "private_oram_external_recovery"
    staging_directories_before = sorted(
        path.relative_to(recovery_root)
        for path in recovery_root.glob("*/*")
        if path.is_dir()
    )
    replacement = requests.post(
        f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/begin",
        json=checkpoint_bundle,
        timeout=30,
    )
    assert 400 <= replacement.status_code < 500
    assert sorted(
        path.relative_to(recovery_root)
        for path in recovery_root.glob("*/*")
        if path.is_dir()
    ) == staging_directories_before
    verified = _post_result(
        f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/verify",
        {"operation_token": operation_token},
    )
    assert verified["phase"] == "verified"

    start = Barrier(2)

    def submit(operation: str) -> requests.Response:
        start.wait(timeout=10)
        return requests.post(
            f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/{operation}",
            json={"operation_token": operation_token},
            timeout=60,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(submit, ["commit", "abort"]))

    assert any(response.status_code == 200 for response in responses)
    assert all(response.status_code < 500 for response in responses)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, [owner_url])
    _assert_replica_can_open_current_sessions(
        owner_url,
        BASE_EPOCH,
        fixture["hnsw"]["manifest"]["root_hash"],
        fixture["result"]["manifest"]["root_hash"],
    )


def test_private_oram_external_restore_prepare_cas_failure_republishes_old_collection(
    tmp_path: pathlib.Path,
):
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(
        tmp_path,
        1,
        1,
        extra_env={
            "QDRANT_STAGING_PRIVATE_ORAM_EXTERNAL_RECOVERY_REJECT_PREPARE": "1",
        },
    )
    owner_url = peer_urls[0]
    _upload_hnsw(owner_url, fixture)
    _upload_result_oram(owner_url, fixture)
    snapshot_path, checkpoint_bundle = _export_private_oram_recovery_snapshot(
        owner_url,
        tmp_path,
        fixture,
    )
    operation_token = _begin_and_upload_private_oram_snapshot(
        owner_url,
        snapshot_path,
        checkpoint_bundle,
    )
    verified = _post_result(
        f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/verify",
        {"operation_token": operation_token},
    )
    assert verified["phase"] == "verified"

    rejected = requests.post(
        f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/commit",
        json={"operation_token": operation_token},
        timeout=60,
    )
    assert 400 <= rejected.status_code < 600
    recovery_root = peer_dirs[0] / "storage" / "private_oram_external_recovery"
    assert list(recovery_root.glob("*/install.json")) == []
    wait_collection_exists_and_active_on_all_peers(COLLECTION, [owner_url])

    assert (
        _post_result(
            f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/abort",
            {"operation_token": operation_token},
        )
        is True
    )
    _assert_replica_can_open_current_sessions(
        owner_url,
        BASE_EPOCH,
        fixture["hnsw"]["manifest"]["root_hash"],
        fixture["result"]["manifest"]["root_hash"],
    )


@pytest.mark.parametrize(
    ("replication_factor", "shard_number"),
    [(2, 1), (1, 2)],
    ids=["rf2-single-shard", "rf1-two-shard-split-owners"],
)
def test_private_oram_recovery_export_rejects_unsupported_topology_without_side_effects(
    tmp_path: pathlib.Path,
    replication_factor: int,
    shard_number: int,
):
    peer_urls, peer_dirs, _, _, _ = _start_private_oram_cluster(
        tmp_path,
        2,
        replication_factor,
        shard_number=shard_number,
    )
    peer_ids = [get_cluster_info(peer_url)["peer_id"] for peer_url in peer_urls]
    owners_by_shard: dict[int, set[int]] = {}
    for peer_id, peer_url in zip(peer_ids, peer_urls, strict=True):
        cluster_info = get_collection_cluster_info(peer_url, COLLECTION)
        for shard in cluster_info["local_shards"]:
            owners_by_shard.setdefault(shard["shard_id"], set()).add(peer_id)

    assert len(owners_by_shard) == shard_number
    if replication_factor == 2:
        assert list(owners_by_shard.values()) == [set(peer_ids)]
    else:
        assert all(len(owners) == 1 for owners in owners_by_shard.values())
        assert set.union(*owners_by_shard.values()) == set(peer_ids)

    assert all(_private_oram_layout_state(peer_dir) is None for peer_dir in peer_dirs)
    snapshot_names_before = []
    snapshot_files_before = []
    for peer_url, peer_dir in zip(peer_urls, peer_dirs, strict=True):
        snapshots = requests.get(
            f"{peer_url}/collections/{COLLECTION}/snapshots",
            timeout=30,
        )
        assert_http_ok(snapshots)
        snapshot_names_before.append(
            sorted(snapshot["name"] for snapshot in snapshots.json()["result"])
        )
        snapshot_dir = peer_dir / "snapshots" / COLLECTION
        snapshot_files_before.append(
            sorted(
                str(path.relative_to(snapshot_dir))
                for path in snapshot_dir.rglob("*")
                if path.is_file()
            )
            if snapshot_dir.exists()
            else []
        )

    client_recovery_state_digest = base64.urlsafe_b64encode(
        hashlib.sha256(b"qdrant-sec-test-unsupported-topology-state-v1").digest()
    ).rstrip(b"=").decode()
    rejected = requests.post(
        f"{peer_urls[0]}/collections/{COLLECTION}/private-oram/recovery/export-context",
        json={
            "expected_committed_backup_generation": 0,
            "backup_generation": 1,
            "client_recovery_state_digest": client_recovery_state_digest,
            "owner_signing_key_id": PRIVATE_ORAM_RECOVERY_SIGNING_KEY_ID,
        },
        timeout=30,
    )
    assert 400 <= rejected.status_code < 500

    assert all(_private_oram_layout_state(peer_dir) is None for peer_dir in peer_dirs)
    for index, (peer_url, peer_dir) in enumerate(
        zip(peer_urls, peer_dirs, strict=True)
    ):
        snapshots = requests.get(
            f"{peer_url}/collections/{COLLECTION}/snapshots",
            timeout=30,
        )
        assert_http_ok(snapshots)
        assert sorted(
            snapshot["name"] for snapshot in snapshots.json()["result"]
        ) == snapshot_names_before[index]
        snapshot_dir = peer_dir / "snapshots" / COLLECTION
        snapshot_files_after = (
            sorted(
                str(path.relative_to(snapshot_dir))
                for path in snapshot_dir.rglob("*")
                if path.is_file()
            )
            if snapshot_dir.exists()
            else []
        )
        assert snapshot_files_after == snapshot_files_before[index]


def test_private_oram_recovery_export_rejects_degraded_configured_rf2_without_side_effects(
    tmp_path: pathlib.Path,
):
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(tmp_path, 2, 2)
    coordinator_url, removed_url = peer_urls
    coordinator_info = get_collection_cluster_info(coordinator_url, COLLECTION)
    shard_id = coordinator_info["local_shards"][0]["shard_id"]
    removed_peer_id = get_cluster_info(removed_url)["peer_id"]
    _upload_hnsw(coordinator_url, fixture)
    _upload_result_oram(coordinator_url, fixture)

    removed = requests.post(
        f"{coordinator_url}/collections/{COLLECTION}/cluster",
        json={
            "drop_replica": {
                "shard_id": shard_id,
                "peer_id": removed_peer_id,
            }
        },
        timeout=60,
    )
    assert_http_ok(removed)
    wait_for_collection_local_shards_count(removed_url, COLLECTION, 0)
    wait_for_collection_shard_transfers_count(coordinator_url, COLLECTION, 0)
    collection = requests.get(
        f"{coordinator_url}/collections/{COLLECTION}",
        timeout=30,
    )
    assert_http_ok(collection)
    assert collection.json()["result"]["config"]["params"]["replication_factor"] == 2

    layouts_before = [
        _private_oram_layout_state(peer_dir) for peer_dir in peer_dirs
    ]
    snapshot_names_before = []
    recovery_files_before = []
    for peer_url, peer_dir in zip(peer_urls, peer_dirs, strict=True):
        snapshots = requests.get(
            f"{peer_url}/collections/{COLLECTION}/snapshots",
            timeout=30,
        )
        assert_http_ok(snapshots)
        snapshot_names_before.append(
            sorted(snapshot["name"] for snapshot in snapshots.json()["result"])
        )
        recovery_root = peer_dir / "storage" / "private_oram_external_recovery"
        recovery_files_before.append(
            sorted(
                str(path.relative_to(recovery_root))
                for path in recovery_root.rglob("*")
                if path.is_file()
            )
            if recovery_root.exists()
            else []
        )

    client_recovery_state_digest = base64.urlsafe_b64encode(
        hashlib.sha256(b"qdrant-sec-test-degraded-rf2-state-v1").digest()
    ).rstrip(b"=").decode()
    rejected = requests.post(
        f"{coordinator_url}/collections/{COLLECTION}/private-oram/recovery/export-context",
        json={
            "expected_committed_backup_generation": 0,
            "backup_generation": 1,
            "client_recovery_state_digest": client_recovery_state_digest,
            "owner_signing_key_id": PRIVATE_ORAM_RECOVERY_SIGNING_KEY_ID,
        },
        timeout=30,
    )
    assert 400 <= rejected.status_code < 500

    assert [
        _private_oram_layout_state(peer_dir) for peer_dir in peer_dirs
    ] == layouts_before
    for index, (peer_url, peer_dir) in enumerate(
        zip(peer_urls, peer_dirs, strict=True)
    ):
        snapshots = requests.get(
            f"{peer_url}/collections/{COLLECTION}/snapshots",
            timeout=30,
        )
        assert_http_ok(snapshots)
        assert sorted(
            snapshot["name"] for snapshot in snapshots.json()["result"]
        ) == snapshot_names_before[index]
        recovery_root = peer_dir / "storage" / "private_oram_external_recovery"
        recovery_files_after = (
            sorted(
                str(path.relative_to(recovery_root))
                for path in recovery_root.rglob("*")
                if path.is_file()
            )
            if recovery_root.exists()
            else []
        )
        assert recovery_files_after == recovery_files_before[index]


def test_private_oram_recovery_export_rejects_collection_alias_without_side_effects(
    tmp_path: pathlib.Path,
):
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(tmp_path, 1, 1)
    owner_url = peer_urls[0]
    _upload_hnsw(owner_url, fixture)
    _upload_result_oram(owner_url, fixture)
    alias = f"{COLLECTION}-recovery-alias"
    created = requests.post(
        f"{owner_url}/collections/aliases",
        json={
            "actions": [
                {
                    "create_alias": {
                        "collection_name": COLLECTION,
                        "alias_name": alias,
                    }
                }
            ]
        },
        timeout=30,
    )
    assert_http_ok(created)

    layout_before = _private_oram_layout_state(peer_dirs[0])
    snapshots_before = requests.get(
        f"{owner_url}/collections/{COLLECTION}/snapshots",
        timeout=30,
    )
    assert_http_ok(snapshots_before)
    snapshot_names_before = sorted(
        snapshot["name"] for snapshot in snapshots_before.json()["result"]
    )
    recovery_root = peer_dirs[0] / "storage" / "private_oram_external_recovery"
    recovery_files_before = (
        sorted(
            str(path.relative_to(recovery_root))
            for path in recovery_root.rglob("*")
            if path.is_file()
        )
        if recovery_root.exists()
        else []
    )

    client_recovery_state_digest = base64.urlsafe_b64encode(
        hashlib.sha256(b"qdrant-sec-test-recovery-alias-state-v1").digest()
    ).rstrip(b"=").decode()
    rejected = requests.post(
        f"{owner_url}/collections/{alias}/private-oram/recovery/export-context",
        json={
            "expected_committed_backup_generation": 0,
            "backup_generation": 1,
            "client_recovery_state_digest": client_recovery_state_digest,
            "owner_signing_key_id": PRIVATE_ORAM_RECOVERY_SIGNING_KEY_ID,
        },
        timeout=30,
    )
    assert 400 <= rejected.status_code < 500

    assert _private_oram_layout_state(peer_dirs[0]) == layout_before
    snapshots_after = requests.get(
        f"{owner_url}/collections/{COLLECTION}/snapshots",
        timeout=30,
    )
    assert_http_ok(snapshots_after)
    assert sorted(
        snapshot["name"] for snapshot in snapshots_after.json()["result"]
    ) == snapshot_names_before
    recovery_files_after = (
        sorted(
            str(path.relative_to(recovery_root))
            for path in recovery_root.rglob("*")
            if path.is_file()
        )
        if recovery_root.exists()
        else []
    )
    assert recovery_files_after == recovery_files_before


def test_private_oram_external_recovery_export_rejects_untrusted_contexts(
    tmp_path: pathlib.Path,
):
    peer_urls, _, fixture, _, _ = _start_private_oram_cluster(tmp_path, 1, 1)
    owner_url = peer_urls[0]
    _upload_hnsw(owner_url, fixture)
    _upload_result_oram(owner_url, fixture)

    client_recovery_state_digest = base64.urlsafe_b64encode(
        hashlib.sha256(b"qdrant-sec-test-adversarial-recovery-state-v1").digest()
    ).rstrip(b"=").decode()
    export_url = (
        f"{owner_url}/collections/{COLLECTION}/private-oram/recovery/export-context"
    )
    valid_request = {
        "expected_committed_backup_generation": 0,
        "backup_generation": 1,
        "client_recovery_state_digest": client_recovery_state_digest,
        "owner_signing_key_id": PRIVATE_ORAM_RECOVERY_SIGNING_KEY_ID,
    }
    export = _post_result(export_url, valid_request)
    intent = _private_oram_recovery_signing_intent(
        owner_url,
        export,
        fixture,
        client_recovery_state_digest,
    )

    signer_tampering = []
    tampered = json.loads(json.dumps(export))
    tampered["index_states"][0]["state"]["root_hash"] = "A" * 43
    signer_tampering.append(tampered)
    tampered = json.loads(json.dumps(export))
    tampered["index_states"].pop()
    signer_tampering.append(tampered)
    tampered = json.loads(json.dumps(export))
    tampered["index_states"][1] = tampered["index_states"][0]
    signer_tampering.append(tampered)
    tampered = json.loads(json.dumps(export))
    tampered["checkpoint"]["collection_id"] = "untrusted-collection-binding"
    signer_tampering.append(tampered)
    tampered = json.loads(json.dumps(export))
    tampered["checkpoint"]["index_state_digest"] = "B" * 43
    signer_tampering.append(tampered)
    tampered = json.loads(json.dumps(export))
    tampered["checkpoint"]["owner_snapshot_authority_digest"] = "D" * 43
    signer_tampering.append(tampered)
    tampered = json.loads(json.dumps(export))
    tampered["checkpoint"]["backup_generation"] = 999
    signer_tampering.append(tampered)
    tampered = json.loads(json.dumps(export))
    tampered["checkpoint"]["client_recovery_state_digest"] = "C" * 43
    signer_tampering.append(tampered)
    tampered = json.loads(json.dumps(export))
    tampered["checkpoint"]["source_peer_id"] += 1
    tampered["checkpoint"]["owner_peer_ids"] = [
        tampered["checkpoint"]["source_peer_id"]
    ]
    signer_tampering.append(tampered)
    for tampered_export in signer_tampering:
        assert (
            _sign_private_oram_recovery_checkpoint(
                tampered_export,
                fixture,
                intent,
                expect_success=False,
            )
            is None
        )

    rejected_requests = [
        {
            **valid_request,
            "expected_committed_backup_generation": 7,
            "backup_generation": 8,
        },
        {**valid_request, "backup_generation": 0},
        {**valid_request, "client_recovery_state_digest": "malformed-digest-sentinel"},
        {
            **valid_request,
            "owner_signing_key_id": "tenant-a/unknown-recovery-key-sentinel",
        },
    ]
    for rejected_request in rejected_requests:
        response = requests.post(export_url, json=rejected_request, timeout=30)
        assert 400 <= response.status_code < 500
        for secret in [
            rejected_request["client_recovery_state_digest"],
            rejected_request["owner_signing_key_id"],
            fixture["hnsw"]["manifest"]["root_hash"],
            fixture["result"]["manifest"]["root_hash"],
        ]:
            assert secret not in response.text

    active_session = _open_hnsw_owner_session(owner_url, BASE_EPOCH)
    blocked = requests.post(
        export_url,
        json={**valid_request, "backup_generation": 2},
        timeout=30,
    )
    assert 400 <= blocked.status_code < 600
    for secret in [
        active_session["session_id"],
        active_session["root_hash"],
        client_recovery_state_digest,
    ]:
        assert secret not in blocked.text
    assert (
        _post_result(
            f"{owner_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session/{active_session['session_id']}/close",
            {},
        )
        is True
    )


def test_private_oram_storage_wal_snapshot_logs_and_metrics_do_not_leak_sentinels(
    tmp_path: pathlib.Path,
):
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(
        tmp_path,
        1,
        1,
        capture_stderr=True,
    )
    owner_url = peer_urls[0]
    owner_dir = peer_dirs[0]
    _upload_hnsw(owner_url, fixture)
    _upload_result_oram(owner_url, fixture)
    recovery_snapshot_path, recovery_bundle = _export_private_oram_recovery_snapshot(
        owner_url,
        tmp_path,
        fixture,
    )
    assert recovery_bundle["checkpoint"]["client_recovery_state_digest"] != fixture[
        "result"
    ]["client_recovery_state_base64url"]
    _exercise_hnsw_owner_session(owner_url, fixture)
    _exercise_result_owner_session(owner_url, fixture)

    unrefreshed_snapshot = requests.post(
        f"{owner_url}/collections/{COLLECTION}/snapshots?wait=true",
        timeout=60,
    )
    assert unrefreshed_snapshot.status_code == 400
    assert "current epoch/root does not match manifest" in unrefreshed_snapshot.text
    assert fixture["hnsw"]["commit"]["new_root_hash"] not in unrefreshed_snapshot.text
    assert fixture["result"]["commit"]["new_root_hash"] not in unrefreshed_snapshot.text

    _refresh_private_oram_manifests(owner_url, fixture)

    snapshot_response = requests.post(
        f"{owner_url}/collections/{COLLECTION}/snapshots?wait=true",
        timeout=60,
    )
    assert_http_ok(snapshot_response)
    snapshot_name = snapshot_response.json()["result"]["name"]
    snapshot_path = owner_dir / "snapshots" / COLLECTION / snapshot_name
    assert snapshot_path.is_file()

    extracted_snapshot = tmp_path / "expanded-snapshot"
    extracted_snapshot.mkdir()
    subprocess.run(
        [
            "tar",
            "--extract",
            "--sparse",
            "--file",
            str(snapshot_path),
            "--directory",
            str(extracted_snapshot),
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )
    snapshot_files = [path for path in extracted_snapshot.rglob("*") if path.is_file()]
    assert any("private_hnsw_oram" in path.parts for path in snapshot_files)
    assert any("private_result_oram" in path.parts for path in snapshot_files)

    metrics = requests.get(
        f"{owner_url}/metrics",
        params={"anonymize": "false"},
        timeout=30,
    )
    assert_http_ok(metrics)
    telemetry = requests.get(
        f"{owner_url}/telemetry",
        params={"anonymize": "false", "details_level": 2},
        timeout=30,
    )
    assert_http_ok(telemetry)
    _assert_private_oram_plaintext_sentinels_absent_from_bytes(
        {
            "operator-metrics": metrics.content,
            "operator-telemetry": telemetry.content,
            "snapshot-rejection-response": unrefreshed_snapshot.content,
        },
        fixture,
    )

    owner_process = processes.pop()
    owner_process.interrupt()
    assert owner_process.proc.returncode is not None
    storage_path = owner_dir / "storage"
    shard_wal_path = storage_path / "collections" / COLLECTION / "0" / "wal"
    metadata_wal_path = storage_path / "collections_meta_wal"
    raft_state_files = [
        path
        for path in storage_path.iterdir()
        if path.name == "raft_state.json" or path.name.startswith(".raft-state-")
    ]
    assert any(path.is_file() for path in shard_wal_path.iterdir())
    assert any(path.is_file() for path in metadata_wal_path.iterdir())
    assert any(path.is_file() for path in raft_state_files)
    log_path = pathlib.Path(init_pytest_log_folder())
    _assert_private_oram_plaintext_sentinels_absent(
        {
            "live-storage": storage_path,
            "shard-wal": shard_wal_path,
            "collection-metadata-wal": metadata_wal_path,
            **{
                f"raft-state-{index}": path
                for index, path in enumerate(raft_state_files)
            },
            "snapshot-archive": snapshot_path,
            "recovery-snapshot-archive": recovery_snapshot_path,
            "expanded-snapshot": extracted_snapshot,
            "combined-process-stdout-stderr": log_path,
        },
        fixture,
    )


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


def _private_oram_consensus_protocol_projection(
    peer_dir: pathlib.Path,
) -> dict | None:
    try:
        with open(peer_dir / "storage" / "raft_state.json") as state_file:
            state = json.load(state_file)
    except (OSError, json.JSONDecodeError):
        return None
    return {
        field: state.get(field, {})
        for field in (
            "private_oram_epochs",
            "private_oram_layouts",
            "private_oram_mutation_states",
            "private_oram_mutation_lease_slots",
        )
    }


def _wait_for_private_oram_consensus_protocol_projection(
    peer_dirs: list[pathlib.Path],
) -> dict:
    observed: dict[str, dict] = {}

    def projection_is_uniform() -> bool:
        projections = [
            _private_oram_consensus_protocol_projection(peer_dir)
            for peer_dir in peer_dirs
        ]
        if projections[0] is None or any(
            projection != projections[0] for projection in projections[1:]
        ):
            return False
        observed["projection"] = projections[0]
        return True

    wait_for(projection_is_uniform, wait_for_timeout=30)
    return observed["projection"]


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
    peer_urls, peer_dirs, fixture, _, _ = _start_private_oram_cluster(
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
    # Restarting the source can elect either peer, so follow the current leader.
    wait_for(
        lambda: (
            current_leader := get_cluster_info(source_url)["raft_info"]["leader"]
        )
        in (source_peer_id, target_peer_id)
        and all_nodes_cluster_info_consistent(peer_urls, current_leader)
    )

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
    # Restoration publishes these directories asynchronously. The strict locator below
    # asserts that a directory exists, so it cannot serve as the readiness predicate.
    wait_for(
        lambda: all(
            len([
                path
                for path in peer_dirs[target_index].rglob(pattern)
                if path.is_dir()
            ]) == 1
            for pattern in (
                f"private_hnsw_oram/{VECTOR}/buckets",
                "private_result_oram/buckets",
            )
        ),
        wait_for_timeout=30,
    )
    assert _private_oram_buckets_dir(peer_dirs[target_index], "hnsw").is_dir()
    assert _private_oram_buckets_dir(peer_dirs[target_index], "result").is_dir()
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
