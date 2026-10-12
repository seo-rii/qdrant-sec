"""Private ORAM mutation V2 collection enrollment on a live cluster (docs/private-oram-v2-enrollment.md).

A pinned single-peer cluster activates mutation V2, stores a private HNSW index and performs one
V1 write-back. The client then reads the enrollment template, signs an immutable manifest and a
genesis state with its owner key, and enrolls the collection: the server proposes the genesis
state and enrolls the collection's owner, after which a mutation session opens on the enrolled
state. Re-enrolling the same genesis state succeeds; a different one is refused. Linux only (peer
identities are Linux-only).

The peer is both the Raft leader and the collection's only owner, so the owner enrollment runs
locally. Remote owners are reached over the TLS-only internal owner RPCs, which these
plain-HTTP test clusters do not configure.
"""

import base64
import json
import os
import pathlib
import subprocess
import sys

import pytest
import requests

from .assertions import assert_http_ok
from .test_private_oram_sessions import (
    COLLECTION,
    IDS_VISIBLE_RESULT_PRIVACY,
    PLACEHOLDER_COLLECTION_ID,
    VECTOR,
    _collection_uuid,
    _exercise_hnsw_owner_session,
    _open_hnsw_owner_session,
    _post_result,
    _private_oram_fixture,
    _upload_hnsw,
    _write_private_oram_runtime_config,
)
from .test_private_oram_v2_activation import (
    _activation_bundle,
    _bootstrap_identity,
    _free_port_triple,
    _status,
)
from .utils import (
    PROJECT_ROOT,
    get_cluster_info,
    kill_all_processes,
    make_peer_folders,
    start_first_peer,
    wait_collection_exists_and_active_on_all_peers,
    wait_for,
    wait_peer_added,
)

PEER_ID = 101
MUTATION_ROUTE = f"/collections/{COLLECTION}/private-oram/v2/mutation"
# Mirrors the canonical u64 field names of the private ORAM V2 wire (decimal strings).
U64_FIELDS = {
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
    "reserved_physical_slots",
    "rk_epoch",
    "signed_at_unix",
    "state_sequence",
    "writer_fence",
}

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="private ORAM peer identities are Linux-only",
)


@pytest.fixture(autouse=True)
def cleanup_v2_enrollment_peers():
    yield
    kill_all_processes()


def _to_wire(value):
    if isinstance(value, dict):
        return {
            key: str(item)
            if key in U64_FIELDS and isinstance(item, int) and not isinstance(item, bool)
            else _to_wire(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_to_wire(item) for item in value]
    return value


def _from_wire(value):
    if isinstance(value, dict):
        return {
            key: int(item) if key in U64_FIELDS and isinstance(item, str) else _from_wire(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_from_wire(item) for item in value]
    return value


def _mutation_post(peer_url: str, path: str, body: dict) -> requests.Response:
    return requests.post(f"{peer_url}{MUTATION_ROUTE}/{path}", json=_to_wire(body), timeout=180)


def _enrollment_bundles(fixture: dict, template: dict) -> dict:
    completed = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "qdrant-sec",
            "--example",
            "private_oram_v2_enrollment_fixture",
        ],
        cwd=PROJECT_ROOT,
        input=json.dumps({"manifest": fixture["hnsw"]["manifest"], "template": template}),
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _write_config(peer_dir: pathlib.Path, runtime_fixture: dict, activation: dict) -> None:
    _write_private_oram_runtime_config(peer_dir, runtime_fixture)
    bundle_path = peer_dir / "private_oram_v2_authority_bundle.json"
    bundle_path.write_bytes(activation["bundle_canonical_json"].encode())
    settings = {
        "authority": activation["authority"],
        "cluster_identity_digest": activation["cluster_identity_digest"],
        "cluster_first_voter_peer_id": PEER_ID,
        "authority_bundle_path": str(bundle_path),
    }
    # JSON is valid YAML, so the nested settings are written as a flow mapping.
    with (peer_dir / "config" / "local.yaml").open("a") as config:
        config.write(
            "cluster:\n"
            "  consensus:\n"
            f"    private_oram_mutation_v2_activation: {json.dumps(settings)}\n"
        )


def test_private_oram_collection_enrolls_after_v2_activation(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
):
    # A V2 manifest needs free physical slots: the uploaded index declares 4 of its 14 slots
    # free instead of counting every empty slot as a dummy.
    monkeypatch.setenv("QDRANT_PRIVATE_ORAM_FIXTURE_RESERVED_SLOTS", "4")
    (peer_dir,) = make_peer_folders(tmp_path, 1)
    base_port = _free_port_triple()
    identity = _bootstrap_identity(peer_dir, PEER_ID, base_port)
    activation = _activation_bundle(
        [
            {
                "peer_id": PEER_ID,
                "host": "127.0.0.1",
                "p2p_port": base_port,
                "public_key": identity["public_key"],
            }
        ],
        identity["binary_capability_digest"],
    )
    runtime_fixture = _private_oram_fixture(
        PLACEHOLDER_COLLECTION_ID, None, IDS_VISIBLE_RESULT_PRIVACY
    )
    _write_config(peer_dir, runtime_fixture, activation)

    peer_url, _ = start_first_peer(
        peer_dir,
        "v2_enrollment_peer_0.log",
        port=base_port,
        extra_env={"QDRANT__CLUSTER__PEER_ID": str(PEER_ID)},
    )
    assert wait_peer_added(peer_url) == PEER_ID
    activated = requests.post(
        f"{peer_url}/cluster/private-oram/mutation-v2/activate?timeout=60", timeout=120
    )
    assert_http_ok(activated)
    wait_for(lambda: _status(peer_url)["status"] == "active", wait_for_timeout=60)

    create = requests.put(
        f"{peer_url}/collections/{COLLECTION}",
        json={
            "vectors": {VECTOR: {"size": 2, "distance": "Euclid"}},
            "shard_number": 1,
            "replication_factor": 1,
            "write_consistency_factor": 1,
            "encryption": {
                "version": 1,
                "key_id": "tenant-a/vector-private-rk",
                "crypto_schema_version": 1,
                "encryption_epoch": 7,
                "migration_state": "active",
                "rules": [
                    {
                        "id": "text_private_hnsw",
                        "selector": {"kind": "vector_names", "names": [VECTOR]},
                        "instance": "docs_private_hnsw_v1",
                        "binding": "private-hnsw-oram/v1",
                    }
                ],
            },
        },
        timeout=30,
    )
    assert_http_ok(create)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, [peer_url])
    fixture = _private_oram_fixture(
        _collection_uuid(peer_url), None, IDS_VISIBLE_RESULT_PRIVACY
    )
    _upload_hnsw(peer_url, fixture)

    def ready_for_session() -> bool:
        try:
            session = _open_hnsw_owner_session(peer_url, 42, IDS_VISIBLE_RESULT_PRIVACY)
        except Exception:  # noqa: BLE001 - HTTP helpers raise plain Exception
            return False
        _post_result(
            f"{peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session/"
            f"{session['session_id']}/close",
            {},
        )
        return True

    wait_for(ready_for_session, wait_for_timeout=60)

    # Before any V1 write-back the index has no write-back digest and cannot enroll yet.
    template_response = _mutation_post(peer_url, "enrollment-template", {"vector_name": VECTOR})
    assert_http_ok(template_response)
    template = _from_wire(template_response.json()["result"])
    assert template["enrolled"] is False
    assert template["indexes"][0]["writeback_digest"] is None

    _exercise_hnsw_owner_session(peer_url, fixture)
    template_response = _mutation_post(peer_url, "enrollment-template", {"vector_name": VECTOR})
    assert_http_ok(template_response)
    template = _from_wire(template_response.json()["result"])
    assert template["collection_id"] == fixture["hnsw"]["manifest"]["collection_id"]
    assert template["indexes"][0]["root_hash"] == fixture["hnsw"]["commit"]["new_root_hash"]
    assert template["indexes"][0]["writeback_digest"] is not None

    bundles = _enrollment_bundles(fixture, template)
    enroll_body = {
        "client_id": "tenant-a/multi-peer-hnsw-sdk",
        "vector_name": VECTOR,
        "immutable_manifest": bundles["immutable_manifest"],
        "genesis_state": bundles["genesis_state"],
    }
    enrolled = _mutation_post(peer_url, "enroll", enroll_body)
    assert_http_ok(enrolled)
    assert enrolled.json()["result"]["genesis_state_digest"]

    template_response = _mutation_post(peer_url, "enrollment-template", {"vector_name": VECTOR})
    assert_http_ok(template_response)
    assert template_response.json()["result"]["enrolled"] is True

    # Re-enrolling the same genesis state succeeds and resumes nothing; a different one fails.
    assert_http_ok(_mutation_post(peer_url, "enroll", enroll_body))
    tampered = json.loads(json.dumps(enroll_body))
    tampered["genesis_state"]["state"]["client_state_digest"] = "A" * 43
    refused = _mutation_post(peer_url, "enroll", tampered)
    assert refused.status_code == 400, refused.text

    # The enrolled genesis state is what a mutation session opens on.
    opened = _mutation_post(
        peer_url,
        "open",
        {
            "client_id": "tenant-a/multi-peer-hnsw-sdk",
            "vector_name": VECTOR,
            "mutation_id": base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode(),
            "immutable_manifest": bundles["immutable_manifest"],
            "old_state": bundles["genesis_state"],
        },
    )
    assert_http_ok(opened)
    session = opened.json()["result"]
    assert session["old_state_digest"] == enrolled.json()["result"]["genesis_state_digest"]
    closed = _mutation_post(peer_url, "close", {"session_id": session["session_id"]})
    assert_http_ok(closed)
    assert get_cluster_info(peer_url)["peer_id"] == PEER_ID
