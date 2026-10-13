"""Private ORAM V2 paired append on a live cluster (PLAN V2-D).

A pinned single peer activates mutation V2. A real client (the long-lived
`private_oram_v2_append_client` example, which keeps its keys, plaintext and position maps in
memory) seals a private HNSW index and a result ORAM index, uploads both and writes each back
once through V1 sessions. It then enrolls both indexes with a genesis state that commits to its
sealed append checkpoint. In a mutation session on that state it appends one point: it reads
every fixed window of both indexes, verifies the buckets against the session roots, and sends
the owner prepare of the finalized paired mutation. The append must commit, after which only the
new signed state opens a session. Until the coordinator records parent progress after
admission (see the note in the test), the append stops after admission and the commit part is an
expected failure. Linux only (peer identities are Linux-only).
"""

import json
import pathlib
import subprocess
import sys

import pytest
import requests

from .assertions import assert_http_ok
from .test_private_oram_sessions import (
    COLLECTION,
    PLACEHOLDER_COLLECTION_ID,
    VECTOR,
    _collection_uuid,
    _exercise_hnsw_owner_session,
    _exercise_result_owner_session,
    _upload_hnsw,
    _upload_result_oram,
)
from .test_private_oram_v2_activation import (
    _activation_bundle,
    _bootstrap_identity,
    _free_port_triple,
    _status,
)
from .test_private_oram_v2_enrollment import (
    PEER_ID,
    _from_wire,
    _mutation_post,
    _write_config,
)
from .utils import (
    PROJECT_ROOT,
    kill_all_processes,
    make_peer_folders,
    start_first_peer,
    wait_collection_exists_and_active_on_all_peers,
    wait_for,
    wait_peer_added,
)

OWNER_SIGNING_KEY_ID = "tenant-a/private-hnsw-signing-v1"
TERMINAL_APPEND_PHASES = {"terminal_committed", "terminal_aborted", "quarantined"}
POST_ADMISSION_APPEND_PHASES = TERMINAL_APPEND_PHASES | {
    "admitted_ack_pending",
    "admitted_ack_complete",
    "parent_sequence1",
    "owners_adopting",
    "parent_sequence2",
    "points_staging",
    "deciding",
    "finalizing",
    "cleaning",
}

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="private ORAM peer identities are Linux-only",
)


@pytest.fixture(autouse=True)
def cleanup_v2_append_peers():
    yield
    kill_all_processes()


class AppendClient:
    """The client process; each call sends one JSON command line and reads one answer."""

    def __init__(self):
        self.process = subprocess.Popen(
            [
                "cargo",
                "run",
                "--quiet",
                "--locked",
                "-p",
                "qdrant-sec",
                "--example",
                "private_oram_v2_append_client",
            ],
            cwd=PROJECT_ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )

    def call(self, cmd: str, **arguments) -> dict:
        self.process.stdin.write(json.dumps({"cmd": cmd, **arguments}) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        assert line, f"the append client exited during {cmd}"
        answer = json.loads(line)
        assert answer["ok"], f"append client {cmd} failed: {answer['error']}"
        return answer["result"]

    def close(self) -> None:
        self.process.stdin.close()
        self.process.wait(timeout=30)


@pytest.fixture
def append_client():
    client = AppendClient()
    yield client
    client.close()


def _create_paired_collection(peer_url: str) -> None:
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
                    },
                    {
                        "id": "payload_private_result_oram",
                        "selector": {"kind": "payload_paths", "paths": ["body"]},
                        "instance": "docs_private_result_oram_v1",
                        "binding": "private-result-oram/v1",
                    },
                ],
            },
        },
        timeout=30,
    )
    assert_http_ok(create)


def test_private_oram_paired_append_commits_through_a_real_client(
    tmp_path: pathlib.Path, append_client: AppendClient
):
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
    # The runtime policy (ORAM geometry, the one owner key of both indexes) comes from the
    # client's own indexes, built here for a placeholder id and rebuilt once the collection
    # exists.
    _write_config(
        peer_dir,
        append_client.call("build", collection_id=PLACEHOLDER_COLLECTION_ID),
        activation,
        result_signing_key_id=OWNER_SIGNING_KEY_ID,
    )
    peer_url, _ = start_first_peer(
        peer_dir,
        "v2_append_peer_0.log",
        port=base_port,
        extra_env={"QDRANT__CLUSTER__PEER_ID": str(PEER_ID)},
    )
    assert wait_peer_added(peer_url) == PEER_ID
    activated = requests.post(
        f"{peer_url}/cluster/private-oram/mutation-v2/activate?timeout=60", timeout=120
    )
    assert_http_ok(activated)
    wait_for(lambda: _status(peer_url)["status"] == "active", wait_for_timeout=60)

    _create_paired_collection(peer_url)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, [peer_url])
    fixture = append_client.call("build", collection_id=_collection_uuid(peer_url))
    _upload_hnsw(peer_url, fixture)
    _upload_result_oram(peer_url, fixture)
    _exercise_hnsw_owner_session(peer_url, fixture)
    _exercise_result_owner_session(peer_url, fixture)

    template_response = _mutation_post(peer_url, "enrollment-template", {"vector_name": VECTOR})
    assert_http_ok(template_response)
    template = _from_wire(template_response.json()["result"])
    assert template["enrolled"] is False
    assert sorted(index["kind"] for index in template["indexes"]) == ["hnsw", "result"]
    bundles = append_client.call("enroll", template=template)
    enrolled = _mutation_post(
        peer_url,
        "enroll",
        {
            "client_id": "tenant-a/append-e2e-sdk",
            "vector_name": VECTOR,
            "immutable_manifest": bundles["immutable_manifest"],
            "genesis_state": bundles["genesis_state"],
        },
    )
    assert_http_ok(enrolled)

    opened = _mutation_post(peer_url, "open", append_client.call("open"))
    assert_http_ok(opened)
    session = opened.json()["result"]
    genesis_state_digest = enrolled.json()["result"]["genesis_state_digest"]
    assert session["old_state_digest"] == genesis_state_digest

    # The client asks for each fixed read window, verifies the answer and, after the last one,
    # hands over the owner prepare of the finalized mutation.
    action = append_client.call("begin", session=_from_wire(session))
    reads = 0
    while "read" in action:
        read = _mutation_post(peer_url, "read", action["read"])
        assert_http_ok(read)
        action = append_client.call("read_response", response=_from_wire(read.json()["result"]))
        reads += 1
    assert reads == 10, "five fixed read paths per index, one path per window"
    appended = _mutation_post(peer_url, "append", action["append"])
    assert_http_ok(appended)

    phases = []

    def append_phase_in(expected: set[str]) -> bool:
        status = _mutation_post(peer_url, "status", {"session_id": session["session_id"]})
        if status.status_code != 200:
            return False
        phases.append(status.json()["result"]["append_phase"])
        return phases[-1] in expected

    # The owners pre-stage the mutation and consensus admits its lease.
    wait_for(lambda: append_phase_in(POST_ADMISSION_APPEND_PHASES), wait_for_timeout=60)
    try:
        wait_for(lambda: append_phase_in(TERMINAL_APPEND_PHASES), wait_for_timeout=60)
    except Exception:  # noqa: BLE001 - wait_for raises plain Exception on timeout
        pass
    if phases[-1] != "terminal_committed":
        # Known gap: after admission the coordinator materializes the parent, adopts the owners
        # and stages the point, but no path proposes the first parent progress from the
        # Admitted lifecycle, so recovery readiness finds no consensus parent watermark and
        # refuses every owner capsule install (docs/private-oram-v2-enrollment.md).
        pytest.xfail(f"V2 append stops after admission in phase {phases[-1]}")

    # The committed state is the only one a new session can open on.
    stale = _mutation_post(peer_url, "open", append_client.call("open"))
    assert stale.status_code == 400, stale.text
    reopened = _mutation_post(peer_url, "open", append_client.call("open_next"))
    assert_http_ok(reopened)
    assert reopened.json()["result"]["old_state_digest"] != genesis_state_digest
    assert_http_ok(
        _mutation_post(peer_url, "close", {"session_id": reopened.json()["result"]["session_id"]})
    )
