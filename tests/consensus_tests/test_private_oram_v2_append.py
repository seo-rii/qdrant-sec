"""Private ORAM V2 paired append on a live cluster (PLAN V2-D).

A pinned single peer activates mutation V2. A real client (the long-lived
`private_oram_v2_append_client` example, which keeps its keys, plaintext and position maps in
memory) seals a private HNSW index and a result ORAM index, uploads both and writes each back
once through V1 sessions. It then enrolls both indexes with a genesis state that commits to its
sealed append checkpoint. In a mutation session on that state it appends one point: it reads
every fixed window of both indexes, verifies the buckets against the session roots, and sends
the owner prepare of the finalized paired mutation. The append must commit, after which only the
new signed state opens a session, and no plaintext of the appended point or the client keys may
appear in the peer's files or log.

A second test runs the same append on three peers with internal TLS and a replica each, so the
coordinator pre-stages, adopts and terminates the mutation on two remote owners through the
TLS-only owner RPCs. Linux only (peer identities are Linux-only).
"""

import json
import pathlib
import subprocess
import sys
import time

import pytest
import requests

from .assertions import assert_http_ok
from .test_private_oram_sessions import (
    BASE_EPOCH,
    COLLECTION,
    PLACEHOLDER_COLLECTION_ID,
    VECTOR,
    _collection_uuid,
    _exercise_hnsw_owner_session,
    _exercise_result_owner_session,
    _open_hnsw_owner_session,
    _open_result_owner_session,
    _post_result,
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
    TLS_PEER_IDS,
    _from_wire,
    _generate_tls_certs,
    _mutation_post,
    _write_config,
)
from .test_private_oram_leak_scan import _files_under
from .utils import (
    PROJECT_ROOT,
    get_cluster_info,
    get_leader,
    init_pytest_log_folder,
    kill_all_processes,
    make_peer_folders,
    start_first_peer,
    start_peer,
    wait_collection_exists_and_active_on_all_peers,
    wait_for,
    wait_for_uniform_cluster_status,
    wait_peer_added,
)

OWNER_SIGNING_KEY_ID = "tenant-a/private-hnsw-signing-v1"
POST_ADMISSION_APPEND_PHASES = {
    "terminal_committed",
    "terminal_aborted",
    "quarantined",
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


def _create_paired_collection(peer_url: str, replication_factor: int = 1) -> None:
    create = requests.put(
        f"{peer_url}/collections/{COLLECTION}",
        json={
            "vectors": {VECTOR: {"size": 2, "distance": "Euclid"}},
            "shard_number": 1,
            "replication_factor": replication_factor,
            "write_consistency_factor": replication_factor,
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


def _v1_sessions_open(peer_url: str, fixture: dict) -> bool:
    """Whether the peer serves V1 owner sessions on both uploaded indexes."""
    collection_url = f"{peer_url}/collections/{COLLECTION}"
    try:
        hnsw = _open_hnsw_owner_session(
            peer_url, BASE_EPOCH, fixture["hnsw"]["manifest"]["result_privacy"]
        )
        _post_result(
            f"{collection_url}/private-hnsw/{VECTOR}/session/{hnsw['session_id']}/close", {}
        )
        result = _open_result_owner_session(peer_url, BASE_EPOCH)
        _post_result(
            f"{collection_url}/private-result-oram/session/{result['session_id']}/close", {}
        )
    except Exception:  # noqa: BLE001 - HTTP helpers raise plain Exception
        return False
    return True


def _enroll(peer_url: str, append_client: AppendClient) -> str:
    """Enrolls both indexes with the client's genesis state; returns its digest."""
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
    return enrolled.json()["result"]["genesis_state_digest"]


def _append_one_point(peer_url: str, append_client: AppendClient, old_state_digest: str) -> dict:
    """Opens a mutation session on the client's state, appends one point and waits until the
    append is admitted. Returns what the commit checks and the leakage scan need, and the cost."""
    opened = _mutation_post(peer_url, "open", append_client.call("open"))
    assert_http_ok(opened)
    session = opened.json()["result"]
    assert session["old_state_digest"] == old_state_digest

    # The client asks for each fixed read window, verifies the answer and, after the last one,
    # hands over the owner prepare of the finalized mutation.
    action = append_client.call("begin", session=_from_wire(session))
    sentinels = [bytes.fromhex(sentinel) for sentinel in action["plaintext_sentinels"]]
    reads = 0
    read_bytes = 0
    read_seconds = 0.0
    while "read" in action:
        started = time.monotonic()
        read = _mutation_post(peer_url, "read", action["read"])
        read_seconds += time.monotonic() - started
        assert_http_ok(read)
        read_bytes += len(read.content)
        action = append_client.call("read_response", response=_from_wire(read.json()["result"]))
        reads += 1
    assert reads == 10, "five fixed read paths per index, one path per window"
    written_ciphertext = action["written_ciphertext"]
    append_body_bytes = len(json.dumps(action["append"]).encode())
    appended_at = time.monotonic()
    appended = _mutation_post(peer_url, "append", action["append"])
    assert_http_ok(appended)

    phases = []

    def append_phase_in(expected: set[str]) -> bool:
        status = _mutation_post(peer_url, "status", {"session_id": session["session_id"]})
        if status.status_code != 200:
            return False
        phases.append(status.json()["result"]["append_phase"])
        return phases[-1] in expected

    # The owners pre-stage the mutation, consensus admits its lease, the coordinator records the
    # parent progress, certifies recovery readiness and commits; the supervisor then records the
    # decision, collects the owner terminals and cleans up.
    wait_for(
        lambda: append_phase_in(POST_ADMISSION_APPEND_PHASES),
        wait_for_timeout=60,
        wait_for_interval=0.2,
    )
    assert "quarantined" not in phases and "terminal_aborted" not in phases, phases
    return {
        "sentinels": sentinels,
        "written_ciphertext": written_ciphertext,
        "appended_at": appended_at,
        "cost": {
            "read_windows": reads,
            "read_response_bytes": read_bytes,
            "read_seconds": round(read_seconds, 3),
            "append_request_bytes": append_body_bytes,
            "admitted_seconds": round(time.monotonic() - appended_at, 1),
        },
    }


def _leader_url(peer_urls: list[str]) -> str:
    urls_by_peer_id = {get_cluster_info(url)["peer_id"]: url for url in peer_urls}
    return urls_by_peer_id[get_leader(peer_urls[0])]


def _wait_for_appended_state(
    peer_urls: list[str], append_client: AppendClient, genesis_state_digest: str
) -> None:
    """The append is committed once a session opens on the appended state; until the supervisor
    has cleaned up, the collection's mutation slot is still busy. Afterwards the genesis state no
    longer opens. Mutation sessions are coordinated by the Raft leader, which can change while
    the peers apply the append's large material entries."""
    genesis_open = append_client.call("open")
    appended_open = append_client.call("open_next")
    reopened = {}

    def appended_state_opens() -> bool:
        leader_url = _leader_url(peer_urls)
        response = _mutation_post(leader_url, "open", appended_open)
        if response.status_code != 200:
            return False
        reopened.update(response.json()["result"], leader_url=leader_url)
        return True

    wait_for(appended_state_opens, wait_for_timeout=300, wait_for_interval=0.5)
    leader_url = reopened["leader_url"]
    assert reopened["old_state_digest"] != genesis_state_digest
    assert_http_ok(_mutation_post(leader_url, "close", {"session_id": reopened["session_id"]}))
    stale = _mutation_post(leader_url, "open", genesis_open)
    assert stale.status_code == 400, stale.text


def _assert_no_plaintext_leaks(
    peer_dirs: list[pathlib.Path], appended: dict
) -> None:
    """Leakage scan (PLAN V2-D5): nothing of the appended point or the client keys may reach the
    peers' storage, Raft state or logs, while every owner peer holds the bucket ciphertext the
    append wrote."""
    kill_all_processes()
    written = appended["written_ciphertext"].encode()
    for peer_dir in peer_dirs:
        assert any(
            written in data for _, data in _files_under(peer_dir)
        ), f"{peer_dir.name} does not hold the appended buckets"
    files = [
        file
        for root in [*peer_dirs, pathlib.Path(init_pytest_log_folder())]
        for file in _files_under(root)
    ]
    leaks = [
        (str(path), sentinel.hex())
        for path, data in files
        for sentinel in appended["sentinels"]
        if sentinel in data
    ]
    assert not leaks, f"plaintext sentinels leaked: {leaks[:5]}"


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

    genesis_state_digest = _enroll(peer_url, append_client)
    appended = _append_one_point(peer_url, append_client, genesis_state_digest)
    _wait_for_appended_state([peer_url], append_client, genesis_state_digest)

    # Server-side cost of one paired append on a single peer (tree height 2): the fixed read
    # windows the client fetched, the owner prepare it sent, and how long the server took to
    # admit the mutation and to commit and clear it so the next session can open.
    report = {
        **appended["cost"],
        "committed_and_cleared_seconds": round(time.monotonic() - appended["appended_at"], 1),
    }
    (pathlib.Path(init_pytest_log_folder()) / "append_latency.json").write_text(
        json.dumps(report, indent=2)
    )
    print(f"V2 paired append cost: {report}")

    _assert_no_plaintext_leaks([peer_dir], appended)


def test_private_oram_paired_append_commits_on_every_owner_over_tls(
    tmp_path: pathlib.Path, append_client: AppendClient
):
    """Three peers with internal TLS each hold a replica of both indexes, so the coordinator
    pre-stages, adopts and terminates the append on itself and two remote owners."""
    tls_env = _generate_tls_certs(tmp_path / "tls")
    peer_dirs = make_peer_folders(tmp_path, len(TLS_PEER_IDS))
    base_ports = [_free_port_triple() for _ in TLS_PEER_IDS]
    identities = [
        _bootstrap_identity(peer_dir, peer_id, base_port)
        for peer_dir, peer_id, base_port in zip(peer_dirs, TLS_PEER_IDS, base_ports)
    ]
    activation = _activation_bundle(
        [
            {
                "peer_id": peer_id,
                "host": "127.0.0.1",
                "p2p_port": base_port,
                "public_key": identity["public_key"],
                "tls": True,
            }
            for peer_id, base_port, identity in zip(TLS_PEER_IDS, base_ports, identities)
        ],
        identities[0]["binary_capability_digest"],
    )
    runtime_fixture = append_client.call("build", collection_id=PLACEHOLDER_COLLECTION_ID)
    for peer_dir in peer_dirs:
        _write_config(
            peer_dir, runtime_fixture, activation, result_signing_key_id=OWNER_SIGNING_KEY_ID
        )

    bootstrap_url, bootstrap_uri = start_first_peer(
        peer_dirs[0],
        "v2_tls_append_peer_0.log",
        port=base_ports[0],
        extra_env={**tls_env, "QDRANT__CLUSTER__PEER_ID": str(TLS_PEER_IDS[0])},
        p2p_tls=True,
    )
    leader = wait_peer_added(bootstrap_url)
    peer_urls = [bootstrap_url]
    for index in range(1, len(TLS_PEER_IDS)):
        peer_urls.append(
            start_peer(
                peer_dirs[index],
                f"v2_tls_append_peer_{index}.log",
                bootstrap_uri,
                port=base_ports[index],
                extra_env={**tls_env, "QDRANT__CLUSTER__PEER_ID": str(TLS_PEER_IDS[index])},
                p2p_tls=True,
            )
        )
    wait_for_uniform_cluster_status(peer_urls, leader)
    leader_url = next(url for url in peer_urls if get_cluster_info(url)["peer_id"] == leader)
    activated = requests.post(
        f"{leader_url}/cluster/private-oram/mutation-v2/activate?timeout=60", timeout=120
    )
    assert_http_ok(activated)
    wait_for(
        lambda: all(_status(url)["status"] == "active" for url in peer_urls),
        wait_for_timeout=60,
    )

    _create_paired_collection(leader_url, len(TLS_PEER_IDS))
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    fixture = append_client.call("build", collection_id=_collection_uuid(leader_url))
    _upload_hnsw(leader_url, fixture)
    _upload_result_oram(leader_url, fixture)
    for peer_url in peer_urls:
        wait_for(lambda url=peer_url: _v1_sessions_open(url, fixture), wait_for_timeout=60)
    _exercise_hnsw_owner_session(leader_url, fixture)
    _exercise_result_owner_session(leader_url, fixture)

    genesis_state_digest = _enroll(leader_url, append_client)
    appended = _append_one_point(leader_url, append_client, genesis_state_digest)
    _wait_for_appended_state(peer_urls, append_client, genesis_state_digest)
    print(
        "V2 paired append cost on three TLS peers: "
        f"{appended['cost']}, committed and cleared after "
        f"{round(time.monotonic() - appended['appended_at'], 1)} s"
    )

    _assert_no_plaintext_leaks(peer_dirs, appended)
