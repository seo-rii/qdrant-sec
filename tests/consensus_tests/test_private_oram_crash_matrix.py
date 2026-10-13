"""Whole-process kill matrix for replicated private HNSW ORAM write-backs (PLAN V2-E).

The coordinating peer aborts at a named point of the replicated write-back (no unwinding, no
destructors, like `kill -9`) and is restarted without the crash point. The cluster must then
converge: before the consensus CAS the old epoch stays authoritative and the same commit
succeeds after the restart; after the CAS every peer serves the new epoch. A second matrix
kills a replica while it applies the committed epoch CAS from the Raft log, before and after
it saves the consensus state; restarted, it must replay the entry and serve the new epoch.

Requires a `target/debug/qdrant` built with `--features private-oram-crash-points`; the tests
run only when QDRANT_PRIVATE_ORAM_CRASH_TESTS=1.
"""

import os
import pathlib
import time

import pytest
import requests

from .test_private_oram_sessions import (
    BASE_EPOCH,
    COLLECTION,
    IDS_VISIBLE_RESULT_PRIVACY,
    NEXT_EPOCH,
    VECTOR,
    _exercise_hnsw_owner_session,
    _open_hnsw_owner_session,
    _post_result,
    _read_hnsw_owner_session,
    _start_private_oram_cluster,
    _upload_hnsw,
)
from .utils import (
    get_cluster_info,
    get_uri,
    kill_all_processes,
    processes,
    start_peer,
    wait_collection_exists_and_active_on_all_peers,
    wait_for,
    wait_for_peer_online,
    wait_for_uniform_cluster_status,
)

CRASH_POINT_ENV = "QDRANT_PRIVATE_ORAM_CRASH_POINT"
# A killed coordinator's session lease blocks new sessions until it expires (300 s in
# production); crash-point builds shorten it so the matrix can observe the expiry.
SHORT_LEASE_ENV = {"QDRANT_PRIVATE_ORAM_TEST_SESSION_LEASE_SECS": "15"}
BEFORE_CAS = [
    "replicated_writeback_after_local_prepare",
    "replicated_writeback_after_replica_prepare",
]
AFTER_CAS = [
    "replicated_writeback_after_cas",
    "replicated_writeback_after_replica_finalize",
]
RAFT_APPLY = [
    "raft_apply_epoch_cas_before_save",
    "raft_apply_epoch_cas_after_save",
]

@pytest.fixture(autouse=True)
def cleanup_crash_matrix_peers():
    yield
    kill_all_processes()


pytestmark = pytest.mark.skipif(
    os.environ.get("QDRANT_PRIVATE_ORAM_CRASH_TESTS") != "1",
    reason="needs a qdrant binary built with --features private-oram-crash-points",
)


LAST_ERROR: dict[str, str] = {}


def _wait_until(condition, description: str, timeout: float) -> None:
    deadline = time.time() + timeout
    while not condition():
        if time.time() > deadline:
            raise AssertionError(
                f"timed out waiting for {description}; last error: {LAST_ERROR.get('error')}"
            )
        time.sleep(0.5)


def _serves_epoch(peer_url: str, epoch: int, root_hash: str) -> bool:
    try:
        session = _open_hnsw_owner_session(peer_url, epoch, IDS_VISIBLE_RESULT_PRIVACY)
    except Exception as error:  # noqa: BLE001 - HTTP helpers raise plain Exception
        LAST_ERROR["error"] = f"{peer_url} epoch {epoch}: {error}"
        return False
    try:
        return session["index_epoch"] == epoch and session["root_hash"] == root_hash
    finally:
        try:
            _post_result(
                f"{peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session/"
                f"{session['session_id']}/close",
                {},
            )
        except Exception:  # noqa: BLE001
            pass


@pytest.mark.parametrize("coordinator_role", ["follower", "leader"])
@pytest.mark.parametrize("crash_point", BEFORE_CAS + AFTER_CAS)
def test_coordinator_abort_during_replicated_writeback_converges(
    tmp_path: pathlib.Path, crash_point: str, coordinator_role: str
):
    peer_urls, peer_dirs, fixture, leader, _ = _start_private_oram_cluster(
        tmp_path,
        3,
        3,
        include_result_oram=False,
        extra_env={**SHORT_LEASE_ENV, CRASH_POINT_ENV: crash_point},
    )
    hnsw = fixture["hnsw"]
    base_root = hnsw["manifest"]["root_hash"]
    next_root = hnsw["commit"]["new_root_hash"]
    _upload_hnsw(peer_urls[0], fixture)

    # The coordinator is the peer receiving the commit. Killing the Raft leader as coordinator
    # also forces a leader election while the write-back is in flight.
    peer_ids = [get_cluster_info(peer_url)["peer_id"] for peer_url in peer_urls]
    leader_index = peer_ids.index(leader)
    coordinator = (
        leader_index
        if coordinator_role == "leader"
        else next(index for index in range(len(peer_urls)) if index != leader_index)
    )
    coordinator_url = peer_urls[coordinator]
    # Wait until the coordinator applied the upload's consensus records.
    wait_for(
        lambda: _serves_epoch(coordinator_url, BASE_EPOCH, base_root),
        wait_for_timeout=60,
    )
    session = _open_hnsw_owner_session(
        coordinator_url, BASE_EPOCH, hnsw["manifest"]["result_privacy"]
    )
    _read_hnsw_owner_session(coordinator_url, fixture, session)
    commit = hnsw["commit"]
    try:
        requests.post(
            f"{coordinator_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/oram/commit",
            json={
                "session_id": session["session_id"],
                "old_epoch": commit["old_epoch"],
                "new_epoch": commit["new_epoch"],
                "old_root_hash": commit["old_root_hash"],
                "new_root_hash": commit["new_root_hash"],
                "updated_buckets": commit["updated_buckets"],
                "commit_signature": commit["signature"],
            },
            timeout=60,
        )
    except requests.RequestException:
        pass
    crashed = next(
        process for process in processes if get_uri(process.http_port) == coordinator_url
    )
    assert crashed.proc.wait(timeout=60) != 0, f"coordinator did not abort at {crash_point}"

    port = crashed.p2p_port
    bootstrap = next(process for process in processes if process is not crashed)
    bootstrap_uri = get_uri(bootstrap.p2p_port)
    processes.remove(crashed)
    crashed.kill()  # already dead; this releases its reserved ports for the restart
    restarted_url = start_peer(
        peer_dirs[coordinator],
        f"private_oram_crash_restart_{crash_point}.log",
        bootstrap_uri,
        port=port,
        extra_env=SHORT_LEASE_ENV,
    )
    peer_urls[coordinator] = restarted_url
    wait_for_peer_online(restarted_url, path="/cluster")
    if coordinator_role == "leader":
        # A new leader was elected while the old one was down.
        wait_for(lambda: _cluster_agrees_on_a_leader(peer_urls), wait_for_timeout=60)
    else:
        wait_for_uniform_cluster_status(peer_urls, leader)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)

    if crash_point in BEFORE_CAS:
        # The CAS was never proposed: every peer still serves the old epoch, and the same
        # write-back succeeds once the coordinator is back.
        for peer_url in peer_urls:
            _wait_until(
                lambda url=peer_url: _serves_epoch(url, BASE_EPOCH, base_root),
                f"{peer_url} to serve the old epoch after {crash_point}",
                60,
            )
        _wait_until(
            lambda: _commit_succeeds(restarted_url, fixture),
            f"the write-back to succeed after {crash_point}",
            120,
        )

    for peer_url in peer_urls:
        _wait_until(
            lambda url=peer_url: _serves_epoch(url, NEXT_EPOCH, next_root),
            f"{peer_url} to serve the new epoch after {crash_point}",
            120,
        )


def _cluster_agrees_on_a_leader(peer_urls: list[str]) -> bool:
    try:
        leaders = {
            get_cluster_info(peer_url)["raft_info"]["leader"] for peer_url in peer_urls
        }
    except Exception:  # noqa: BLE001
        return False
    return len(leaders) == 1 and None not in leaders


def _commit_succeeds(peer_url: str, fixture: dict) -> bool:
    try:
        _exercise_hnsw_owner_session(peer_url, fixture)
    except Exception as error:  # noqa: BLE001 - HTTP helpers raise plain Exception
        LAST_ERROR["error"] = f"commit on {peer_url}: {error}"
        return False
    return True


def _restart_peer(
    peer_urls: list[str],
    peer_dirs: list[pathlib.Path],
    index: int,
    log_file: str,
    extra_env: dict[str, str],
) -> str:
    """Stops peer `index` if it still runs and starts it again on the same p2p port."""
    process = next(
        process for process in processes if get_uri(process.http_port) == peer_urls[index]
    )
    # Either call releases the peer's reserved ports for the restart.
    if process.proc.poll() is None:
        process.interrupt()
    else:
        process.kill()
    port = process.p2p_port
    bootstrap = next(other for other in processes if other is not process)
    processes.remove(process)
    peer_urls[index] = start_peer(
        peer_dirs[index], log_file, get_uri(bootstrap.p2p_port), port=port, extra_env=extra_env
    )
    wait_for_peer_online(peer_urls[index], path="/cluster")
    return peer_urls[index]


@pytest.mark.parametrize("crash_point", RAFT_APPLY)
def test_replica_abort_while_applying_the_epoch_cas_replays_it(
    tmp_path: pathlib.Path, crash_point: str
):
    peer_urls, peer_dirs, fixture, leader, _ = _start_private_oram_cluster(
        tmp_path, 3, 3, include_result_oram=False, extra_env=SHORT_LEASE_ENV
    )
    hnsw = fixture["hnsw"]
    base_root = hnsw["manifest"]["root_hash"]
    next_root = hnsw["commit"]["new_root_hash"]
    _upload_hnsw(peer_urls[0], fixture)
    for peer_url in peer_urls:
        wait_for(
            lambda url=peer_url: _serves_epoch(url, BASE_EPOCH, base_root),
            wait_for_timeout=60,
        )

    # Only the victim, a follower, runs with the crash point armed, so it alone dies while
    # applying the write-back's epoch CAS; the leader coordinates the write-back.
    peer_ids = [get_cluster_info(peer_url)["peer_id"] for peer_url in peer_urls]
    leader_url = peer_urls[peer_ids.index(leader)]
    victim = next(index for index, peer_id in enumerate(peer_ids) if peer_id != leader)
    victim_url = _restart_peer(
        peer_urls,
        peer_dirs,
        victim,
        f"private_oram_raft_apply_armed_{crash_point}.log",
        {**SHORT_LEASE_ENV, CRASH_POINT_ENV: crash_point},
    )
    wait_for_uniform_cluster_status(peer_urls, leader)
    wait_for(
        lambda: _serves_epoch(victim_url, BASE_EPOCH, base_root),
        wait_for_timeout=60,
    )

    try:
        _exercise_hnsw_owner_session(leader_url, fixture)
    except Exception as error:  # noqa: BLE001 - the replica finalize may fail with the victim
        LAST_ERROR["error"] = f"commit on {leader_url}: {error}"
    victim_process = next(
        process for process in processes if get_uri(process.http_port) == victim_url
    )
    assert victim_process.proc.wait(timeout=60) != 0, f"replica did not abort at {crash_point}"

    _restart_peer(
        peer_urls,
        peer_dirs,
        victim,
        f"private_oram_raft_apply_restart_{crash_point}.log",
        SHORT_LEASE_ENV,
    )
    wait_for_uniform_cluster_status(peer_urls, leader)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    for peer_url in peer_urls:
        _wait_until(
            lambda url=peer_url: _serves_epoch(url, NEXT_EPOCH, next_root),
            f"{peer_url} to serve the new epoch after {crash_point}",
            120,
        )
