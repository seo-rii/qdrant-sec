"""Linux process-crash durability gates for paired private ORAM mutations.

The SIGKILL matrix runs in the regular consensus suite. The dm-flakey matrix is
deliberately opt-in because it needs root, CAP_SYS_ADMIN, loop devices, the
device-mapper flakey target, and an ext4 mount. Enable it with
QDRANT_RUN_PRIVATE_ORAM_DM_FLAKEY_DURABILITY=1 in an isolated CI runner.

dm-flakey's always-down ``drop_writes`` table lets ext4 finish unmounting while
discarding writes that were not already durable at the selected protocol
boundary. Remounting through the normal table then exercises ext4 journal
recovery without touching a host block device.
"""

import base64
import hashlib
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass

import pytest
import requests

from . import test_private_oram_sessions as private_oram
from . import utils as consensus_utils
from .assertions import assert_http_ok


RUN_DM_FLAKEY_DURABILITY = "QDRANT_RUN_PRIVATE_ORAM_DM_FLAKEY_DURABILITY"
DM_FLAKEY_IMAGE_MIB = "QDRANT_PRIVATE_ORAM_DM_FLAKEY_IMAGE_MIB"
CAP_SYS_ADMIN = 21
SUPERVISOR_PAUSE_ENV = (
    "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_SUPERVISOR_SCAN_PAUSE_FILE"
)
SUPERVISOR_PAUSE_MARKER = (
    "Private ORAM staging mutation supervisor scan pause reached"
)

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="private ORAM durability process gates require Linux",
)


@dataclass(frozen=True)
class CrashPoint:
    name: str
    pause_env: str
    pause_marker: str
    expected_at_cut: str
    pause_supervisor: bool = False
    expect_consensus_commit: bool = False
    arm_pause_after_finalize: bool = False
    exact_material_at_cut: bool = True


CRASH_POINTS = (
    CrashPoint(
        name="post-admission-exact-old",
        pause_env=(
            "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_POST_ADMISSION_PAUSE_FILE"
        ),
        pause_marker=(
            "Private ORAM staging mutation append post-admission pause reached"
        ),
        expected_at_cut="old",
    ),
    CrashPoint(
        name="post-consensus-pre-owner-reconcile-exact-old",
        pause_env=(
            "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_PRE_COMMIT_PROJECTION_PAUSE_FILE"
        ),
        pause_marker=(
            "Private ORAM staging mutation commit pre-projection pause reached"
        ),
        expected_at_cut="old",
        pause_supervisor=True,
        expect_consensus_commit=True,
    ),
)

FILESYSTEM_CRASH_POINTS = (
    CrashPoint(
        name="hnsw-temp-fsynced-pre-rename",
        pause_env="QDRANT_STAGING_PRIVATE_HNSW_ORAM_PRE_RENAME_PAUSE_FILE",
        pause_marker="Private HNSW ORAM staging atomic write pre-rename pause reached",
        expected_at_cut="old",
        expect_consensus_commit=True,
        arm_pause_after_finalize=True,
        exact_material_at_cut=False,
    ),
    CrashPoint(
        name="hnsw-post-rename-pre-directory-fsync",
        pause_env=(
            "QDRANT_STAGING_PRIVATE_HNSW_ORAM_POST_RENAME_PRE_DIR_FSYNC_PAUSE_FILE"
        ),
        pause_marker=(
            "Private HNSW ORAM staging atomic write post-rename "
            "pre-directory-fsync pause reached"
        ),
        expected_at_cut="old",
        expect_consensus_commit=True,
        arm_pause_after_finalize=True,
        exact_material_at_cut=False,
    ),
)


@dataclass(frozen=True)
class IndexState:
    index_epoch: int
    root_hash: str


@dataclass(frozen=True)
class PairedState:
    hnsw: IndexState
    result: IndexState


@dataclass(frozen=True)
class RestartPeer:
    peer_dir: pathlib.Path
    p2p_port: int
    extra_env: dict[str, str]


@dataclass
class PausedMutation:
    prepared: dict
    finalized: dict
    old: PairedState
    new: PairedState
    pause_files: tuple[pathlib.Path, ...]
    restart_peers: tuple[RestartPeer, ...]


@pytest.fixture(autouse=True)
def cleanup_private_oram_durability_processes():
    yield
    consensus_utils.kill_all_processes()


def _index_state(value: dict) -> IndexState:
    return IndexState(
        index_epoch=int(value["index_epoch"]),
        root_hash=value["root_hash"],
    )


def _paired_state_from_v2_state(state: dict) -> PairedState:
    indexes = {index["kind"]: _index_state(index) for index in state["indexes"]}
    assert set(indexes) == {"hnsw", "result"}
    return PairedState(hnsw=indexes["hnsw"], result=indexes["result"])


def _old_paired_state(fixture: dict) -> PairedState:
    return PairedState(
        hnsw=_index_state(fixture["hnsw"]["manifest"]),
        result=_index_state(fixture["result"]["manifest"]),
    )


def _owner_store_roots(peer_dir: pathlib.Path) -> dict[str, pathlib.Path]:
    collections = peer_dir / "storage" / "collections"
    hnsw_roots = list(collections.glob(f"*/private_hnsw_oram/{private_oram.VECTOR}"))
    result_roots = list(collections.glob("*/private_result_oram"))
    assert len(hnsw_roots) == 1, hnsw_roots
    assert len(result_roots) == 1, result_roots
    return {"hnsw": hnsw_roots[0], "result": result_roots[0]}


def _read_current_index_state(store_root: pathlib.Path) -> IndexState:
    current_path = store_root / "epochs" / "current.json"
    current = json.loads(current_path.read_text())
    assert set(current) == {"index_epoch", "root_hash"}, current
    return _index_state(current)


def _read_owner_paired_state(peer_dir: pathlib.Path) -> PairedState:
    roots = _owner_store_roots(peer_dir)
    return PairedState(
        hnsw=_read_current_index_state(roots["hnsw"]),
        result=_read_current_index_state(roots["result"]),
    )


def _assert_exact_old_or_new(
    peer_dir: pathlib.Path,
    old: PairedState,
    new: PairedState,
    *,
    expected: str | None = None,
) -> str:
    observed = _read_owner_paired_state(peer_dir)
    matches = [name for name, state in (("old", old), ("new", new)) if observed == state]
    assert matches, (
        "private ORAM owner stores are mixed or invalid after a crash boundary: "
        f"observed={observed!r}, exact_old={old!r}, exact_new={new!r}"
    )
    assert len(matches) == 1
    if expected is not None:
        assert matches[0] == expected, (
            f"crash boundary expected exact-{expected}, observed exact-{matches[0]}"
        )
    return matches[0]


def _expected_updated_buckets(finalized: dict) -> dict[str, list[dict]]:
    prepared_indexes = finalized["rest_append_body"]["owner_prepare"]["indexes"]
    batches = {}
    for index in prepared_indexes:
        batch = index["ordered_encrypted_buckets"]
        final_by_bucket = {
            int(bucket["bucket_id"]): bucket for bucket in batch["buckets"]
        }
        batches[batch["kind"]] = [
            final_by_bucket[bucket_id] for bucket_id in sorted(final_by_bucket)
        ]
    assert set(batches) == {"hnsw", "result"}
    return batches


def _wait_for_consensus_commit_at_cut(peer_dirs: list[pathlib.Path], finalized: dict) -> None:
    def exact_commit_is_uniform() -> bool:
        projections = [
            private_oram._private_oram_consensus_protocol_projection(peer_dir)
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
        active = authority["state"]["lease_slot"]["active"]
        return (
            state["state_sequence"] == 1
            and state["signed_state_digest"] == finalized["new_state_digest"]
            and active is not None
            and isinstance(active.get("phase"), dict)
            and "consensus_committed" in active["phase"]
        )

    consensus_utils.wait_for(exact_commit_is_uniform, wait_for_timeout=60)


def _assert_bucket_matches(stored: dict, expected: dict, state: IndexState) -> None:
    assert int(stored["bucket_id"]) == int(expected["bucket_id"])
    assert int(stored["index_epoch"]) == state.index_epoch
    assert int(expected["index_epoch"]) == state.index_epoch
    for field in ("ciphertext", "ciphertext_sha256", "bucket_commitment"):
        assert stored[field] == expected[field]


def _assert_exact_store_material(
    peer_dir: pathlib.Path,
    state_name: str,
    paused: PausedMutation,
) -> None:
    roots = _owner_store_roots(peer_dir)
    state = paused.old if state_name == "old" else paused.new
    expected_by_kind = (
        {
            "hnsw": paused.prepared["fixture"]["hnsw"]["buckets"],
            "result": paused.prepared["fixture"]["result"]["buckets"],
        }
        if state_name == "old"
        else _expected_updated_buckets(paused.finalized)
    )

    for kind, expected_index in (("hnsw", state.hnsw), ("result", state.result)):
        root = roots[kind]
        merkle = json.loads((root / "merkle" / "nodes.dat").read_text())
        assert int(merkle["index_epoch"]) == expected_index.index_epoch
        assert merkle["root_hash"] == expected_index.root_hash
        for expected_bucket in expected_by_kind[kind]:
            bucket_id = int(expected_bucket["bucket_id"])
            stored = json.loads(
                (root / "buckets" / f"{bucket_id:08}.bucket").read_text()
            )
            _assert_bucket_matches(stored, expected_bucket, expected_index)

        if state_name == "new":
            commit = json.loads(
                (
                    root
                    / "epochs"
                    / f"{expected_index.index_epoch:08}.commit"
                ).read_text()
            )
            assert int(commit["index_epoch"]) == expected_index.index_epoch
            assert commit["root_hash"] == expected_index.root_hash
            assert commit.get("writeback_digest")


def _owner_processes(peer_urls: list[str]):
    by_url = {
        consensus_utils.get_uri(process.http_port): process
        for process in consensus_utils.processes
    }
    selected = [by_url[url] for url in peer_urls]
    assert len(selected) == len(peer_urls)
    assert all(process.proc.poll() is None for process in selected)
    return selected


def _signal_sigkill(peer_processes) -> None:
    for process in peer_processes:
        process.proc.send_signal(signal.SIGKILL)


def _reap_sigkilled(peer_processes) -> None:
    for process in peer_processes:
        return_code = process.proc.wait(timeout=30)
        assert return_code == -signal.SIGKILL, return_code
        for port in (process.http_port, process.grpc_port, process.p2p_port):
            consensus_utils.busy_ports.pop(port, None)
        consensus_utils.processes.remove(process)


def _sigkill_cluster(peer_processes) -> None:
    _signal_sigkill(peer_processes)
    _reap_sigkilled(peer_processes)


def _assert_active_mutation_fails_closed(
    owner_url: str,
    current: PairedState,
    finalized: dict,
) -> None:
    requests_to_reject = (
        (
            f"private-hnsw/{private_oram.VECTOR}",
            {
                "client_id": "tenant-a/durability-hnsw-probe",
                "desired_epoch": current.hnsw.index_epoch,
                "fixed_budget": True,
                "result_privacy": "private_payload_oram_required",
            },
        ),
        (
            "private-result-oram",
            {
                "client_id": "tenant-a/durability-result-probe",
                "desired_epoch": current.result.index_epoch,
                "fixed_budget": True,
            },
        ),
    )
    sensitive_ciphertext = finalized["rest_append_body"]["owner_prepare"][
        "indexes"
    ][0]["ordered_encrypted_buckets"]["buckets"][0]["ciphertext"]
    for endpoint, body in requests_to_reject:
        response = requests.post(
            f"{owner_url}/collections/{private_oram.COLLECTION}/{endpoint}/session",
            json=body,
            timeout=30,
        )
        assert 400 <= response.status_code < 500, response.text
        assert sensitive_ciphertext not in response.text


def _prepare_paused_mutation(
    data_root: pathlib.Path,
    control_root: pathlib.Path,
    crash_point: CrashPoint,
    run_label: str,
) -> PausedMutation:
    data_root.mkdir(parents=True, exist_ok=True)
    control_root.mkdir(parents=True, exist_ok=True)
    pause_file = control_root / f"{run_label}-{crash_point.name}.pause"
    if not crash_point.arm_pause_after_finalize:
        pause_file.write_text("pause")
    pause_files = [pause_file]
    owner_env = {crash_point.pause_env: str(pause_file)}

    if crash_point.pause_supervisor:
        supervisor_pause = control_root / f"{run_label}-supervisor.pause"
        supervisor_pause.write_text("pause")
        pause_files.append(supervisor_pause)
        owner_env[SUPERVISOR_PAUSE_ENV] = str(supervisor_pause)

    owner_env["QDRANT__CLUSTER__CONSENSUS__TICK_PERIOD_MS"] = "25"
    follower_env = {"QDRANT__CLUSTER__CONSENSUS__TICK_PERIOD_MS": "1000"}
    peer_envs = [owner_env, follower_env.copy(), follower_env.copy()]
    prepared = private_oram._prepare_private_oram_mutation_v2_collection(
        data_root,
        peer_envs,
        fixture_logical_capacity=4,
    )
    owner_url = prepared["leader_url"]
    owner_log = (
        pathlib.Path(consensus_utils.init_pytest_log_folder())
        / "private_oram_mutation_v2_peer_0.log"
    )
    if crash_point.pause_supervisor:
        consensus_utils.wait_for(
            lambda: owner_log.exists()
            and SUPERVISOR_PAUSE_MARKER in owner_log.read_text(errors="replace"),
            wait_for_timeout=30,
        )

    opened, _ = private_oram._open_private_oram_mutation_v2_session(
        prepared,
        f"private-oram-durability-{run_label}-{crash_point.name}".encode(),
    )
    append_context = private_oram._private_oram_mutation_v2_append_context(
        prepared,
        opened,
    )
    _, read_responses = private_oram._execute_private_oram_mutation_v2_reads(
        owner_url,
        append_context,
    )
    finalized = private_oram._run_private_oram_mutation_v2_fixture_command(
        "finalize-mutation-v2-append",
        {"context": append_context, "read_responses": read_responses},
    )
    if crash_point.arm_pause_after_finalize:
        pause_file.write_text("pause")
    accepted = private_oram._post_result(
        f"{owner_url}/collections/{private_oram.COLLECTION}/private-oram/v2/mutation/append",
        finalized["rest_append_body"],
    )
    assert accepted == {"accepted": True, "phase": "prestage_pending"}
    consensus_utils.wait_for(
        lambda: owner_log.exists()
        and crash_point.pause_marker in owner_log.read_text(errors="replace"),
        wait_for_timeout=300,
    )

    old = _old_paired_state(prepared["fixture"])
    new_state = finalized["rest_append_body"]["owner_prepare"]["mutation_bundle"][
        "mutation"
    ]["new_state"]["state"]
    new = _paired_state_from_v2_state(new_state)
    if crash_point.expect_consensus_commit:
        _wait_for_consensus_commit_at_cut(prepared["peer_dirs"], finalized)
    observed_name = _assert_exact_old_or_new(
        prepared["peer_dirs"][0],
        old,
        new,
        expected=crash_point.expected_at_cut,
    )

    restart_peers = tuple(
        RestartPeer(
            peer_dir=peer_dir,
            p2p_port=process.p2p_port,
            extra_env=extra_env,
        )
        for peer_dir, process, extra_env in zip(
            prepared["peer_dirs"],
            _owner_processes(prepared["peer_urls"]),
            peer_envs,
            strict=True,
        )
    )
    paused = PausedMutation(
        prepared=prepared,
        finalized=finalized,
        old=old,
        new=new,
        pause_files=tuple(pause_files),
        restart_peers=restart_peers,
    )
    if crash_point.exact_material_at_cut:
        _assert_exact_store_material(prepared["peer_dirs"][0], observed_name, paused)
    _assert_active_mutation_fails_closed(
        owner_url,
        old if observed_name == "old" else new,
        finalized,
    )
    return paused


def _release_pause_files(paused: PausedMutation) -> None:
    for pause_file in paused.pause_files:
        pause_file.unlink(missing_ok=True)


def _restart_private_oram_cluster(paused: PausedMutation) -> list[str]:
    first = paused.restart_peers[0]
    first_url, bootstrap_uri = consensus_utils.start_first_peer(
        first.peer_dir,
        "private_oram_durability_peer_0_restart.log",
        port=first.p2p_port,
        extra_env=first.extra_env,
        capture_stderr=True,
    )
    peer_urls = [first_url]
    for index, peer in enumerate(paused.restart_peers[1:], start=1):
        peer_urls.append(
            consensus_utils.start_peer(
                peer.peer_dir,
                f"private_oram_durability_peer_{index}_restart.log",
                bootstrap_uri,
                port=peer.p2p_port,
                extra_env=peer.extra_env,
                capture_stderr=True,
            )
        )
    for peer_url in peer_urls:
        consensus_utils.wait_for_peer_online(peer_url, path="/cluster")

    elected: dict[str, int] = {}

    def uniform_leader_is_elected() -> bool:
        try:
            leaders = [
                consensus_utils.get_cluster_info(peer_url)["raft_info"]["leader"]
                for peer_url in peer_urls
            ]
        except (requests.RequestException, KeyError):
            return False
        if leaders[0] is None or any(leader != leaders[0] for leader in leaders[1:]):
            return False
        elected["leader"] = leaders[0]
        return True

    consensus_utils.wait_for(uniform_leader_is_elected, wait_for_timeout=60)
    consensus_utils.wait_for_uniform_cluster_status(peer_urls, elected["leader"])
    consensus_utils.wait_collection_exists_and_active_on_all_peers(
        private_oram.COLLECTION,
        peer_urls,
    )
    return peer_urls


def _wait_for_supervisors_ready(peer_urls: list[str]) -> None:
    def all_ready() -> bool:
        for peer_url in peer_urls:
            try:
                response = requests.get(
                    f"{peer_url}/cluster/private-oram/mutation-v2/status",
                    timeout=30,
                )
                if response.status_code != 200:
                    return False
                status = response.json()["result"]["supervisor"]
            except (requests.RequestException, KeyError, ValueError):
                return False
            if (
                status["state"] != "ready"
                or status["process_local_pending"] != 0
                or status["owned_elsewhere"] != 0
                or status["awaiting_cleanup"] != 0
                or status["failed"] != 0
            ):
                return False
        return True

    consensus_utils.wait_for(all_ready, wait_for_timeout=300)


def _current_leader_url(peer_urls: list[str]) -> str:
    infos = {
        peer_url: consensus_utils.get_cluster_info(peer_url)
        for peer_url in peer_urls
    }
    leader_id = next(iter(infos.values()))["raft_info"]["leader"]
    assert leader_id is not None
    return next(
        peer_url
        for peer_url, info in infos.items()
        if info["peer_id"] == leader_id
    )


def _assert_owner_can_open_current_sessions(
    owner_url: str,
    state: PairedState,
) -> None:
    sessions = (
        (
            f"private-hnsw/{private_oram.VECTOR}",
            {
                "client_id": "tenant-a/durability-hnsw-sdk",
                "desired_epoch": state.hnsw.index_epoch,
                "fixed_budget": True,
                "result_privacy": "private_payload_oram_required",
            },
            state.hnsw.root_hash,
        ),
        (
            "private-result-oram",
            {
                "client_id": "tenant-a/durability-result-sdk",
                "desired_epoch": state.result.index_epoch,
                "fixed_budget": True,
            },
            state.result.root_hash,
        ),
    )
    for endpoint, body, expected_root in sessions:
        opened = private_oram._post_result(
            f"{owner_url}/collections/{private_oram.COLLECTION}/{endpoint}/session",
            body,
        )
        assert opened["index_epoch"] == state.hnsw.index_epoch
        assert opened["root_hash"] == expected_root
        close_url = (
            f"{owner_url}/collections/{private_oram.COLLECTION}/{endpoint}"
            f"/session/{opened['session_id']}/close"
        )
        uncertain_timeout = False
        for _ in range(3):
            response = requests.post(close_url, json={}, timeout=30)
            if response.status_code == 200:
                assert response.json()["result"] is True
                break
            detail = response.text
            if response.status_code >= 500 and "consensus operation commit" in detail:
                uncertain_timeout = True
                time.sleep(1)
                continue
            if (
                uncertain_timeout
                and response.status_code == 400
                and "session is missing or expired" in detail
            ):
                break
            assert_http_ok(response)
        else:
            raise AssertionError("private ORAM session close did not converge")


def _refresh_live_manifests(owner_url: str, paused: PausedMutation) -> None:
    refreshes = (
        (
            f"private-hnsw/{private_oram.VECTOR}",
            paused.finalized["manifest_refresh"]["hnsw"],
            paused.new.hnsw,
        ),
        (
            "private-result-oram",
            paused.finalized["manifest_refresh"]["result"],
            paused.new.result,
        ),
    )
    for endpoint, refresh, expected in refreshes:
        updated = private_oram._post_result(
            f"{owner_url}/collections/{private_oram.COLLECTION}/{endpoint}/manifest",
            refresh,
        )
        assert updated == {
            "index_epoch": expected.index_epoch,
            "root_hash": expected.root_hash,
        }


def _verify_next_generation_read_proofs(
    coordinator_url: str,
    owner_url: str,
    paused: PausedMutation,
) -> None:
    mutation_id = base64.urlsafe_b64encode(
        hashlib.sha256(b"private-oram-durability-proof-verification").digest()
    ).decode().rstrip("=")
    open_body = private_oram._private_oram_v2_wire_body(
        {
            "client_id": "tenant-a/durability-proof-sdk",
            "vector_name": private_oram.VECTOR,
            "mutation_id": mutation_id,
            "immutable_manifest": paused.prepared["signed_genesis"][
                "rest_enroll_body"
            ]["immutable_manifest"],
            "old_state": paused.finalized["next_signed_state"],
        }
    )
    opened = private_oram._post_result(
        f"{coordinator_url}/collections/{private_oram.COLLECTION}/private-oram/v2/mutation/open",
        open_body,
    )
    assert opened["mutation_lease_generation"] == "2"
    append_context = private_oram._private_oram_mutation_v2_append_context(
        paused.prepared,
        opened,
        old_state=paused.finalized["next_signed_state"],
        client_checkpoint=paused.finalized["next_client_checkpoint"],
        encrypted_client_checkpoint=paused.finalized["encrypted_client_checkpoint"],
    )
    _, read_responses = private_oram._execute_private_oram_mutation_v2_reads(
        owner_url,
        append_context,
    )
    verified = private_oram._run_private_oram_mutation_v2_fixture_command(
        "finalize-mutation-v2-append",
        {"context": append_context, "read_responses": read_responses},
    )
    assert verified["rest_append_body"]["owner_prepare"]["indexes"]
    closed = private_oram._post_result(
        f"{coordinator_url}/collections/{private_oram.COLLECTION}/private-oram/v2/mutation/close",
        {"session_id": opened["session_id"]},
    )
    assert closed is True


def _assert_recovered_exact_new(peer_urls: list[str], paused: PausedMutation) -> None:
    peer_dirs = paused.prepared["peer_dirs"]
    # Restart reconciliation must finish the admitted mutation before its new
    # epochs can be checked; the supervisor barrier also waits for durable cleanup.
    _wait_for_supervisors_ready(peer_urls)
    private_oram._wait_for_private_oram_epochs(
        peer_dirs,
        paused.new.hnsw.index_epoch,
        2,
    )
    observed_name = _assert_exact_old_or_new(
        peer_dirs[0],
        paused.old,
        paused.new,
        expected="new",
    )
    _assert_exact_store_material(peer_dirs[0], observed_name, paused)
    leader_url = _current_leader_url(peer_urls)
    _refresh_live_manifests(peer_urls[0], paused)
    _assert_owner_can_open_current_sessions(peer_urls[0], paused.new)
    _verify_next_generation_read_proofs(leader_url, peer_urls[0], paused)


def _run_crash_case(
    data_root: pathlib.Path,
    control_root: pathlib.Path,
    crash_point: CrashPoint,
    run_label: str,
    crash_cluster,
) -> None:
    paused = _prepare_paused_mutation(
        data_root,
        control_root,
        crash_point,
        run_label,
    )
    peer_processes = _owner_processes(paused.prepared["peer_urls"])
    crash_cluster(peer_processes)

    observed_name = _assert_exact_old_or_new(
        paused.prepared["peer_dirs"][0],
        paused.old,
        paused.new,
        expected=crash_point.expected_at_cut,
    )
    if crash_point.exact_material_at_cut:
        _assert_exact_store_material(
            paused.prepared["peer_dirs"][0],
            observed_name,
            paused,
        )
    _release_pause_files(paused)
    restarted_urls = _restart_private_oram_cluster(paused)
    _assert_recovered_exact_new(restarted_urls, paused)


def _effective_capabilities() -> int | None:
    try:
        for line in pathlib.Path("/proc/self/status").read_text().splitlines():
            if line.startswith("CapEff:"):
                return int(line.split(":", 1)[1].strip(), 16)
    except (OSError, ValueError):
        return None
    return None


def _dm_flakey_skip_reason() -> str | None:
    if os.getenv(RUN_DM_FLAKEY_DURABILITY) != "1":
        return (
            f"true power-loss simulation is opt-in; set {RUN_DM_FLAKEY_DURABILITY}=1 "
            "on an isolated privileged Linux runner"
        )
    if os.geteuid() != 0:
        return "dm-flakey durability gate requires uid 0"
    capabilities = _effective_capabilities()
    if capabilities is None or capabilities & (1 << CAP_SYS_ADMIN) == 0:
        return "dm-flakey durability gate requires CAP_SYS_ADMIN"

    required_commands = (
        "blockdev",
        "dmsetup",
        "losetup",
        "mkfs.ext4",
        "mount",
        "umount",
    )
    missing = [command for command in required_commands if shutil.which(command) is None]
    if missing:
        return f"dm-flakey durability gate is missing commands: {', '.join(missing)}"
    for device in ("/dev/mapper/control", "/dev/loop-control"):
        if not pathlib.Path(device).exists():
            return f"dm-flakey durability gate requires {device}"

    targets = subprocess.run(
        ["dmsetup", "targets"],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if targets.returncode != 0:
        detail = (targets.stderr or targets.stdout).strip()[:300]
        return f"device-mapper control is unavailable: {detail}"
    if not any(line.split(maxsplit=1)[0] == "flakey" for line in targets.stdout.splitlines()):
        return "kernel/device-mapper does not expose the flakey target"

    free_loop = subprocess.run(
        ["losetup", "--find"],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if free_loop.returncode != 0:
        detail = (free_loop.stderr or free_loop.stdout).strip()[:300]
        return f"no usable loop device is available: {detail}"
    return None


class DmFlakeyExt4:
    def __init__(self, control_root: pathlib.Path, label: str):
        self.control_root = control_root
        self.name = f"qdrant-oram-{label}-{uuid.uuid4().hex[:10]}"
        self.image = control_root / f"{self.name}.img"
        self.mount_point = control_root / f"{self.name}-mount"
        self.loop_device: str | None = None
        self.sectors: int | None = None
        self.mapping_created = False
        self.mounted = False

    @property
    def mapper_path(self) -> pathlib.Path:
        return pathlib.Path("/dev/mapper") / self.name

    def _run(
        self,
        args: list[str],
        *,
        check: bool = True,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            args,
            check=check,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def _table(self, *, drop_writes: bool) -> str:
        assert self.loop_device is not None
        assert self.sectors is not None
        if drop_writes:
            return (
                f"0 {self.sectors} flakey {self.loop_device} 0 "
                "0 3600 1 drop_writes"
            )
        return f"0 {self.sectors} flakey {self.loop_device} 0 3600 1"

    def _reload_table(self, table: str) -> None:
        self._run(["dmsetup", "suspend", "--noflush", self.name])
        try:
            self._run(["dmsetup", "reload", self.name, "--table", table])
        except BaseException:
            self._run(["dmsetup", "resume", self.name], check=False)
            raise
        self._run(["dmsetup", "resume", self.name])

    def __enter__(self) -> "DmFlakeyExt4":
        self.control_root.mkdir(parents=True, exist_ok=True)
        self.mount_point.mkdir(mode=0o700)
        image_mib = int(os.getenv(DM_FLAKEY_IMAGE_MIB, "2048"))
        if image_mib < 512 or image_mib > 16 * 1024:
            raise AssertionError(
                f"{DM_FLAKEY_IMAGE_MIB} must be between 512 and 16384 MiB"
            )
        with self.image.open("wb") as image_file:
            image_file.truncate(image_mib * 1024 * 1024)

        try:
            attached = self._run(
                ["losetup", "--find", "--show", str(self.image)],
                timeout=30,
            )
            self.loop_device = attached.stdout.strip()
            assert self.loop_device.startswith("/dev/loop"), self.loop_device
            size = self._run(["blockdev", "--getsz", self.loop_device])
            self.sectors = int(size.stdout.strip())
            assert self.sectors > 0
            self._run(
                ["dmsetup", "create", self.name, "--table", self._table(drop_writes=False)]
            )
            self.mapping_created = True
            # Minimal privileged CI images often have no udev daemon. Explicitly
            # materialize the mapper node instead of relying on udev side effects.
            self._run(["dmsetup", "mknodes", self.name])
            if not self.mapper_path.is_block_device():
                raise AssertionError(
                    f"dmsetup did not create block device {self.mapper_path}"
                )
            self._run(
                [
                    "mkfs.ext4",
                    "-F",
                    "-q",
                    "-E",
                    "lazy_itable_init=0,lazy_journal_init=0",
                    str(self.mapper_path),
                ],
                timeout=120,
            )
            self._run(
                [
                    "mount",
                    "-t",
                    "ext4",
                    "-o",
                    "data=ordered,commit=60",
                    str(self.mapper_path),
                    str(self.mount_point),
                ]
            )
            self.mounted = True
            os.chmod(self.mount_point, 0o700)
            return self
        except BaseException:
            self.close()
            raise

    def power_cut(self, peer_processes) -> None:
        # Freeze without a flush, kill every process, then acknowledge and drop all
        # dirty writeback while ext4 unmounts through the always-down flakey table.
        self._run(["dmsetup", "suspend", "--noflush", self.name])
        resumed = False
        try:
            _signal_sigkill(peer_processes)
            self._run(
                [
                    "dmsetup",
                    "reload",
                    self.name,
                    "--table",
                    self._table(drop_writes=True),
                ]
            )
            self._run(["dmsetup", "resume", self.name])
            resumed = True
        finally:
            if not resumed:
                self._run(["dmsetup", "resume", self.name], check=False)
        _reap_sigkilled(peer_processes)

        self._run(["umount", str(self.mount_point)], timeout=120)
        self.mounted = False
        self._reload_table(self._table(drop_writes=False))
        self._run(
            [
                "mount",
                "-t",
                "ext4",
                "-o",
                "data=ordered,commit=60",
                str(self.mapper_path),
                str(self.mount_point),
            ],
            timeout=120,
        )
        self.mounted = True

    def close(self) -> None:
        if self.mounted:
            unmounted = self._run(
                ["umount", str(self.mount_point)],
                check=False,
                timeout=120,
            )
            if unmounted.returncode != 0:
                self._run(
                    ["umount", "-l", str(self.mount_point)],
                    check=False,
                    timeout=30,
                )
            self.mounted = False
        if self.mapping_created:
            self._run(
                ["dmsetup", "remove", "--retry", self.name],
                check=False,
                timeout=60,
            )
            self.mapping_created = False
        if self.loop_device is not None:
            self._run(
                ["losetup", "--detach", self.loop_device],
                check=False,
                timeout=30,
            )
            self.loop_device = None
        self.image.unlink(missing_ok=True)
        try:
            self.mount_point.rmdir()
        except OSError:
            pass

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


@pytest.mark.parametrize("crash_point", CRASH_POINTS, ids=lambda point: point.name)
def test_private_oram_v2_sigkill_durability_matrix(
    tmp_path: pathlib.Path,
    crash_point: CrashPoint,
):
    _run_crash_case(
        tmp_path / "data",
        tmp_path / "control",
        crash_point,
        "sigkill",
        _sigkill_cluster,
    )


@pytest.mark.parametrize(
    "crash_point", FILESYSTEM_CRASH_POINTS, ids=lambda point: point.name
)
def test_private_oram_v2_sigkill_atomic_publication_matrix(
    tmp_path: pathlib.Path,
    crash_point: CrashPoint,
):
    _run_crash_case(
        tmp_path / "data",
        tmp_path / "control",
        crash_point,
        "sigkill-atomic",
        _sigkill_cluster,
    )


@pytest.mark.parametrize(
    "crash_point", FILESYSTEM_CRASH_POINTS, ids=lambda point: point.name
)
def test_private_oram_v2_dm_flakey_ext4_power_loss_matrix(
    tmp_path: pathlib.Path,
    crash_point: CrashPoint,
):
    skip_reason = _dm_flakey_skip_reason()
    if skip_reason is not None:
        pytest.skip(skip_reason)

    with DmFlakeyExt4(tmp_path / "dm-flakey", crash_point.name) as filesystem:
        try:
            _run_crash_case(
                filesystem.mount_point / "data",
                tmp_path / "control",
                crash_point,
                "dm-flakey",
                filesystem.power_cut,
            )
        finally:
            # The ext4 mount cannot be dismantled while restarted peers hold it.
            consensus_utils.kill_all_processes()
