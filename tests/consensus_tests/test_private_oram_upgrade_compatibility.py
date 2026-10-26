import base64
import copy
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import tarfile
import time
from dataclasses import dataclass

import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .assertions import assert_http_ok
from . import test_private_oram_sessions as private_oram
from .utils import (
    PROJECT_ROOT,
    get_cluster_info,
    get_qdrant_exec,
    get_uri,
    make_peer_folders,
    wait_collection_exists_and_active_on_all_peers,
    wait_for_uniform_cluster_status,
    wait_peer_added,
)


PREVIOUS_BINARY_ENV = "QDRANT_PRIVATE_ORAM_PREVIOUS_BINARY"
PREVIOUS_REVISION_ENV = "QDRANT_PRIVATE_ORAM_PREVIOUS_REVISION"
BUILD_PREVIOUS_BINARY_ENV = "QDRANT_BUILD_PRIVATE_ORAM_PREVIOUS_BINARY"
CURRENT_BINARY_ENV = "QDRANT_PRIVATE_ORAM_CURRENT_BINARY"
PINNED_PREVIOUS_REVISION = "74b0ba5492b480f293946280e4cd562d484ba927"
LEGACY_V3_BINARY_CAPABILITY_DIGEST = "dAtfKtcZBHNaXhM-amdoNULrgFbKmnO_EWz8LcJy3l4"
WIRE_9 = 9
PEER_IDS = (101, 102, 103)
AUTHORITY_SIGNATURE_DOMAIN = (
    "qdrant-sec/private-oram-activation-authority-manifest-signature/v1"
)
TEST_ONLY_AUTHORITY_SEED = bytes([0x6A]) * 32

# Only the dedicated upgrade job prepares the required previous executable.
pytestmark = pytest.mark.private_oram_upgrade


def _truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _unavailable(message: str) -> None:
    if _truthy_env("CI"):
        pytest.fail(message, pytrace=False)
    pytest.skip(message)


def _require_binary(path: pathlib.Path, label: str) -> pathlib.Path:
    if not path.is_file() or not os.access(path, os.X_OK):
        _unavailable(f"{label} is missing or not executable: {path}")
    return path.resolve()


def _resolve_revision(revision: str) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "--verify", f"{revision}^{{commit}}"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        pytest.fail(
            f"private ORAM previous revision cannot be resolved: {revision}",
            pytrace=False,
        )
    return completed.stdout.strip()


def _build_previous_binary(build_root: pathlib.Path, revision: str) -> pathlib.Path:
    source_root = build_root / "source"
    archive_path = build_root / "source.tar"
    completed = subprocess.run(
        [
            "git",
            "archive",
            "--format=tar",
            f"--output={archive_path}",
            revision,
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        pytest.fail(
            f"failed to archive previous Qdrant revision {revision}: {completed.stderr[-2000:]}",
            pytrace=False,
        )
    source_root.mkdir()
    with tarfile.open(archive_path, mode="r:") as archive:
        archive.extractall(source_root)

    target_root = build_root / "target"
    env = os.environ.copy()
    env["CARGO_INCREMENTAL"] = "0"
    env["CARGO_BUILD_BUILD_DIR"] = str(build_root / "build")
    completed = subprocess.run(
        [
            "cargo",
            "build",
            "--locked",
            "--bin",
            "qdrant",
            "--features",
            "staging",
            "--target-dir",
            str(target_root),
        ],
        cwd=source_root,
        env=env,
        capture_output=True,
        text=True,
        timeout=3600,
    )
    if completed.returncode != 0:
        pytest.fail(
            "failed to build the pinned previous Qdrant binary:\n"
            f"{completed.stderr[-8000:]}",
            pytrace=False,
        )
    return _require_binary(target_root / "debug" / "qdrant", "built previous binary")


@dataclass(frozen=True)
class _QdrantBinaries:
    current: pathlib.Path
    previous: pathlib.Path
    previous_revision: str


@pytest.fixture(scope="session")
def qdrant_binaries(tmp_path_factory: pytest.TempPathFactory) -> _QdrantBinaries:
    current = _require_binary(
        pathlib.Path(os.environ.get(CURRENT_BINARY_ENV, get_qdrant_exec())),
        f"current Qdrant binary (set {CURRENT_BINARY_ENV})",
    )
    revision = _resolve_revision(
        os.environ.get(PREVIOUS_REVISION_ENV, PINNED_PREVIOUS_REVISION)
    )
    configured_previous = os.environ.get(PREVIOUS_BINARY_ENV)
    if configured_previous:
        previous = _require_binary(
            pathlib.Path(configured_previous),
            f"previous Qdrant binary from {PREVIOUS_BINARY_ENV}",
        )
    elif _truthy_env(BUILD_PREVIOUS_BINARY_ENV):
        previous = _build_previous_binary(
            tmp_path_factory.mktemp("private-oram-previous-binary"), revision
        )
    else:
        _unavailable(
            "real previous Qdrant binary required; set "
            f"{PREVIOUS_BINARY_ENV}, or set {BUILD_PREVIOUS_BINARY_ENV}=1 to build "
            f"the pinned revision {revision}"
        )
        raise AssertionError("unreachable")

    if current == previous:
        pytest.fail("current and previous Qdrant binary paths must differ", pytrace=False)
    return _QdrantBinaries(current, previous, revision)


@dataclass
class _RunningPeer:
    process: subprocess.Popen
    api_url: str
    p2p_url: str
    log_path: pathlib.Path
    log_file: object

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        self.log_file.close()


@pytest.fixture
def running_peers():
    peers: list[_RunningPeer] = []
    yield peers
    for peer in reversed(peers):
        peer.stop()


def _compatible_peer_dirs(
    tmp_path: pathlib.Path, count: int, previous_revision: str
) -> list[pathlib.Path]:
    peer_dirs = make_peer_folders(tmp_path, count)
    previous_config = subprocess.run(
        ["git", "show", f"{previous_revision}:config/config.yaml"],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        timeout=30,
    ).stdout
    for peer_dir in peer_dirs:
        (peer_dir / "config" / "config.yaml").write_bytes(previous_config)
    return peer_dirs


def _peer_env(port_base: int, tick_period_ms: int = 100) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "QDRANT__CLUSTER__ENABLED": "true",
            "QDRANT__CLUSTER__P2P__PORT": str(port_base),
            "QDRANT__SERVICE__GRPC_PORT": str(port_base + 1),
            "QDRANT__SERVICE__HTTP_PORT": str(port_base + 2),
            "QDRANT__CLUSTER__CONSENSUS__TICK_PERIOD_MS": str(tick_period_ms),
            "QDRANT__TELEMETRY_DISABLED": "true",
            "QDRANT__LOG_LEVEL": "info,raft::raft=warn",
        }
    )
    return env


def _bootstrap_identity(
    binary: pathlib.Path, peer_dir: pathlib.Path, port_base: int
) -> dict:
    completed = subprocess.run(
        [str(binary), "--bootstrap-private-oram-peer-identity"],
        cwd=peer_dir,
        env=_peer_env(port_base),
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        pytest.fail(
            f"{binary} could not bootstrap a private ORAM peer identity:\n"
            f"{completed.stderr[-4000:]}",
            pytrace=False,
        )
    return json.loads(
        next(line for line in reversed(completed.stdout.splitlines()) if line.startswith("{"))
    )


def _activation_fixture(
    peer_ids: tuple[int, ...],
    port_bases: list[int],
    identities: list[dict],
    capability_digest: str,
) -> dict:
    request = {
        "cluster_first_voter_peer_id": peer_ids[0],
        "peers": [
            {
                "peer_id": peer_id,
                "p2p_uri": get_uri(port_base),
                "signer": identity["public_key"],
            }
            for peer_id, port_base, identity in zip(
                peer_ids, port_bases, identities, strict=True
            )
        ],
        "required_binary_capability_digest": capability_digest,
    }
    completed = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "qdrant-sec",
            "--example",
            private_oram.ACTIVATION_FIXTURE_EXAMPLE,
        ],
        cwd=PROJECT_ROOT,
        input=json.dumps(request, separators=(",", ":")),
        capture_output=True,
        text=True,
        timeout=180,
    )
    if completed.returncode != 0:
        pytest.fail(
            f"private ORAM activation fixture failed: {completed.stderr[-4000:]}",
            pytrace=False,
        )
    return json.loads(completed.stdout)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _push_u16(message: bytearray, value: int) -> None:
    message.extend(value.to_bytes(2, "big"))


def _push_u32(message: bytearray, value: int) -> None:
    message.extend(value.to_bytes(4, "big"))


def _push_u64(message: bytearray, value: int) -> None:
    message.extend(value.to_bytes(8, "big"))


def _push_str(message: bytearray, value: str) -> None:
    encoded = value.encode()
    _push_u64(message, len(encoded))
    message.extend(encoded)


def _authority_manifest_message(manifest: dict) -> bytes:
    message = bytearray()
    domain = AUTHORITY_SIGNATURE_DOMAIN.encode()
    _push_u32(message, len(domain))
    message.extend(domain)
    _push_u16(message, int(manifest["version"]))
    _push_str(message, manifest["cluster_identity_nonce"])
    _push_str(message, manifest["cluster_identity_digest"])
    _push_u64(message, int(manifest["cluster_first_voter_peer_id"]))
    _push_u64(message, int(manifest["registry_generation"]))
    parent = manifest["parent_manifest_digest"]
    message.append(0 if parent is None else 1)
    if parent is not None:
        _push_str(message, parent)
    _push_str(message, manifest["required_capability"])
    _push_str(message, manifest["required_binary_capability_digest"])
    _push_u64(message, int(manifest["authority_key_epoch"]))
    _push_str(message, manifest["authority_key_id"])
    _push_u32(message, len(manifest["peers"]))
    for peer in manifest["peers"]:
        signer = peer["signer"]
        _push_u64(message, int(peer["peer_id"]))
        _push_str(message, peer["peer_uri_digest"])
        _push_u16(message, int(signer["version"]))
        _push_str(message, signer["alg"])
        _push_u64(message, int(signer["key_epoch"]))
        _push_str(message, signer["key_id"])
        _push_str(message, signer["public_key"])
    return bytes(message)


def _successor_activation_fixture(genesis: dict, capability_digest: str) -> dict:
    predecessor = json.loads(genesis["bundle_canonical_json"])
    predecessor_digest = _b64url(
        hashlib.sha256(_authority_manifest_message(predecessor["manifest"])).digest()
    )
    manifest = copy.deepcopy(predecessor["manifest"])
    manifest["registry_generation"] = str(int(manifest["registry_generation"]) + 1)
    manifest["parent_manifest_digest"] = predecessor_digest
    manifest["required_binary_capability_digest"] = capability_digest

    private_key = Ed25519PrivateKey.from_private_bytes(TEST_ONLY_AUTHORITY_SEED)
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert _b64url(public_key) == genesis["authority_public_key"]["public_key"]
    signature = {
        "version": 1,
        "alg": "ed25519",
        "key_epoch": manifest["authority_key_epoch"],
        "key_id": manifest["authority_key_id"],
        "sig": _b64url(private_key.sign(_authority_manifest_message(manifest))),
    }
    successor = copy.deepcopy(genesis)
    successor["bundle_canonical_json"] = json.dumps(
        {"manifest": manifest, "signature": signature}, separators=(",", ":")
    )
    return successor


def _start_peer(
    peers: list[_RunningPeer],
    binary: pathlib.Path,
    peer_dir: pathlib.Path,
    port_base: int,
    log_name: str,
    bootstrap_url: str | None = None,
    tick_period_ms: int = 100,
) -> _RunningPeer:
    log_path = peer_dir.parent / log_name
    log_file = log_path.open("w")
    p2p_url = get_uri(port_base)
    args = [str(binary)]
    if bootstrap_url is not None:
        args.extend(["--bootstrap", bootstrap_url])
    args.extend(["--uri", p2p_url])
    process = subprocess.Popen(
        args,
        cwd=peer_dir,
        env=_peer_env(port_base, tick_period_ms),
        stdout=log_file,
        stderr=log_file,
    )
    peer = _RunningPeer(process, get_uri(port_base + 2), p2p_url, log_path, log_file)
    peers.append(peer)

    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process.poll() is not None:
            log_file.flush()
            pytest.fail(
                f"Qdrant peer exited during startup ({binary}):\n"
                f"{log_path.read_text(errors='replace')[-8000:]}",
                pytrace=False,
            )
        try:
            response = requests.get(f"{peer.api_url}/cluster", timeout=1)
            if response.status_code == 200:
                return peer
        except requests.RequestException:
            pass
        time.sleep(0.2)
    pytest.fail(f"Qdrant peer did not become ready: {log_path}", pytrace=False)


def _stop_peer(peers: list[_RunningPeer], peer: _RunningPeer) -> None:
    peer.stop()
    peers.remove(peer)


def _activation_status(peer_url: str) -> dict:
    response = requests.get(
        f"{peer_url}/cluster/private-oram/mutation-v2/status", timeout=30
    )
    assert_http_ok(response)
    return response.json()["result"]


def _activate(peer_url: str) -> requests.Response:
    return requests.post(
        f"{peer_url}/cluster/private-oram/mutation-v2/activate",
        params={"timeout": 60},
        timeout=70,
    )


def _raft_state(peer_dir: pathlib.Path) -> dict:
    return json.loads((peer_dir / "storage" / "raft_state.json").read_text())


def _wait_for_activation_state_quiescent(
    peer_dirs: list[pathlib.Path], timeout: float = 45
) -> None:
    deadline = time.monotonic() + timeout
    last_fingerprint: tuple[str, ...] | None = None
    stable_since: float | None = None
    while time.monotonic() < deadline:
        try:
            states = [_raft_state(peer_dir) for peer_dir in peer_dirs]
        except (OSError, json.JSONDecodeError):
            states = []
        ready = bool(states) and all(
            state.get("private_oram_activation_authority") is not None
            and len(state.get("apply_progress_queue", [])) == 2
            and state["apply_progress_queue"][0]
            == state["apply_progress_queue"][1] + 1
            and state["state"]["hard_state"]["commit"]
            == state["apply_progress_queue"][1]
            for state in states
        )
        fingerprint = (
            tuple(
                hashlib.sha256(
                    (peer_dir / "storage" / "raft_state.json").read_bytes()
                ).hexdigest()
                for peer_dir in peer_dirs
            )
            if ready
            else None
        )
        now = time.monotonic()
        if fingerprint is not None and fingerprint == last_fingerprint:
            stable_since = stable_since or now
            if now - stable_since >= 1:
                return
        else:
            last_fingerprint = fingerprint
            stable_since = now if fingerprint is not None else None
        time.sleep(0.1)
    pytest.fail("private ORAM activation state did not become quiescent", pytrace=False)


def _protected_files(peer_dir: pathlib.Path) -> dict[str, str]:
    storage = peer_dir / "storage"
    roots = [
        storage / "raft_state.json",
        storage / "raft_state",
        storage / "private_oram_mutation_floor_v2",
    ]
    for collection in (storage / "collections").glob("*"):
        roots.extend(
            [
                collection / "private_hnsw_oram",
                collection / "private_result_oram",
                collection / "private_oram_mutations",
            ]
        )
    snapshot: dict[str, str] = {}
    for root in roots:
        paths = [root] if root.is_file() else list(root.rglob("*")) if root.is_dir() else []
        for path in paths:
            if path.is_file():
                snapshot[str(path.relative_to(peer_dir))] = hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
    return snapshot


def _prepare_valid_enrollment(peer_urls: list[str], leader_url: str, leader_id: int) -> dict:
    create = requests.put(
        f"{leader_url}/collections/{private_oram.COLLECTION}",
        json=private_oram._private_oram_collection_create_body(
            replication_factor=1, shard_number=1, sharding_method="custom"
        ),
        timeout=30,
    )
    assert_http_ok(create)
    wait_collection_exists_and_active_on_all_peers(private_oram.COLLECTION, peer_urls)
    create_shard = requests.put(
        f"{leader_url}/collections/{private_oram.COLLECTION}/shards?timeout=60",
        json={
            "shard_key": "upgrade-compatibility",
            "shards_number": 1,
            "replication_factor": 1,
            "placement": [leader_id],
        },
        timeout=60,
    )
    assert_http_ok(create_shard)
    wait_collection_exists_and_active_on_all_peers(private_oram.COLLECTION, peer_urls)

    fixture = private_oram._private_oram_mutation_v2_fixture(
        private_oram._collection_uuid(leader_url)
    )
    private_oram._upload_hnsw(leader_url, fixture)
    private_oram._upload_result_oram(leader_url, fixture)
    context_url = (
        f"{leader_url}/collections/{private_oram.COLLECTION}/private-oram/v2/mutation/"
        f"enrollment-context/{private_oram.VECTOR}"
    )
    deadline = time.monotonic() + 30
    while True:
        response = requests.get(context_url, timeout=30)
        if response.status_code == 200 or time.monotonic() >= deadline:
            break
        time.sleep(0.25)
    assert_http_ok(response)
    context = response.json()["result"]
    signed = private_oram._sign_private_oram_mutation_v2_genesis(context, fixture)
    return {
        "context_url": context_url,
        "enroll_body": private_oram._private_oram_v2_wire_body(
            signed["rest_enroll_body"]
        ),
    }


def _run_expected_downgrade_failure(
    binary: pathlib.Path,
    peer_dir: pathlib.Path,
    port_base: int,
    log_path: pathlib.Path,
) -> str:
    with log_path.open("w") as log_file:
        process = subprocess.Popen(
            [str(binary), "--uri", get_uri(port_base)],
            cwd=peer_dir,
            env=_peer_env(port_base),
            stdout=log_file,
            stderr=log_file,
        )
        try:
            return_code = process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
            pytest.fail("previous Qdrant binary started on wire-9 protected data", pytrace=False)
    diagnostic = log_path.read_text(errors="replace")
    assert return_code != 0, diagnostic
    assert "Loading raft state from" in diagnostic, diagnostic
    assert (
        "private ORAM activation authority requires a different binary capability"
        not in diagnostic
    ), diagnostic
    stored_schema_rejected = "unknown field `capability_upgrade`" in diagnostic
    stored_floor_rejected = "private ORAM" in diagnostic and any(
        term in diagnostic.lower() for term in ("floor", "protocol")
    )
    assert stored_schema_rejected or stored_floor_rejected, diagnostic
    return diagnostic


@pytest.mark.longrunning
@pytest.mark.xdist_group(name="private_oram_upgrade_compatibility")
def test_previous_binary_downgrade_fails_closed_without_mutating_wire_9_state(
    tmp_path: pathlib.Path,
    qdrant_binaries: _QdrantBinaries,
    running_peers: list[_RunningPeer],
):
    port_base = private_oram._available_private_oram_peer_port_bases(1)[0]
    peer_dir = _compatible_peer_dirs(
        tmp_path, 1, qdrant_binaries.previous_revision
    )[0]
    bootstrap_fixture = private_oram._private_oram_mutation_v2_fixture(
        private_oram.PLACEHOLDER_COLLECTION_ID
    )
    private_oram._write_private_oram_mutation_v2_runtime_config(
        peer_dir, bootstrap_fixture, PEER_IDS[0]
    )
    previous_identity = _bootstrap_identity(qdrant_binaries.previous, peer_dir, port_base)
    assert (
        previous_identity["binary_capability_digest"] == LEGACY_V3_BINARY_CAPABILITY_DIGEST
    )
    genesis = _activation_fixture(
        (PEER_IDS[0],), [port_base], [previous_identity], LEGACY_V3_BINARY_CAPABILITY_DIGEST
    )
    private_oram._write_private_oram_mutation_v2_runtime_config(
        peer_dir, bootstrap_fixture, PEER_IDS[0], genesis
    )
    peer = _start_peer(
        running_peers,
        qdrant_binaries.previous,
        peer_dir,
        port_base,
        "previous-active-floor.log",
    )
    leader = wait_peer_added(peer.api_url)
    assert leader == PEER_IDS[0]
    assert_http_ok(_activate(peer.api_url))
    assert _activation_status(peer.api_url)["reservation_v3_write_floor_active"] is True
    _stop_peer(running_peers, peer)
    previous_state = _raft_state(peer_dir)
    previous_floor = previous_state["private_oram_mutation_format_floor"]
    assert previous_floor["minimum_reader_protocol"] < WIRE_9
    assert previous_floor["minimum_writer_protocol"] < WIRE_9
    assert (
        previous_floor["required_binary_capability_digest"]
        == LEGACY_V3_BINARY_CAPABILITY_DIGEST
    )

    identity = _bootstrap_identity(qdrant_binaries.current, peer_dir, port_base)
    assert identity["public_key"] == previous_identity["public_key"]
    assert identity["binary_capability_digest"] != LEGACY_V3_BINARY_CAPABILITY_DIGEST
    successor = _successor_activation_fixture(genesis, identity["binary_capability_digest"])
    successor_manifest = json.loads(successor["bundle_canonical_json"])["manifest"]
    successor_digest = _b64url(
        hashlib.sha256(_authority_manifest_message(successor_manifest)).digest()
    )
    private_oram._write_private_oram_mutation_v2_runtime_config(
        peer_dir, bootstrap_fixture, PEER_IDS[0], successor
    )

    # Persist the signed successor, then restart before all-peer prepare/enable.
    # Neither boot may advance the old floor or activate writes for the new binary.
    rotated_authority = None
    for restart in range(2):
        peer = _start_peer(
            running_peers,
            qdrant_binaries.current,
            peer_dir,
            port_base,
            f"wire9-before-prepare-{restart}.log",
        )
        leader = wait_peer_added(peer.api_url)
        assert leader == PEER_IDS[0]
        _wait_for_activation_state_quiescent([peer_dir])
        state = _raft_state(peer_dir)
        assert state["private_oram_mutation_format_floor"] == previous_floor
        authority = state["private_oram_activation_authority"]
        assert authority["manifest_digest"] == successor_digest
        assert int(authority["bundle"]["manifest"]["registry_generation"]) == 2
        upgrade_proof = authority["capability_upgrade"]
        assert (
            upgrade_proof["predecessor"]
            == previous_state["private_oram_activation_authority"]["bundle"]
        )
        assert upgrade_proof["format_floor_digest"] == previous_floor["floor_digest"]
        if rotated_authority is None:
            rotated_authority = authority
        else:
            assert authority == rotated_authority
        assert _activation_status(peer.api_url)["reservation_v3_write_floor_active"] is False
        if restart == 0:
            _stop_peer(running_peers, peer)

    activated = _activate(peer.api_url)
    assert_http_ok(activated)
    status = _activation_status(peer.api_url)
    assert status["status"] == "active"
    assert status["reservation_v3_write_floor_active"] is True
    enrollment = _prepare_valid_enrollment([peer.api_url], peer.api_url, leader)
    enrolled = requests.post(
        f"{peer.api_url}/collections/{private_oram.COLLECTION}/private-oram/v2/mutation/enroll",
        json=enrollment["enroll_body"],
        timeout=60,
    )
    assert_http_ok(enrolled)
    _stop_peer(running_peers, peer)

    state = _raft_state(peer_dir)
    floor = state["private_oram_mutation_format_floor"]
    assert floor["minimum_reader_protocol"] == WIRE_9
    assert floor["minimum_writer_protocol"] == WIRE_9
    assert floor["required_binary_capability_digest"] == identity["binary_capability_digest"]
    assert state["private_oram_mutation_states"]

    # Let the previous binary reach persisted state using its original compatible settings.
    private_oram._write_private_oram_mutation_v2_runtime_config(
        peer_dir, bootstrap_fixture, PEER_IDS[0], genesis
    )
    before = _protected_files(peer_dir)
    assert any("private_oram_mutation_floor_v2" in path for path in before)

    _run_expected_downgrade_failure(
        qdrant_binaries.previous,
        peer_dir,
        port_base,
        tmp_path / "wire9-downgrade.log",
    )
    assert _protected_files(peer_dir) == before


@pytest.mark.longrunning
@pytest.mark.xdist_group(name="private_oram_upgrade_compatibility")
def test_mixed_version_voter_blocks_wire_9_activation_and_enrollment(
    tmp_path: pathlib.Path,
    qdrant_binaries: _QdrantBinaries,
    running_peers: list[_RunningPeer],
):
    port_bases = private_oram._available_private_oram_peer_port_bases(3)
    peer_dirs = _compatible_peer_dirs(tmp_path, 3, qdrant_binaries.previous_revision)
    bootstrap_fixture = private_oram._private_oram_mutation_v2_fixture(
        private_oram.PLACEHOLDER_COLLECTION_ID
    )
    for peer_dir, peer_id in zip(peer_dirs, PEER_IDS, strict=True):
        private_oram._write_private_oram_mutation_v2_runtime_config(
            peer_dir, bootstrap_fixture, peer_id
        )
    old_identities = [
        _bootstrap_identity(qdrant_binaries.previous, peer_dir, port_base)
        for peer_dir, port_base in zip(peer_dirs, port_bases, strict=True)
    ]
    assert {
        identity["binary_capability_digest"] for identity in old_identities
    } == {LEGACY_V3_BINARY_CAPABILITY_DIGEST}
    genesis = _activation_fixture(
        PEER_IDS,
        port_bases,
        old_identities,
        LEGACY_V3_BINARY_CAPABILITY_DIGEST,
    )

    bootstrap_peers = [
        _start_peer(
            running_peers,
            qdrant_binaries.current,
            peer_dirs[0],
            port_bases[0],
            "mixed-bootstrap-current-0.log",
            tick_period_ms=25,
        )
    ]
    bootstrap_leader = wait_peer_added(bootstrap_peers[0].api_url)
    assert bootstrap_leader == PEER_IDS[0]
    for index in (1, 2):
        bootstrap_peers.append(
            _start_peer(
                running_peers,
                qdrant_binaries.current,
                peer_dirs[index],
                port_bases[index],
                f"mixed-bootstrap-current-{index}.log",
                bootstrap_url=bootstrap_peers[0].p2p_url,
                tick_period_ms=25,
            )
        )
        wait_for_uniform_cluster_status(
            [peer.api_url for peer in bootstrap_peers], bootstrap_leader
        )
    for peer in reversed(bootstrap_peers):
        _stop_peer(running_peers, peer)

    for peer_dir, peer_id in zip(peer_dirs, PEER_IDS, strict=True):
        private_oram._write_private_oram_mutation_v2_runtime_config(
            peer_dir, bootstrap_fixture, peer_id, genesis
        )

    old_peers = [
        _start_peer(
            running_peers,
            qdrant_binaries.previous,
            peer_dirs[0],
            port_bases[0],
            "mixed-old-0.log",
            tick_period_ms=10,
        )
    ]
    for index in (1, 2):
        old_peers.append(
            _start_peer(
                running_peers,
                qdrant_binaries.previous,
                peer_dirs[index],
                port_bases[index],
                f"mixed-old-{index}.log",
                tick_period_ms=1000,
            )
        )
    old_leader = wait_peer_added(old_peers[0].api_url, expected_size=3)
    assert old_leader == PEER_IDS[0]
    wait_for_uniform_cluster_status([peer.api_url for peer in old_peers], old_leader)
    _wait_for_activation_state_quiescent(peer_dirs)
    assert _activation_status(old_peers[0].api_url)[
        "reservation_v3_write_floor_active"
    ] is False
    assert all(
        _raft_state(peer_dir).get("private_oram_mutation_format_floor") is None
        for peer_dir in peer_dirs
    )

    _stop_peer(running_peers, old_peers[2])
    successor = _successor_activation_fixture(
        genesis, _bootstrap_identity(qdrant_binaries.current, peer_dirs[2], port_bases[2])[
            "binary_capability_digest"
        ]
    )
    for index in (0, 2):
        private_oram._write_private_oram_mutation_v2_runtime_config(
            peer_dirs[index], bootstrap_fixture, PEER_IDS[index], successor
        )
    current_peer_2 = _start_peer(
        running_peers,
        qdrant_binaries.current,
        peer_dirs[2],
        port_bases[2],
        "mixed-current-2.log",
        bootstrap_url=old_peers[0].p2p_url,
        tick_period_ms=10,
    )
    _stop_peer(running_peers, old_peers[0])

    deadline = time.monotonic() + 45
    current_leader = None
    while time.monotonic() < deadline:
        try:
            info = get_cluster_info(current_peer_2.api_url)
            if info["raft_info"]["leader"] == PEER_IDS[2]:
                current_leader = PEER_IDS[2]
                break
        except (AssertionError, requests.RequestException):
            pass
        time.sleep(0.2)
    assert current_leader == PEER_IDS[2]
    current_peer_0 = _start_peer(
        running_peers,
        qdrant_binaries.current,
        peer_dirs[0],
        port_bases[0],
        "mixed-current-0.log",
        bootstrap_url=current_peer_2.p2p_url,
        tick_period_ms=10,
    )
    mixed_peers = [current_peer_0, old_peers[1], current_peer_2]
    mixed_urls = [peer.api_url for peer in mixed_peers]
    wait_for_uniform_cluster_status(mixed_urls, current_leader)

    enrollment = _prepare_valid_enrollment(
        mixed_urls, current_peer_2.api_url, current_leader
    )
    before_floors = [
        _raft_state(peer_dir).get("private_oram_mutation_format_floor")
        for peer_dir in peer_dirs
    ]
    failed_activation = _activate(current_peer_2.api_url)
    assert failed_activation.status_code >= 400, failed_activation.text
    assert "acknowledgement failed" in failed_activation.text
    assert _activation_status(current_peer_2.api_url)[
        "reservation_v3_write_floor_active"
    ] is False
    assert [
        _raft_state(peer_dir).get("private_oram_mutation_format_floor")
        for peer_dir in peer_dirs
    ] == before_floors

    rejected_enrollment = requests.post(
        f"{current_peer_2.api_url}/collections/{private_oram.COLLECTION}/private-oram/v2/mutation/enroll",
        json=enrollment["enroll_body"],
        timeout=60,
    )
    assert rejected_enrollment.status_code >= 400, rejected_enrollment.text
    assert "active cluster capability floor" in rejected_enrollment.text
    assert requests.get(enrollment["context_url"], timeout=30).json()["result"][
        "enrollment_status"
    ] == "open"
    assert all(
        not _raft_state(peer_dir).get("private_oram_mutation_states", {})
        for peer_dir in peer_dirs
    )
