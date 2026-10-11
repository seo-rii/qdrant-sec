"""Cluster-wide plaintext leakage scan for private HNSW ORAM (PLAN V2-D5).

A three-peer cluster stores a private HNSW index built from distinctive plaintext points,
snapshots the collection, serves a session read and commits a replicated write-back through a
follower. After the peers stop, every file under every peer directory (collection storage,
Raft WAL and state, snapshots) and every peer log must be free of the fixture's plaintext
node ids, point and fetch tokens, vectors and client resource key.
"""

import pathlib

import pytest
import requests

from .assertions import assert_http_ok
from .test_private_oram_sessions import (
    COLLECTION,
    IDS_VISIBLE_RESULT_PRIVACY,
    NEXT_EPOCH,
    VECTOR,
    _exercise_hnsw_owner_session,
    _open_hnsw_owner_session,
    _post_result,
    _start_private_oram_cluster,
    _upload_hnsw,
)
from .utils import (
    get_cluster_info,
    init_pytest_log_folder,
    kill_all_processes,
    wait_for,
)


@pytest.fixture(autouse=True)
def cleanup_leak_scan_peers():
    yield
    kill_all_processes()


def _files_under(root: pathlib.Path):
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            yield path, path.read_bytes()


def _serves_next_epoch(peer_url: str, root_hash: str) -> bool:
    try:
        session = _open_hnsw_owner_session(peer_url, NEXT_EPOCH, IDS_VISIBLE_RESULT_PRIVACY)
    except Exception:  # noqa: BLE001 - HTTP helpers raise plain Exception
        return False
    _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session/"
        f"{session['session_id']}/close",
        {},
    )
    return session["root_hash"] == root_hash


def test_private_oram_cluster_storage_and_logs_hold_no_plaintext(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("QDRANT_PRIVATE_ORAM_FIXTURE_LEAK_SCAN", "1")
    peer_urls, peer_dirs, fixture, leader, _ = _start_private_oram_cluster(
        tmp_path, 3, 3, include_result_oram=False
    )
    hnsw = fixture["hnsw"]
    sentinels = [bytes.fromhex(sentinel) for sentinel in hnsw["plaintext_sentinels"]]
    assert len(sentinels) > 10

    _upload_hnsw(peer_urls[0], fixture)
    wait_for(
        lambda: _ready_for_session(peer_urls[0], hnsw["manifest"]["result_privacy"]),
        wait_for_timeout=60,
    )
    # Snapshot before the commit: afterwards the snapshot preflight requires the client to
    # upload a refreshed manifest, which this fixture does not produce.
    snapshot = requests.post(
        f"{peer_urls[0]}/collections/{COLLECTION}/snapshots?wait=true", timeout=120
    )
    assert_http_ok(snapshot)
    follower = next(
        url for url in peer_urls if get_cluster_info(url)["peer_id"] != leader
    )
    wait_for(
        lambda: _ready_for_session(follower, hnsw["manifest"]["result_privacy"]),
        wait_for_timeout=60,
    )
    _exercise_hnsw_owner_session(follower, fixture)
    for peer_url in peer_urls:
        wait_for(
            lambda url=peer_url: _serves_next_epoch(url, hnsw["commit"]["new_root_hash"]),
            wait_for_timeout=60,
        )
    kill_all_processes()

    roots = [*peer_dirs, pathlib.Path(init_pytest_log_folder())]
    files = [file for root in roots for file in _files_under(root)]
    assert any(path.suffix == ".snapshot" for path, _ in files), "no snapshot was written"

    # Positive control: the uploaded ciphertext must be visible to the scan.
    ciphertext = hnsw["buckets"][0]["ciphertext"].encode()
    assert any(ciphertext in data for _, data in files), "scan does not see stored buckets"

    leaks = [
        (str(path), sentinel.hex())
        for path, data in files
        for sentinel in sentinels
        if sentinel in data
    ]
    assert not leaks, f"plaintext sentinels leaked: {leaks[:5]}"


def _ready_for_session(peer_url: str, result_privacy: str) -> bool:
    try:
        session = _open_hnsw_owner_session(peer_url, 42, result_privacy)
    except Exception:  # noqa: BLE001 - HTTP helpers raise plain Exception
        return False
    _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session/"
        f"{session['session_id']}/close",
        {},
    )
    return True
