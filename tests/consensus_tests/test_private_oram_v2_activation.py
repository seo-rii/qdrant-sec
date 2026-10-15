"""Multi-process private ORAM mutation V2 activation (PLAN V2-E).

Three peers with fixed ids and ports bootstrap their private ORAM signing identities, are pinned
in a test-authority-signed activation bundle, start as a cluster, and the Raft leader activates
mutation V2: every peer must then report the protocol as active. Linux only (peer identities
are Linux-only).
"""

import json
import pathlib
import random
import socket
import subprocess
import sys
from contextlib import closing

import pytest
import requests

from .assertions import assert_http_ok
from .utils import (
    PROJECT_ROOT,
    get_cluster_info,
    get_env,
    get_qdrant_exec,
    kill_all_processes,
    make_peer_folders,
    start_first_peer,
    start_peer,
    wait_for,
    wait_for_uniform_cluster_status,
    wait_peer_added,
)

PEER_IDS = [101, 102, 103]

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="private ORAM peer identities are Linux-only",
)


@pytest.fixture(autouse=True)
def cleanup_v2_activation_peers():
    yield
    kill_all_processes()


def _free_port_triple() -> int:
    for _ in range(200):
        base = random.randint(20000, 60000)
        try:
            for port in range(base, base + 3):
                with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                    sock.bind(("127.0.0.1", port))
        except OSError:
            continue
        return base
    raise RuntimeError("no three consecutive free ports")


def _bootstrap_identity(peer_dir: pathlib.Path, peer_id: int, base_port: int) -> dict:
    env = get_env(base_port, base_port + 1, base_port + 2)
    env["QDRANT__CLUSTER__PEER_ID"] = str(peer_id)
    completed = subprocess.run(
        [get_qdrant_exec(), "--bootstrap-private-oram-peer-identity"],
        cwd=peer_dir,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return json.loads(completed.stdout.strip().splitlines()[-1])


def _activation_bundle(peers: list[dict], binary_capability_digest: str) -> dict:
    completed = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "qdrant-sec",
            "--example",
            "private_oram_v2_activation_fixture",
        ],
        cwd=PROJECT_ROOT,
        input=json.dumps(
            {
                "first_voter_peer_id": PEER_IDS[0],
                "binary_capability_digest": binary_capability_digest,
                "peers": peers,
            }
        ),
        check=True,
        capture_output=True,
        text=True,
        timeout=300,
    )
    return json.loads(completed.stdout)


def _write_activation_config(peer_dir: pathlib.Path, fixture: dict) -> None:
    bundle_path = peer_dir / "private_oram_v2_authority_bundle.json"
    bundle_path.write_bytes(fixture["bundle_canonical_json"].encode())
    # JSON is valid YAML, so the nested settings are written as flow mappings.
    activation = {
        "authority": fixture["authority"],
        "cluster_identity_digest": fixture["cluster_identity_digest"],
        "cluster_first_voter_peer_id": PEER_IDS[0],
        "authority_bundle_path": str(bundle_path),
    }
    config = (
        "cluster:\n"
        "  consensus:\n"
        f"    private_oram_mutation_v2_activation: {json.dumps(activation)}\n"
    )
    (peer_dir / "config" / "local.yaml").write_text(config)


def _wait_for_stable_voters(peer_urls: list[str]) -> None:
    """Activation requires a stable voter configuration. Peers join as learners and the leader
    promotes them one at a time once it has no uncommitted entries, which on a slow host can lag
    the cluster's formation."""
    wait_for(
        lambda: all(get_cluster_info(url)["raft_info"]["is_voter"] for url in peer_urls),
        wait_for_timeout=60,
    )


def _status(peer_url: str) -> dict:
    response = requests.get(f"{peer_url}/cluster/private-oram/mutation-v2/status", timeout=30)
    assert_http_ok(response)
    return response.json()["result"]


def test_private_oram_mutation_v2_activates_across_a_pinned_cluster(tmp_path: pathlib.Path):
    peer_dirs = make_peer_folders(tmp_path, len(PEER_IDS))
    base_ports = [_free_port_triple() for _ in PEER_IDS]
    identities = [
        _bootstrap_identity(peer_dir, peer_id, base_port)
        for peer_dir, peer_id, base_port in zip(peer_dirs, PEER_IDS, base_ports)
    ]
    capability = identities[0]["binary_capability_digest"]
    assert all(identity["binary_capability_digest"] == capability for identity in identities)
    fixture = _activation_bundle(
        [
            {
                "peer_id": peer_id,
                "host": "127.0.0.1",
                "p2p_port": base_port,
                "public_key": identity["public_key"],
            }
            for peer_id, base_port, identity in zip(PEER_IDS, base_ports, identities)
        ],
        capability,
    )
    for peer_dir in peer_dirs:
        _write_activation_config(peer_dir, fixture)

    bootstrap_url, bootstrap_uri = start_first_peer(
        peer_dirs[0],
        "v2_activation_peer_0.log",
        port=base_ports[0],
        extra_env={"QDRANT__CLUSTER__PEER_ID": str(PEER_IDS[0])},
    )
    leader = wait_peer_added(bootstrap_url)
    peer_urls = [bootstrap_url]
    for index in range(1, len(PEER_IDS)):
        peer_urls.append(
            start_peer(
                peer_dirs[index],
                f"v2_activation_peer_{index}.log",
                bootstrap_uri,
                port=base_ports[index],
                extra_env={"QDRANT__CLUSTER__PEER_ID": str(PEER_IDS[index])},
            )
        )
    wait_for_uniform_cluster_status(peer_urls, leader)
    assert [get_cluster_info(url)["peer_id"] for url in peer_urls] == PEER_IDS

    leader_url = next(url for url in peer_urls if get_cluster_info(url)["peer_id"] == leader)
    _wait_for_stable_voters(peer_urls)
    response = requests.post(
        f"{leader_url}/cluster/private-oram/mutation-v2/activate?timeout=60", timeout=120
    )
    assert_http_ok(response)
    assert response.json()["result"]["status"] == "active", response.json()

    def all_peers_active() -> bool:
        return all(_status(url)["status"] == "active" for url in peer_urls)

    wait_for(all_peers_active, wait_for_timeout=60)
