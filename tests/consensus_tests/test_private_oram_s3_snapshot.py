import base64
import hashlib
import io
import json
import os
import pathlib
import subprocess
import tarfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable

import pytest
import requests

from . import test_private_oram_sessions as private_oram
from .assertions import assert_http_ok


RUN_MINIO_GATE = "QDRANT_RUN_PRIVATE_ORAM_MINIO_SNAPSHOT"
MINIO_SERVER_IMAGE_ENV = "QDRANT_PRIVATE_ORAM_MINIO_SERVER_IMAGE"
MINIO_CLIENT_IMAGE_ENV = "QDRANT_PRIVATE_ORAM_MINIO_CLIENT_IMAGE"
MINIO_SERVER_IMAGE = (
    "minio/minio@sha256:"
    "14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"
)
MINIO_CLIENT_IMAGE = (
    "minio/mc@sha256:"
    "a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727"
)
MINIO_ACCESS_KEY = "qdrant-private-oram-test"
MINIO_SECRET_KEY = "qdrant-private-oram-test-secret"
MINIO_BUCKET = "private-oram-gate3"


def _truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


pytestmark = [
    pytest.mark.longrunning,
    pytest.mark.skipif(
        not _truthy_env(RUN_MINIO_GATE),
        reason=f"set {RUN_MINIO_GATE}=1 to run the isolated MinIO gate",
    ),
]


@pytest.fixture(autouse=True)
def cleanup_private_oram_processes():
    yield
    private_oram.kill_all_processes()


def _docker(
    args: list[str],
    *,
    check: bool = True,
    text: bool = True,
    timeout: int = 120,
) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["docker", *args],
            check=check,
            capture_output=True,
            text=text,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as error:
        pytest.fail(
            f"MinIO Docker command failed: {type(error).__name__}",
            pytrace=False,
        )


@dataclass(frozen=True)
class MinioStore:
    container_name: str
    endpoint_url: str
    client_image: str

    @property
    def host_alias(self) -> str:
        return (
            f"http://{MINIO_ACCESS_KEY}:{MINIO_SECRET_KEY}"
            "@127.0.0.1:9000"
        )

    def mc(
        self,
        args: list[str],
        *,
        text: bool = True,
        timeout: int = 120,
    ) -> subprocess.CompletedProcess:
        return _docker(
            [
                "run",
                "--rm",
                "--network",
                f"container:{self.container_name}",
                "--env",
                f"MC_HOST_gate={self.host_alias}",
                self.client_image,
                *args,
            ],
            text=text,
            timeout=timeout,
        )

    def object_entries(self) -> list[dict]:
        result = self.mc(
            ["ls", "--recursive", "--json", f"gate/{MINIO_BUCKET}"]
        )
        return [
            json.loads(line)
            for line in result.stdout.splitlines()
            if line.strip()
        ]

    def object_keys(self) -> list[str]:
        return sorted(
            entry["key"]
            for entry in self.object_entries()
            if entry.get("type") == "file"
        )

    def read_object(self, key: str) -> bytes:
        result = self.mc(
            ["cat", f"gate/{MINIO_BUCKET}/{key}"],
            text=False,
            timeout=180,
        )
        return result.stdout


@pytest.fixture
def minio_store() -> MinioStore:
    server_image = os.environ.get(MINIO_SERVER_IMAGE_ENV, MINIO_SERVER_IMAGE)
    client_image = os.environ.get(MINIO_CLIENT_IMAGE_ENV, MINIO_CLIENT_IMAGE)
    container_name = f"qdrant-private-oram-minio-{uuid.uuid4().hex[:12]}"
    started = _docker(
        [
            "run",
            "--detach",
            "--rm",
            "--name",
            container_name,
            "--publish",
            "127.0.0.1::9000",
            "--tmpfs",
            "/data:rw,size=2147483648,mode=0700",
            "--env",
            f"MINIO_ROOT_USER={MINIO_ACCESS_KEY}",
            "--env",
            f"MINIO_ROOT_PASSWORD={MINIO_SECRET_KEY}",
            server_image,
            "server",
            "/data",
            "--address",
            ":9000",
        ],
        timeout=180,
    )
    assert started.stdout.strip()
    try:
        port = _docker(["port", container_name, "9000/tcp"]).stdout.strip()
        assert port.startswith("127.0.0.1:"), port
        endpoint_url = f"http://{port}"
        deadline = time.monotonic() + 60
        while True:
            try:
                response = requests.get(
                    f"{endpoint_url}/minio/health/live",
                    timeout=1,
                )
                if response.status_code == 200:
                    break
            except requests.RequestException:
                pass
            if time.monotonic() >= deadline:
                pytest.fail("MinIO did not become healthy", pytrace=False)
            time.sleep(0.2)

        store = MinioStore(container_name, endpoint_url, client_image)
        store.mc(["mb", "--ignore-existing", f"gate/{MINIO_BUCKET}"])
        assert store.object_keys() == []
        yield store
    finally:
        _docker(["stop", "--time", "10", container_name], check=False, timeout=30)


def _configure_minio_snapshots(
    monkeypatch: pytest.MonkeyPatch,
    store: MinioStore,
) -> None:
    original: Callable = private_oram._write_private_oram_mutation_v2_runtime_config

    def write_config(
        peer_dir: pathlib.Path,
        fixture: dict,
        peer_id: int,
        activation: dict | None = None,
    ) -> None:
        original(peer_dir, fixture, peer_id, activation)
        config_path = peer_dir / "config" / "local.yaml"
        s3_config = f"""

storage:
  snapshots_config:
    snapshots_storage: s3
    s3_config:
      bucket: {json.dumps(MINIO_BUCKET)}
      region: us-east-1
      access_key: {json.dumps(MINIO_ACCESS_KEY)}
      secret_key: {json.dumps(MINIO_SECRET_KEY)}
      endpoint_url: {json.dumps(store.endpoint_url)}
"""
        config_path.write_text(config_path.read_text() + s3_config)

    monkeypatch.setattr(
        private_oram,
        "_write_private_oram_mutation_v2_runtime_config",
        write_config,
    )


def _download_full_snapshot(owner_url: str, snapshot_name: str) -> bytes:
    response = requests.get(
        f"{owner_url}/snapshots/{snapshot_name}",
        timeout=180,
    )
    assert_http_ok(response)
    assert response.content
    return response.content


def _assert_full_snapshot_is_self_contained(
    archive_bytes: bytes,
    expected_collection: str,
) -> None:
    with io.BytesIO(archive_bytes) as archive_file:
        with tarfile.open(fileobj=archive_file, mode="r:*") as archive:
            config_member = archive.extractfile("config.json")
            assert config_member is not None
            config = json.loads(config_member.read())
            child_name = config["collections_mapping"][expected_collection]
            child_member = archive.extractfile(child_name)
            assert child_member is not None
            child_bytes = child_member.read()

    with io.BytesIO(child_bytes) as child_file:
        with tarfile.open(fileobj=child_file, mode="r:*") as child:
            names = {
                member.name.removeprefix("./").rstrip("/")
                for member in child.getmembers()
            }
    assert any("private_hnsw_oram" in name for name in names)
    assert any("private_result_oram" in name for name in names)


def _wait_for_mutation_acknowledgement(
    prepared: dict,
    digest: str,
    generation: int,
) -> None:
    def acknowledged() -> bool:
        projections = [
            private_oram._private_oram_consensus_protocol_projection(peer_dir)
            for peer_dir in prepared["peer_dirs"]
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
            state["state_sequence"] == generation
            and state["signed_state_digest"] == digest
            and activated["lease_slot"]["generation"] == generation
            and activated["lease_slot"]["active"] is None
            and activated["lifecycle"]["active"] is None
            and last_cleared is not None
            and last_cleared["generation"] == generation
            and isinstance(last_cleared["resolution"], dict)
            and "acknowledged" in last_cleared["resolution"]
        )

    private_oram.wait_for(acknowledged, wait_for_timeout=300)


@pytest.mark.xdist_group(name="private_oram_minio_snapshot")
def test_private_oram_v2_minio_snapshot_and_external_recovery_gate(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    minio_store: MinioStore,
):
    _configure_minio_snapshots(monkeypatch, minio_store)
    pause_file = tmp_path / "private-oram-minio-snapshot.pause"
    pause_file.write_text("pause")
    consensus_env = {
        "QDRANT__CLUSTER__CONSENSUS__TICK_PERIOD_MS": "1000",
    }
    prepared = private_oram._prepare_private_oram_mutation_v2_collection(
        tmp_path,
        [
            {
                **consensus_env,
                "QDRANT_STAGING_PRIVATE_ORAM_SNAPSHOT_POST_PREPARE_PAUSE_FILE": str(
                    pause_file
                )
            },
            consensus_env.copy(),
            consensus_env.copy(),
        ],
        fixture_logical_capacity=4,
        sharding_method="auto",
    )
    owner_url = prepared["leader_url"]
    owner_dir = prepared["peer_dirs"][0]
    owner_log = (
        pathlib.Path(private_oram.init_pytest_log_folder())
        / "private_oram_mutation_v2_peer_0.log"
    )
    owner_prestage_root = (
        owner_dir
        / "storage"
        / "collections"
        / private_oram.COLLECTION
        / "private_hnsw_oram"
        / private_oram.VECTOR
        / "temp"
        / "private-oram-owner-prestage-v2"
    )
    unexpected_entry = owner_prestage_root / "unexpected.minio-snapshot-entry"
    marker = "Private ORAM staging full snapshot post-prepare pause reached"

    assert minio_store.object_keys() == []
    with ThreadPoolExecutor(max_workers=1) as executor:
        snapshot_future = executor.submit(
            requests.post,
            f"{owner_url}/snapshots?wait=true",
            timeout=180,
        )
        try:
            private_oram.wait_for(
                lambda: owner_log.exists()
                and marker in owner_log.read_text(errors="replace"),
                wait_for_timeout=120,
            )
            assert minio_store.object_keys() == []
            unexpected_entry.write_bytes(b"force post-prepare validation failure")
        finally:
            pause_file.unlink(missing_ok=True)
        failed_snapshot = snapshot_future.result(timeout=180)
    unexpected_entry.unlink(missing_ok=True)
    assert failed_snapshot.status_code == 500, failed_snapshot.text
    assert (
        "private ORAM V2 snapshot owner archive chain is not ready"
        in failed_snapshot.text
    )
    assert minio_store.object_keys() == []

    full_snapshot_response = requests.post(
        f"{owner_url}/snapshots?wait=true",
        timeout=180,
    )
    assert_http_ok(full_snapshot_response)
    full_snapshot = full_snapshot_response.json()["result"]
    full_key = f"snapshots/{full_snapshot['name']}"
    assert minio_store.object_keys() == [full_key]
    collection_snapshots = requests.get(
        f"{owner_url}/collections/{private_oram.COLLECTION}/snapshots",
        timeout=30,
    )
    assert_http_ok(collection_snapshots)
    assert collection_snapshots.json()["result"] == []

    full_object = minio_store.read_object(full_key)
    assert len(full_object) == full_snapshot["size"]
    assert _download_full_snapshot(owner_url, full_snapshot["name"]) == full_object
    _assert_full_snapshot_is_self_contained(full_object, private_oram.COLLECTION)

    opened, _ = private_oram._open_private_oram_mutation_v2_session(
        prepared,
        b"private-oram-minio-generation-one",
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
        {
            "context": append_context,
            "read_responses": read_responses,
        },
    )
    accepted = private_oram._post_result(
        f"{owner_url}/collections/{private_oram.COLLECTION}/"
        "private-oram/v2/mutation/append",
        finalized["rest_append_body"],
    )
    assert accepted == {"accepted": True, "phase": "prestage_pending"}
    _wait_for_mutation_acknowledgement(
        prepared,
        finalized["new_state_digest"],
        1,
    )

    generation_one_state = finalized["next_signed_state"]["state"]
    for endpoint, refresh, expected_kind in [
        (
            f"private-hnsw/{private_oram.VECTOR}",
            finalized["manifest_refresh"]["hnsw"],
            "hnsw",
        ),
        (
            "private-result-oram",
            finalized["manifest_refresh"]["result"],
            "result",
        ),
    ]:
        refreshed = private_oram._post_result(
            f"{owner_url}/collections/{private_oram.COLLECTION}/{endpoint}/manifest",
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
    snapshot_path, checkpoint_bundle = (
        private_oram._export_private_oram_recovery_snapshot(
            owner_url,
            tmp_path,
            prepared["fixture"],
            expected_indexes=expected_indexes,
        )
    )
    checkpoint = checkpoint_bundle["checkpoint"]
    object_keys = minio_store.object_keys()
    assert full_key in object_keys
    collection_keys = [
        key
        for key in object_keys
        if key.startswith(f"snapshots/{private_oram.COLLECTION}/")
    ]
    assert len(collection_keys) == 1
    collection_key = collection_keys[0]
    collection_object = minio_store.read_object(collection_key)
    assert collection_object == snapshot_path.read_bytes()
    assert len(collection_object) == checkpoint["snapshot_size_bytes"]
    assert (
        hashlib.sha256(collection_object).hexdigest()
        == checkpoint["snapshot_sha256"]
    )

    client_backup = base64.urlsafe_b64decode(
        prepared["fixture"]["result"]["client_recovery_state_base64url"]
        + "="
        * (
            -len(prepared["fixture"]["result"]["client_recovery_state_base64url"])
            % 4
        )
    )
    assert client_backup not in full_object
    assert client_backup not in collection_object

    private_oram._restore_private_oram_snapshot(
        owner_url,
        snapshot_path,
        checkpoint_bundle,
    )
    next_mutation_id = base64.urlsafe_b64encode(
        hashlib.sha256(b"private-oram-minio-post-restore-generation-two").digest()
    ).decode().rstrip("=")
    next_open = private_oram._post_result(
        f"{owner_url}/collections/{private_oram.COLLECTION}/"
        "private-oram/v2/mutation/open",
        private_oram._private_oram_v2_wire_body(
            {
                "client_id": "tenant-a/minio-post-restore-sdk",
                "vector_name": private_oram.VECTOR,
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
    next_append_context = private_oram._private_oram_mutation_v2_append_context(
        prepared,
        next_open,
        old_state=finalized["next_signed_state"],
        client_checkpoint=finalized["next_client_checkpoint"],
        encrypted_client_checkpoint=finalized["encrypted_client_checkpoint"],
    )
    _, next_read_responses = private_oram._execute_private_oram_mutation_v2_reads(
        owner_url,
        next_append_context,
    )
    next_finalized = private_oram._run_private_oram_mutation_v2_fixture_command(
        "finalize-mutation-v2-append",
        {
            "context": next_append_context,
            "read_responses": next_read_responses,
        },
    )
    next_accepted = private_oram._post_result(
        f"{owner_url}/collections/{private_oram.COLLECTION}/"
        "private-oram/v2/mutation/append",
        next_finalized["rest_append_body"],
    )
    assert next_accepted == {"accepted": True, "phase": "prestage_pending"}
    _wait_for_mutation_acknowledgement(
        prepared,
        next_finalized["new_state_digest"],
        2,
    )

    deleted_full = requests.delete(
        f"{owner_url}/snapshots/{full_snapshot['name']}?wait=true",
        timeout=60,
    )
    assert_http_ok(deleted_full)
    collection_snapshot_name = pathlib.PurePosixPath(collection_key).name
    deleted_collection = requests.delete(
        f"{owner_url}/collections/{private_oram.COLLECTION}/snapshots/"
        f"{collection_snapshot_name}?wait=true",
        timeout=60,
    )
    assert_http_ok(deleted_collection)
    assert minio_store.object_keys() == []
