from concurrent.futures import ThreadPoolExecutor
from time import monotonic, sleep

import pytest
import requests

from openapi.helpers.collection_setup import drop_collection
from openapi.helpers.helpers import (
    get_api_string,
    qdrant_host_headers,
    request_with_validation,
    skip_if_no_feature,
)
from openapi.helpers.settings import QDRANT_HOST


def _debug_request(**kwargs):
    api = kwargs["api"]
    path_params = kwargs.get("path_params") or {}
    query_params = kwargs.get("query_params") or {}
    body = kwargs.get("body")
    return requests.post(
        url=get_api_string(QDRANT_HOST, api, path_params),
        params=query_params,
        json=body,
        headers=qdrant_host_headers(),
    )


def run_parallel(first_call, second_call):
    wal_url = get_api_string(
        QDRANT_HOST,
        "/collections/{collection_name}/shards/0/wal",
        first_call["path_params"],
    )

    def latest_wal_id(timeout):
        response = requests.get(
            wal_url,
            params={"entries": 1},
            headers=qdrant_host_headers(),
            timeout=timeout,
        )
        response.raise_for_status()
        entries = response.json()["result"]
        return entries[0]["id"] if entries else -1

    baseline_id = latest_wal_id(timeout=1)
    with ThreadPoolExecutor(max_workers=2) as executor:
        # The WAL reader takes the same lock held until the update is enqueued.
        # Observing a new entry therefore orders the requests at the server.
        # Keep admission within two seconds, leaving room for the one-second
        # update timeout before even the shortest five-second delay finishes.
        deadline = monotonic() + 2
        first_future = executor.submit(_debug_request, **first_call)
        while True:
            remaining = deadline - monotonic()
            assert remaining > 0, "Delay operation was not enqueued before the deadline"
            if latest_wal_id(timeout=min(1, remaining)) > baseline_id:
                break
            sleep(min(0.01, remaining))

        assert monotonic() < deadline, "Delay admission exceeded the two-second deadline"
        second_future = executor.submit(request_with_validation, **second_call)
        return first_future.result(), second_future.result()


@pytest.fixture(autouse=True)
def setup(collection_name):
    drop_collection(collection_name)

    response = request_with_validation(
        api="/collections/{collection_name}",
        method="PUT",
        path_params={"collection_name": collection_name},
        body={"shard_number": 1, "sparse_vectors": {"bm25": {}}},
    )

    assert response.ok

    yield
    drop_collection(collection_name=collection_name)


def test_wait_timeout_ack(collection_name):
    skip_if_no_feature("staging")
    sleep, op = run_parallel(
        {
            "api": "/collections/{collection_name}/debug",
            "method": "POST",
            "path_params": {"collection_name": collection_name},
            "body": {"delay": {"duration_sec": 5.0}},
        },
        {
            "api": "/collections/{collection_name}/points",
            "method": "PUT",
            "path_params": {"collection_name": collection_name},
            "query_params": {"wait": "true", "timeout": 1},
            "body": {
                "points": [
                    {
                        "id": 1,
                        "vector": {
                            "bm25": {
                                "text": "Lorem ipsum, dolor sit amet.",
                                "model": "qdrant/bm25",
                            }
                        },
                    }
                ]
            },
        },
    )
    assert sleep.ok and sleep.json()["result"]["status"] == "acknowledged"
    assert op.ok and op.json()["result"]["status"] == "wait_timeout"


def test_wait_timeout_completed(collection_name):
    skip_if_no_feature("staging")
    sleep, op = run_parallel(
        {
            "api": "/collections/{collection_name}/debug",
            "method": "POST",
            "path_params": {"collection_name": collection_name},
            "query_params": {"wait": "true"},
            "body": {"delay": {"duration_sec": 5.0}},
        },
        {
            "api": "/collections/{collection_name}/points",
            "method": "PUT",
            "path_params": {"collection_name": collection_name},
            "query_params": {"wait": "true", "timeout": 1},
            "body": {
                "points": [
                    {
                        "id": 1,
                        "vector": {
                            "bm25": {
                                "text": "Lorem ipsum, dolor sit amet.",
                                "model": "qdrant/bm25",
                            }
                        },
                    }
                ]
            },
        },
    )
    assert sleep.ok and sleep.json()["result"]["status"] == "completed"
    assert op.ok and op.json()["result"]["status"] == "wait_timeout"


def test_wait_timeout_twice(collection_name):
    skip_if_no_feature("staging")
    sleep, op = run_parallel(
        {
            "api": "/collections/{collection_name}/debug",
            "method": "POST",
            "path_params": {"collection_name": collection_name},
            "query_params": {"wait": "true", "timeout": 5},
            "body": {"delay": {"duration_sec": 10.0}},
        },
        {
            "api": "/collections/{collection_name}/points",
            "method": "PUT",
            "path_params": {"collection_name": collection_name},
            "query_params": {"wait": "true", "timeout": 1},
            "body": {
                "points": [
                    {
                        "id": 1,
                        "vector": {
                            "bm25": {
                                "text": "Lorem ipsum, dolor sit amet.",
                                "model": "qdrant/bm25",
                            }
                        },
                    }
                ]
            },
        },
    )
    assert sleep.ok and sleep.json()["result"]["status"] == "wait_timeout"
    assert op.ok and op.json()["result"]["status"] == "wait_timeout"
