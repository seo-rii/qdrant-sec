#!/usr/bin/env bash
# Some OpenAPI files in this repository are generated and based upon other
# sources. When these sources change, the generated files must be generated
# (and committed) again. It is the task of the contributing user to do this
# properly.
#
# This tests makes sure the generated OpenAPI files are consistent with its
# sources. If this fails, you probably have to generate the OpenAPI files again.
#
# Read more here: https://github.com/qdrant/qdrant/blob/master/docs/DEVELOPMENT.md#rest

set -ex

# Ensure current path is project root
cd "$(dirname "$0")/../"

OPENAPI_DIFF="./docs/redoc/master/.diff.openapi.json"
cleanup() {
    rm -f "$OPENAPI_DIFF"
}
trap cleanup EXIT

# Keep current version of file to check
cp ./docs/redoc/master/openapi.json "$OPENAPI_DIFF"

# Regenerate OpenAPI files
tools/generate_openapi_models.sh

# Ensure generated files are the same as files in this repository
if diff -Zwa ./docs/redoc/master/openapi.json "$OPENAPI_DIFF"
then
    set +x
    echo "No diffs found."
else
    set +x
    echo "ERROR: Generated OpenAPI files are not consistent with files in this repository, see diff above."
    echo "ERROR: See: https://github.com/qdrant/qdrant/blob/master/docs/DEVELOPMENT.md#rest"
    exit 1
fi

NUMBER_OF_APIS=$(cat ./docs/redoc/master/openapi.json | jq '[.paths[] | length] | add')

EXPECTED_NUMBER_OF_APIS=87

if [ "$NUMBER_OF_APIS" -ne "$EXPECTED_NUMBER_OF_APIS" ]; then
    echo "ERROR: It looks like the total number of APIs has changed."
    echo "ERROR: Expected: $EXPECTED_NUMBER_OF_APIS, got: $NUMBER_OF_APIS"
    echo "ERROR: Verify that all new APIs are correctly whitelisted (or not) for the metrics endpoint"
    echo "ERROR: See: 'REST_ENDPOINT_WHITELIST' and 'GRPC_ENDPOINT_WHITELIST'"
    echo "ERROR: once consistency is restored, please update EXPECTED_NUMBER_OF_APIS in this script"
    exit 1
fi

PRIVATE_ORAM_OPERATIONS=(
    "get|/collections/{collection_name}/private-hnsw/{vector_name}/manifest|get_private_hnsw_manifest"
    "post|/collections/{collection_name}/private-hnsw/{vector_name}/manifest|upload_private_hnsw_manifest"
    "post|/collections/{collection_name}/private-hnsw/{vector_name}/buckets|upload_private_hnsw_buckets"
    "post|/collections/{collection_name}/private-hnsw/{vector_name}/session|open_private_hnsw_session"
    "post|/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths|read_private_hnsw_paths"
    "post|/collections/{collection_name}/private-hnsw/{vector_name}/oram/commit|commit_private_hnsw_paths"
    "post|/collections/{collection_name}/private-hnsw/{vector_name}/session/{session_id}/close|close_private_hnsw_session"
    "get|/collections/{collection_name}/private-result-oram/manifest|get_private_result_oram_manifest"
    "post|/collections/{collection_name}/private-result-oram/manifest|upload_private_result_oram_manifest"
    "post|/collections/{collection_name}/private-result-oram/buckets|upload_private_result_oram_buckets"
    "post|/collections/{collection_name}/private-result-oram/session|open_private_result_oram_session"
    "post|/collections/{collection_name}/private-result-oram/oram/read_buckets|read_private_result_oram_buckets"
    "post|/collections/{collection_name}/private-result-oram/oram/commit|commit_private_result_oram_buckets"
    "post|/collections/{collection_name}/private-result-oram/session/{session_id}/close|close_private_result_oram_session"
)

for PRIVATE_ORAM_OPERATION in "${PRIVATE_ORAM_OPERATIONS[@]}"; do
    IFS='|' read -r METHOD API_PATH OPERATION_ID <<< "$PRIVATE_ORAM_OPERATION"
    if ! jq -e \
        --arg method "$METHOD" \
        --arg path "$API_PATH" \
        --arg operation_id "$OPERATION_ID" \
        '.paths[$path][$method].operationId == $operation_id' \
        ./docs/redoc/master/openapi.json >/dev/null
    then
        echo "ERROR: Missing private ORAM OpenAPI operation: $METHOD $API_PATH -> $OPERATION_ID"
        exit 1
    fi
done
