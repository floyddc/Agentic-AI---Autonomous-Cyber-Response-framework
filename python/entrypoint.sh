#!/bin/sh

set -eu

RERANKER_MODEL="${RERANKER_MODEL:-cross-encoder/ms-marco-MiniLM-L2-v2}"

echo "-------------------- Checking Reranker ${RERANKER_MODEL}... --------------------"

python -c '
import os
from huggingface_hub import snapshot_download

snapshot_download(
    repo_id=os.environ["RERANKER_MODEL"],
    cache_dir=os.environ.get("HF_HOME", "/root/.cache/huggingface"),
)
'

echo "-------------------- Reranker ${RERANKER_MODEL} downloaded. --------------------"

exec "$@"