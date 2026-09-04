#!/bin/sh

set -eu

RERANKER_MODEL="${RERANKER_MODEL:-cross-encoder/ms-marco-MiniLM-L2-v2}"

python -c '
import os
from huggingface_hub import snapshot_download
from sentence_transformers import CrossEncoder

model_path = snapshot_download(
    repo_id=os.environ["RERANKER_MODEL"],
    cache_dir=os.environ.get("HF_HOME", "/root/.cache/huggingface"),
)

CrossEncoder(model_path)
' 

echo "-------------------- Reranker ${RERANKER_MODEL} ready. --------------------"

exec "$@"
