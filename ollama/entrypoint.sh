#!/bin/sh

set -eu


# ============================================================
# Models
# ============================================================

TRIAGE_MODEL="${TRIAGE_MODEL:-qwen3:0.6b}"
PLAN_MODEL="${PLAN_MODEL:-qwen3:4b-instruct}"
EMBEDDING_MODEL="${EMBEDDING_MODEL:-qllama/multilingual-e5-small:q4_k_m}"


# ============================================================
# Start Ollama
# ============================================================

ollama serve &

echo "-------------------- Waiting for Ollama... --------------------"

until ollama list >/dev/null 2>&1
do
    sleep 1
done

echo "-------------------- Ollama ready. --------------------"


# ============================================================
# Download models if necessary
# ============================================================

if ! ollama list | grep -q "${TRIAGE_MODEL}"; then

    echo "-------------------- Downloading ${TRIAGE_MODEL}... --------------------"

    ollama pull "${TRIAGE_MODEL}"

else

    echo "-------------------- ${TRIAGE_MODEL} already set. --------------------"

fi


if ! ollama list | grep -q "${PLAN_MODEL}"; then

    echo "-------------------- Downloading ${PLAN_MODEL}... --------------------"

    ollama pull "${PLAN_MODEL}"

else

    echo "-------------------- ${PLAN_MODEL} already set. --------------------"

fi


if ! ollama list | grep -q "${EMBEDDING_MODEL}"; then

    echo "-------------------- Downloading ${EMBEDDING_MODEL}... --------------------"

    ollama pull "${EMBEDDING_MODEL}"

else

    echo "-------------------- ${EMBEDDING_MODEL} already set. --------------------"

fi


# ============================================================
# Ollama server remains alive
# ============================================================

echo "-------------------- Ollama startup complete. --------------------"

wait