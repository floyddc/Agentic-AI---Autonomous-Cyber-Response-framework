#!/bin/sh

set -eu

QWEN_MODEL="${CHAT_MODEL:-qwen3:4b-instruct}"
WARMUP_MARKER="/tmp/qwen-warmup-complete"

ollama serve &

echo "-------------------- Waiting for Ollama... --------------------"

until ollama list >/dev/null 2>&1
do
    sleep 1
done

echo "-------------------- Ollama ready. --------------------"

if ! ollama list | grep -q "${QWEN_MODEL}"; then
    echo "-------------------- Downloading ${QWEN_MODEL}... --------------------"
    ollama pull "${QWEN_MODEL}"
else
    echo "-------------------- ${QWEN_MODEL} already set. --------------------"
fi

if ! ollama list | grep -q "multilingual-e5-small"; then
    echo "-------------------- Downloading qllama/multilingual-e5-small... --------------------"
    ollama pull qllama/multilingual-e5-small
else
    echo "-------------------- qllama/multilingual-e5-small already set. --------------------"
fi

if [ ! -f "${WARMUP_MARKER}" ]; then
    printf '\n\n\n'
    echo "-------------------- Warming up ${QWEN_MODEL}... --------------------"
    printf '\n\n\n'
    ollama run "${QWEN_MODEL}" "Warm-up" >/dev/null
    touch "${WARMUP_MARKER}"
    printf '\n\n\n'
    echo "-------------------- ${QWEN_MODEL} warm-up complete. --------------------"
    printf '\n\n\n'
fi

wait
