#!/bin/sh

set -eu

TRIAGE_MODEL="${TRIAGE_MODEL:-qwen3:0.6b}"
PLAN_MODEL="${PLAN_MODEL:-qwen3:4b-instruct}"
TRIAGE_WARMUP_MARKER="/tmp/qwen3:0.6b-warmup-complete"
PLAN_WARMUP_MARKER="/tmp/qwen3:4b-instruct-warmup-complete"

ollama serve &

echo "-------------------- Waiting for Ollama... --------------------"

until ollama list >/dev/null 2>&1
do
    sleep 1
done

echo "-------------------- Ollama ready. --------------------"

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

if ! ollama list | grep -q "multilingual-e5-small"; then
    echo "-------------------- Downloading qllama/multilingual-e5-small... --------------------"
    ollama pull qllama/multilingual-e5-small
else
    echo "-------------------- qllama/multilingual-e5-small already set. --------------------"
fi

if [ ! -f "${TRIAGE_WARMUP_MARKER}" ]; then
    printf '\n\n\n'
    echo "-------------------- Warming up ${TRIAGE_MODEL}... --------------------"
    printf '\n\n\n'
    ollama run "${TRIAGE_MODEL}" "Warm-up" >/dev/null
    touch "${TRIAGE_WARMUP_MARKER}"
    printf '\n\n\n'
    echo "-------------------- ${TRIAGE_MODEL} warm-up complete. --------------------"
    printf '\n\n\n'
fi

if [ ! -f "${PLAN_WARMUP_MARKER}" ]; then
    printf '\n\n\n'
    echo "-------------------- Warming up ${PLAN_MODEL}... --------------------"
    printf '\n\n\n'
    ollama run "${PLAN_MODEL}" "Warm-up" >/dev/null
    touch "${PLAN_WARMUP_MARKER}"
    printf '\n\n\n'
    echo "-------------------- ${PLAN_MODEL} warm-up complete. --------------------"
    printf '\n\n\n'
fi

wait
