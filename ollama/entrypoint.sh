#!/bin/sh

ollama serve &

echo "Waiting for Ollama..."

until ollama list >/dev/null 2>&1
do
    sleep 1
done

echo "Ollama ready."

if ! ollama list | grep -q "qwen3:4b-instruct"; then
    echo "Downloading qwen3:4b-instruct..."
    ollama pull qwen3:4b-instruct
else
    echo "qwen3:4b-instruct already set."
fi

wait
