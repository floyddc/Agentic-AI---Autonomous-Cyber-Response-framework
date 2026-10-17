#!/usr/bin/env bash

# Prima clona la repo del progetto, apri /python/config.py e cambia eventualmente i modelli Ollama.

set -Eeuo pipefail

# ============================================================
# Configurazione
# ============================================================

PROJECT_DIR="./Agentic AI - Autonomous Cyber-Response framework"
CONFIG_FILE="$PROJECT_DIR/python/config.py"

# ============================================================
# Gestione errori
# ============================================================

trap 'echo "❌ Errore alla riga $LINENO. Operazione interrotta." >&2' ERR

echo "🚀 Avvio configurazione Ollama..."

# ============================================================
# 1. Verifica dei prerequisiti
# ============================================================

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "❌ File non trovato: $CONFIG_FILE" >&2
    echo "Esegui lo script dalla directory che contiene il progetto." >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "❌ Python 3 è necessario per leggere config.py." >&2
    exit 1
fi

# ============================================================
# 2. Estrazione dei modelli da config.py
# ============================================================

readarray -t MODELS < <(python3 - "$CONFIG_FILE" <<'PY'
import ast
import sys

config_file = sys.argv[1]

with open(config_file, encoding="utf-8") as f:
    source = f.read()

tree = ast.parse(source, filename=config_file)
values = {}

for node in ast.walk(tree):
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = node.value

        for target in targets:
            if isinstance(target, ast.Name) and target.id in (
                "TRIAGE_MODEL",
                "PLAN_MODEL",
            ):
                try:
                    values[target.id] = ast.literal_eval(value)
                except (ValueError, TypeError):
                    pass

for name in ("TRIAGE_MODEL", "PLAN_MODEL"):
    value = values.get(name)

    if not isinstance(value, str) or not value.strip():
        sys.exit(f"Errore: {name} non trovato o non valorizzato "
                 "con una stringa letterale in config.py.")

    print(value.strip())
PY
)

TRIAGE_MODEL="${MODELS[0]}"
PLAN_MODEL="${MODELS[1]}"

echo "📦 Modello di triage: $TRIAGE_MODEL"
echo "📦 Modello di pianificazione: $PLAN_MODEL"

# ============================================================
# 3. Installazione di Ollama
# ============================================================

echo "📥 Installazione di Ollama..."
curl -fsSL https://ollama.com/install.sh | sh

# ============================================================
# 4. Download dei modelli
# ============================================================

echo "📥 Download del modello di triage..."
ollama pull "$TRIAGE_MODEL"

if [[ "$PLAN_MODEL" != "$TRIAGE_MODEL" ]]; then
    echo "📥 Download del modello di pianificazione..."
    ollama pull "$PLAN_MODEL"
else
    echo "ℹ️ I due modelli coincidono: download già effettuato."
fi

# ============================================================
# 5. Configurazione systemd di Ollama
# ============================================================

echo "⚙️ Configurazione del servizio Ollama..."

sudo mkdir -p /etc/systemd/system/ollama.service.d

sudo tee /etc/systemd/system/ollama.service.d/override.conf >/dev/null <<'EOF'
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
EOF

# ============================================================
# 6. Ricarica e riavvio del servizio
# ============================================================

echo "🔄 Ricaricamento configurazione systemd..."
sudo systemctl daemon-reload

echo "🔄 Riavvio di Ollama..."
sudo systemctl restart ollama

# Verifica che il servizio sia attivo
if ! sudo systemctl is-active --quiet ollama; then
    echo "❌ Ollama non risulta attivo dopo il riavvio." >&2
    sudo systemctl status ollama --no-pager || true
    exit 1
fi

# ============================================================
# 7. Completamento
# ============================================================

echo "✅ Tutte le operazioni sono state completate correttamente!"