# Agentic AI - Autonomous Cyber-Response framework

## Tasks
- Sviluppo degli AI Agents per l'ingestion, l'interpretazione e la classificazione degli eventi di sicurezza EDR.
- Sviluppo e integrazione delle logiche di orchestrazione con le API XDR per l'esecuzione automatizzata del contenimento.

## Obiettivi
- Analizzare in tempo reale gli alert EDR tramite AI Agents per valutare accuratamente la criticità delle minacce.
- Ridurre drasticamente il MTTR neutralizzando gli attacchi attraverso azioni di contenimento autonome via XDR.

## Passi preliminari
- Allocazione risorse: `notepad "$env:USERPROFILE\.wslconfig"` da PowerShell
  ```
  [wsl2]
  memory=5GB
  processors=8
  swap=4GB
  ```
  - `memory=8GB` se hai almeno 16GB di RAM.
- Riavvia WSL: `wsl --shutdown` e riavvia Docker Desktop.
- Check: `wsl -d <WSL DISTRO>` -> `egrep '^processor' /proc/cpuinfo | sort -u | wc -l`

## Come avviare
- Creazione container: `docker compose build --no-cache`
- Avvio container: `docker compose up -d`
- Download Qwen: `docker exec -it ollama ollama pull qwen3:4b-instruct` 
- Download embedding model (per il RAG): `docker exec -it ollama ollama pull qllama/multilingual-e5-small`
- Check modelli: `docker exec ollama ollama list`
- Warm-up iniziale di Qwen (consigliato per evitare il primo avvio molto lento):
  `docker exec -it ollama ollama run qwen3:4b-instruct`
  - una volta caricato il modello, esci con `Ctrl+D` oppure scrivendo un messaggio e poi chiudendo la sessione
- Utilizzo memoria: `docker exec -it ollama ollama ps`
- Il sistema RAG esegue anche un warm-up automatico prima della chat, così il primo prompt reale è significativamente più veloce.

## Stack minimale
Servizi attivi in [docker-compose.yml](docker-compose.yml):
- `ollama` — model server (LLM chat + embedding).
- `python-app` — orchestrator/agenti ([RAG/](RAG) + [python/](python)), connesso a `ollama` e `postgres`.
- `postgres` — Incident Registry + Audit Store (schema iniziale in [postgres/init/001_incident_registry.sql](postgres/init/001_incident_registry.sql)), esposto su `localhost:5432` (utente/password/db: `cyberresponse` / `cyberresponse` / `incident_registry`).

## RAG
Il sistema RAG vive in `RAG/` e legge/scrive dati sotto `knowledge/` (montato nel container `python-app`).

- Popola i documenti sorgente sotto `knowledge/base/{mitre_attack,attack_patterns,observables,procedures}`,
  `knowledge/policies/` e `knowledge/actions_catalog/` (file `.md`, `.txt` o `.json`).

- In alternativa, scarica dataset reali da HuggingFace ed esegui la conversione automatica nel formato `knowledge/`:
  `docker exec -it python-app python -m RAG.fetch_datasets --mitre --telemetry`
  - `--mitre`: [sarahwei/cyber_MITRE_attack_tactics-and-techniques](https://huggingface.co/datasets/sarahwei/cyber_MITRE_attack_tactics-and-techniques) (654 Q&A su tattiche/tecniche MITRE ATT&CK v15) → `knowledge/base/mitre_attack/`.
  - `--telemetry`: campione del dataset [An24/IntrusionDetectionSystem-NSL_KDD](https://huggingface.co/datasets/An24/IntrusionDetectionSystem-NSL_KDD) (traffico di rete etichettato attacco/normale) → `knowledge/raw_data/xrd_telemetry/nsl_kdd_sample.json` (dati grezzi, non indicizzati dal RAG).

- Seed del Docs store da filesystem a Postgres (da ripetere quando cambiano i file sotto `knowledge/base/*`):
   - `docker exec -it python-app python -m RAG.seed_knowledge_base`

     - `docker exec -it postgres psql -U cyberresponse -d incident_registry` per controllare il DB `incident_registry`. 
     - `docker exec -it postgres psql -U cyberresponse -d knowledge` per controllare il DB `incident_registry`. 
     - `\dt` per vedere le tabelle.
     - `\q` per uscire.
     - Poi sintassi SQL.

- Costruisci/aggiorna l'indice vettoriale (persistito in `knowledge/indices/`):
  `docker exec -it python-app python -m RAG.build_index`

- Test reranker:
  - `docker exec python python -c "from RAG.context_builder import build_context; print(build_context('How can PowerShell be used for execution?'))"`
  
- Avvia la chat con retrieval-augmented generation. Prima del prompt interattivo il modello viene riscaldato automaticamente:
  `docker exec -it python-app python -m RAG.rag_chat`