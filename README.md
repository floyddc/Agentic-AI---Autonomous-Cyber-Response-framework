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
- Avvio container: `docker compose up`
  - Lo script all'avvio dovrebbe scaricare subito l'LLM (ed effettuarne il warm-up) e il modello di embeddings.
- Check modelli: `docker exec ollama ollama list`
- Utilizzo memoria: `docker exec -it ollama ollama ps`
- Check del filesystem dei container: `docker exec -it <CONTAINER_NAME> bash`

## Stack minimale
Servizi attivi in [docker-compose.yml](docker-compose.yml):
- `ollama` — model server (LLM chat + embedding).
- `python-app` — orchestrator/agenti ([RAG/](RAG) + [python/](python)), connesso a `ollama` e `postgres`.
- `postgres` — Incident Registry + Audit Store (schema iniziale in [postgres/init/001_incident_registry.sql](postgres/init/001_incident_registry.sql)), esposto su `localhost:5432` (utente/password/db: `cyberresponse` / `cyberresponse` / `incident_registry`).
- `otel-collector` — OpenTelemetry Collector che riceve le metriche del Logging Agent via OTLP (porte `4317` gRPC / `4318` HTTP) e le stampa a log (config in [otel-collector/config.yaml](otel-collector/config.yaml)), pronto per essere ripuntato su un backend reale (es. Prometheus/Grafana).

## RAG
Il sistema RAG vive in `RAG/` e legge/scrive dati sotto `knowledge/` (montato nel container `python-app`).

- Popola i documenti sorgente sotto `knowledge/base/{mitre_attack,attack_patterns,observables,procedures}`,
  `knowledge/policies/` e `knowledge/actions_catalog/` (file `.md`, `.txt` o `.json`).

- In alternativa, scarica dataset reali da HuggingFace ed esegui la conversione automatica nel formato `knowledge/`:
  - `docker exec -it python-app python -m RAG.fetch_datasets --mitre --telemetry`
    - `--mitre`: [sarahwei/cyber_MITRE_attack_tactics-and-techniques](https://huggingface.co/datasets/sarahwei/cyber_MITRE_attack_tactics-and-techniques) (654 Q&A su tattiche/tecniche MITRE ATT&CK v15) → `knowledge/base/mitre_attack/`.
    - `--telemetry`: campione del dataset [An24/IntrusionDetectionSystem-NSL_KDD](https://huggingface.co/datasets/An24/IntrusionDetectionSystem-NSL_KDD) (traffico di rete etichettato attacco/normale) → `knowledge/raw_data/xrd_telemetry/nsl_kdd_sample.json` (dati grezzi, non indicizzati dal RAG).

- Seed del Docs store da filesystem a Postgres (da ripetere quando cambiano i file sotto `knowledge/base/*`):
   - `docker exec -it python-app python -m RAG.seed_knowledge_base`

     - `docker exec -it postgres psql -U cyberresponse -d incident_registry` per controllare il DB `incident_registry`. 
    - `docker exec -it postgres psql -U cyberresponse -d knowledge` per controllare il DB `knowledge`. 
     - `\dt` per vedere le tabelle.
     - `\q` per uscire.
     - Poi sintassi SQL.

- Costruisci/aggiorna l'indice vettoriale (persistito in `knowledge/indices/`):
  `docker exec -it python-app python -m RAG.build_index`

- Test del solo **Retrieve Agent** (recupero contesto da ChromaDB + reranker, senza LLM):
  `docker exec -it python-app python -m RAG.retrieve_agent "How can PowerShell be used for execution?"`

- Test del solo **Response Agent** (generazione con Qwen fornendo un contesto):
  `docker exec python-app python -c "from RAG.response_agent import ResponseAgent; print(ResponseAgent().ask('Come isolare un host?', context='Policy: Isolare via EDR API in caso di malware.'))"`

- Test del **flusso completo** (Retrieve Agent + Response Agent):
  - Singola query: `docker exec python-app python -c "from RAG.api import query_rag; print(query_rag('How can PowerShell be used for execution?'))"`
  - Chat interattiva: `docker exec -it python-app python -m RAG.rag_chat`

## Test del workflow orchestrato
L'`OrchestratorAgent` gestisce un alert dall'ingestion fino alla risposta automatizzata con il seguente flusso:

```text
new -> triage -> triaged -> retrieve -> validation -> validated -> response -> responded
```

In caso di errore tecnico o di piano d'azione non approvato dalla policy, lo stato diventa `failed`.

### 1. Verifica dei servizi
Da PowerShell, nella directory principale del progetto:

```powershell
docker compose up -d
docker compose ps
docker inspect --format='{{.State.Health.Status}}' ollama
docker inspect --format='{{.State.Health.Status}}' postgres
```

Prima di eseguire il workflow, `ollama` e `postgres` devono risultare healthy e `python-app` deve essere in esecuzione.

### 2. Prepara un alert EDR di test
Il file viene scritto nella directory `knowledge/`, che e' montata nel container `python-app`.

```powershell
@'
{
  "_source": "EDR",
  "external_id": "test-edr-001",
  "host": "workstation-042",
  "user": "alice",
  "alert": "Suspicious PowerShell execution with encoded command",
  "command_line": "powershell.exe -EncodedCommand ...",
  "indicators": ["198.51.100.42"],
  "message": "Possible command and control activity"
}
'@ | Set-Content -Encoding utf8 knowledge/raw_data/edr_alerts/test_alert.json
```

### 3. Esegui l'orchestratore
Il comando seguente esegue `TriageAgent`, `RetrieveAgent`, `ResponseAgent`, `ValidationAgent` e `ResponseLayer` nello stesso workflow:

```powershell
docker exec python-app python -m RAG.orchestrator_agent /app/knowledge/raw_data/edr_alerts/test_alert.json
```

Nel JSON restituito verificare:

- `incident_id` valorizzato;
- `status` uguale a `responded` in caso di esecuzione completata;
- presenza di `triage`, `context`, `action_plan`, `validation` ed `execution`;
- `validation.approved_actions` contenente almeno un'azione approvata.

Il modello puo' proporre azioni diverse in base al contesto. Se propone un'azione non presente nel catalogo, oppure nessuna azione, il risultato atteso e' `status: "failed"` con `phase: "validation"`: questo indica un rifiuto corretto della policy, non un errore del database.

### 4. Controlla stato e audit trail
Sostituire `<INCIDENT_ID>` con l'ID restituito dal comando precedente:

```powershell
docker exec postgres psql -U cyberresponse -d incident_registry -c "SELECT id, source, external_id, severity, status, created_at, updated_at FROM incidents WHERE id = <INCIDENT_ID>;"
docker exec postgres psql -U cyberresponse -d incident_registry -c "SELECT agent, action, details, created_at FROM audit_log WHERE incident_id = <INCIDENT_ID> ORDER BY created_at;"
```

La seconda query deve mostrare almeno le azioni di `orchestrator_agent`, `triage_agent`, `retrieve_agent`, `response_agent`, `validation_agent` e `response_layer`.

### 5. Test rapido senza file
Per provare il percorso direttamente da Python:

```powershell
docker exec python-app python -c "from RAG.orchestrator_agent import handle_alert; import json; result = handle_alert('EDR', {'host': 'workstation-042', 'alert': 'Suspicious PowerShell execution', 'indicators': ['198.51.100.42']}, 'test-edr-002'); print(json.dumps(result, indent=2, default=str))"
```

### 6. Controlla metriche e log

```powershell
docker exec -it python-app python -m RAG.logging_agent --tail 30
docker logs otel-collector --tail 50
```

Per una nuova esecuzione con gli stessi dati usare un `external_id` differente. Gli script SQL dentro `postgres/init/` vengono eseguiti automaticamente solo quando il volume Postgres viene creato per la prima volta.

## Logging Agent
Il **Logging Agent** ([RAG/logging_agent.py](RAG/logging_agent.py)) riceve, correla e salva le metriche di
tutti i componenti del sistema (Retrieve Agent, Response Agent, Incident Registry, ...). Ogni
event record viene scritto su Postgres nella tabella `agent_metrics` e, in parallelo, esportato come metrica OpenTelemetry (counter
`agent_events_total`, histogram `agent_duration_ms`) verso il servizio `otel-collector`.

- Gli agenti esistenti (`RetrieveAgent`, `ResponseAgent`, `IncidentRegistry`) sono già
  strumentati: ogni chiamata a `retrieve`, `ask`, `create_incident`, `close_incident` e
  `log_action` produce automaticamente una metrica (componente, azione, esito, durata).
- Per strumentare un nuovo componente, basta avvolgerne il codice con il context manager:
  ```python
  from RAG.logging_agent import logging_agent

  with logging_agent.track("multi_agent_orchestration", "run_cycle", incident_id=incident_id):
      ...
  ```
- Ispeziona le ultime metriche salvate su Postgres:
  `docker exec -it python-app python -m RAG.logging_agent --tail 20`
  - oppure via psql: `docker exec -it postgres psql -U cyberresponse -d incident_registry -c "SELECT * FROM agent_metrics ORDER BY created_at DESC LIMIT 20;"`
- Ispeziona le metriche esportate via OpenTelemetry (debug exporter):
  `docker logs otel-collector`