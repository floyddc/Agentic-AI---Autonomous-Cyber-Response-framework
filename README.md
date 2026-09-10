# Agentic AI - Autonomous Cyber-Response framework

## Tasks
- Sviluppo degli AI Agents per l'ingestion, l'interpretazione e la classificazione degli eventi di sicurezza EDR.
- Sviluppo e integrazione delle logiche di orchestrazione con le API XDR per l'esecuzione automatizzata del contenimento.

## Obiettivi
- Analizzare in tempo reale gli alert EDR tramite AI Agents per valutare accuratamente la criticità delle minacce.
- Ridurre drasticamente il MTTR neutralizzando gli attacchi attraverso azioni di contenimento autonome via XDR.

## Passi preliminari
**1. Allocazione risorse:** `notepad "$env:USERPROFILE\.wslconfig"` (PowerShell).
  ```
  [wsl2]
  memory=5GB
  processors=8
  swap=4GB
  ```
  - `memory=8GB` se hai almeno 16GB di RAM.

**2. Riavvio WSL:** `wsl --shutdown` e riavvia Docker Desktop.

**3. Check:** `wsl -d <WSL DISTRO>` -> `egrep '^processor' /proc/cpuinfo | sort -u | wc -l`

## Avvio dei container
**1. Creazione container:** `docker compose build --no-cache`

**2. Avvio container:** `docker compose up`
  
  - Lo script all'avvio dovrebbe scaricare subito l'LLM (ed effettuarne il warm-up) e il modello di embeddings.

**3. Check:**
  - Modelli: `docker exec ollama ollama list`
  - Utilizzo memoria: `docker exec -it ollama ollama ps`
  - Filesystem dei container: `docker exec -it <CONTAINER_NAME> bash`

**Prima di eseguire il workflow, `ollama` e `postgres` devono risultare healthy e `python-app` deve essere in esecuzione.**

### Preparare un alert EDR di test

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

Il file viene scritto nella directory `knowledge/`, che e' montata nel container `python-app`.

## Setup del RAG Engine
Il sistema RAG vive in `RAG/` e legge/scrive dati sotto `knowledge/` (montato nel container `python-app`).

**1. Popolare i documenti sorgente** sotto `knowledge/base/{mitre_attack,attack_patterns,observables,procedures}`, `knowledge/policies/` e `knowledge/actions_catalog/` (file `.md`, `.txt` o `.json`). In alternativa, **scaricare dataset reali da HuggingFace** ed eseguire conversione automatica nel formato `knowledge/`, tramite:

  - `docker exec -it python-app python -m knowledge.fetch_datasets --mitre --telemetry`

      - `--mitre`: [sarahwei/cyber_MITRE_attack_tactics-and-techniques](https://huggingface.co/datasets/sarahwei/cyber_MITRE_attack_tactics-and-techniques) (654 Q&A su tattiche/tecniche MITRE ATT&CK v15) → `knowledge/base/mitre_attack/`.

      - `--telemetry`: campione del dataset [An24/IntrusionDetectionSystem-NSL_KDD](https://huggingface.co/datasets/An24/IntrusionDetectionSystem-NSL_KDD) (traffico di rete etichettato attacco/normale) → `knowledge/raw_data/xrd_telemetry/nsl_kdd_sample.json` (dati grezzi, non indicizzati dal RAG).

**2. Seeding dei documenti da filesystem a Postgres** (da ripetere quando cambiano i file sotto `knowledge/base/*`):

   - `docker exec -it python-app python -m postgres.seed_knowledge_base`

     - Check del DB `incident_registry`:
       - `docker exec -it postgres psql -U cyberresponse -d incident_registry` 

     - Check del DB `knowledge`:
       - `docker exec -it postgres psql -U cyberresponse -d knowledge` 

     - Vedere tabelle: `\dt`

     - Uscire: `\q`
     
     - Poi sintassi SQL.

**3. Costruire/aggiornare indice vettoriale** (persistito in `knowledge/indices/`):

  - `docker exec -it python-app python -m RAG.build_index`

**4. Test del flusso completo (Retrieve Agent + Response Agent):**

  - `docker exec python-app python -c "from RAG.api import query_rag; print(query_rag('How can PowerShell be used for execution?'))"`


## Eseguire il workflow MAPE-K
Il comando seguente esegue `TriageAgent`, `RetrieveAgent`, `ActionPlannerAgent`, `ValidationAgent` e `ResponseLayer` nello stesso workflow:

  - `docker exec python-app python -m MAPE.orchestrator_agent /app/knowledge/raw_data/edr_alerts/test_alert.json`

Nel JSON restituito verificare:

- `incident_id` valorizzato.

- `status` uguale a `responded` in caso di esecuzione completata.

- presenza di `triage`, `context`, `action_plan`, `validation` ed `execution`.

- `validation.approved_actions` contenente almeno un'azione approvata.

Il modello puo' proporre azioni diverse in base al contesto. Se propone un'azione non presente nel catalogo, oppure nessuna azione, il risultato atteso e' `status: "failed"` con `phase: "validation"`: questo indica un rifiuto corretto della policy, non un errore del database.

## Controllare stato e audit trail
Sostituire `<INCIDENT_ID>` con l'ID restituito dal comando precedente:

  - `docker exec postgres psql -U cyberresponse -d incident_registry -c "SELECT id, source, external_id, severity, status, created_at, updated_at FROM incidents WHERE id = <INCIDENT_ID>;"`

  - `docker exec postgres psql -U cyberresponse -d incident_registry -c "SELECT agent, action, details, created_at FROM audit_log WHERE incident_id = <INCIDENT_ID> ORDER BY created_at;"`

La seconda query deve mostrare almeno le azioni di `orchestrator_agent`, `triage_agent`, `retrieve_agent`, `action_planner_agent`, `validation_agent` e `response_layer`.

## Controllare metriche e log

  - `docker exec -it python-app python -m MAPE.logging_agent --tail 30`

  - `docker logs otel-collector --tail 50`


Per una nuova esecuzione con gli stessi dati usare un `external_id` differente. Gli script SQL dentro `postgres/init/` vengono eseguiti automaticamente solo quando il volume Postgres viene creato per la prima volta.
