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
  memory=6GB
  processors=8
  swap=4GB
  ```
  - `memory=8-12GB` se hai almeno 16GB di RAM.

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

  - `docker exec -it python-app python -m knowledge.fetch_datasets --mitre --telemetry --observables --threatfox-days <N> --sample-size <N>`

**2. Seeding dei documenti da filesystem a Postgres** (da ripetere quando cambiano i file sotto `knowledge/base/*`):

   - `docker exec -it python-app python -m postgres.seed_knowledge_base`

     - Check del DB `incident_registry`:
       - `docker exec -it postgres psql -U cyberresponse -d incident_registry` 

     - Check del DB `knowledge`:
       - `docker exec -it postgres psql -U cyberresponse -d knowledge` 

     - Vedere tabelle: `\dt`

     - Uscire: `\q`
     
     - Poi sintassi SQL, es:
       - Eliminare record delle metriche, azzerando il contatore degli id: `TRUNCATE TABLE agent_metrics RESTART IDENTITY;`

**3. Costruire/aggiornare indice vettoriale** (persistito in `knowledge/indices/`):

  - `docker exec -it python-app python -m RAG.build_index`


## Eseguire il workflow MAPE-K
Il comando seguente esegue `TriageAgent`, `RetrieveAgent`, `ActionPlannerAgent`, `ValidationAgent` e `ResponseLayer` nello stesso workflow:

  - `docker exec python-app python -m MAPE.orchestrator /app/knowledge/raw_data/edr_alerts/test_alert.json`

Nel JSON restituito verificare:

- `incident_id` valorizzato.

- `status` uguale a `responded` in caso di esecuzione completata.

- presenza di `triage`, `context`, `action_plan`, `validation` ed `response`.

- `validation.approved_actions` contenente almeno un'azione approvata.

Il modello puo' proporre azioni diverse in base al contesto. Se propone un'azione non presente nel catalogo, oppure nessuna azione, il risultato atteso e' `status: "failed"` con `phase: "validation"`: questo indica un rifiuto corretto della policy, non un errore del database.

## Controllare metriche e log

  - `docker exec -it python-app python -m MAPE.logging_agent --tail <N>`

  - `docker logs otel-collector --tail <N>`

  - `docker exec -it python-app python -m MAPE.logging_agent --clear` per pulire.

Per una nuova esecuzione con gli stessi dati usare un `external_id` differente. Gli script SQL dentro `postgres/init/` vengono eseguiti automaticamente solo quando il volume Postgres viene creato per la prima volta.


## Controllare stato e audit trail
Sostituire `<INCIDENT_ID>` con l'ID restituito dal comando precedente:

  - `docker exec postgres psql -U cyberresponse -d incident_registry -c "SELECT id, source, external_id, severity, status, created_at, updated_at FROM incidents WHERE id = <INCIDENT_ID>;"`

  - `docker exec postgres psql -U cyberresponse -d incident_registry -c "SELECT agent, action, details, created_at FROM audit_log WHERE incident_id = <INCIDENT_ID> ORDER BY created_at;"`

La seconda query deve mostrare almeno le azioni di `orchestrator`, `triage_agent`, `retrieve_agent`, `action_planner_agent`, `validation_agent` e `response_layer`.


## [WORK IN PROGRESS] MQTT BROKER CLUSTER

- Avviare i 3 broker con `docker compose up -d emqx-1 emqx-2 emqx-3`.

- Dopo qualche seconod, check del cluster con `docker compose exec emqx-1 emqx ctl cluster status`.
  - Dovrebbe apparire un output del tipo:
     ```
     Cluster status: #{running_nodes =>
                      ['emqx@node1.emqx.local','emqx@node2.emqx.local','emqx@node3.emqx.local'],
                  stopped_nodes => []}
     ```

- Check del failover con `docker compose stop emqx-1` e poi `docker compose exec emqx-2 emqx ctl cluster status`.
  - Dovrebbe apparire un output del tipo:
     ```
     Cluster status: #{running_nodes =>
                      ['emqx@node2.emqx.local','emqx@node3.emqx.local'],
                  stopped_nodes => ['emqx@node1.emqx.local']}
     ```
  - Riavvio del broker con `docker compose start emqx-1`

- Test della connessione e pubblicazione messaggi: `docker compose exec python python test_mqtt.py`
  - Dovrebbe apparire un output del tipo:
    ```
    2026-09-29 07:53:19,694 INFO MQTT.client: Connecting to MQTT broker emqx-1:1883
    2026-09-29 07:53:19,860 INFO MQTT.client: Connected to MQTT broker emqx-1:1883
    2026-09-29 07:53:19,903 INFO MQTT.client: Subscribed to MQTT topic=cyberresponse/test qos=1 mid=1
    2026-09-29 07:53:20,904 INFO __main__: Publishing test message
    2026-09-29 07:53:20,911 INFO MQTT.client: MQTT message received topic=cyberresponse/test payload={"event_id": "mqtt-test-001", "message": "hello from cyber-response", "source": "python"}
    2026-09-29 07:53:20,911 INFO __main__: TEST RECEIVED: topic=cyberresponse/test payload={"event_id": "mqtt-test-001", "message": "hello from cyber-response", "source": "python"}
    2026-09-29 07:53:22,911 WARNING MQTT.client: Disconnected from MQTT broker: Normal disconnection
    2026-09-29 07:53:22,912 INFO __main__: MQTT test completed successfully
    ```