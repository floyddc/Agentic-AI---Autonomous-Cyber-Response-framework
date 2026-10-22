# Autonomous Cyber-Response Framework

AI Agent-driven framework for ingesting, interpreting, and classifying EDR security events. Orchestration logic allows automated containment execution.

- [Alert example](#alert-example)
- [Windows setup](#windows-setup)
- [Linux/MacOS setup](#linuxmacos-setup)
- [Repository and containers setup](#repository-and-containers-setup)
- [Dataset download](#dataset-download)
- [DB seeding](#db-seeding)
- [Vector index building](#vector-index-building)
- [Logs management](#logs-management)
- [Run the MAPE-K workflow](#run-the-mape-k-workflow)


## Alert example 
```json
{
  "_source": "EDR",
  "external_id": "test-edr-001",
  "alert_customer_id": 1,
  "host": "workstation-042",
  "user": "alice",
  "alert": "Suspicious PowerShell execution with encoded command",
  "command_line": "powershell.exe -EncodedCommand ...",
  "indicators": ["198.51.100.42"],
  "message": "Possible command and control activity"
}
```
Nested fields are possible, but `alert_customer_id` is absolutely required.

## Windows setup
You need:
- Docker Desktop.
- WSL.
  - Choose how many resources you want to allocate. Type `notepad "$env:USERPROFILE\.wslconfig"` and paste/modify: 
  ```
  [wsl2]
  memory=<RAM_GB>
  processors=<N_CPU>
  swap=<GB>
  ```
  - Then restart the WSL with `wsl --shutdown`.
- Ollama.
  - Install it from here: https://ollama.com/download/OllamaSetup.exe

## Linux/MacOS setup
You need:
- Docker.
- Ollama.
  - Install it with this command: `curl -fsSL https://ollama.com/install.sh | sh`

No other installations are required. 

## Repository and containers setup
```bash
git clone https://github.com/floyddc/AutonomousCyberResponseFramework.git
cd AutonomousCyberResponseFramework
```
```bash
echo "<HF_TOKEN=xxxxxx>" > .env
```
```bash
docker compose build
docker compose up
```
And wait for the pipeline warmup to complete (see logs with `docker logs python-app`).


## Dataset download
All files are stored in `knowledge/base/` and divided into different folders.
```powershell
docker exec -it python-app python -m knowledge.fetch_datasets --mitre --telemetry --observables --threatfox-days <N> --sample-size <N>
```
`sample-size` is the maximum limit of MITRE procedures to be saved. I suggest 200 just for beginning.


## DB seeding
```powershell
docker exec -it python-app python -m postgres.seed_knowledge_base`
```

## Vector index building
The index is stored in `knowledge/indices/`
- First run:
  ```powershell
  docker compose run --rm --no-deps python python -m RAG.build_index --reset
  ```
- Then, periodically:
  ```powershell
  docker compose run --rm --no-deps python python -m RAG.build_index
  ```


## Logs management
- Clean all:
  ```powershell
  docker exec -it python-app python -m MAPE.logging_agent --clear; truncate -s 0 "$(docker inspect --format='{{.LogPath}}' python-app)"
  ```
- Print logs of the last run:
  ```powershell
  docker exec -it python-app python -m MAPE.logging_agent --tail 14; docker logs python-app
  ```

## Run the MAPE-K workflow
- Windows:
  ```powershell
  curl.exe -X POST http://localhost:8000/alerts -H "Content-Type: application/json" --data-binary "@<ALERT_PATH>"
  ```
- Linux/MacOS:
  ```powershell
  curl -X POST http://localhost:8000/alerts -H "Content-Type: application/json" --data-binary "@<ALERT_PATH>"
  ```



## Grafana - to review
- `localhost:3000`
  - Default credentials: `admin / admin`

## Prometheus - to review
- `localhost:9090`