## Comandi per installare Ollama e Qwen
- Creazione container: `docker compose build`
- Avvio container: `docker compose up -d` con `docker-compose.yml` pronto
- Download Qwen: `docker exec -it ollama ollama pull qwen3:4b-instruct` 
- Check modelli: `docker exec ollama ollama list`
- Avvio: `docker exec -it ollama ollama run qwen3:4b-instruct`
- Utilizzo memoria: `docker exec -it ollama ollama ps`

<br><br>


- `docker compose down`
- `docker compose build --no-cache ollama`
- `docker compose up -d --force-recreate ollama`


- Allocazione risorse: `notepad "$env:USERPROFILE\.wslconfig"` da PS
  ```
  [wsl2]
  memory=5GB
  processors=8
  swap=4GB
  ```
  - `memory=8GB` se hai almeno 16GB di RAM.
  - Riavvia WSL: `wsl --shutdown` e riavvia Docker desktop
  - Check: `wsl -d <WSL DISTRO>` -> `egrep '^processor' /proc/cpuinfo | sort -u | wc -l`

 ```
                  ┌──────────────┐
                  │ EDR / SIEM   │
                  │ XDR          │
                  └──────┬───────┘
                         │
                       ALERT
                         ▼
              ┌────────────────────┐
              │ INCIDENT REGISTRY  │
              │                    │
              │ Alert / Case       │
              └─────────┬──────────┘
                        │
                       CASE
                        ▼
              ┌────────────────────┐
              │ AI TRIAGE &        │
              │ CONTAINMENT        │
              └─────────┬──────────┘
                        │
                 Knowledge Query
                        ▼
              ┌────────────────────┐
              │ KNOWLEDGE LAYER    │
              │                    │
              │ RAG                │
              │ MITRE / Sigma      │
              │ Runbooks / TI      │
              │ Historical Cases   │
              └─────────┬──────────┘
                        │
                     Context
                        ▼
              ┌────────────────────┐
              │ DECISION AGENTS    │
              └─────────┬──────────┘
                        ▼
              ┌────────────────────┐
              │ ORCHESTRATION      │
              └─────────┬──────────┘
                        ▼
              ┌────────────────────┐
              │ RESPONSE           │
              └─────────┬──────────┘
                        │
                        └────────────► Incident Registry

 ```

  ```
EDR/SIEM/XDR
     ↓
┌───────────────────────┐
│ AI PLATFORM           │
│                       │
│ AI Triage             │
│ Ollama + Qwen3        │
│ RAG / Vector DB       │
│ Incident Registry     │
│ Decision Agents       │
│ Orchestrator          │
└──────────┬────────────┘
           ↓
         XDR
           ↓
 Endpoint / Network / Cloud
  ```

Componente Responsabilità<br>
EDR / SIEM / XDR	    Monitoraggio e detection<br>
Incident Registry	Gestione di alert e case<br>
AI Triage & Containment	Analisi e investigazione<br>
RAG / Knowledge Layer	Fornitura di conoscenza/evidenze<br>
Decision Agents	Decisione sulla risposta<br>
Orchestration	Esecuzione/coordinamento<br>
Response	Contenimento effettivo