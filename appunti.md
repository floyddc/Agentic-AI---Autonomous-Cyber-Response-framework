## Comandi per installare Ollama e Qwen
- Creazione container: `docker compose build`
- Avvio container: `docker compose up -d` con `docker-compose.yml` pronto
- Download Qwen: `docker exec -it ollama ollama pull qwen3:4b-instruct` 
- Check modelli: `docker exec ollama ollama list`
- Avvio: `docker exec -it ollama ollama run qwen3:4b-instruct`
- Utilizzo memoria: `docker exec -it ollama ollama ps`
- Crazione modello nothink (ora dovrebbe stare in `entrypoint.sh`): `docker exec ollama ollama create qwen3:4b-nothink -f /Modelfile`

docker compose down
docker compose build --no-cache ollama
docker compose up -d --force-recreate ollama


- Allocazione risorse: `notepad "$env:USERPROFILE\.wslconfig"` da PS
  ```
  [wsl2]
  memory=5GB
  processors=8
  swap=4GB
  ```
  - Riavvia WSL: `wsl --shutdown` e riavvia Docker desktop
  - Check: `wsl -d Ubuntu-24.04 free -h`

su CPU: qwen3.8 quantizzato, fine tuning per disattivare thinking
da affiancare dflash2

oppure direttamente qwen3.8flash