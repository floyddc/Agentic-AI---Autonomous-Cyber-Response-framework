```
[EDR / External Source]
       │
       ▼ (HTTP / Webhook)
[Ingestion API] ──(DB Transaction)──► 1. INSERT INTO incidents (status='new')
                                       2. INSERT INTO event_outbox (INCIDENT_CREATED)
                                       
[OutboxPublisher Daemon] ◄──(POLL SKIP LOCKED)── event_outbox
       │
       ▼ (MQTT Publish)
   [EMQX Cluster]
       │
       ├─► $share/retrieve-workers/cyberresponse/incident/created
       │          │
       │          ▼
       │   [RetrieveAgent Worker]
       │          │
       │          ├─► 1. INSERT INTO event_inbox (status='received')
       │          ├─► 2. Update event_inbox (status='processing')
       │          ├─► 3. Logica RAG / Ollama
       │          └─► 4. registry.transition(status='retrieved')
       │                      │
       │                      └─► DB Transaction:
       │                             - UPDATE incidents.status = 'retrieved'
       │                             - INSERT INTO audit_log
       │                             - INSERT INTO event_outbox (INCIDENT_RETRIEVED)
       │
       └─► [MaintenanceDaemon] (In sottofondo ogni 60s)
                  │
                  └─► recover_stale_events() -> Ripristina eventi bloccati in 'processing'
```