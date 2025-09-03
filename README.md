# OpenRelik Worker: IP Extractor (WORK IN PROGRESS)

## Description
This worker extracts IPv4 and IPv6 addresses from:

- **Windows Event Logs** (`.evtx` files)  
  → Parses event records, extracts IPs from fields and text, and can include context such as timestamp, channel, provider, event ID, and record ID.

- **Linux / Text Logs** (`.log`, `.txt`, `syslog`, `auth.log`, `messages`, `secure`, including `.gz`/`.bz2`)  
  → Scans plain text using regex, detects syslog-like timestamps and common web access log formats, and includes file name, line number, and log kind (syslog/access).

Outputs can include:
- Unique IPs (`.txt`, `.json`)
- Full per-record context (`.json`)
- Optional CSV (Timesketch-friendly)
- Optional NDJSON (streaming / grep-friendly)

This worker can be used in OpenRelik workflows or as a standalone container for quick log parsing.

---

## Deploy

Add the following service definition to your `docker-compose.yml` (or Tilt config):

```yaml
openrelik-worker-ip-extractor:
  container_name: openrelik-worker-ip-extractor
  image: ghcr.io/openrelik/openrelik-worker-ip-extractor:latest
  restart: always
  environment:
    - REDIS_URL=redis://openrelik-redis:6379
    - OPENRELIK_PYDEBUG=0
  depends_on:
    - openrelik-redis
  volumes:
    - ./data:/usr/share/openrelik/data
  command: >
    celery --app=src.app worker --task-events --concurrency=4
    --loglevel=INFO -Q openrelik-worker-ip-extractor
  # ports:
  #   - 5678:5678 # For debugging purposes.

Once deployed, the worker will register as “IP Extractor (EVTX + Linux logs)” in the OpenRelik UI.
