# -------- Base: slim, fast, pure-Python worker --------
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates tzdata curl \
  && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Default for your stack; can still be overridden by compose
ENV REDIS_URL=redis://openrelik-redis:6379

WORKDIR /openrelik

COPY pyproject.toml ./
RUN python -m pip install --upgrade pip

COPY src ./src
COPY openrelik.yaml ./openrelik.yaml
RUN pip install .

# Optional CLI for local tests
RUN printf '%s\n' \
'#!/usr/bin/env python3' \
'import sys, json, os' \
'from src.evtx_ip_extract import extract_ips_from_evtx_files' \
'' \
'def main():' \
'    if len(sys.argv) < 3:' \
'        print("Usage: extract-ips <evtx1> [<evtx2> ...] <out_dir> [include_context=true|false]")' \
'        sys.exit(1)' \
'    args = sys.argv[1:]' \
'    include_context = True' \
'    if args[-1].lower() in ("true","false"):' \
'        include_context = (args[-1].lower() == "true")' \
'        args = args[:-1]' \
'    out_dir = args[-1]' \
'    evtx_files = args[:-1]' \
'    os.makedirs(out_dir, exist_ok=True)' \
'    res = extract_ips_from_evtx_files(evtx_files, include_context=include_context)' \
'    with open(os.path.join(out_dir, "unique_ips.json"), "w", encoding="utf-8") as f:' \
'        json.dump(res.get("unique_ips", []), f, ensure_ascii=False, indent=2)' \
'    if include_context:' \
'        with open(os.path.join(out_dir, "ip_hits_with_context.json"), "w", encoding="utf-8") as f:' \
'            json.dump(res.get("records", []), f, ensure_ascii=False, indent=2, default=str)' \
'    print(json.dumps({"counts": res.get("counts", {}), "out_dir": out_dir}, indent=2))' \
'' \
'if __name__ == "__main__":' \
'    main()' \
> /usr/local/bin/extract-ips && chmod +x /usr/local/bin/extract-ips

CMD ["celery", "--app=src.app", "worker", "--task-events", "--concurrency=1", "--loglevel=INFO", "-Q", "openrelik-worker-ip-extractor"]
