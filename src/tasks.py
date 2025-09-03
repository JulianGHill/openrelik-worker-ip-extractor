from __future__ import annotations
import csv
import json
import os
from typing import Dict, List, Optional, Tuple

# OpenRelik worker common helpers
from openrelik_worker_common.file_utils import create_output_file
from openrelik_worker_common.logging import Logger
from openrelik_worker_common.task_utils import create_task_result, get_input_files

# Celery app (from the template)
from .app import celery
from celery import signals

# Core extractors
from .evtx_ip_extract import extract_ips_from_evtx_files
from .linux_ip_extract import extract_ips_from_text_files  # <-- NEW

# --------------------------------------------------------------------------------------
# Task registration
# --------------------------------------------------------------------------------------
TASK_NAME = "openrelik-worker-ip-extractor.tasks.extract_ips"

TASK_METADATA = {
    "display_name": "IP Extractor (EVTX + Linux logs)",
    "description": (
        "Extract IPv4/IPv6 addresses from Windows Event Logs (.evtx) and Linux text logs "
        "(.log/.txt/syslog/auth.log/messages/secure, including .gz/.bz2). "
        "Optionally emits per-record context, CSV, and NDJSON."
    ),
    # Rendered as a form in the UI; values arrive in task_config
    "task_config": [
        {
            "name": "include_context",
            "label": "Include per-record context",
            "description": "Return detailed records (timestamp/channel/provider/event_id/record_id/source/line_no).",
            "type": "checkbox",
            "required": False,
        },
        {
            "name": "ignore_private",
            "label": "Ignore private ranges (RFC1918 etc.)",
            "description": "Filter out 10.0.0.0/8, 172.16/12, 192.168/16, unique local IPv6, etc.",
            "type": "checkbox",
            "required": False,
        },
        {
            "name": "include_linux_logs",
            "label": "Scan Linux text logs (.log/.gz/.bz2/syslog/auth.log/messages/secure)",
            "description": "Also parse generic text logs for IPs.",
            "type": "checkbox",
            "required": False,
        },
        {
            "name": "emit_csv",
            "label": "Also write CSV (Timesketch-friendly)",
            "description": "Write a CSV with common context columns.",
            "type": "checkbox",
            "required": False,
        },
        {
            "name": "emit_ndjson",
            "label": "Also write NDJSON (one JSON per line)",
            "description": "Useful for streaming/grep-friendly processing.",
            "type": "checkbox",
            "required": False,
        },
    ],
}

log = Logger()
logger = log.get_logger(__name__)


@signals.task_prerun.connect
def on_task_prerun(sender, task_id, task, args, kwargs, **_):
    log.bind(task_id=task_id, task_name=task.name, worker_name=TASK_METADATA.get("display_name"))


@celery.task(bind=True, name=TASK_NAME, metadata=TASK_METADATA)
def command(
    self,
    pipe_result: str = None,
    input_files: list = None,
    output_path: str = None,
    workflow_id: str = None,
    task_config: dict = None,
) -> str:
    """
    Extract IPs from EVTX and (optionally) Linux text logs and write outputs.

    Returns:
        Base64-encoded dict via create_task_result.
    """
    # ------------------------------------------------------------
    # Setup / inputs
    # ------------------------------------------------------------
    log.bind(workflow_id=workflow_id)
    logger.info(f"Starting {TASK_NAME} for workflow_id={workflow_id}")

    cfg = task_config or {}
    include_context: bool = bool(cfg.get("include_context", True))
    ignore_private: bool = bool(cfg.get("ignore_private", True))
    include_linux_logs: bool = bool(cfg.get("include_linux_logs", True))
    emit_csv: bool = bool(cfg.get("emit_csv", False))
    emit_ndjson: bool = bool(cfg.get("emit_ndjson", False))

    # Collect input files (from previous pipe or from UI-provided inputs)
    files = get_input_files(pipe_result, input_files or [])

    evtx_paths: List[str] = []
    text_paths: List[str] = []

    # Common Linux log basenames (no extension)
    linux_names = {"syslog", "auth.log", "messages", "secure"}

    for f in files:
        p = f.get("path")
        if not p or not os.path.isfile(p):
            continue
        lp = p.lower()
        if lp.endswith(".evtx"):
            evtx_paths.append(p)
        elif include_linux_logs:
            if lp.endswith((".log", ".txt", ".gz", ".bz2")) or os.path.basename(lp) in linux_names:
                text_paths.append(p)

    if not evtx_paths and not text_paths:
        raise RuntimeError(
            "No supported input files found. "
            "Accepted: .evtx, .log, .txt, .gz, .bz2, or syslog/auth.log/messages/secure."
        )

    # ------------------------------------------------------------
    # Extract from EVTX and Linux logs
    # ------------------------------------------------------------
    combined_unique = set()
    combined_records: List[Dict] = []
    counts = {"evtx_unique": 0, "linux_unique": 0, "evtx_records": 0, "linux_records": 0}

    if evtx_paths:
        evtx_res = extract_ips_from_evtx_files(
            evtx_paths=evtx_paths,
            include_context=include_context,
            ignore_private=ignore_private,
            ignore_link_local=True,
            ignore_reserved=False,
            ignore_loopback=True,
            ignore_multicast=True,
        )
        evtx_unique = set(evtx_res.get("unique_ips", []))
        combined_unique |= evtx_unique
        if include_context:
            combined_records.extend(evtx_res.get("records", []))
        counts["evtx_unique"] = len(evtx_unique)
        counts["evtx_records"] = len(evtx_res.get("records", [])) if include_context else 0

    if text_paths:
        text_res = extract_ips_from_text_files(
            log_paths=text_paths,
            include_context=include_context,
            ignore_private=ignore_private,
            ignore_link_local=True,
            ignore_reserved=False,
            ignore_loopback=True,
            ignore_multicast=True,
        )
        text_unique = set(text_res.get("unique_ips", []))
        combined_unique |= text_unique
        if include_context:
            combined_records.extend(text_res.get("records", []))
        counts["linux_unique"] = len(text_unique)
        counts["linux_records"] = len(text_res.get("records", [])) if include_context else 0

    unique_ips = sorted(combined_unique)

    # ------------------------------------------------------------
    # Write outputs
    # ------------------------------------------------------------
    output_files = []

    # 1) unique IPs (txt + json)
    uniq_txt = create_output_file(
        output_path, display_name="unique_ips", extension="txt", data_type="ip-list"
    )
    with open(uniq_txt.path, "w", encoding="utf-8") as fh:
        for ip in unique_ips:
            fh.write(f"{ip}\n")
    output_files.append(uniq_txt.to_dict())

    uniq_json = create_output_file(
        output_path, display_name="unique_ips", extension="json", data_type="json"
    )
    with open(uniq_json.path, "w", encoding="utf-8") as fh:
        json.dump(unique_ips, fh, ensure_ascii=False, indent=2)
    output_files.append(uniq_json.to_dict())

    # 2) records (json) if context was requested
    if include_context:
        hits_json = create_output_file(
            output_path, display_name="ip_hits_with_context", extension="json", data_type="json"
        )
        with open(hits_json.path, "w", encoding="utf-8") as fh:
            json.dump(combined_records, fh, ensure_ascii=False, indent=2, default=str)
        output_files.append(hits_json.to_dict())

        # Optional CSV (Timesketch-friendly)
        if emit_csv:
            hits_csv = create_output_file(
                output_path, display_name="ip_hits_with_context", extension="csv", data_type="csv"
            )
            _write_records_csv(hits_csv.path, combined_records)
            output_files.append(hits_csv.to_dict())

        # Optional NDJSON
        if emit_ndjson:
            hits_ndjson = create_output_file(
                output_path, display_name="ip_hits_with_context", extension="ndjson", data_type="jsonl"
            )
            with open(hits_ndjson.path, "w", encoding="utf-8") as fh:
                for rec in combined_records:
                    fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
            output_files.append(hits_ndjson.to_dict())

    # ------------------------------------------------------------
    # Finalize
    # ------------------------------------------------------------
    if not output_files:
        raise RuntimeError("No output files were produced by IP Extractor.")

    command_string = f"ip_extractor (Python) on EVTX:{len(evtx_paths)} Linux:{len(text_paths)}"

    logger.info(
        "Completed IP extraction",
        extra={"unique_count": len(unique_ips), "records": len(combined_records)},
    )

    return create_task_result(
        output_files=output_files,
        workflow_id=workflow_id,
        command=command_string,
        meta={
            "counts": {
                **counts,
                "total_unique": len(unique_ips),
                "total_records": len(combined_records) if include_context else 0,
            },
            "files_processed": {"evtx": len(evtx_paths), "linux": len(text_paths)},
            "include_context": include_context,
            "ignore_private": ignore_private,
            "include_linux_logs": include_linux_logs,
        },
    )


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------
def _write_records_csv(path: str, records: List[Dict]) -> None:
    """
    Write a CSV that accommodates both EVTX and Linux-text records.
    Columns not applicable to a given record will be empty.
    """
    headers = [
        "timestamp",       # EVTX: created | Linux: created (parsed or raw)
        "ip",
        "event_id",        # EVTX only
        "channel",         # EVTX only
        "provider",        # EVTX only
        "record_id",       # EVTX only (event_record_id)
        "source",          # Linux only (file path)
        "line_no",         # Linux only (line number)
        "kind",            # Linux only (syslog/access)
    ]
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(headers)
        for r in records:
            w.writerow([
                r.get("created") or "",
                r.get("ip") or "",
                r.get("event_id") or "",
                r.get("channel") or "",
                r.get("provider") or "",
                r.get("event_record_id") or "",
                r.get("source") or "",
                r.get("line_no") or "",
                r.get("kind") or "",
            ])
