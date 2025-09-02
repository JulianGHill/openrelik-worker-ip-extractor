from __future__ import annotations
import json
import os
from typing import Dict, List

# OpenRelik worker common helpers
from openrelik_worker_common.file_utils import create_output_file
from openrelik_worker_common.logging import Logger
from openrelik_worker_common.task_utils import create_task_result, get_input_files

# Celery app (from the template)
from .app import celery
from celery import signals

# Your core logic
from .evtx_ip_extract import extract_ips_from_evtx_files

# --------------------------------------------------------------------------------------
# Task registration
# --------------------------------------------------------------------------------------
TASK_NAME = "openrelik-worker-ip-extractor.tasks.extract_ips"

TASK_METADATA = {
    "display_name": "EVTX IP Extractor",
    "description": (
        "Parses Windows Event Logs (.evtx) and extracts IPv4/IPv6 addresses. "
        "Optionally includes per-event context (timestamp/channel/provider/event_id/record_id)."
    ),
    # Rendered as a form in the UI; values arrive in task_config
    "task_config": [
        {
            "name": "include_context",
            "label": "Include per-event context",
            "description": "Return detailed records (timestamp, channel, provider, event_id, record_id).",
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
            "name": "emit_csv",
            "label": "Also write CSV for Timesketch",
            "description": "Write a CSV with timestamp,ip,event_id,channel,provider,record_id.",
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
    log.bind(task_id=task_id, task_name=task.name,
             worker_name=TASK_METADATA.get("display_name"))


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
    Extract IPs from EVTX files and write outputs.

    Args:
        pipe_result: Base64-encoded result from a previous task (if any).
        input_files: Input file dicts (unused when pipe_result exists).
        output_path: Directory where outputs must be written.
        workflow_id: OpenRelik workflow ID.
        task_config: Dict of UI-configured options.

    Returns:
        Base64-encoded dict via create_task_result.
    """
    # ------------------------------------------------------------
    # Setup / inputs
    # ------------------------------------------------------------
    log.bind(workflow_id=workflow_id)
    logger.info(f"Starting {TASK_NAME} for workflow_id={workflow_id}")

    cfg = task_config or {}
    include_context = bool(cfg.get("include_context", True))
    ignore_private = bool(cfg.get("ignore_private", True))
    emit_csv = bool(cfg.get("emit_csv", False))
    emit_ndjson = bool(cfg.get("emit_ndjson", False))

    # Collect input files (from previous pipe or from UI-provided inputs)
    files = get_input_files(pipe_result, input_files or [])
    evtx_paths: List[str] = []
    for f in files:
        p = f.get("path")
        if p and p.lower().endswith(".evtx") and os.path.isfile(p):
            evtx_paths.append(p)

    if not evtx_paths:
        raise RuntimeError("No .evtx input files found for EVTX IP extraction.")

    # ------------------------------------------------------------
    # Extract
    # ------------------------------------------------------------
    result = extract_ips_from_evtx_files(
        evtx_paths=evtx_paths,
        include_context=include_context,
        ignore_private=ignore_private,
        ignore_link_local=True,
        ignore_reserved=False,
        ignore_loopback=True,
        ignore_multicast=True,
    )

    unique_ips = result.get("unique_ips", [])
    records = result.get("records", [])

    # ------------------------------------------------------------
    # Write outputs
    # ------------------------------------------------------------
    output_files = []

    # 1) unique IPs (txt + json)
    uniq_txt = create_output_file(
        output_path,
        display_name="unique_ips",
        extension="txt",
        data_type="ip-list",
    )
    with open(uniq_txt.path, "w", encoding="utf-8") as fh:
        for ip in unique_ips:
            fh.write(f"{ip}\n")
    output_files.append(uniq_txt.to_dict())

    uniq_json = create_output_file(
        output_path,
        display_name="unique_ips",
        extension="json",
        data_type="json",
    )
    with open(uniq_json.path, "w", encoding="utf-8") as fh:
        json.dump(unique_ips, fh, ensure_ascii=False, indent=2)
    output_files.append(uniq_json.to_dict())

    # 2) records (json) if context was requested
    if include_context:
        hits_json = create_output_file(
            output_path,
            display_name="ip_hits_with_context",
            extension="json",
            data_type="json",
        )
        with open(hits_json.path, "w", encoding="utf-8") as fh:
            json.dump(records, fh, ensure_ascii=False, indent=2, default=str)
        output_files.append(hits_json.to_dict())

        # Optional CSV (Timesketch-friendly)
        if emit_csv:
            hits_csv = create_output_file(
                output_path,
                display_name="ip_hits_with_context",
                extension="csv",
                data_type="csv",
            )
            _write_records_csv(hits_csv.path, records)
            output_files.append(hits_csv.to_dict())

        # Optional NDJSON
        if emit_ndjson:
            hits_ndjson = create_output_file(
                output_path,
                display_name="ip_hits_with_context",
                extension="ndjson",
                data_type="jsonl",
            )
            with open(hits_ndjson.path, "w", encoding="utf-8") as fh:
                for rec in records:
                    fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
            output_files.append(hits_ndjson.to_dict())

    # ------------------------------------------------------------
    # Finalize
    # ------------------------------------------------------------
    if not output_files:
        raise RuntimeError("No output files were produced by EVTX IP Extractor.")

    # This string is informational in the UI
    command_string = "evtx_ip_extract (Python) on {} file(s)".format(len(evtx_paths))

    logger.info(
        "Completed EVTX IP extraction",
        extra={"unique_count": len(unique_ips), "records": len(records)},
    )

    return create_task_result(
        output_files=output_files,
        workflow_id=workflow_id,
        command=command_string,
        meta={
            "counts": result.get("counts", {}),
            "evtx_files_processed": len(evtx_paths),
            "include_context": include_context,
            "ignore_private": ignore_private,
        },
    )


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------
def _write_records_csv(path: str, records: List[Dict]) -> None:
    """Write a simple CSV for Timesketch ingestion."""
    import csv

    headers = ["timestamp", "ip", "event_id", "channel", "provider", "record_id"]
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
            ])
