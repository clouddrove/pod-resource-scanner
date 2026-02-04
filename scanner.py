#!/usr/bin/env python3
"""
Kubernetes Pod Resource Scanner

Works on any Kubernetes cluster (AKS, GKE, EKS, on-prem). Scans all namespaces,
pods, and nodes for CPU/memory/ephemeral-storage requests and limits.
Exports CSV and optionally updates a Google Sheet. Produces recommendations
for scale up/down and limit changes.
"""

import os
import csv
import sys
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from kubernetes import client, config
from kubernetes.client.rest import ApiException

from quantity import (
    parse_quantity,
    quantity_to_millicores,
    quantity_to_bytes,
    format_bytes,
    format_millicores,
)

LOG = logging.getLogger("scanner")


def setup_logging() -> None:
    level = os.environ.get("POD_SCANNER_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
        stream=sys.stdout,
    )
    # Kubernetes client can be noisy
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def load_k8s_config() -> None:
    """Load in-cluster config when in K8s, else kubeconfig."""
    try:
        config.load_incluster_config()
        LOG.info("Using in-cluster Kubernetes config")
    except config.ConfigException:
        config.load_kube_config()
        LOG.info("Using kubeconfig")


def get_all_pods(v1: client.CoreV1Api) -> list:
    """List pods across all namespaces."""
    try:
        return v1.list_pod_for_all_namespaces(watch=False).items
    except ApiException as e:
        LOG.error("Failed to list pods: %s", e)
        raise


def get_nodes(v1: client.CoreV1Api) -> list:
    """List all nodes (works on AKS, GKE, EKS, on-prem)."""
    try:
        return v1.list_node(watch=False).items
    except ApiException as e:
        LOG.error("Failed to list nodes: %s", e)
        raise


def _get_resource_val(src: Any, res: str) -> Optional[str]:
    """Get resource value from node status capacity/allocatable (dict or object)."""
    if src is None:
        return None
    val = None
    if isinstance(src, dict):
        val = src.get(res) or src.get(res.replace("-", "_"))
    else:
        val = getattr(src, res, None) or getattr(src, res.replace("-", "_"), None)
    if val is not None:
        return str(val).strip()
    return None


def node_capacity_allocatable(node) -> Dict[str, Dict[str, str]]:
    """Extract capacity and allocatable for cpu, memory, ephemeral-storage."""
    out = {"capacity": {}, "allocatable": {}}
    for key in ("capacity", "allocatable"):
        src = getattr(node.status, key, None) or {}
        for res in ("cpu", "memory", "ephemeral-storage"):
            val = _get_resource_val(src, res)
            if val:
                out[key][res] = val
    return out


def get_workload_info(apps_v1: client.AppsV1Api, pod) -> tuple:
    """Return (kind, name, replicas) for deployment/statefulset/daemonset if applicable."""
    replicas = ""
    kind = ""
    name = ""
    owner_refs = pod.metadata.owner_references or []
    for ref in owner_refs:
        if ref.controller:
            kind = ref.kind or ""
            name = ref.name or ""
            try:
                if kind == "ReplicaSet":
                    rs = apps_v1.read_namespaced_replica_set(
                        ref.name, pod.metadata.namespace
                    )
                    for or_ref in (rs.metadata.owner_references or []):
                        if or_ref.controller and or_ref.kind == "Deployment":
                            kind = "Deployment"
                            name = or_ref.name
                            dep = apps_v1.read_namespaced_deployment(
                                or_ref.name, pod.metadata.namespace
                            )
                            replicas = str(dep.spec.replicas or 0)
                            break
                    if not replicas and kind == "ReplicaSet":
                        replicas = str(rs.spec.replicas or 0)
                elif kind == "StatefulSet":
                    sts = apps_v1.read_namespaced_stateful_set(
                        ref.name, pod.metadata.namespace
                    )
                    replicas = str(sts.spec.replicas or 0)
                elif kind == "DaemonSet":
                    ds = apps_v1.read_namespaced_daemon_set(
                        ref.name, pod.metadata.namespace
                    )
                    replicas = str(ds.status.number_ready or 0) + " (DS)"
            except ApiException:
                pass
            break
    return (kind, name, replicas)


def scan(v1: client.CoreV1Api, apps_v1: client.AppsV1Api) -> List[dict]:
    """Scan all namespaces and pods; return list of row dicts (with node and ephemeral-storage)."""
    pods = get_all_pods(v1)
    rows = []
    for pod in pods:
        ns = pod.metadata.namespace
        pod_name = pod.metadata.name
        node_name = (pod.spec.node_name or "") if pod.spec else ""
        status = (pod.status.phase or "").strip()
        kind, workload_name, replicas = get_workload_info(apps_v1, pod)
        containers = pod.spec.containers if pod.spec else []
        for c in containers:
            res = c.resources or {}
            req = res.requests or {}
            lim = res.limits or {}
            rows.append({
                "namespace": ns,
                "pod": pod_name,
                "container": c.name,
                "node": node_name,
                "workload_kind": kind,
                "workload_name": workload_name,
                "replicas": replicas,
                "cpu_request": parse_quantity(req.get("cpu", "")),
                "cpu_limit": parse_quantity(lim.get("cpu", "")),
                "memory_request": parse_quantity(req.get("memory", "")),
                "memory_limit": parse_quantity(lim.get("memory", "")),
                "ephemeral_storage_request": parse_quantity(req.get("ephemeral-storage", "")),
                "ephemeral_storage_limit": parse_quantity(lim.get("ephemeral-storage", "")),
                "status": status,
            })
    return rows


def scan_nodes(v1: client.CoreV1Api) -> List[dict]:
    """Scan all nodes; return list of node rows (capacity + allocatable for CPU, memory, disk)."""
    nodes = get_nodes(v1)
    out = []
    for node in nodes:
        name = node.metadata.name
        cap_alloc = node_capacity_allocatable(node)
        cap = cap_alloc.get("capacity", {})
        alloc = cap_alloc.get("allocatable", {})
        out.append({
            "node": name,
            "cpu_capacity": cap.get("cpu", ""),
            "cpu_allocatable": alloc.get("cpu", ""),
            "memory_capacity": cap.get("memory", ""),
            "memory_allocatable": alloc.get("memory", ""),
            "ephemeral_storage_capacity": cap.get("ephemeral-storage", ""),
            "ephemeral_storage_allocatable": alloc.get("ephemeral-storage", ""),
        })
    return out


def namespace_summary(rows: List[dict]) -> List[dict]:
    """Aggregate by namespace: pod count and container count."""
    from collections import defaultdict
    by_ns = defaultdict(lambda: {"pods": set(), "containers": 0})
    for r in rows:
        by_ns[r["namespace"]]["pods"].add(r["pod"])
        by_ns[r["namespace"]]["containers"] += 1
    out = []
    for ns, data in sorted(by_ns.items()):
        out.append({
            "namespace": ns,
            "pod_count": len(data["pods"]),
            "container_count": data["containers"],
        })
    return out


def node_requested_totals(rows: List[dict]) -> Dict[str, Dict[str, float]]:
    """Per-node sum of requested CPU (millicores), memory (bytes), ephemeral-storage (bytes)."""
    from collections import defaultdict
    by_node = defaultdict(lambda: {"cpu": 0.0, "memory": 0.0, "ephemeral_storage": 0.0})
    for r in rows:
        node = r.get("node") or "_unscheduled_"
        by_node[node]["cpu"] += quantity_to_millicores(r.get("cpu_request", ""))
        by_node[node]["memory"] += quantity_to_bytes(r.get("memory_request", ""))
        by_node[node]["ephemeral_storage"] += quantity_to_bytes(r.get("ephemeral_storage_request", ""))
    return dict(by_node)


def node_utilization(node_rows: List[dict], requested: Dict[str, Dict[str, float]]) -> List[dict]:
    """Merge node capacity/allocatable with requested sums; add utilization pct."""
    out = []
    for n in node_rows:
        node_name = n["node"]
        req = requested.get(node_name, {})
        cpu_alloc = quantity_to_millicores(n.get("cpu_allocatable", ""))
        mem_alloc = quantity_to_bytes(n.get("memory_allocatable", ""))
        disk_alloc = quantity_to_bytes(n.get("ephemeral_storage_allocatable", ""))
        cpu_req = req.get("cpu", 0) or 0
        mem_req = req.get("memory", 0) or 0
        disk_req = req.get("ephemeral_storage", 0) or 0
        out.append({
            **n,
            "cpu_requested_millicores": round(cpu_req, 0),
            "memory_requested_bytes": round(mem_req, 0),
            "ephemeral_storage_requested_bytes": round(disk_req, 0),
            "cpu_util_pct": round(100 * cpu_req / cpu_alloc, 1) if cpu_alloc else 0,
            "memory_util_pct": round(100 * mem_req / mem_alloc, 1) if mem_alloc else 0,
            "disk_util_pct": round(100 * disk_req / disk_alloc, 1) if disk_alloc else 0,
        })
    return out


def build_recommendations(
    node_util: List[dict],
    pod_rows: List[dict],
    util_scale_up_pct: float = 75.0,
    util_scale_down_pct: float = 25.0,
) -> List[dict]:
    """Produce recommendations: scale up/down nodes, set or adjust limits."""
    recs = []
    # Node-level: scale up if any node is heavily utilized, scale down if underutilized
    for nu in node_util:
        node = nu.get("node", "")
        if node == "_unscheduled_":
            continue
        cpu_pct = nu.get("cpu_util_pct") or 0
        mem_pct = nu.get("memory_util_pct") or 0
        disk_pct = nu.get("disk_util_pct") or 0
        if cpu_pct >= util_scale_up_pct or mem_pct >= util_scale_up_pct or disk_pct >= util_scale_up_pct:
            recs.append({
                "type": "scale_up",
                "target": f"node:{node}",
                "reason": f"High utilization: CPU {cpu_pct}%, memory {mem_pct}%, disk {disk_pct}%",
                "action": "Consider adding nodes or moving workloads to reduce pressure.",
            })
        if cpu_pct <= util_scale_down_pct and mem_pct <= util_scale_down_pct and disk_pct <= util_scale_down_pct and (cpu_pct + mem_pct + disk_pct) > 0:
            recs.append({
                "type": "scale_down",
                "target": f"node:{node}",
                "reason": f"Low utilization: CPU {cpu_pct}%, memory {mem_pct}%, disk {disk_pct}%",
                "action": "Consider removing node or consolidating workloads to save cost.",
            })
    # Cluster-level from same data
    total_cpu_alloc = sum(quantity_to_millicores(n.get("cpu_allocatable", "")) for n in node_util if n.get("node") != "_unscheduled_")
    total_mem_alloc = sum(quantity_to_bytes(n.get("memory_allocatable", "")) for n in node_util if n.get("node") != "_unscheduled_")
    total_cpu_req = sum(n.get("cpu_requested_millicores", 0) for n in node_util)
    total_mem_req = sum(n.get("memory_requested_bytes", 0) for n in node_util)
    if total_cpu_alloc and total_cpu_req / total_cpu_alloc >= util_scale_up_pct / 100:
        recs.append({
            "type": "scale_up",
            "target": "cluster",
            "reason": f"Cluster CPU requested {100 * total_cpu_req / total_cpu_alloc:.1f}% of allocatable",
            "action": "Consider adding nodes to the cluster.",
        })
    if total_cpu_alloc and 0 < total_cpu_req / total_cpu_alloc <= util_scale_down_pct / 100:
        recs.append({
            "type": "scale_down",
            "target": "cluster",
            "reason": f"Cluster CPU requested {100 * total_cpu_req / total_cpu_alloc:.1f}% of allocatable",
            "action": "Consider scaling down node pool to save cost.",
        })
    # Container-level: missing limits, or limit >> request
    seen = set()
    for r in pod_rows:
        key = (r.get("namespace"), r.get("pod"), r.get("container"))
        if key in seen:
            continue
        seen.add(key)
        ns, pod, cont = r.get("namespace"), r.get("pod"), r.get("container")
        cpu_req = quantity_to_millicores(r.get("cpu_request", ""))
        cpu_lim = quantity_to_millicores(r.get("cpu_limit", ""))
        mem_req = quantity_to_bytes(r.get("memory_request", ""))
        mem_lim = quantity_to_bytes(r.get("memory_limit", ""))
        if (cpu_req or mem_req) and not cpu_lim and not mem_lim:
            recs.append({
                "type": "change_limits",
                "target": f"{ns}/{pod}/{cont}",
                "reason": "Has requests but no limits set",
                "action": "Set CPU/memory limits for predictability and fairness.",
            })
        if cpu_lim > 0 and cpu_req > 0 and cpu_lim >= 4 * cpu_req:
            recs.append({
                "type": "change_limits",
                "target": f"{ns}/{pod}/{cont}",
                "reason": f"CPU limit ({cpu_lim}m) is 4x+ request ({cpu_req}m)",
                "action": "Consider lowering CPU limit to match usage and free capacity.",
            })
        if mem_lim > 0 and mem_req > 0 and mem_lim >= 4 * mem_req:
            recs.append({
                "type": "change_limits",
                "target": f"{ns}/{pod}/{cont}",
                "reason": f"Memory limit >> request (limit {format_bytes(mem_lim)}, request {format_bytes(mem_req)})",
                "action": "Consider lowering memory limit to match usage.",
            })
    return recs


POD_HEADERS = [
    "cluster", "namespace", "pod", "container", "node", "workload_kind", "workload_name", "replicas",
    "cpu_request", "cpu_limit", "memory_request", "memory_limit",
    "ephemeral_storage_request", "ephemeral_storage_limit", "status",
]

# Columns added per row from node utilization and namespace summary (single combined CSV)
NODE_UTIL_COLUMNS = [
    "node_cpu_capacity", "node_cpu_allocatable", "node_memory_capacity", "node_memory_allocatable",
    "node_ephemeral_storage_capacity", "node_ephemeral_storage_allocatable",
    "node_cpu_requested_millicores", "node_memory_requested_bytes", "node_ephemeral_storage_requested_bytes",
    "node_cpu_util_pct", "node_memory_util_pct", "node_disk_util_pct",
]
NS_SUMMARY_COLUMNS = ["ns_pod_count", "ns_container_count"]
COMBINED_HEADERS = POD_HEADERS + NODE_UTIL_COLUMNS + NS_SUMMARY_COLUMNS + ["recommendations"]
# Single cumulative file: scan_date first so history is in one place
HISTORY_CSV_HEADERS = ["scan_date"] + COMBINED_HEADERS
OUTPUT_CSV_NAME = "all-resources.csv"

# Human-readable column names for CSV/Sheet (same order as HISTORY_CSV_HEADERS)
DISPLAY_HEADERS = [
    "Scan Date",
    "Cluster",
    "Namespace",
    "Pod",
    "Container",
    "Node",
    "Workload Kind",
    "Workload Name",
    "Replicas",
    "CPU Request",
    "CPU Limit",
    "Memory Request",
    "Memory Limit",
    "Ephemeral Storage Request",
    "Ephemeral Storage Limit",
    "Status",
    "Node CPU Capacity",
    "Node CPU Allocatable",
    "Node Memory Capacity",
    "Node Memory Allocatable",
    "Node Disk Capacity",
    "Node Disk Allocatable",
    "Node CPU Requested",
    "Node Memory Requested",
    "Node Disk Requested",
    "Node CPU Util %",
    "Node Memory Util %",
    "Node Disk Util %",
    "Namespace Pod Count",
    "Namespace Container Count",
    "Recommendations",
]

# Sheet layout: metrics vertical (rows), containers horizontal (columns) for easy side-by-side comparison
SHEET_METRIC_ROWS = [
    "Scan Date", "CPU Request", "CPU Limit", "Memory Request", "Memory Limit",
    "Status", "Node CPU %", "Node Mem %", "Node Disk %", "Recommendations",
]
_SHEET_METRIC_KEYS = [
    "scan_date", "cpu_request", "cpu_limit", "memory_request", "memory_limit",
    "status", "node_cpu_util_pct", "node_memory_util_pct", "node_disk_util_pct", "recommendations",
]


def _format_value_for_display(key: str, value: Any) -> str:
    """Return a human-readable string for a given column value."""
    if value is None or value == "":
        return ""
    if key in ("cpu_request", "cpu_limit"):
        mc = quantity_to_millicores(str(value)) if isinstance(value, str) else float(value)
        return format_millicores(mc) if mc else str(value)
    if key in (
        "memory_request",
        "memory_limit",
        "ephemeral_storage_request",
        "ephemeral_storage_limit",
        "node_memory_capacity",
        "node_memory_allocatable",
        "node_ephemeral_storage_capacity",
        "node_ephemeral_storage_allocatable",
        "node_memory_requested_bytes",
        "node_ephemeral_storage_requested_bytes",
    ):
        n = quantity_to_bytes(str(value)) if isinstance(value, str) else float(value)
        return format_bytes(n) if n else str(value)
    if key in ("node_cpu_capacity", "node_cpu_allocatable"):
        # Stored as cores (e.g. "8") — convert to millicores for formatter
        s = str(value).strip()
        if not s:
            return ""
        if s.endswith("m"):
            return format_millicores(quantity_to_millicores(s))
        try:
            cores = float(s)
            return format_millicores(cores * 1000) if cores > 0 else ""
        except ValueError:
            return s
    if key == "node_cpu_requested_millicores":
        try:
            return format_millicores(float(value))
        except (TypeError, ValueError):
            return str(value)
    if key in ("node_cpu_util_pct", "node_memory_util_pct", "node_disk_util_pct"):
        try:
            pct = float(value)
            return f"{pct:.1f}%" if pct == pct else ""
        except (TypeError, ValueError):
            return str(value)
    return str(value).strip()


def _format_row_for_display(row: dict) -> dict:
    """Return a new row dict with human-readable values for CSV/Sheet display."""
    out = {}
    for k in HISTORY_CSV_HEADERS:
        v = row.get(k)
        if k in (
            "scan_date",
            "cluster",
            "namespace",
            "pod",
            "container",
            "node",
            "workload_kind",
            "workload_name",
            "replicas",
            "status",
            "ns_pod_count",
            "ns_container_count",
            "recommendations",
        ):
            out[k] = v if v is not None and str(v).strip() else ""
        else:
            out[k] = _format_value_for_display(k, v) if v else ""
    return out


def _build_combined_rows(
    rows: List[dict],
    summary: List[dict],
    node_util: List[dict],
    recommendations: List[dict],
) -> List[dict]:
    """Merge pod rows with node utilization, namespace summary, and recommendations into one row per container."""
    node_by_key = {(r["cluster"], r["node"]): r for r in node_util}
    summary_by_key = {(s["cluster"], s["namespace"]): s for s in summary}
    recs_by_target: Dict[str, List[str]] = {}
    for rec in recommendations:
        target = rec.get("target") or ""
        if not target.startswith("node:") and target != "cluster":
            part = f"{rec.get('type', '')}: {rec.get('reason', '')} | {rec.get('action', '')}"
            recs_by_target.setdefault(target, []).append(part)
    combined = []
    for r in rows:
        row = dict(r)
        key = (r.get("cluster"), r.get("node"))
        nu = node_by_key.get(key, {})
        for col in (
            "cpu_capacity", "cpu_allocatable", "memory_capacity", "memory_allocatable",
            "ephemeral_storage_capacity", "ephemeral_storage_allocatable",
            "cpu_requested_millicores", "memory_requested_bytes", "ephemeral_storage_requested_bytes",
            "cpu_util_pct", "memory_util_pct", "disk_util_pct",
        ):
            row["node_" + col] = nu.get(col, "")
        ns_key = (r.get("cluster"), r.get("namespace"))
        s = summary_by_key.get(ns_key, {})
        row["ns_pod_count"] = s.get("pod_count", "")
        row["ns_container_count"] = s.get("container_count", "")
        target = f"{r.get('namespace', '')}/{r.get('pod', '')}/{r.get('container', '')}"
        row["recommendations"] = "; ".join(recs_by_target.get(target, []))
        combined.append(row)
    return combined


def write_csv(
    rows: List[dict],
    summary: List[dict],
    node_rows: List[dict],
    node_util: List[dict],
    recommendations: List[dict],
    output_dir: Path,
    run_ts: str,
) -> None:
    """Append combined data (with scan_date) to the single cumulative CSV; raw headers and values for parsing."""
    output_dir.mkdir(parents=True, exist_ok=True)
    combined = _build_combined_rows(rows, summary, node_util, recommendations)
    for r in combined:
        r["scan_date"] = run_ts
    path = output_dir / OUTPUT_CSV_NAME
    file_exists = path.exists()
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=HISTORY_CSV_HEADERS, extrasaction="ignore")
        if not file_exists:
            w.writeheader()
        w.writerows(combined)
    LOG.info("Appended %s rows to %s (scan_date=%s)", len(combined), path, run_ts)


def _container_column_label(row: dict) -> str:
    """Short label for sheet column: namespace / pod / container."""
    ns = (row.get("namespace") or "").strip()
    pod = (row.get("pod") or "").strip()
    cont = (row.get("container") or "").strip()
    return f"{ns} / {pod} / {cont}" if (ns or pod or cont) else "—"


def update_google_sheet(
    rows: List[dict],
    summary: List[dict],
    node_util: List[dict],
    recommendations: List[dict],
    run_ts: str,
):
    """Update Google Sheet: metrics vertical (rows), containers horizontal (columns) for easy comparison."""
    import gspread
    from google.oauth2.service_account import Credentials

    creds_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    sheet_key = os.environ.get("POD_SCANNER_SHEET_ID") or os.environ.get("POD_SCANNER_SHEET_KEY")
    if not sheet_key or not creds_path or not Path(creds_path).exists():
        LOG.info("Skipping Google Sheet: set POD_SCANNER_SHEET_ID and mount service account JSON")
        return

    scopes = [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive",
    ]
    creds = Credentials.from_service_account_file(creds_path, scopes=scopes)
    gc = gspread.authorize(creds)
    sh = gc.open_by_key(sheet_key.strip())

    combined = _build_combined_rows(rows, summary, node_util, recommendations)
    for r in combined:
        r["scan_date"] = run_ts
    formatted = [_format_row_for_display(r) for r in combined]
    # Sort by namespace, pod, container for stable column order
    formatted.sort(key=lambda r: (
        str(r.get("namespace", "")),
        str(r.get("pod", "")),
        str(r.get("container", "")),
    ))

    num_metrics = len(SHEET_METRIC_ROWS)
    num_containers = len(formatted)
    if num_containers == 0:
        LOG.info("No container data; skipping Google Sheet update")
        return

    # Build transposed matrix: rows = metrics, columns = [Metric name, container1, container2, ...]
    # Row 1: ["Metric", label1, label2, ...]
    header_row = ["Metric"] + [_container_column_label(r) for r in formatted]
    data_rows = []
    for i, metric_name in enumerate(SHEET_METRIC_ROWS):
        key = _SHEET_METRIC_KEYS[i]
        values = [str(r.get(key, "")) for r in formatted]
        data_rows.append([metric_name] + values)

    try:
        ws = sh.worksheet("All Resources")
    except gspread.WorksheetNotFound:
        ws = sh.add_worksheet("All Resources", rows=num_metrics + 10, cols=num_containers + 10)

    sheet_data = [header_row] + data_rows
    ws.update(range_name="A1", values=sheet_data, value_input_option="RAW")
    LOG.info(
        "Updated sheet 'All Resources' (metrics vertical, containers horizontal): %s metrics × %s containers (scan_date=%s)",
        num_metrics, num_containers, run_ts,
    )

    _update_dashboard_sheet(sh, summary, node_util, recommendations, run_ts, formatted, combined)


def _dashboard_get_existing_chart_ids(sh, dashboard_sheet_id: int) -> List[int]:
    """Fetch chart IDs embedded in the Dashboard sheet so we can remove them before re-adding."""
    import urllib.request

    creds_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if not creds_path or not Path(creds_path).exists():
        return []
    from google.oauth2.service_account import Credentials
    from google.auth.transport.requests import Request as AuthRequest
    scopes = ["https://www.googleapis.com/auth/spreadsheets"]
    creds = Credentials.from_service_account_file(creds_path, scopes=scopes)
    creds.refresh(AuthRequest())
    token = creds.token
    spreadsheet_id = sh.id
    url = (
        f"https://sheets.googleapis.com/v4/spreadsheets/{spreadsheet_id}"
        "?fields=sheets(properties(sheetId,title),charts)"
    )
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req) as resp:
            data = __import__("json").loads(resp.read().decode())
    except Exception:
        return []
    chart_ids: List[int] = []
    for sheet in data.get("sheets", []):
        if sheet.get("properties", {}).get("sheetId") == dashboard_sheet_id:
            for ch in sheet.get("charts", []):
                cid = ch.get("chartId")
                if cid is not None:
                    chart_ids.append(cid)
            break
    return chart_ids


# Option B: one new tab per run (historical data); Dashboard visualizes the latest run. Keep last N run tabs.
_RUN_SHEET_PREFIX = "Run "
_DASHBOARD_NS_HEADER_ROW = 2   # 0-based: row 2 = headers, row 3+ = data

# Colors (RGB 0–1) for Run tab and Dashboard
_COLORS = {
    "light_blue": {"red": 0.73, "green": 0.87, "blue": 1},
    "blue_header": {"red": 0.26, "green": 0.52, "blue": 0.96},
    "light_green": {"red": 0.73, "green": 1, "blue": 0.85},
    "green_header": {"red": 0.2, "green": 0.72, "blue": 0.45},
    "light_orange": {"red": 1, "green": 0.92, "blue": 0.73},
    "orange_header": {"red": 0.95, "green": 0.6, "blue": 0.2},
    "light_purple": {"red": 0.9, "green": 0.85, "blue": 1},
    "purple_header": {"red": 0.55, "green": 0.4, "blue": 0.85},
    "light_gray": {"red": 0.96, "green": 0.96, "blue": 0.96},
    "dash_title": {"red": 0.25, "green": 0.47, "blue": 0.85},
    "dash_row1": {"red": 0.87, "green": 0.92, "blue": 1},
    "dash_row2": {"red": 0.85, "green": 1, "blue": 0.9},
    "dash_row3": {"red": 1, "green": 0.95, "blue": 0.85},
    "dash_row4": {"red": 0.94, "green": 0.94, "blue": 0.96},
}
_DASHBOARD_NS_END_ROW = 52     # 0-based endRowIndex for namespace table
_RUN_NODE_MAX_DATA = 10
_RUN_REC_TYPE_MAX_DATA = 10
_RUN_REC_DETAILED_MAX = 100
_DASHBOARD_NODE_END_ROW = 2 + 1 + _RUN_NODE_MAX_DATA   # 0-based: title+header+data
_DASHBOARD_REC_END_ROW = 2 + 1 + _RUN_REC_TYPE_MAX_DATA


def _update_dashboard_sheet(
    sh,
    summary: List[dict],
    node_util: List[dict],
    recommendations: List[dict],
    run_ts: str,
    formatted_combined: Optional[List[dict]] = None,
    combined_raw: Optional[List[dict]] = None,
) -> None:
    """Create a new 'Run <timestamp>' tab each run; keep last N run tabs; Dashboard visualizes the latest (historical data)."""
    run_tab_title = _RUN_SHEET_PREFIX + run_ts
    data_ws = sh.add_worksheet(run_tab_title, rows=115, cols=23)
    data_sheet_id = data_ws.id
    ns_totals: Dict[str, Dict[str, Any]] = {}
    max_ns_rows = 50
    max_node_data = min(_RUN_NODE_MAX_DATA, max(1, len(node_util)))

    # Row 0: last scan timestamp (referenced by Dashboard KPIs)
    data_ws.update(range_name="A1", values=[["Last scan: " + run_ts]], value_input_option="RAW")
    # Namespace block: A2 = title, A3:C3 = headers, A4:C52 = data
    ns_sorted = sorted(summary, key=lambda x: (str(x.get("cluster", "")), str(x.get("namespace", ""))))
    ns_rows = [["By Namespace"], ["Namespace", "Pod Count", "Container Count"]]
    for s in ns_sorted[: max_ns_rows - 1]:
        ns_rows.append([
            str(s.get("namespace", "")),
            s.get("pod_count", ""),
            s.get("container_count", ""),
        ])
    while len(ns_rows) < 2 + max_ns_rows:
        ns_rows.append(["", "", ""])
    data_ws.update(range_name="A2", values=ns_rows, value_input_option="RAW")
    # Node utilization: E2 = title, E3:H3 = headers, E4:H = data (compact, no empty padding)
    node_sorted = sorted(node_util, key=lambda x: (str(x.get("cluster", "")), str(x.get("node", ""))))
    node_rows = [["Node utilization (%)"], ["Node", "CPU %", "Memory %", "Disk %"]]
    for nu in node_sorted[:max_node_data]:
        node_rows.append([
            str(nu.get("node", "")),
            nu.get("cpu_util_pct", ""),
            nu.get("memory_util_pct", ""),
            nu.get("disk_util_pct", ""),
        ])
    data_ws.update(range_name="E2", values=node_rows, value_input_option="RAW")
    # Recommendations by type: J2 = title, J3:K3 = headers, J4:K = data (compact)
    rec_by_type: Dict[str, int] = {}
    for r in recommendations:
        t = str(r.get("type") or "other")
        rec_by_type[t] = rec_by_type.get(t, 0) + 1
    rec_sorted = sorted(rec_by_type.items())
    rec_rows = [["Recommendations by type"], ["Type", "Count"]]
    for t, count in rec_sorted[:_RUN_REC_TYPE_MAX_DATA]:
        rec_rows.append([t, count])
    data_ws.update(range_name="J2", values=rec_rows, value_input_option="RAW")
    # Recommendations (detailed): L2 = title, L3:O3 = headers, L4:O = up to 100 rows (Type, Target, Reason, Action)
    rec_detail_rows = [["Recommendations (detailed)", "", "", ""], ["Type", "Target", "Reason", "Action"]]
    for r in recommendations[:_RUN_REC_DETAILED_MAX]:
        rec_detail_rows.append([
            str(r.get("type") or ""),
            str(r.get("target") or ""),
            str(r.get("reason") or ""),
            str(r.get("action") or ""),
        ])
    data_ws.update(range_name="L2", values=rec_detail_rows, value_input_option="RAW")

    # Container details (request / limit / suggestions) — full 8 columns at P1 so limits and suggestions are visible
    if formatted_combined:
        detail_header = [
            "Namespace", "Pod", "Container", "CPU Request", "CPU Limit",
            "Memory Request", "Memory Limit", "Recommendations",
        ]
        # Title row must span 8 columns so the whole table is written (no truncated columns)
        detail_rows = [["Container details (request / limit / suggestions)", "", "", "", "", "", "", ""], detail_header]
        for r in formatted_combined[:1000]:
            detail_rows.append([
                str(r.get("namespace", "")),
                str(r.get("pod", "")),
                str(r.get("container", "")),
                str(r.get("cpu_request", "")),
                str(r.get("cpu_limit", "")),
                str(r.get("memory_request", "")),
                str(r.get("memory_limit", "")),
                str(r.get("recommendations", "")),
            ])
        data_ws.update(range_name="P1", values=detail_rows, value_input_option="RAW")

    # Resource totals by namespace (CPU / memory requested) for Dashboard charts and pod compare
    if combined_raw:
        for r in combined_raw:
            ns = str(r.get("namespace") or "").strip()
            if ns not in ns_totals:
                ns_totals[ns] = {"cpu_m": 0.0, "mem_bytes": 0.0}
            ns_totals[ns]["cpu_m"] += quantity_to_millicores(r.get("cpu_request", ""))
            ns_totals[ns]["mem_bytes"] += quantity_to_bytes(r.get("memory_request", ""))
        res_header = ["Resource totals by namespace (top by CPU)", "", ""]
        res_cols = ["Namespace", "Total CPU (m)", "Total Memory (Gi)"]
        res_rows = [res_header, res_cols]
        for ns, tot in sorted(ns_totals.items(), key=lambda x: -x[1]["cpu_m"])[:50]:
            mem_gi = round(tot["mem_bytes"] / (1024 ** 3), 2)
            res_rows.append([ns, round(tot["cpu_m"]), mem_gi])
        while len(res_rows) < 2 + 50:
            res_rows.append(["", "", ""])
        data_ws.update(range_name="A54", values=res_rows, value_input_option="RAW")

    # Freeze top 2 rows and first 4 columns on run tab so headers stay visible when scrolling
    requests: List[dict] = []
    requests.append({
        "updateSheetProperties": {
            "properties": {
                "sheetId": data_sheet_id,
                "gridProperties": {"frozenRowCount": 2, "frozenColumnCount": 4},
            },
            "fields": "gridProperties.frozenRowCount,gridProperties.frozenColumnCount",
        },
    })
    # Widen container details columns (P–W) so CPU Limit, Memory, Recommendations are readable
    requests.append({
        "updateDimensionProperties": {
            "range": {
                "sheetId": data_sheet_id,
                "dimension": "COLUMNS",
                "startIndex": 15,
                "endIndex": 23,
            },
            "properties": {"pixelSize": 130},
            "fields": "pixelSize",
        },
    })

    # Prune old run tabs: keep only the last N (so we have historical data but not hundreds of tabs)
    keep_n = int(os.environ.get("POD_SCANNER_SHEET_RUN_TABS_KEEP", "10"))
    all_run_sheets = [data_ws] + [
        w for w in sh.worksheets()
        if w.title.startswith(_RUN_SHEET_PREFIX) and w.id != data_ws.id
    ]
    all_run_sheets.sort(key=lambda w: w.title)  # oldest first (ISO timestamp sorts correctly)
    to_delete = all_run_sheets[: max(0, len(all_run_sheets) - keep_n)]
    for ws in to_delete:
        requests.append({"deleteSheet": {"sheetId": ws.id}})
    # Runs we keep (newest last); for historical comparison we want newest first
    runs_kept = all_run_sheets[-keep_n:]
    run_titles_newest_first = [w.title for w in reversed(runs_kept)]

    # --- Dashboard tab: title, KPI cards, Top 10, historical comparison, and charts ---
    try:
        dash_ws = sh.worksheet("Dashboard")
    except Exception:
        dash_ws = sh.add_worksheet("Dashboard", rows=95, cols=14)
    dashboard_sheet_id = dash_ws.id

    # Dashboard formulas reference the new run tab by name (escape single quote in sheet name)
    _dn = "'" + run_tab_title.replace("'", "''") + "'!"
    dash_title = "Pod Resource Scanner — Dashboard"
    _node_end = str(3 + _RUN_NODE_MAX_DATA)   # 1-based row after last node data (title+header+10)
    _rec_end = str(3 + _RUN_REC_TYPE_MAX_DATA)
    kpi_rows = [
        [dash_title, "", "", "", "", "Last run: "],
        ["Total Pods", "=SUM(" + _dn + "B4:B52)", "Total Containers", "=SUM(" + _dn + "C4:C52)", "Nodes", "=COUNTA(" + _dn + "E4:E" + _node_end + ")"],
        ["Recommendations", "=SUM(" + _dn + "K4:K" + _rec_end + ")", "Avg Node CPU %", "=IFERROR(ROUND(AVERAGE(" + _dn + "F4:F" + _node_end + "),1)&\"%\",\"—\")", "Avg Memory %", "=IFERROR(ROUND(AVERAGE(" + _dn + "G4:G" + _node_end + "),1)&\"%\",\"—\")"],
        ["Total CPU requested (m)", "=SUM(" + _dn + "B56:B105)", "Total Memory (Gi)", "=IFERROR(ROUND(SUM(" + _dn + "C56:C105), 2)&\" Gi\",\"—\")", "Avg Disk %", "=IFERROR(ROUND(AVERAGE(" + _dn + "H4:H" + _node_end + "),1)&\"%\",\"—\")"],
        ["Recommendations = limit/request suggestions. See run tab for full container list.", "", "Top 10 namespaces by CPU:", "", "", "=" + _dn + "A1"],
    ]
    # Top 10 namespaces by CPU (table: Rank, Namespace, CPU (m))
    top10_header = ["Rank", "Namespace", "CPU (m)"]
    top10_rows = [top10_header]
    for i in range(10):
        r = 56 + i  # run tab data rows 56-65
        top10_rows.append([i + 1, "=" + _dn + "A" + str(r), "=" + _dn + "B" + str(r)])
    dash_ws.clear()
    # Extra blank row between KPIs and Top 10 table to reduce clutter
    dash_ws.update(range_name="A1", values=kpi_rows + [[]] + [[]] + top10_rows, value_input_option="USER_ENTERED")

    # Historical comparison: one row per run tab so you can compare across runs
    comparison_header = ["Run", "Total Pods", "Total Containers", "Total CPU (m)", "Total Memory (Gi)", "Recommendations"]
    comparison_rows = [
        ["Historical comparison (last " + str(keep_n) + " runs) — click Run tab to open", "", "", "", "", ""],
        comparison_header,
    ]
    for title in run_titles_newest_first:
        ref = "'" + title.replace("'", "''") + "'!"
        comparison_rows.append([
            title,
            "=SUM(" + ref + "B4:B52)",
            "=SUM(" + ref + "C4:C52)",
            "=SUM(" + ref + "B56:B105)",
            "=IFERROR(ROUND(SUM(" + ref + "C56:C105), 2)&\" Gi\",\"—\")",
            "=SUM(" + ref + "K4:K" + _rec_end + ")",
        ])
    dash_ws.update(range_name="E6", values=comparison_rows, value_input_option="USER_ENTERED")

    # Dashboard: colored KPI rows (title = blue with white text, then alternating row colors)
    _d = dashboard_sheet_id
    requests.append({
        "repeatCell": {
            "range": {"sheetId": _d, "startRowIndex": 0, "endRowIndex": 1, "startColumnIndex": 0, "endColumnIndex": 6},
            "cell": {"userEnteredFormat": {"backgroundColor": _COLORS["dash_title"], "textFormat": {"bold": True, "foregroundColor": {"red": 1, "green": 1, "blue": 1}, "fontSize": 12}}},
            "fields": "userEnteredFormat.backgroundColor,userEnteredFormat.textFormat.bold,userEnteredFormat.textFormat.foregroundColor,userEnteredFormat.textFormat.fontSize",
        },
    })
    for row, color_key in [(1, "dash_row1"), (2, "dash_row2"), (3, "dash_row3"), (4, "dash_row4"), (5, "dash_row4")]:
        requests.append({
            "repeatCell": {
                "range": {"sheetId": _d, "startRowIndex": row, "endRowIndex": row + 1, "startColumnIndex": 0, "endColumnIndex": 6},
                "cell": {"userEnteredFormat": {"backgroundColor": _COLORS[color_key]}},
                "fields": "userEnteredFormat.backgroundColor",
            },
        })
    # Top 10 table header (row 7 after extra blank row)
    requests.append({
        "repeatCell": {
            "range": {"sheetId": _d, "startRowIndex": 7, "endRowIndex": 8, "startColumnIndex": 0, "endColumnIndex": 3},
            "cell": {"userEnteredFormat": {"backgroundColor": _COLORS["light_gray"], "textFormat": {"bold": True}}},
            "fields": "userEnteredFormat.backgroundColor,userEnteredFormat.textFormat.bold",
        },
    })
    # Historical comparison: title row (E6) and header row (E7)
    requests.append({
        "repeatCell": {
            "range": {"sheetId": _d, "startRowIndex": 5, "endRowIndex": 6, "startColumnIndex": 4, "endColumnIndex": 10},
            "cell": {"userEnteredFormat": {"backgroundColor": _COLORS["light_purple"], "textFormat": {"bold": True}}},
            "fields": "userEnteredFormat.backgroundColor,userEnteredFormat.textFormat.bold",
        },
    })
    requests.append({
        "repeatCell": {
            "range": {"sheetId": _d, "startRowIndex": 6, "endRowIndex": 7, "startColumnIndex": 4, "endColumnIndex": 10},
            "cell": {"userEnteredFormat": {"backgroundColor": _COLORS["purple_header"], "textFormat": {"bold": True, "foregroundColor": {"red": 1, "green": 1, "blue": 1}}}},
            "fields": "userEnteredFormat.backgroundColor,userEnteredFormat.textFormat.bold,userEnteredFormat.textFormat.foregroundColor",
        },
    })

    # Delete existing charts on Dashboard only
    chart_ids = _dashboard_get_existing_chart_ids(sh, dashboard_sheet_id)
    for cid in chart_ids:
        requests.append({"deleteEmbeddedObject": {"objectId": cid}})

    # Charts: data from run tab (data_sheet_id), positioned on Dashboard (dashboard_sheet_id)
    # Place charts below KPIs: anchor row 5
    ns_end_row = _DASHBOARD_NS_END_ROW
    # Horizontal bar so namespace labels are readable (no truncation)
    requests.append({
        "addChart": {
            "chart": {
                "spec": {
                    "title": "Pods by Namespace",
                    "basicChart": {
                        "chartType": "BAR",
                        "legendPosition": "RIGHT_LEGEND",
                        "axis": [
                            {"position": "BOTTOM_AXIS", "title": "Count"},
                            {"position": "LEFT_AXIS", "title": "Namespace"},
                        ],
                        "domains": [{
                            "domain": {
                                "sourceRange": {
                                    "sources": [{
                                        "sheetId": data_sheet_id,
                                        "startRowIndex": _DASHBOARD_NS_HEADER_ROW,
                                        "endRowIndex": ns_end_row,
                                        "startColumnIndex": 0,
                                        "endColumnIndex": 1,
                                    }],
                                },
                            },
                        }],
                        "series": [
                            {
                                "series": {
                                    "sourceRange": {
                                        "sources": [{
                                            "sheetId": data_sheet_id,
                                            "startRowIndex": _DASHBOARD_NS_HEADER_ROW,
                                            "endRowIndex": ns_end_row,
                                            "startColumnIndex": 1,
                                            "endColumnIndex": 2,
                                        }],
                                    },
                                },
                                "targetAxis": "BOTTOM_AXIS",
                            },
                            {
                                "series": {
                                    "sourceRange": {
                                        "sources": [{
                                            "sheetId": data_sheet_id,
                                            "startRowIndex": _DASHBOARD_NS_HEADER_ROW,
                                            "endRowIndex": ns_end_row,
                                            "startColumnIndex": 2,
                                            "endColumnIndex": 3,
                                        }],
                                    },
                                },
                                "targetAxis": "BOTTOM_AXIS",
                            },
                        ],
                        "headerCount": 1,
                    },
                },
                "position": {
                    "overlayPosition": {
                        "anchorCell": {"sheetId": dashboard_sheet_id, "rowIndex": 20, "columnIndex": 0},
                        "offsetXPixels": 10,
                        "offsetYPixels": 0,
                        "widthPixels": 400,
                        "heightPixels": 320,
                    },
                },
            },
        },
    })

    node_end_row = _DASHBOARD_NODE_END_ROW  # compact: title+header+up to 10 node rows
    requests.append({
        "addChart": {
            "chart": {
                "spec": {
                    "title": "Node utilization (%)",
                    "basicChart": {
                        "chartType": "BAR",
                        "legendPosition": "RIGHT_LEGEND",
                        "axis": [
                            {"position": "BOTTOM_AXIS", "title": "Utilization %"},
                            {"position": "LEFT_AXIS", "title": "Node"},
                        ],
                        "domains": [{
                            "domain": {
                                "sourceRange": {
                                    "sources": [{
                                        "sheetId": data_sheet_id,
                                        "startRowIndex": _DASHBOARD_NS_HEADER_ROW,
                                        "endRowIndex": node_end_row,
                                        "startColumnIndex": 4,
                                        "endColumnIndex": 5,
                                    }],
                                },
                            },
                        }],
                        "series": [
                            {
                                "series": {
                                    "sourceRange": {
                                        "sources": [{
                                            "sheetId": data_sheet_id,
                                            "startRowIndex": _DASHBOARD_NS_HEADER_ROW,
                                            "endRowIndex": node_end_row,
                                            "startColumnIndex": 5,
                                            "endColumnIndex": 6,
                                        }],
                                    },
                                },
                                "targetAxis": "BOTTOM_AXIS",
                            },
                            {
                                "series": {
                                    "sourceRange": {
                                        "sources": [{
                                            "sheetId": data_sheet_id,
                                            "startRowIndex": _DASHBOARD_NS_HEADER_ROW,
                                            "endRowIndex": node_end_row,
                                            "startColumnIndex": 6,
                                            "endColumnIndex": 7,
                                        }],
                                    },
                                },
                                "targetAxis": "BOTTOM_AXIS",
                            },
                            {
                                "series": {
                                    "sourceRange": {
                                        "sources": [{
                                            "sheetId": data_sheet_id,
                                            "startRowIndex": _DASHBOARD_NS_HEADER_ROW,
                                            "endRowIndex": node_end_row,
                                            "startColumnIndex": 7,
                                            "endColumnIndex": 8,
                                        }],
                                    },
                                },
                                "targetAxis": "BOTTOM_AXIS",
                            },
                        ],
                        "headerCount": 1,
                    },
                },
                "position": {
                    "overlayPosition": {
                        "anchorCell": {"sheetId": dashboard_sheet_id, "rowIndex": 20, "columnIndex": 5},
                        "offsetXPixels": 10,
                        "offsetYPixels": 0,
                        "widthPixels": 400,
                        "heightPixels": 320,
                    },
                },
            },
        },
    })

    rec_end_row = min(3 + len(rec_sorted), _DASHBOARD_REC_END_ROW)  # title+header+data
    pie_spec = {
        "title": "Recommendations by type",
        "pieChart": {
            "legendPosition": "RIGHT_LEGEND",
            "domain": {
                "sourceRange": {
                    "sources": [{
                        "sheetId": data_sheet_id,
                        "startRowIndex": _DASHBOARD_NS_HEADER_ROW,
                        "endRowIndex": rec_end_row,
                        "startColumnIndex": 9,
                        "endColumnIndex": 10,
                    }],
                },
            },
            "series": {
                "sourceRange": {
                    "sources": [{
                        "sheetId": data_sheet_id,
                        "startRowIndex": _DASHBOARD_NS_HEADER_ROW,
                        "endRowIndex": rec_end_row,
                        "startColumnIndex": 10,
                        "endColumnIndex": 11,
                    }],
                },
            },
        },
    }
    requests.append({
        "addChart": {
            "chart": {
                "spec": pie_spec,
                "position": {
                    "overlayPosition": {
                        "anchorCell": {"sheetId": dashboard_sheet_id, "rowIndex": 20, "columnIndex": 10},
                        "offsetXPixels": 10,
                        "offsetYPixels": 0,
                        "widthPixels": 320,
                        "heightPixels": 320,
                    },
                },
            },
        },
    })

    # Resource charts (from Run tab "Resource totals by namespace" block at A54)
    _res_start, _res_end = 55, 75  # 0-based: header row 55, data 56-74 (top 19)
    if combined_raw and ns_totals:
        requests.append({
            "addChart": {
                "chart": {
                    "spec": {
                        "title": "CPU requested by namespace (top 20)",
                        "basicChart": {
                            "chartType": "BAR",
                            "legendPosition": "RIGHT_LEGEND",
                            "axis": [
                                {"position": "BOTTOM_AXIS", "title": "CPU (millicores)"},
                                {"position": "LEFT_AXIS", "title": "Namespace"},
                            ],
                            "domains": [{
                                "domain": {
                                    "sourceRange": {
                                        "sources": [{
                                            "sheetId": data_sheet_id,
                                            "startRowIndex": _res_start,
                                            "endRowIndex": _res_end,
                                            "startColumnIndex": 0,
                                            "endColumnIndex": 1,
                                        }],
                                    },
                                },
                            }],
                            "series": [{
                                "series": {
                                    "sourceRange": {
                                        "sources": [{
                                            "sheetId": data_sheet_id,
                                            "startRowIndex": _res_start,
                                            "endRowIndex": _res_end,
                                            "startColumnIndex": 1,
                                            "endColumnIndex": 2,
                                        }],
                                    },
                                },
                                "targetAxis": "BOTTOM_AXIS",
                            }],
                            "headerCount": 1,
                        },
                    },
                    "position": {
                        "overlayPosition": {
                            "anchorCell": {"sheetId": dashboard_sheet_id, "rowIndex": 44, "columnIndex": 0},
                            "offsetXPixels": 10,
                            "offsetYPixels": 0,
                            "widthPixels": 450,
                            "heightPixels": 320,
                        },
                    },
                },
            },
        })
        requests.append({
            "addChart": {
                "chart": {
                    "spec": {
                        "title": "Memory requested by namespace (top 20)",
                        "basicChart": {
                            "chartType": "BAR",
                            "legendPosition": "RIGHT_LEGEND",
                            "axis": [
                                {"position": "BOTTOM_AXIS", "title": "Memory (Gi)"},
                                {"position": "LEFT_AXIS", "title": "Namespace"},
                            ],
                            "domains": [{
                                "domain": {
                                    "sourceRange": {
                                        "sources": [{
                                            "sheetId": data_sheet_id,
                                            "startRowIndex": _res_start,
                                            "endRowIndex": _res_end,
                                            "startColumnIndex": 0,
                                            "endColumnIndex": 1,
                                        }],
                                    },
                                },
                            }],
                            "series": [{
                                "series": {
                                    "sourceRange": {
                                        "sources": [{
                                            "sheetId": data_sheet_id,
                                            "startRowIndex": _res_start,
                                            "endRowIndex": _res_end,
                                            "startColumnIndex": 2,
                                            "endColumnIndex": 3,
                                        }],
                                    },
                                },
                                "targetAxis": "BOTTOM_AXIS",
                            }],
                            "headerCount": 1,
                        },
                    },
                    "position": {
                        "overlayPosition": {
                            "anchorCell": {"sheetId": dashboard_sheet_id, "rowIndex": 44, "columnIndex": 5},
                            "offsetXPixels": 10,
                            "offsetYPixels": 0,
                            "widthPixels": 450,
                            "heightPixels": 320,
                        },
                    },
                },
            },
        })

    # Run tab: colored section titles and bold colored header rows
    _r = data_sheet_id
    _bg = "userEnteredFormat.backgroundColor"
    _bold = "userEnteredFormat.textFormat.bold"
    # Section title rows (light backgrounds)
    for (sr, er, sc, ec), color_key in [
        ((1, 2, 0, 4), "light_blue"),      # By Namespace
        ((1, 2, 4, 8), "light_green"),     # Node utilization
        ((1, 2, 9, 11), "light_orange"),   # Recommendations by type
        ((1, 2, 11, 15), "light_orange"),  # Recommendations (detailed)
    ]:
        requests.append({
            "repeatCell": {
                "range": {"sheetId": _r, "startRowIndex": sr, "endRowIndex": er, "startColumnIndex": sc, "endColumnIndex": ec},
                "cell": {"userEnteredFormat": {"backgroundColor": _COLORS[color_key]}},
                "fields": _bg,
            },
        })
    # Table header rows (darker background + bold)
    for (sr, er, sc, ec), color_key in [
        ((2, 3, 0, 4), "blue_header"),
        ((2, 3, 4, 8), "green_header"),
        ((2, 3, 9, 11), "orange_header"),
        ((2, 3, 11, 15), "orange_header"),
    ]:
        requests.append({
            "repeatCell": {
                "range": {"sheetId": _r, "startRowIndex": sr, "endRowIndex": er, "startColumnIndex": sc, "endColumnIndex": ec},
                "cell": {"userEnteredFormat": {"backgroundColor": _COLORS[color_key], "textFormat": {"bold": True, "foregroundColor": {"red": 1, "green": 1, "blue": 1}}}},
                "fields": _bg + "," + _bold + ",userEnteredFormat.textFormat.foregroundColor",
            },
        })
    # Right-align numeric columns across all summary tables for a professional look
    requests.append({
        "repeatCell": {
            "range": {"sheetId": _r, "startRowIndex": 3, "endRowIndex": 53, "startColumnIndex": 1, "endColumnIndex": 3},
            "cell": {"userEnteredFormat": {"horizontalAlignment": "RIGHT"}},
            "fields": "userEnteredFormat.horizontalAlignment",
        },
    })
    requests.append({
        "repeatCell": {
            "range": {"sheetId": _r, "startRowIndex": 3, "endRowIndex": 3 + _RUN_NODE_MAX_DATA, "startColumnIndex": 5, "endColumnIndex": 8},
            "cell": {"userEnteredFormat": {"horizontalAlignment": "RIGHT"}},
            "fields": "userEnteredFormat.horizontalAlignment",
        },
    })
    requests.append({
        "repeatCell": {
            "range": {"sheetId": _r, "startRowIndex": 3, "endRowIndex": 3 + _RUN_REC_TYPE_MAX_DATA, "startColumnIndex": 10, "endColumnIndex": 11},
            "cell": {"userEnteredFormat": {"horizontalAlignment": "RIGHT"}},
            "fields": "userEnteredFormat.horizontalAlignment",
        },
    })
    # Container details: title row and header row (columns P–W)
    if formatted_combined:
        requests.append({
            "repeatCell": {
                "range": {"sheetId": _r, "startRowIndex": 0, "endRowIndex": 1, "startColumnIndex": 15, "endColumnIndex": 23},
                "cell": {"userEnteredFormat": {"backgroundColor": _COLORS["light_purple"]}},
                "fields": _bg,
            },
        })
        requests.append({
            "repeatCell": {
                "range": {"sheetId": _r, "startRowIndex": 1, "endRowIndex": 2, "startColumnIndex": 15, "endColumnIndex": 23},
                "cell": {"userEnteredFormat": {"backgroundColor": _COLORS["purple_header"], "textFormat": {"bold": True, "foregroundColor": {"red": 1, "green": 1, "blue": 1}}}},
                "fields": _bg + "," + _bold + ",userEnteredFormat.textFormat.foregroundColor",
            },
        })
    # Last scan cell (A1) subtle background
    requests.append({
        "repeatCell": {
            "range": {"sheetId": _r, "startRowIndex": 0, "endRowIndex": 1, "startColumnIndex": 0, "endColumnIndex": 1},
            "cell": {"userEnteredFormat": {"backgroundColor": _COLORS["light_gray"]}},
            "fields": _bg,
        },
    })
    # Resource totals by namespace: section title and header (rows 54–55 in sheet = 0-based 53–55)
    _res_title_row, _res_header_row, _res_data_start = 53, 54, 55
    requests.append({
        "repeatCell": {
            "range": {"sheetId": _r, "startRowIndex": _res_title_row, "endRowIndex": _res_header_row, "startColumnIndex": 0, "endColumnIndex": 3},
            "cell": {"userEnteredFormat": {"backgroundColor": _COLORS["light_blue"]}},
            "fields": _bg,
        },
    })
    requests.append({
        "repeatCell": {
            "range": {"sheetId": _r, "startRowIndex": _res_header_row, "endRowIndex": _res_data_start, "startColumnIndex": 0, "endColumnIndex": 3},
            "cell": {"userEnteredFormat": {"backgroundColor": _COLORS["blue_header"], "textFormat": {"bold": True, "foregroundColor": {"red": 1, "green": 1, "blue": 1}}}},
            "fields": _bg + "," + _bold + ",userEnteredFormat.textFormat.foregroundColor",
        },
    })
    # Right-align and format numeric columns (Total CPU m, Total Memory Gi) for Resource totals data
    requests.append({
        "repeatCell": {
            "range": {"sheetId": _r, "startRowIndex": _res_data_start, "endRowIndex": _res_data_start + 50, "startColumnIndex": 1, "endColumnIndex": 3},
            "cell": {"userEnteredFormat": {"horizontalAlignment": "RIGHT", "numberFormat": {"type": "NUMBER", "pattern": "#,##0.00"}}},
            "fields": "userEnteredFormat.horizontalAlignment,userEnteredFormat.numberFormat",
        },
    })

    if requests:
        sh.batch_update({"requests": requests})
    LOG.info(
        "Added run tab '%s', pruned to last %s run tabs, updated Dashboard (KPIs + charts → latest run)",
        run_tab_title, keep_n,
    )


def validate_config(output_dir: Path, update_sheet: bool) -> None:
    """Check config and environment; raise on critical errors."""
    if not output_dir.parent.exists() and output_dir != output_dir.parent:
        raise SystemExit(f"Output parent dir does not exist: {output_dir.parent}")
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        probe = output_dir / ".write_probe"
        probe.write_text("ok")
        probe.unlink()
    except OSError as e:
        raise SystemExit(f"Cannot write to output dir {output_dir}: {e}") from e
    if update_sheet:
        creds = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        sheet_id = os.environ.get("POD_SCANNER_SHEET_ID") or os.environ.get("POD_SCANNER_SHEET_KEY")
        if not sheet_id or not creds:
            LOG.warning("Google Sheet update requested but POD_SCANNER_SHEET_ID or GOOGLE_APPLICATION_CREDENTIALS unset")
        elif not Path(creds).exists():
            raise SystemExit(f"Google credentials file not found: {creds}")


def write_last_success(output_dir: Path, run_ts: str, cluster: str) -> None:
    """Write last-success marker for monitoring (e.g. Prometheus node_exporter textfile)."""
    path = output_dir / "last_success.txt"
    try:
        path.write_text(f"timestamp={run_ts}\ncluster={cluster}\n", encoding="utf-8")
        LOG.debug("Wrote %s", path)
    except OSError as e:
        LOG.warning("Could not write last_success.txt: %s", e)


def cleanup_old_snapshots(output_dir: Path, keep_days: int) -> None:
    """No-op: all data is in a single append-only CSV (all-resources.csv); we do not delete history."""


def inject_cluster(cluster_name: str, rows: List[dict], summary: List[dict],
                   node_rows: List[dict], node_util: List[dict], recommendations: List[dict]) -> None:
    """Add cluster column to all data for multi-cluster reporting."""
    for r in rows:
        r["cluster"] = cluster_name
    for s in summary:
        s["cluster"] = cluster_name
    for n in node_rows:
        n["cluster"] = cluster_name
    for nu in node_util:
        nu["cluster"] = cluster_name
    for rec in recommendations:
        rec["cluster"] = cluster_name


def main() -> None:
    setup_logging()
    run_ts = datetime.utcnow().strftime("%Y-%m-%dT%H%M%SZ")
    output_dir = Path(os.environ.get("POD_SCANNER_OUTPUT_DIR", "/output"))
    cluster_name = os.environ.get("POD_SCANNER_CLUSTER_NAME", "").strip()
    util_scale_up = float(os.environ.get("POD_SCANNER_UTIL_SCALE_UP_PCT", "75"))
    util_scale_down = float(os.environ.get("POD_SCANNER_UTIL_SCALE_DOWN_PCT", "25"))
    retention_days = int(os.environ.get("POD_SCANNER_RETENTION_DAYS", "0"))
    update_sheet = os.environ.get("POD_SCANNER_UPDATE_GOOGLE_SHEET", "").lower() in ("1", "true", "yes")

    try:
        validate_config(output_dir, update_sheet)
    except SystemExit as e:
        LOG.error("%s", e)
        sys.exit(1)

    try:
        load_k8s_config()
        v1 = client.CoreV1Api()
        apps_v1 = client.AppsV1Api()

        rows = scan(v1, apps_v1)
        summary = namespace_summary(rows)
        node_rows = scan_nodes(v1)
        requested = node_requested_totals(rows)
        node_util = node_utilization(node_rows, requested)
        recommendations = build_recommendations(
            node_util, rows,
            util_scale_up_pct=util_scale_up,
            util_scale_down_pct=util_scale_down,
        )
        inject_cluster(cluster_name, rows, summary, node_rows, node_util, recommendations)

        write_csv(rows, summary, node_rows, node_util, recommendations, output_dir, run_ts)
        write_last_success(output_dir, run_ts, cluster_name or "default")
        cleanup_old_snapshots(output_dir, retention_days)

        if update_sheet:
            update_google_sheet(rows, summary, node_util, recommendations, run_ts)

        LOG.info("Scan complete at %s: containers=%s namespaces=%s nodes=%s recommendations=%s",
                 run_ts, len(rows), len(summary), len(node_rows), len(recommendations))
    except ApiException as e:
        LOG.exception("Kubernetes API error: %s", e)
        sys.exit(1)
    except Exception as e:
        LOG.exception("Scan failed: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
