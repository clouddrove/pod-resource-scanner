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

from quantity import parse_quantity, quantity_to_millicores, quantity_to_bytes

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
                "reason": f"Memory limit >> request (limit {mem_lim:.0f}, request {mem_req:.0f} bytes)",
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
):
    """Write a single combined CSV with pod, node, namespace, and recommendation data."""
    output_dir.mkdir(parents=True, exist_ok=True)
    combined = _build_combined_rows(rows, summary, node_util, recommendations)
    out_file = output_dir / f"all-resources-{run_ts}.csv"
    with open(out_file, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COMBINED_HEADERS, extrasaction="ignore")
        w.writeheader()
        w.writerows(combined)
    LOG.info("Wrote %s (%s rows)", out_file, len(combined))


def append_csv_with_timestamp(rows: List[dict], output_dir: Path, run_ts: str) -> None:
    """Append pod-level data with a timestamp column for weekly history."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "pod-resources-history.csv"
    headers = ["scan_date"] + POD_HEADERS
    for r in rows:
        r["scan_date"] = run_ts
    file_exists = path.exists()
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        if not file_exists:
            w.writeheader()
        w.writerows(rows)
    LOG.info("Appended %s rows to %s", len(rows), path)


def update_google_sheet(
    rows: List[dict],
    summary: List[dict],
    node_util: List[dict],
    recommendations: List[dict],
    run_ts: str,
):
    """Update Google Sheet with one combined sheet (all data) and optional History append."""
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

    # Single sheet: all data (pod + node + namespace + recommendations), same as all-resources-*.csv
    combined = _build_combined_rows(rows, summary, node_util, recommendations)
    try:
        ws_all = sh.worksheet("All Resources")
    except gspread.WorksheetNotFound:
        ws_all = sh.add_worksheet("All Resources", rows=1, cols=len(COMBINED_HEADERS))
    ws_all.clear()
    all_cells = [["Last updated: " + run_ts]] + [COMBINED_HEADERS] + [[r.get(h, "") for h in COMBINED_HEADERS] for r in combined]
    ws_all.update("A1", all_cells, value_input_option="RAW")
    LOG.info("Updated sheet 'All Resources' (%s rows)", len(combined))

    # History: append weekly rows for trend
    history_headers = ["scan_date"] + POD_HEADERS
    new_rows = [[run_ts] + [r.get(h, "") for h in POD_HEADERS] for r in rows]
    try:
        ws_history = sh.worksheet("History")
    except gspread.WorksheetNotFound:
        ws_history = sh.add_worksheet("History", rows=1, cols=len(history_headers))
        ws_history.update("A1", [history_headers], value_input_option="RAW")
    if new_rows:
        ws_history.append_rows(new_rows, value_input_option="RAW")
    LOG.info("Appended to sheet 'History' for weekly trend")


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
    """Remove snapshot CSVs older than keep_days to avoid filling PVC."""
    if keep_days <= 0:
        return
    import time
    cutoff = time.time() - (keep_days * 86400)
    removed = 0
    for pattern in ("all-resources-*.csv",):
        for f in output_dir.glob(pattern):
            try:
                if f.stat().st_mtime < cutoff:
                    f.unlink()
                    removed += 1
            except OSError as e:
                LOG.warning("Could not remove %s: %s", f, e)
    if removed:
        LOG.info("Cleaned up %s old snapshot file(s)", removed)


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
        append_csv_with_timestamp(rows, output_dir, run_ts)
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
