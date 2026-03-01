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
import json
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


def scan(
    v1: client.CoreV1Api,
    apps_v1: client.AppsV1Api,
    exclude_namespaces: frozenset = frozenset(),
    pod_metrics: dict = {},
    hpa_targets: frozenset = frozenset(),
) -> List[dict]:
    """Scan all namespaces and pods; return list of row dicts (with node and ephemeral-storage).

    Args:
        exclude_namespaces: namespaces to skip entirely.
        pod_metrics: dict keyed by "ns/pod/container" → {"cpu_usage": "...", "memory_usage": "..."}.
        hpa_targets: frozenset of (namespace, kind, name) tuples for HPA-managed workloads.
    """
    pods = get_all_pods(v1)
    rows = []
    for pod in pods:
        ns = pod.metadata.namespace
        if ns in exclude_namespaces:
            continue
        pod_name = pod.metadata.name
        node_name = (pod.spec.node_name or "") if pod.spec else ""
        status = (pod.status.phase or "").strip()
        kind, workload_name, replicas = get_workload_info(apps_v1, pod)

        # Detect OOM-killed containers from last_state
        oom_set: set = set()
        for cs in (pod.status.container_statuses or []):
            try:
                if (cs.last_state and cs.last_state.terminated
                        and cs.last_state.terminated.reason == "OOMKilled"):
                    oom_set.add(cs.name)
            except AttributeError:
                pass

        hpa_managed = 1 if (ns, kind, workload_name) in hpa_targets else 0

        containers = pod.spec.containers if pod.spec else []
        for c in containers:
            res = c.resources or {}
            req = res.requests or {}
            lim = res.limits or {}
            usage = pod_metrics.get(f"{ns}/{pod_name}/{c.name}", {})
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
                "cpu_usage": usage.get("cpu_usage", ""),
                "memory_usage": usage.get("memory_usage", ""),
                "oom_killed": 1 if c.name in oom_set else 0,
                "hpa_managed": hpa_managed,
                "est_monthly_cost_usd": "",  # populated later by enrich_with_cost()
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


def get_pod_metrics(custom_api) -> Dict[str, Dict[str, str]]:
    """Fetch per-container actual usage from metrics-server.

    Returns dict keyed by "namespace/pod/container" → {"cpu_usage": "125m", "memory_usage": "256Mi"}.
    Degrades gracefully — returns {} if metrics-server is unavailable.
    """
    try:
        result = custom_api.list_cluster_custom_object(
            group="metrics.k8s.io", version="v1beta1", plural="pods"
        )
        out: Dict[str, Dict[str, str]] = {}
        for pod in result.get("items", []):
            ns = pod["metadata"]["namespace"]
            pname = pod["metadata"]["name"]
            for c in pod.get("containers", []):
                key = f"{ns}/{pname}/{c['name']}"
                usage = c.get("usage", {})
                out[key] = {
                    "cpu_usage": usage.get("cpu", ""),
                    "memory_usage": usage.get("memory", ""),
                }
        LOG.debug("Fetched usage metrics for %s containers", len(out))
        return out
    except Exception as e:
        LOG.debug("metrics-server pod metrics not available: %s", e)
        return {}


def get_node_metrics(custom_api) -> Dict[str, Dict[str, str]]:
    """Fetch per-node actual usage from metrics-server.

    Returns dict keyed by node name → {"cpu_usage": "1200m", "memory_usage": "4Gi"}.
    Degrades gracefully — returns {} if metrics-server is unavailable.
    """
    try:
        result = custom_api.list_cluster_custom_object(
            group="metrics.k8s.io", version="v1beta1", plural="nodes"
        )
        out: Dict[str, Dict[str, str]] = {}
        for node in result.get("items", []):
            name = node["metadata"]["name"]
            usage = node.get("usage", {})
            out[name] = {
                "cpu_usage": usage.get("cpu", ""),
                "memory_usage": usage.get("memory", ""),
            }
        LOG.debug("Fetched usage metrics for %s nodes", len(out))
        return out
    except Exception as e:
        LOG.debug("metrics-server node metrics not available: %s", e)
        return {}


def get_hpa_targets(autoscaling_v2) -> frozenset:
    """Return frozenset of (namespace, kind, name) tuples for all HPA targets.

    Degrades gracefully — returns frozenset() if API is unavailable.
    """
    try:
        hpas = autoscaling_v2.list_horizontal_pod_autoscaler_for_all_namespaces(watch=False)
        targets = set()
        for hpa in hpas.items:
            ns = hpa.metadata.namespace
            ref = hpa.spec.scale_target_ref
            targets.add((ns, ref.kind, ref.name))
        LOG.debug("Found %s HPA targets", len(targets))
        return frozenset(targets)
    except Exception as e:
        LOG.debug("HPA listing not available: %s", e)
        return frozenset()


def scan_resource_quotas(v1: client.CoreV1Api, exclude_namespaces: frozenset = frozenset()) -> List[dict]:
    """Scan ResourceQuota objects across all namespaces.

    Returns a list of quota row dicts. Degrades gracefully — returns [] on any error.
    """
    try:
        quotas = v1.list_resource_quota_for_all_namespaces(watch=False)
        rows = []
        for q in quotas.items:
            ns = q.metadata.namespace
            if ns in exclude_namespaces:
                continue
            hard = q.status.hard or {}
            used = q.status.used or {}
            rows.append({
                "namespace": ns,
                "quota_name": q.metadata.name,
                "cpu_hard": hard.get("requests.cpu", hard.get("cpu", "")),
                "cpu_used": used.get("requests.cpu", used.get("cpu", "")),
                "memory_hard": hard.get("requests.memory", hard.get("memory", "")),
                "memory_used": used.get("requests.memory", used.get("memory", "")),
                "pods_hard": hard.get("pods", ""),
                "pods_used": used.get("pods", ""),
            })
        LOG.debug("Found %s ResourceQuota objects", len(rows))
        return rows
    except Exception as e:
        LOG.debug("ResourceQuota listing not available: %s", e)
        return []


def write_resource_quotas_csv(quota_rows: List[dict], output_dir: Path, run_ts: str) -> None:
    """Append resource quota rows (with scan_date) to resource-quotas.csv."""
    if not quota_rows:
        return
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / QUOTA_CSV_NAME
    file_exists = path.exists()
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=QUOTA_HEADERS, extrasaction="ignore")
        if not file_exists:
            w.writeheader()
        for row in quota_rows:
            row_out = {"scan_date": run_ts, **row}
            w.writerow({k: _csv_safe(v) for k, v in row_out.items()})
    LOG.info("Appended %s quota rows to %s", len(quota_rows), path)


def enrich_with_cost(
    rows: List[dict],
    cost_cpu_core_hour: float = 0.048,
    cost_mem_gb_hour: float = 0.006,
) -> None:
    """Mutate rows in-place: add est_monthly_cost_usd based on CPU/memory requests.

    Formula: (cpu_cores * cpu_rate + mem_GiB * mem_rate) * 730 hours/month.
    Sets "" when both request values are zero or missing.
    """
    _GIB = 1024 ** 3
    for r in rows:
        cpu_mc = quantity_to_millicores(r.get("cpu_request", ""))
        mem_b = quantity_to_bytes(r.get("memory_request", ""))
        if not cpu_mc and not mem_b:
            r["est_monthly_cost_usd"] = ""
            continue
        cost = (cpu_mc / 1000.0 * cost_cpu_core_hour + mem_b / _GIB * cost_mem_gb_hour) * 730
        r["est_monthly_cost_usd"] = round(cost, 4)


def read_previous_scan(output_dir: Path) -> Dict[str, dict]:
    """Read the most recent scan data from CSV for comparison. Returns dict keyed by namespace."""
    csv_path = output_dir / OUTPUT_CSV_NAME
    if not csv_path.exists():
        return {}
    
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        if not rows:
            return {}
        
        # Find the most recent scan_date (last unique timestamp)
        scan_dates = sorted(set(r.get("scan_date", "") for r in rows if r.get("scan_date")), reverse=True)
        if len(scan_dates) < 2:
            # Need at least 2 scans to compare
            return {}
        
        previous_scan_date = scan_dates[1]  # Second most recent
        previous_rows = [r for r in rows if r.get("scan_date") == previous_scan_date]
        
        # Aggregate by namespace (similar to namespace_summary)
        from collections import defaultdict
        by_ns = defaultdict(lambda: {"pods": set(), "containers": 0, "cpu": 0.0, "memory": 0.0})
        for r in previous_rows:
            ns = r.get("namespace", "")
            if not ns:
                continue
            by_ns[ns]["pods"].add(r.get("pod", ""))
            by_ns[ns]["containers"] += 1
            by_ns[ns]["cpu"] += quantity_to_millicores(r.get("cpu_request", ""))
            by_ns[ns]["memory"] += quantity_to_bytes(r.get("memory_request", ""))
        
        result = {}
        for ns, data in by_ns.items():
            result[ns] = {
                "scan_date": previous_scan_date,
                "pod_count": len(data["pods"]),
                "container_count": data["containers"],
                "cpu_requested_millicores": round(data["cpu"], 0),
                "memory_requested_bytes": round(data["memory"], 0),
            }
        
        LOG.info("Loaded previous scan data from %s (%s namespaces)", previous_scan_date, len(result))
        return result
    except Exception as e:
        LOG.warning("Could not read previous scan data: %s", e)
        return {}


def namespace_summary(rows: List[dict], previous_summary: Optional[Dict[str, dict]] = None) -> List[dict]:
    """Aggregate by namespace: pod count, container count, and week-over-week changes."""
    from collections import defaultdict
    by_ns = defaultdict(lambda: {"pods": set(), "containers": 0, "cpu": 0.0, "memory": 0.0})
    for r in rows:
        by_ns[r["namespace"]]["pods"].add(r["pod"])
        by_ns[r["namespace"]]["containers"] += 1
        by_ns[r["namespace"]]["cpu"] += quantity_to_millicores(r.get("cpu_request", ""))
        by_ns[r["namespace"]]["memory"] += quantity_to_bytes(r.get("memory_request", ""))
    out = []
    for ns, data in sorted(by_ns.items()):
        pod_count = len(data["pods"])
        cpu_req = data["cpu"]
        mem_req = data["memory"]
        
        result = {
            "namespace": ns,
            "pod_count": pod_count,
            "container_count": data["containers"],
            "cpu_requested_millicores": round(cpu_req, 0),
            "memory_requested_bytes": round(mem_req, 0),
        }
        
        # Calculate week-over-week changes if previous data exists
        if previous_summary and ns in previous_summary:
            prev = previous_summary[ns]
            prev_cpu = prev.get("cpu_requested_millicores", 0)
            prev_mem = prev.get("memory_requested_bytes", 0)
            prev_pods = prev.get("pod_count", 0)
            
            # Calculate percentage changes
            cpu_change_pct = ((cpu_req - prev_cpu) / prev_cpu * 100) if prev_cpu > 0 else 0.0
            mem_change_pct = ((mem_req - prev_mem) / prev_mem * 100) if prev_mem > 0 else 0.0
            pod_change = pod_count - prev_pods
            
            result["cpu_change_pct"] = round(cpu_change_pct, 1)
            result["memory_change_pct"] = round(mem_change_pct, 1)
            result["pod_count_change"] = pod_change
            result["previous_scan_date"] = prev.get("scan_date", "")
        else:
            # First time seeing this namespace
            result["cpu_change_pct"] = 0.0
            result["memory_change_pct"] = 0.0
            result["pod_count_change"] = 0
            result["previous_scan_date"] = ""
        
        out.append(result)
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


def node_utilization(
    node_rows: List[dict],
    requested: Dict[str, Dict[str, float]],
    node_metrics: Dict[str, Dict[str, str]] = {},
) -> List[dict]:
    """Merge node capacity/allocatable with requested sums and optional metrics-server usage."""
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

        usage = node_metrics.get(node_name, {})
        cpu_usage_mc = quantity_to_millicores(usage.get("cpu_usage", "")) if usage else 0
        mem_usage_b = quantity_to_bytes(usage.get("memory_usage", "")) if usage else 0

        row = {
            **n,
            "cpu_requested_millicores": round(cpu_req, 0),
            "memory_requested_bytes": round(mem_req, 0),
            "ephemeral_storage_requested_bytes": round(disk_req, 0),
            "cpu_util_pct": round(100 * cpu_req / cpu_alloc, 1) if cpu_alloc else 0,
            "memory_util_pct": round(100 * mem_req / mem_alloc, 1) if mem_alloc else 0,
            "disk_util_pct": round(100 * disk_req / disk_alloc, 1) if disk_alloc else 0,
        }
        if cpu_usage_mc or mem_usage_b:
            row["cpu_usage_millicores"] = round(cpu_usage_mc, 0)
            row["memory_usage_bytes"] = round(mem_usage_b, 0)
            row["cpu_usage_pct"] = round(100 * cpu_usage_mc / cpu_alloc, 1) if cpu_alloc else ""
            row["memory_usage_pct"] = round(100 * mem_usage_b / mem_alloc, 1) if mem_alloc else ""
        else:
            row["cpu_usage_millicores"] = ""
            row["memory_usage_bytes"] = ""
            row["cpu_usage_pct"] = ""
            row["memory_usage_pct"] = ""
        out.append(row)
    return out


def build_recommendations(
    node_util: List[dict],
    pod_rows: List[dict],
    namespace_summary: List[dict],
    util_scale_up_pct: float = 75.0,
    util_scale_down_pct: float = 25.0,
    growth_alert_pct: float = 20.0,
    hpa_targets: frozenset = frozenset(),
) -> List[dict]:
    """Produce recommendations: scale up/down nodes, set or adjust limits, OOM risk."""
    recs = []

    # Build a mapping of node → set of (namespace, workload_kind, workload_name) for HPA awareness
    hpa_nodes: Dict[str, bool] = {}
    if hpa_targets:
        for nu in node_util:
            node = nu.get("node", "")
            hpa_nodes[node] = False  # default: no HPA workloads
        for r in pod_rows:
            ns = r.get("namespace", "")
            kind = r.get("workload_kind", "")
            wname = r.get("workload_name", "")
            node = r.get("node", "")
            if (ns, kind, wname) in hpa_targets and node:
                hpa_nodes[node] = True

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
            hpa_suffix = " (HPA-managed workloads present)" if hpa_nodes.get(node) else ""
            recs.append({
                "type": "scale_down",
                "target": f"node:{node}",
                "reason": f"Low utilization: CPU {cpu_pct}%, memory {mem_pct}%, disk {disk_pct}%{hpa_suffix}",
                "action": "Consider removing node or consolidating workloads to save cost.",
            })
    # Cluster-level from same data
    total_cpu_alloc = sum(quantity_to_millicores(n.get("cpu_allocatable", "")) for n in node_util if n.get("node") != "_unscheduled_")
    total_mem_alloc = sum(quantity_to_bytes(n.get("memory_allocatable", "")) for n in node_util if n.get("node") != "_unscheduled_")
    total_cpu_req = sum(n.get("cpu_requested_millicores", 0) for n in node_util if n.get("node") != "_unscheduled_")
    total_mem_req = sum(n.get("memory_requested_bytes", 0) for n in node_util if n.get("node") != "_unscheduled_")
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
    # Container-level: missing limits, limit >> request, OOM risk
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
        if r.get("oom_killed") == 1:
            recs.append({
                "type": "oom_risk",
                "target": f"{ns}/{pod}/{cont}",
                "reason": "Container was OOM-killed; increase memory limit.",
                "action": "Raise memory limit (and request if needed) to prevent OOM kills.",
            })
    
    # Namespace-level: alert on significant growth
    for ns_data in namespace_summary:
        ns = ns_data.get("namespace", "")
        cpu_change = ns_data.get("cpu_change_pct", 0)
        mem_change = ns_data.get("memory_change_pct", 0)
        
        if cpu_change >= growth_alert_pct or mem_change >= growth_alert_pct:
            changes = []
            if cpu_change >= growth_alert_pct:
                changes.append(f"CPU +{cpu_change:.1f}%")
            if mem_change >= growth_alert_pct:
                changes.append(f"memory +{mem_change:.1f}%")
            recs.append({
                "type": "growth_alert",
                "target": f"namespace:{ns}",
                "reason": f"Significant growth since last scan: {', '.join(changes)}",
                "action": "Review namespace for unexpected resource increases or runaway processes.",
            })
    
    return recs


POD_USAGE_COLUMNS = ["cpu_usage", "memory_usage", "oom_killed", "hpa_managed", "est_monthly_cost_usd"]

POD_HEADERS = [
    "cluster", "namespace", "pod", "container", "node", "workload_kind", "workload_name", "replicas",
    "cpu_request", "cpu_limit", "memory_request", "memory_limit",
    "ephemeral_storage_request", "ephemeral_storage_limit",
    "cpu_usage", "memory_usage", "oom_killed", "hpa_managed", "est_monthly_cost_usd",
    "status",
]

# Columns added per row from node utilization and namespace summary (single combined CSV)
NODE_UTIL_COLUMNS = [
    "node_cpu_capacity", "node_cpu_allocatable", "node_memory_capacity", "node_memory_allocatable",
    "node_ephemeral_storage_capacity", "node_ephemeral_storage_allocatable",
    "node_cpu_requested_millicores", "node_memory_requested_bytes", "node_ephemeral_storage_requested_bytes",
    "node_cpu_util_pct", "node_memory_util_pct", "node_disk_util_pct",
]
NS_SUMMARY_COLUMNS = [
    "ns_pod_count", "ns_container_count", "ns_cpu_requested_millicores", 
    "ns_memory_requested_bytes", "ns_cpu_change_pct", "ns_memory_change_pct", 
    "ns_pod_count_change", "ns_previous_scan_date"
]
COMBINED_HEADERS = POD_HEADERS + NODE_UTIL_COLUMNS + NS_SUMMARY_COLUMNS + ["recommendations"]
# Single cumulative file: scan_date first so history is in one place
HISTORY_CSV_HEADERS = ["scan_date"] + COMBINED_HEADERS
OUTPUT_CSV_NAME = "all-resources.csv"
QUOTA_CSV_NAME = "resource-quotas.csv"
QUOTA_HEADERS = [
    "scan_date", "cluster", "namespace", "quota_name",
    "cpu_hard", "cpu_used", "memory_hard", "memory_used", "pods_hard", "pods_used",
]

_CSV_INJECTION_PREFIXES = frozenset("=+-@")


def _csv_safe(value: Any) -> Any:
    """Prefix formula-like strings with a single quote to prevent CSV injection.

    Spreadsheet clients (Excel, Google Sheets) treat a leading apostrophe as a
    text-prefix and display the rest of the value as plain text, so the formula
    is never executed.  Numeric and non-string values are returned unchanged.
    """
    if isinstance(value, str) and value and value[0] in _CSV_INJECTION_PREFIXES:
        return "'" + value
    return value

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
    "CPU Usage",
    "Memory Usage",
    "OOM Killed",
    "HPA Managed",
    "Est. Monthly Cost (USD)",
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
    "Namespace CPU Requested (millicores)",
    "Namespace Memory Requested (bytes)",
    "Namespace CPU Change %",
    "Namespace Memory Change %",
    "Namespace Pod Count Change",
    "Previous Scan Date",
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
    if key in ("node_cpu_util_pct", "node_memory_util_pct", "node_disk_util_pct", "ns_cpu_change_pct", "ns_memory_change_pct"):
        try:
            pct = float(value)
            return f"{pct:+.1f}%" if key in ("ns_cpu_change_pct", "ns_memory_change_pct") else f"{pct:.1f}%"
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
            "ns_cpu_requested_millicores",
            "ns_memory_requested_bytes",
            "ns_pod_count_change",
            "ns_previous_scan_date",
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
        row["ns_cpu_requested_millicores"] = s.get("cpu_requested_millicores", "")
        row["ns_memory_requested_bytes"] = s.get("memory_requested_bytes", "")
        row["ns_cpu_change_pct"] = s.get("cpu_change_pct", "")
        row["ns_memory_change_pct"] = s.get("memory_change_pct", "")
        row["ns_pod_count_change"] = s.get("pod_count_change", "")
        row["ns_previous_scan_date"] = s.get("previous_scan_date", "")
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
        w.writerows([{k: _csv_safe(v) for k, v in row.items()} for row in combined])
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
    quota_rows: Optional[List[dict]] = None,
):
    """Update Google Sheet: new Run <timestamp> tab per run, Dashboard for latest; remove obsolete All Resources tab if present."""
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

    if len(formatted) == 0:
        LOG.info("No container data; skipping Google Sheet update")
        return

    # Remove "All Resources" tab if present (no longer used; Run tabs have container details)
    try:
        sh.del_worksheet(sh.worksheet("All Resources"))
        LOG.info("Removed obsolete 'All Resources' tab from sheet")
    except gspread.WorksheetNotFound:
        pass

    _update_dashboard_sheet(sh, summary, node_util, recommendations, run_ts, formatted, combined, quota_rows=quota_rows)


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
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
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
    quota_rows: Optional[List[dict]] = None,
) -> None:
    """Create a new 'Run <timestamp>' tab each run; keep last N run tabs; Dashboard visualizes the latest (historical data)."""
    run_tab_title = _RUN_SHEET_PREFIX + run_ts
    # 13 container detail cols (P–AB) + quota cols beyond that; allocate 40 cols total
    data_ws = sh.add_worksheet(run_tab_title, rows=115, cols=40)
    data_sheet_id = data_ws.id
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

    # Container details — 13 columns at P1 (P–AB): request/limit + usage + OOM + HPA + cost + recs
    # Sort by namespace (then pod, container) so we can merge the Namespace column per group
    sorted_combined: List[dict] = []
    if formatted_combined:
        sorted_combined = sorted(
            formatted_combined[:1000],
            key=lambda r: (str(r.get("namespace", "")), str(r.get("pod", "")), str(r.get("container", ""))),
        )
        detail_header = [
            "Namespace", "Pod", "Container",
            "CPU Request", "CPU Limit", "Memory Request", "Memory Limit",
            "CPU Usage", "Memory Usage", "OOM Killed", "HPA Managed",
            "Est. Monthly Cost (USD)",
            "Recommendations",
        ]
        # Title row must span 13 columns
        detail_rows = [
            ["Container details (request / limit / usage / cost / suggestions)"] + [""] * 12,
            detail_header,
        ]
        for r in sorted_combined:
            detail_rows.append([
                str(r.get("namespace", "")),
                str(r.get("pod", "")),
                str(r.get("container", "")),
                str(r.get("cpu_request", "")),
                str(r.get("cpu_limit", "")),
                str(r.get("memory_request", "")),
                str(r.get("memory_limit", "")),
                str(r.get("cpu_usage", "")),
                str(r.get("memory_usage", "")),
                str(r.get("oom_killed", "")),
                str(r.get("hpa_managed", "")),
                str(r.get("est_monthly_cost_usd", "")),
                str(r.get("recommendations", "")),
            ])
        data_ws.update(range_name="P1", values=detail_rows, value_input_option="RAW")

    # Resource quota table — at AC1 (column 29, 0-based 28) when quota data is available
    if quota_rows:
        quota_header = ["Namespace", "Quota Name", "CPU Hard", "CPU Used", "Mem Hard", "Mem Used", "Pods Hard", "Pods Used"]
        quota_data_rows = [
            ["Resource Quotas"] + [""] * 7,
            quota_header,
        ]
        for q in quota_rows[:50]:
            quota_data_rows.append([
                str(q.get("namespace", "")),
                str(q.get("quota_name", "")),
                str(q.get("cpu_hard", "")),
                str(q.get("cpu_used", "")),
                str(q.get("memory_hard", "")),
                str(q.get("memory_used", "")),
                str(q.get("pods_hard", "")),
                str(q.get("pods_used", "")),
            ])
        data_ws.update(range_name="AC1", values=quota_data_rows, value_input_option="RAW")

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
    # Widen container details columns (P–AB, 13 cols) so all fields are readable
    requests.append({
        "updateDimensionProperties": {
            "range": {
                "sheetId": data_sheet_id,
                "dimension": "COLUMNS",
                "startIndex": 15,
                "endIndex": 28,
            },
            "properties": {"pixelSize": 130},
            "fields": "pixelSize",
        },
    })
    # Merge Namespace column (P) for consecutive rows with the same namespace
    # NOTE: mergeCells must be batched BEFORE setBasicFilter; Google Sheets rejects merges
    # that overlap an existing filter range.
    if sorted_combined:
        ns_col = 15  # P
        data_start_row = 2  # 0-based: title 0, header 1, data from 2
        i = 0
        while i < len(sorted_combined):
            ns = str(sorted_combined[i].get("namespace", ""))
            j = i + 1
            while j < len(sorted_combined) and str(sorted_combined[j].get("namespace", "")) == ns:
                j += 1
            if j - i >= 2:
                requests.append({
                    "mergeCells": {
                        "range": {
                            "sheetId": data_sheet_id,
                            "startRowIndex": data_start_row + i,
                            "endRowIndex": data_start_row + j,
                            "startColumnIndex": ns_col,
                            "endColumnIndex": ns_col + 1,
                        },
                        "mergeType": "MERGE_ALL",
                    },
                })
            i = j

    # Add basic filter on Container details (P2:AB) — 13 columns.
    # Appended after mergeCells so the filter doesn't block the merges in the same batch.
    if formatted_combined:
        requests.append({
            "setBasicFilter": {
                "filter": {
                    "range": {
                        "sheetId": data_sheet_id,
                        "startRowIndex": 1,
                        "endRowIndex": 115,
                        "startColumnIndex": 15,
                        "endColumnIndex": 28,
                    },
                },
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

    # --- Dashboard tab: title, KPI cards, Top 10, historical comparison, and charts ---
    try:
        dash_ws = sh.worksheet("Dashboard")
    except Exception:
        dash_ws = sh.add_worksheet("Dashboard", rows=25, cols=14)
    dashboard_sheet_id = dash_ws.id

    # Dashboard formulas reference the new run tab by name (escape single quote in sheet name)
    _dn = "'" + run_tab_title.replace("'", "''") + "'!"
    dash_title = "Pod Resource Scanner — Dashboard"
    _node_end = str(3 + _RUN_NODE_MAX_DATA)   # 1-based row after last node data (title+header+10)
    _rec_end = str(3 + _RUN_REC_TYPE_MAX_DATA)

    # Cluster totals: CPU and memory requested vs allocatable (from node_util)
    total_cpu_alloc = sum(quantity_to_millicores(n.get("cpu_allocatable", "")) for n in node_util if n.get("node") != "_unscheduled_")
    total_cpu_req = sum(n.get("cpu_requested_millicores", 0) for n in node_util)
    total_mem_alloc = sum(quantity_to_bytes(n.get("memory_allocatable", "")) for n in node_util if n.get("node") != "_unscheduled_")
    total_mem_req = sum(n.get("memory_requested_bytes", 0) for n in node_util)
    cpu_pct = round(100 * total_cpu_req / total_cpu_alloc, 1) if total_cpu_alloc else 0
    mem_pct = round(100 * total_mem_req / total_mem_alloc, 1) if total_mem_alloc else 0
    mem_req_gi = round(total_mem_req / (1024 ** 3), 2)
    mem_alloc_gi = round(total_mem_alloc / (1024 ** 3), 2)

    # Node scaling guidance from scale_up / scale_down recommendations
    has_scale_up = any(r.get("type") == "scale_up" for r in recommendations)
    has_scale_down = any(r.get("type") == "scale_down" for r in recommendations)
    if has_scale_up:
        scale_nodes_msg = "Consider adding nodes (high utilization or cluster capacity)"
    elif has_scale_down:
        scale_nodes_msg = "Consider scaling down (low utilization — save cost)"
    else:
        scale_nodes_msg = "No action needed"

    # Compute total estimated monthly cost for Dashboard KPI
    total_est_cost = sum(
        float(r.get("est_monthly_cost_usd") or 0)
        for r in (combined_raw or [])
        if r.get("est_monthly_cost_usd") != ""
    )
    cost_kpi = f"${total_est_cost:,.2f} / month" if total_est_cost else "N/A (no cost config)"

    # Dashboard: explainable at a glance — title, explanation, KPIs, CPU/Memory, scale guidance, cost
    kpi_rows = [
        [dash_title, "", "", "", "Last updated: ", "=" + _dn + "A1"],
        ["Summary of the latest scan. Open a Run tab for full details and container-level recommendations.", "", "", "", "", ""],
        ["Pods", "=SUM(" + _dn + "B4:B52)", "Containers", "=SUM(" + _dn + "C4:C52)", "Nodes", "=COUNTA(" + _dn + "E4:E" + _node_end + ")"],
        ["Recommendations to review", "=SUM(" + _dn + "K4:K" + _rec_end + ")", "", "", "", ""],
        ["CPU (cluster)", f"requested: {int(total_cpu_req)} m", f"allocatable: {int(total_cpu_alloc)} m", f"usage: {cpu_pct}%", "", ""],
        ["Memory (cluster)", f"requested: {mem_req_gi} Gi", f"allocatable: {mem_alloc_gi} Gi", f"usage: {mem_pct}%", "", ""],
        ["Scale nodes?", scale_nodes_msg, "", "", "", ""],
        ["Est. monthly cost", cost_kpi, "", "", "", ""],
    ]
    dash_ws.clear()
    dash_ws.update(range_name="A1", values=kpi_rows, value_input_option="USER_ENTERED")

    # Dashboard: title row; explainer row; KPI rows; CPU/Memory rows (light background)
    _d = dashboard_sheet_id
    requests.append({
        "repeatCell": {
            "range": {"sheetId": _d, "startRowIndex": 0, "endRowIndex": 1, "startColumnIndex": 0, "endColumnIndex": 6},
            "cell": {"userEnteredFormat": {"backgroundColor": _COLORS["dash_title"], "textFormat": {"bold": True, "foregroundColor": {"red": 1, "green": 1, "blue": 1}, "fontSize": 12}}},
            "fields": "userEnteredFormat.backgroundColor,userEnteredFormat.textFormat.bold,userEnteredFormat.textFormat.foregroundColor,userEnteredFormat.textFormat.fontSize",
        },
    })
    for row, color_key in [(1, "dash_row4"), (2, "dash_row1"), (3, "dash_row2"), (4, "dash_row3"), (5, "dash_row2"), (6, "dash_row3"), (7, "dash_row2"), (8, "dash_row1")]:
        requests.append({
            "repeatCell": {
                "range": {"sheetId": _d, "startRowIndex": row, "endRowIndex": row + 1, "startColumnIndex": 0, "endColumnIndex": 6},
                "cell": {"userEnteredFormat": {"backgroundColor": _COLORS[color_key]}},
                "fields": "userEnteredFormat.backgroundColor",
            },
        })

    # Delete existing charts on Dashboard only
    chart_ids = _dashboard_get_existing_chart_ids(sh, dashboard_sheet_id)
    for cid in chart_ids:
        requests.append({"deleteEmbeddedObject": {"objectId": cid}})

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
    # Container details: title row and header row (columns P–AB, 13 cols)
    if formatted_combined:
        requests.append({
            "repeatCell": {
                "range": {"sheetId": _r, "startRowIndex": 0, "endRowIndex": 1, "startColumnIndex": 15, "endColumnIndex": 28},
                "cell": {"userEnteredFormat": {"backgroundColor": _COLORS["light_purple"]}},
                "fields": _bg,
            },
        })
        requests.append({
            "repeatCell": {
                "range": {"sheetId": _r, "startRowIndex": 1, "endRowIndex": 2, "startColumnIndex": 15, "endColumnIndex": 28},
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
    if requests:
        sh.batch_update({"requests": requests})
    LOG.info(
        "Added run tab '%s', pruned to last %s run tabs, updated Dashboard (KPIs + charts → latest run)",
        run_tab_title, keep_n,
    )


def write_prometheus_metrics(
    output_dir: Path,
    run_ts: str,
    cluster: str,
    summary: List[dict],
    node_util: List[dict],
    recommendations: List[dict],
) -> None:
    """Write Prometheus textfile collector metrics to pod-scanner.prom."""
    import time as _time

    cluster_label = cluster or "default"
    lines = [
        "# HELP pod_scanner_last_scan_timestamp_seconds Unix timestamp of the last successful scan",
        "# TYPE pod_scanner_last_scan_timestamp_seconds gauge",
        f'pod_scanner_last_scan_timestamp_seconds{{cluster="{cluster_label}"}} {int(_time.time())}',
        "",
        "# HELP pod_scanner_namespace_cpu_requested_millicores Total CPU requested in millicores per namespace",
        "# TYPE pod_scanner_namespace_cpu_requested_millicores gauge",
    ]
    for s in summary:
        ns = s.get("namespace", "")
        lines.append(
            f'pod_scanner_namespace_cpu_requested_millicores{{namespace="{ns}",cluster="{cluster_label}"}}'
            f' {s.get("cpu_requested_millicores", 0)}'
        )
    lines += [
        "",
        "# HELP pod_scanner_namespace_memory_requested_bytes Total memory requested in bytes per namespace",
        "# TYPE pod_scanner_namespace_memory_requested_bytes gauge",
    ]
    for s in summary:
        ns = s.get("namespace", "")
        lines.append(
            f'pod_scanner_namespace_memory_requested_bytes{{namespace="{ns}",cluster="{cluster_label}"}}'
            f' {s.get("memory_requested_bytes", 0)}'
        )
    lines += [
        "",
        "# HELP pod_scanner_namespace_cpu_change_pct Week-over-week CPU change % per namespace",
        "# TYPE pod_scanner_namespace_cpu_change_pct gauge",
    ]
    for s in summary:
        ns = s.get("namespace", "")
        lines.append(
            f'pod_scanner_namespace_cpu_change_pct{{namespace="{ns}",cluster="{cluster_label}"}}'
            f' {s.get("cpu_change_pct", 0)}'
        )
    lines += [
        "",
        "# HELP pod_scanner_node_cpu_util_pct Node CPU utilization % (requests vs allocatable)",
        "# TYPE pod_scanner_node_cpu_util_pct gauge",
    ]
    for nu in node_util:
        node = nu.get("node", "")
        if node == "_unscheduled_":
            continue
        lines.append(
            f'pod_scanner_node_cpu_util_pct{{node="{node}",cluster="{cluster_label}"}}'
            f' {nu.get("cpu_util_pct", 0)}'
        )
    lines += [
        "",
        "# HELP pod_scanner_node_memory_util_pct Node memory utilization % (requests vs allocatable)",
        "# TYPE pod_scanner_node_memory_util_pct gauge",
    ]
    for nu in node_util:
        node = nu.get("node", "")
        if node == "_unscheduled_":
            continue
        lines.append(
            f'pod_scanner_node_memory_util_pct{{node="{node}",cluster="{cluster_label}"}}'
            f' {nu.get("memory_util_pct", 0)}'
        )
    # Usage metrics (only emitted when metrics-server data is present)
    usage_nodes = [nu for nu in node_util if nu.get("cpu_usage_pct") != ""]
    if usage_nodes:
        lines += [
            "",
            "# HELP pod_scanner_node_cpu_usage_pct Node CPU actual usage % (from metrics-server)",
            "# TYPE pod_scanner_node_cpu_usage_pct gauge",
        ]
        for nu in usage_nodes:
            node = nu.get("node", "")
            lines.append(
                f'pod_scanner_node_cpu_usage_pct{{node="{node}",cluster="{cluster_label}"}}'
                f' {nu.get("cpu_usage_pct", 0)}'
            )
        lines += [
            "",
            "# HELP pod_scanner_node_memory_usage_pct Node memory actual usage % (from metrics-server)",
            "# TYPE pod_scanner_node_memory_usage_pct gauge",
        ]
        for nu in usage_nodes:
            node = nu.get("node", "")
            lines.append(
                f'pod_scanner_node_memory_usage_pct{{node="{node}",cluster="{cluster_label}"}}'
                f' {nu.get("memory_usage_pct", 0)}'
            )
    # Recommendation counts by type
    rec_counts: Dict[str, int] = {}
    for rec in recommendations:
        t = str(rec.get("type") or "other")
        rec_counts[t] = rec_counts.get(t, 0) + 1
    lines += [
        "",
        "# HELP pod_scanner_recommendations_total Number of recommendations produced per type",
        "# TYPE pod_scanner_recommendations_total gauge",
    ]
    for rtype, count in sorted(rec_counts.items()):
        lines.append(
            f'pod_scanner_recommendations_total{{type="{rtype}",cluster="{cluster_label}"}}'
            f' {count}'
        )
    lines.append("")  # trailing newline

    output_dir.mkdir(parents=True, exist_ok=True)
    prom_path = output_dir / "pod-scanner.prom"
    try:
        prom_path.write_text("\n".join(lines), encoding="utf-8")
        LOG.info("Wrote Prometheus metrics to %s", prom_path)
    except OSError as e:
        LOG.warning("Could not write Prometheus metrics: %s", e)


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


def inject_cluster(
    cluster_name: str,
    rows: List[dict],
    summary: List[dict],
    node_rows: List[dict],
    node_util: List[dict],
    recommendations: List[dict],
    quota_rows: Optional[List[dict]] = None,
) -> None:
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
    if quota_rows:
        for q in quota_rows:
            q["cluster"] = cluster_name


def main() -> None:
    setup_logging()
    run_ts = datetime.utcnow().strftime("%Y-%m-%dT%H%M%SZ")
    output_dir = Path(os.environ.get("POD_SCANNER_OUTPUT_DIR", "/output"))
    cluster_name = os.environ.get("POD_SCANNER_CLUSTER_NAME", "").strip()
    try:
        util_scale_up = float(os.environ.get("POD_SCANNER_UTIL_SCALE_UP_PCT", "75"))
        util_scale_down = float(os.environ.get("POD_SCANNER_UTIL_SCALE_DOWN_PCT", "25"))
        growth_alert_pct = float(os.environ.get("POD_SCANNER_GROWTH_ALERT_PCT", "20"))
        retention_days = int(os.environ.get("POD_SCANNER_RETENTION_DAYS", "0"))
        cost_cpu = float(os.environ.get("POD_SCANNER_COST_CPU_CORE_HOUR", "0.048"))
        cost_mem = float(os.environ.get("POD_SCANNER_COST_MEM_GB_HOUR", "0.006"))
    except ValueError as e:
        LOG.error("Invalid numeric environment variable: %s", e)
        sys.exit(1)

    exclude_namespaces = frozenset(
        ns.strip()
        for ns in os.environ.get("POD_SCANNER_EXCLUDE_NAMESPACES", "").split(",")
        if ns.strip()
    )
    dry_run = os.environ.get("POD_SCANNER_DRY_RUN", "").lower() in ("1", "true", "yes")
    metrics_enabled = os.environ.get("POD_SCANNER_METRICS_ENABLED", "true").lower() not in ("0", "false", "no")
    update_sheet = os.environ.get("POD_SCANNER_UPDATE_GOOGLE_SHEET", "").lower() in ("1", "true", "yes")

    if exclude_namespaces:
        LOG.info("Excluding namespaces: %s", ", ".join(sorted(exclude_namespaces)))
    if dry_run:
        LOG.info("DRY RUN mode enabled — no files will be written")

    try:
        validate_config(output_dir, update_sheet and not dry_run)
    except SystemExit as e:
        LOG.error("%s", e)
        sys.exit(1)

    try:
        load_k8s_config()
        v1 = client.CoreV1Api()
        apps_v1 = client.AppsV1Api()
        custom_api = client.CustomObjectsApi()
        autoscaling_v2 = client.AutoscalingV2Api()

        # Fetch optional metrics-server and HPA data (graceful degradation on failure)
        pod_metrics = get_pod_metrics(custom_api) if metrics_enabled else {}
        node_metrics = get_node_metrics(custom_api) if metrics_enabled else {}
        hpa_targets = get_hpa_targets(autoscaling_v2)
        quota_rows = scan_resource_quotas(v1, exclude_namespaces)

        # Read previous scan data for comparison
        previous_summary = read_previous_scan(output_dir)

        rows = scan(v1, apps_v1, exclude_namespaces, pod_metrics, hpa_targets)
        enrich_with_cost(rows, cost_cpu, cost_mem)
        summary = namespace_summary(rows, previous_summary)
        node_rows = scan_nodes(v1)
        requested = node_requested_totals(rows)
        node_util = node_utilization(node_rows, requested, node_metrics)
        recommendations = build_recommendations(
            node_util, rows, summary,
            util_scale_up_pct=util_scale_up,
            util_scale_down_pct=util_scale_down,
            growth_alert_pct=growth_alert_pct,
            hpa_targets=hpa_targets,
        )
        inject_cluster(cluster_name, rows, summary, node_rows, node_util, recommendations, quota_rows)

        if dry_run:
            LOG.info(
                "DRY RUN complete: containers=%s namespaces=%s nodes=%s quotas=%s recommendations=%s",
                len(rows), len(summary), len(node_rows), len(quota_rows), len(recommendations),
            )
            for rec in recommendations:
                LOG.info("REC [%s] %s — %s", rec.get("type"), rec.get("target"), rec.get("reason"))
        else:
            write_csv(rows, summary, node_rows, node_util, recommendations, output_dir, run_ts)
            write_resource_quotas_csv(quota_rows, output_dir, run_ts)
            write_last_success(output_dir, run_ts, cluster_name or "default")
            write_prometheus_metrics(output_dir, run_ts, cluster_name, summary, node_util, recommendations)
            cleanup_old_snapshots(output_dir, retention_days)

            if update_sheet:
                update_google_sheet(rows, summary, node_util, recommendations, run_ts, quota_rows=quota_rows)

            LOG.info(
                "Scan complete at %s: containers=%s namespaces=%s nodes=%s quotas=%s recommendations=%s",
                run_ts, len(rows), len(summary), len(node_rows), len(quota_rows), len(recommendations),
            )
    except ApiException as e:
        LOG.exception("Kubernetes API error: %s", e)
        sys.exit(1)
    except Exception as e:
        LOG.exception("Scan failed: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
