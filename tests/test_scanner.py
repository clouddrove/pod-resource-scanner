"""Unit tests for scanner.py core logic (no Kubernetes or Google Sheets required)."""
import sys
import csv
import io
from pathlib import Path
from types import ModuleType
from unittest.mock import patch, MagicMock

# Stub out heavy third-party modules so scanner.py can be imported without
# the kubernetes / gspread packages being installed in the local environment.
def _stub(name: str) -> ModuleType:
    m = ModuleType(name)
    sys.modules[name] = m
    return m

for _pkg in ("kubernetes", "kubernetes.client", "kubernetes.client.rest",
             "kubernetes.config", "gspread", "google.auth", "google.auth.transport",
             "google.auth.transport.requests", "google_auth_oauthlib",
             "google_auth_oauthlib.flow"):
    if _pkg not in sys.modules:
        _stub(_pkg)

# kubernetes sub-attributes accessed at module level
import kubernetes  # noqa: E402
kubernetes.client = _stub("kubernetes.client")
kubernetes.client.CoreV1Api = MagicMock()
kubernetes.client.AppsV1Api = MagicMock()
kubernetes.client.CustomObjectsApi = MagicMock()
kubernetes.client.AutoscalingV2Api = MagicMock()
kubernetes.client.rest = _stub("kubernetes.client.rest")
kubernetes.client.rest.ApiException = Exception
kubernetes.config = _stub("kubernetes.config")
kubernetes.config.ConfigException = Exception

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner import (
    _csv_safe,
    namespace_summary,
    build_recommendations,
    node_utilization,
    node_requested_totals,
    read_previous_scan,
    get_pod_metrics,
    get_hpa_targets,
    enrich_with_cost,
    write_prometheus_metrics,
    scan,
)


# ---------------------------------------------------------------------------
# _csv_safe
# ---------------------------------------------------------------------------

class TestCsvSafe:
    def test_formula_equals(self):
        assert _csv_safe("=SUM(A1:A10)") == "'=SUM(A1:A10)"

    def test_formula_plus(self):
        assert _csv_safe("+1-2") == "'+1-2"

    def test_formula_at(self):
        assert _csv_safe("@IMPORTRANGE()") == "'@IMPORTRANGE()"

    def test_formula_minus(self):
        assert _csv_safe("-1+2") == "'-1+2"

    def test_normal_string_unchanged(self):
        assert _csv_safe("default") == "default"
        assert _csv_safe("kube-system") == "kube-system"

    def test_empty_string_unchanged(self):
        assert _csv_safe("") == ""

    def test_non_string_unchanged(self):
        assert _csv_safe(42) == 42
        assert _csv_safe(3.14) == 3.14
        assert _csv_safe(None) is None


# ---------------------------------------------------------------------------
# namespace_summary
# ---------------------------------------------------------------------------

CONTAINER_ROWS = [
    {"namespace": "default", "pod": "web-1", "container": "nginx",
     "cpu_request": "100m", "memory_request": "128Mi"},
    {"namespace": "default", "pod": "web-1", "container": "sidecar",
     "cpu_request": "50m", "memory_request": "64Mi"},
    {"namespace": "default", "pod": "web-2", "container": "nginx",
     "cpu_request": "100m", "memory_request": "128Mi"},
    {"namespace": "kube-system", "pod": "coredns-1", "container": "coredns",
     "cpu_request": "200m", "memory_request": "256Mi"},
]


class TestNamespaceSummary:
    def test_counts(self):
        result = namespace_summary(CONTAINER_ROWS)
        by_ns = {r["namespace"]: r for r in result}

        assert by_ns["default"]["pod_count"] == 2
        assert by_ns["default"]["container_count"] == 3
        assert by_ns["kube-system"]["pod_count"] == 1
        assert by_ns["kube-system"]["container_count"] == 1

    def test_cpu_aggregation(self):
        result = namespace_summary(CONTAINER_ROWS)
        by_ns = {r["namespace"]: r for r in result}
        # 100 + 50 + 100 = 250 millicores
        assert by_ns["default"]["cpu_requested_millicores"] == 250

    def test_no_previous_data_zero_changes(self):
        result = namespace_summary(CONTAINER_ROWS)
        for row in result:
            assert row["cpu_change_pct"] == 0.0
            assert row["memory_change_pct"] == 0.0
            assert row["pod_count_change"] == 0
            assert row["previous_scan_date"] == ""

    def test_with_previous_data_cpu_growth(self):
        previous = {
            "default": {
                "scan_date": "2026-02-21T120000Z",
                "pod_count": 1,
                "container_count": 1,
                "cpu_requested_millicores": 100,
                "memory_requested_bytes": 128 * 1024 ** 2,
            }
        }
        result = namespace_summary(CONTAINER_ROWS, previous)
        by_ns = {r["namespace"]: r for r in result}
        # 250m now vs 100m before = +150%
        assert by_ns["default"]["cpu_change_pct"] == 150.0
        assert by_ns["default"]["pod_count_change"] == 1   # 2 now vs 1 before

    def test_with_previous_data_new_namespace(self):
        # kube-system has no previous data — should still appear with zero changes
        previous = {"default": {
            "scan_date": "2026-02-21T120000Z",
            "pod_count": 2,
            "container_count": 3,
            "cpu_requested_millicores": 250,
            "memory_requested_bytes": 320 * 1024 ** 2,
        }}
        result = namespace_summary(CONTAINER_ROWS, previous)
        by_ns = {r["namespace"]: r for r in result}
        assert by_ns["kube-system"]["cpu_change_pct"] == 0.0
        assert by_ns["kube-system"]["previous_scan_date"] == ""

    def test_sorted_by_namespace(self):
        result = namespace_summary(CONTAINER_ROWS)
        names = [r["namespace"] for r in result]
        assert names == sorted(names)


# ---------------------------------------------------------------------------
# build_recommendations
# ---------------------------------------------------------------------------

def _make_node_util(cpu_pct, mem_pct, disk_pct=5, node="node1"):
    return {
        "node": node,
        "cpu_util_pct": cpu_pct,
        "memory_util_pct": mem_pct,
        "disk_util_pct": disk_pct,
        "cpu_allocatable": "4",
        "memory_allocatable": "8Gi",
        "cpu_requested_millicores": 4000 * cpu_pct / 100,
        "memory_requested_bytes": int(8 * 1024 ** 3 * mem_pct / 100),
    }


class TestBuildRecommendations:
    def test_scale_up_on_high_cpu(self):
        node_util = [_make_node_util(cpu_pct=80, mem_pct=40)]
        recs = build_recommendations(node_util, [], [], util_scale_up_pct=75)
        types = [r["type"] for r in recs]
        assert "scale_up" in types

    def test_scale_down_on_low_utilization(self):
        node_util = [_make_node_util(cpu_pct=10, mem_pct=10, disk_pct=5)]
        recs = build_recommendations(node_util, [], [], util_scale_down_pct=25)
        types = [r["type"] for r in recs]
        assert "scale_down" in types

    def test_no_recommendation_mid_range(self):
        node_util = [_make_node_util(cpu_pct=50, mem_pct=50)]
        recs = build_recommendations(node_util, [], [],
                                     util_scale_up_pct=75, util_scale_down_pct=25)
        node_recs = [r for r in recs if r.get("target", "").startswith("node:")]
        assert not node_recs

    def test_missing_limits_recommendation(self):
        pod_rows = [{
            "namespace": "default", "pod": "web-1", "container": "nginx",
            "cpu_request": "100m", "cpu_limit": "",
            "memory_request": "128Mi", "memory_limit": "",
        }]
        recs = build_recommendations([], pod_rows, [])
        types = [r["type"] for r in recs]
        assert "change_limits" in types

    def test_cpu_limit_4x_request(self):
        pod_rows = [{
            "namespace": "default", "pod": "web-1", "container": "nginx",
            "cpu_request": "100m", "cpu_limit": "500m",
            "memory_request": "128Mi", "memory_limit": "128Mi",
        }]
        recs = build_recommendations([], pod_rows, [])
        types = [r["type"] for r in recs]
        assert "change_limits" in types

    def test_growth_alert(self):
        ns_summary = [{
            "namespace": "default",
            "cpu_change_pct": 50.0,
            "memory_change_pct": 10.0,
        }]
        recs = build_recommendations([], [], ns_summary, growth_alert_pct=20)
        types = [r["type"] for r in recs]
        assert "growth_alert" in types

    def test_no_growth_alert_below_threshold(self):
        ns_summary = [{
            "namespace": "default",
            "cpu_change_pct": 5.0,
            "memory_change_pct": 5.0,
        }]
        recs = build_recommendations([], [], ns_summary, growth_alert_pct=20)
        types = [r["type"] for r in recs]
        assert "growth_alert" not in types

    def test_unscheduled_node_skipped(self):
        node_util = [{
            "node": "_unscheduled_",
            "cpu_util_pct": 99,
            "memory_util_pct": 99,
            "disk_util_pct": 99,
        }]
        recs = build_recommendations(node_util, [], [])
        node_recs = [r for r in recs if "node:_unscheduled_" in r.get("target", "")]
        assert not node_recs

    def test_no_duplicate_container_recommendations(self):
        # Same container appears twice in pod_rows (e.g. init + regular scan)
        pod_rows = [
            {"namespace": "ns", "pod": "p", "container": "c",
             "cpu_request": "100m", "cpu_limit": "", "memory_request": "128Mi", "memory_limit": ""},
            {"namespace": "ns", "pod": "p", "container": "c",
             "cpu_request": "100m", "cpu_limit": "", "memory_request": "128Mi", "memory_limit": ""},
        ]
        recs = build_recommendations([], pod_rows, [])
        targets = [r["target"] for r in recs if r["type"] == "change_limits"]
        assert len(targets) == 1


# ---------------------------------------------------------------------------
# read_previous_scan
# ---------------------------------------------------------------------------

def _write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


SCAN_FIELDS = ["scan_date", "namespace", "pod", "container", "cpu_request", "memory_request"]


class TestReadPreviousScan:
    def test_no_file_returns_empty(self, tmp_path):
        assert read_previous_scan(tmp_path) == {}

    def test_single_scan_returns_empty(self, tmp_path):
        rows = [
            {"scan_date": "2026-02-26T120000Z", "namespace": "default",
             "pod": "web", "container": "nginx", "cpu_request": "100m", "memory_request": "128Mi"},
        ]
        _write_csv(tmp_path / "all-resources.csv", rows, SCAN_FIELDS)
        # Only one distinct scan date — need at least 2 to compare
        assert read_previous_scan(tmp_path) == {}

    def test_two_scans_returns_previous(self, tmp_path):
        rows = [
            {"scan_date": "2026-02-19T120000Z", "namespace": "default",
             "pod": "web", "container": "nginx", "cpu_request": "50m", "memory_request": "64Mi"},
            {"scan_date": "2026-02-26T120000Z", "namespace": "default",
             "pod": "web", "container": "nginx", "cpu_request": "100m", "memory_request": "128Mi"},
        ]
        _write_csv(tmp_path / "all-resources.csv", rows, SCAN_FIELDS)
        result = read_previous_scan(tmp_path)
        assert "default" in result
        # Previous scan (second most recent) has 50m CPU
        assert result["default"]["cpu_requested_millicores"] == 50.0

    def test_multiple_namespaces(self, tmp_path):
        rows = [
            {"scan_date": "2026-02-19T120000Z", "namespace": "default",
             "pod": "web", "container": "nginx", "cpu_request": "100m", "memory_request": "128Mi"},
            {"scan_date": "2026-02-19T120000Z", "namespace": "kube-system",
             "pod": "dns", "container": "coredns", "cpu_request": "200m", "memory_request": "256Mi"},
            {"scan_date": "2026-02-26T120000Z", "namespace": "default",
             "pod": "web", "container": "nginx", "cpu_request": "150m", "memory_request": "192Mi"},
        ]
        _write_csv(tmp_path / "all-resources.csv", rows, SCAN_FIELDS)
        result = read_previous_scan(tmp_path)
        assert "default" in result
        assert "kube-system" in result

    def test_empty_csv_returns_empty(self, tmp_path):
        _write_csv(tmp_path / "all-resources.csv", [], SCAN_FIELDS)
        assert read_previous_scan(tmp_path) == {}

    def test_corrupt_csv_returns_empty(self, tmp_path):
        (tmp_path / "all-resources.csv").write_text("not,valid\ncsv\x00data\n", encoding="utf-8")
        # Should log a warning and return {} rather than crashing
        result = read_previous_scan(tmp_path)
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# get_pod_metrics
# ---------------------------------------------------------------------------

class TestGetPodMetrics:
    def test_returns_dict_on_success(self):
        mock_api = MagicMock()
        mock_api.list_cluster_custom_object.return_value = {
            "items": [
                {
                    "metadata": {"namespace": "default", "name": "web-1"},
                    "containers": [
                        {"name": "nginx", "usage": {"cpu": "125m", "memory": "256Mi"}},
                    ],
                }
            ]
        }
        result = get_pod_metrics(mock_api)
        assert result == {"default/web-1/nginx": {"cpu_usage": "125m", "memory_usage": "256Mi"}}

    def test_returns_empty_when_api_raises(self):
        mock_api = MagicMock()
        mock_api.list_cluster_custom_object.side_effect = RuntimeError("metrics-server unavailable")
        result = get_pod_metrics(mock_api)
        assert result == {}

    def test_returns_empty_on_empty_items(self):
        mock_api = MagicMock()
        mock_api.list_cluster_custom_object.return_value = {"items": []}
        result = get_pod_metrics(mock_api)
        assert result == {}

    def test_multiple_containers(self):
        mock_api = MagicMock()
        mock_api.list_cluster_custom_object.return_value = {
            "items": [
                {
                    "metadata": {"namespace": "prod", "name": "app-abc"},
                    "containers": [
                        {"name": "app", "usage": {"cpu": "200m", "memory": "512Mi"}},
                        {"name": "sidecar", "usage": {"cpu": "10m", "memory": "32Mi"}},
                    ],
                }
            ]
        }
        result = get_pod_metrics(mock_api)
        assert "prod/app-abc/app" in result
        assert "prod/app-abc/sidecar" in result
        assert result["prod/app-abc/sidecar"]["cpu_usage"] == "10m"


# ---------------------------------------------------------------------------
# OOM detection in scan()
# ---------------------------------------------------------------------------

def _make_container(name, cpu_req="100m", mem_req="128Mi"):
    """Build a minimal fake container object."""
    c = MagicMock()
    c.name = name
    c.resources.requests = {"cpu": cpu_req, "memory": mem_req}
    c.resources.limits = {}
    return c


def _make_pod(ns, name, containers, oom_containers=None, node="node1"):
    """Build a minimal fake pod object."""
    pod = MagicMock()
    pod.metadata.namespace = ns
    pod.metadata.name = name
    pod.metadata.owner_references = []
    pod.spec.node_name = node
    pod.spec.containers = containers
    pod.status.phase = "Running"

    # Build container_statuses for OOM detection
    cs_list = []
    for c in containers:
        cs = MagicMock()
        cs.name = c.name
        if oom_containers and c.name in oom_containers:
            cs.last_state.terminated.reason = "OOMKilled"
        else:
            cs.last_state = None
        cs_list.append(cs)
    pod.status.container_statuses = cs_list
    return pod


class TestOomDetection:
    def test_oom_killed_container_flagged(self):
        containers = [_make_container("nginx")]
        pod = _make_pod("default", "web-1", containers, oom_containers={"nginx"})

        mock_v1 = MagicMock()
        mock_v1.list_pod_for_all_namespaces.return_value.items = [pod]
        mock_apps = MagicMock()
        mock_apps.read_namespaced_replica_set.side_effect = Exception("no rs")

        rows = scan(mock_v1, mock_apps)
        assert rows[0]["oom_killed"] == 1

    def test_normal_container_not_flagged(self):
        containers = [_make_container("nginx")]
        pod = _make_pod("default", "web-1", containers)

        mock_v1 = MagicMock()
        mock_v1.list_pod_for_all_namespaces.return_value.items = [pod]
        mock_apps = MagicMock()

        rows = scan(mock_v1, mock_apps)
        assert rows[0]["oom_killed"] == 0

    def test_mixed_containers_selective_oom(self):
        containers = [_make_container("app"), _make_container("sidecar")]
        pod = _make_pod("default", "web-1", containers, oom_containers={"app"})

        mock_v1 = MagicMock()
        mock_v1.list_pod_for_all_namespaces.return_value.items = [pod]
        mock_apps = MagicMock()

        rows = scan(mock_v1, mock_apps)
        by_cont = {r["container"]: r for r in rows}
        assert by_cont["app"]["oom_killed"] == 1
        assert by_cont["sidecar"]["oom_killed"] == 0


# ---------------------------------------------------------------------------
# get_hpa_targets
# ---------------------------------------------------------------------------

class TestGetHpaTargets:
    def test_returns_frozenset_of_tuples(self):
        mock_api = MagicMock()
        hpa1 = MagicMock()
        hpa1.metadata.namespace = "default"
        hpa1.spec.scale_target_ref.kind = "Deployment"
        hpa1.spec.scale_target_ref.name = "web"
        mock_api.list_horizontal_pod_autoscaler_for_all_namespaces.return_value.items = [hpa1]

        result = get_hpa_targets(mock_api)
        assert isinstance(result, frozenset)
        assert ("default", "Deployment", "web") in result

    def test_returns_empty_frozenset_on_error(self):
        mock_api = MagicMock()
        mock_api.list_horizontal_pod_autoscaler_for_all_namespaces.side_effect = RuntimeError("no HPA")
        result = get_hpa_targets(mock_api)
        assert result == frozenset()

    def test_multiple_hpas(self):
        mock_api = MagicMock()
        items = []
        for ns, kind, name in [("default", "Deployment", "web"), ("prod", "StatefulSet", "db")]:
            h = MagicMock()
            h.metadata.namespace = ns
            h.spec.scale_target_ref.kind = kind
            h.spec.scale_target_ref.name = name
            items.append(h)
        mock_api.list_horizontal_pod_autoscaler_for_all_namespaces.return_value.items = items

        result = get_hpa_targets(mock_api)
        assert ("default", "Deployment", "web") in result
        assert ("prod", "StatefulSet", "db") in result


# ---------------------------------------------------------------------------
# enrich_with_cost
# ---------------------------------------------------------------------------

class TestEnrichWithCost:
    def test_zero_requests_gives_empty_string(self):
        rows = [{"cpu_request": "", "memory_request": ""}]
        enrich_with_cost(rows)
        assert rows[0]["est_monthly_cost_usd"] == ""

    def test_nonzero_requests_gives_float(self):
        rows = [{"cpu_request": "1000m", "memory_request": "1Gi"}]
        enrich_with_cost(rows, cost_cpu_core_hour=0.048, cost_mem_gb_hour=0.006)
        cost = rows[0]["est_monthly_cost_usd"]
        assert isinstance(cost, float)
        assert cost > 0

    def test_formula_correctness(self):
        # 1 core CPU + 1 GiB memory @ default rates * 730 hours
        rows = [{"cpu_request": "1000m", "memory_request": "1Gi"}]
        enrich_with_cost(rows, cost_cpu_core_hour=0.048, cost_mem_gb_hour=0.006)
        expected = round((1.0 * 0.048 + 1.0 * 0.006) * 730, 4)
        assert rows[0]["est_monthly_cost_usd"] == expected

    def test_cpu_only_request(self):
        rows = [{"cpu_request": "500m", "memory_request": ""}]
        enrich_with_cost(rows, cost_cpu_core_hour=0.1, cost_mem_gb_hour=0.0)
        expected = round(0.5 * 0.1 * 730, 4)
        assert rows[0]["est_monthly_cost_usd"] == expected

    def test_mutates_in_place(self):
        rows = [{"cpu_request": "100m", "memory_request": "128Mi"}]
        result = enrich_with_cost(rows)
        assert result is None  # returns None (in-place mutation)
        assert "est_monthly_cost_usd" in rows[0]


# ---------------------------------------------------------------------------
# write_prometheus_metrics
# ---------------------------------------------------------------------------

class TestWritePrometheusMetrics:
    def _run(self, tmp_path, summary=None, node_util=None, recommendations=None):
        write_prometheus_metrics(
            tmp_path,
            "2026-02-28T120000Z",
            "test-cluster",
            summary or [],
            node_util or [],
            recommendations or [],
        )
        return (tmp_path / "pod-scanner.prom").read_text(encoding="utf-8")

    def test_file_created(self, tmp_path):
        content = self._run(tmp_path)
        assert (tmp_path / "pod-scanner.prom").exists()
        assert "pod_scanner_last_scan_timestamp_seconds" in content

    def test_cluster_label_present(self, tmp_path):
        content = self._run(tmp_path)
        assert 'cluster="test-cluster"' in content

    def test_namespace_metrics(self, tmp_path):
        summary = [{"namespace": "default", "cpu_requested_millicores": 250,
                    "memory_requested_bytes": 256 * 1024**2, "cpu_change_pct": 10.0}]
        content = self._run(tmp_path, summary=summary)
        assert 'namespace="default"' in content
        assert "pod_scanner_namespace_cpu_requested_millicores" in content

    def test_node_metrics(self, tmp_path):
        node_util = [{
            "node": "node1", "cpu_util_pct": 45.0, "memory_util_pct": 60.0,
            "cpu_usage_pct": "", "memory_usage_pct": "",
        }]
        content = self._run(tmp_path, node_util=node_util)
        assert 'node="node1"' in content
        assert "pod_scanner_node_cpu_util_pct" in content

    def test_usage_metrics_only_when_available(self, tmp_path):
        # No usage data → no usage metrics
        node_util = [{"node": "n1", "cpu_util_pct": 50, "memory_util_pct": 50,
                      "cpu_usage_pct": "", "memory_usage_pct": ""}]
        content = self._run(tmp_path, node_util=node_util)
        assert "pod_scanner_node_cpu_usage_pct" not in content

        # With usage data → usage metrics emitted
        node_util_with_usage = [{"node": "n1", "cpu_util_pct": 50, "memory_util_pct": 50,
                                  "cpu_usage_pct": 30.0, "memory_usage_pct": 40.0}]
        content2 = self._run(tmp_path, node_util=node_util_with_usage)
        assert "pod_scanner_node_cpu_usage_pct" in content2

    def test_recommendation_counts(self, tmp_path):
        recs = [
            {"type": "scale_down", "target": "node:n1", "reason": "low", "action": "remove"},
            {"type": "change_limits", "target": "ns/pod/c", "reason": "no limits", "action": "set"},
            {"type": "change_limits", "target": "ns/pod/c2", "reason": "4x", "action": "lower"},
        ]
        content = self._run(tmp_path, recommendations=recs)
        assert "pod_scanner_recommendations_total" in content
        assert 'type="scale_down"' in content
        assert 'type="change_limits"' in content

    def test_unscheduled_node_skipped(self, tmp_path):
        node_util = [{"node": "_unscheduled_", "cpu_util_pct": 99, "memory_util_pct": 99,
                      "cpu_usage_pct": "", "memory_usage_pct": ""}]
        content = self._run(tmp_path, node_util=node_util)
        assert "_unscheduled_" not in content


# ---------------------------------------------------------------------------
# OOM recommendations in build_recommendations
# ---------------------------------------------------------------------------

class TestBuildRecommendationsOom:
    def test_oom_killed_container_generates_oom_risk_rec(self):
        pod_rows = [{
            "namespace": "default", "pod": "web-1", "container": "nginx",
            "cpu_request": "100m", "cpu_limit": "200m",
            "memory_request": "128Mi", "memory_limit": "128Mi",
            "oom_killed": 1,
            "node": "node1", "workload_kind": "Deployment", "workload_name": "web",
        }]
        recs = build_recommendations([], pod_rows, [])
        types = [r["type"] for r in recs]
        assert "oom_risk" in types

    def test_non_oom_container_no_oom_risk_rec(self):
        pod_rows = [{
            "namespace": "default", "pod": "web-1", "container": "nginx",
            "cpu_request": "100m", "cpu_limit": "200m",
            "memory_request": "128Mi", "memory_limit": "128Mi",
            "oom_killed": 0,
            "node": "node1", "workload_kind": "Deployment", "workload_name": "web",
        }]
        recs = build_recommendations([], pod_rows, [])
        types = [r["type"] for r in recs]
        assert "oom_risk" not in types

    def test_hpa_annotation_on_scale_down(self):
        node_util = [_make_node_util(cpu_pct=10, mem_pct=10, node="node1")]
        pod_rows = [{
            "namespace": "default", "pod": "web-1", "container": "nginx",
            "cpu_request": "100m", "cpu_limit": "200m",
            "memory_request": "128Mi", "memory_limit": "128Mi",
            "oom_killed": 0,
            "node": "node1", "workload_kind": "Deployment", "workload_name": "web",
        }]
        hpa_targets = frozenset({("default", "Deployment", "web")})
        recs = build_recommendations(node_util, pod_rows, [], util_scale_down_pct=25, hpa_targets=hpa_targets)
        scale_down = [r for r in recs if r["type"] == "scale_down" and "node:" in r.get("target", "")]
        assert scale_down, "Expected scale_down recommendation"
        assert "HPA-managed" in scale_down[0]["reason"]


# ---------------------------------------------------------------------------
# Namespace exclusion in scan()
# ---------------------------------------------------------------------------

class TestNamespaceExclusion:
    def test_excluded_namespace_not_in_output(self):
        containers = [_make_container("nginx")]
        pod_default = _make_pod("default", "web-1", containers)
        pod_kube = _make_pod("kube-system", "dns-1", [_make_container("coredns")])

        mock_v1 = MagicMock()
        mock_v1.list_pod_for_all_namespaces.return_value.items = [pod_default, pod_kube]
        mock_apps = MagicMock()

        rows = scan(mock_v1, mock_apps, exclude_namespaces=frozenset({"kube-system"}))
        namespaces = {r["namespace"] for r in rows}
        assert "default" in namespaces
        assert "kube-system" not in namespaces

    def test_no_exclusion_includes_all(self):
        containers = [_make_container("nginx")]
        pod_default = _make_pod("default", "web-1", containers)
        pod_kube = _make_pod("kube-system", "dns-1", [_make_container("coredns")])

        mock_v1 = MagicMock()
        mock_v1.list_pod_for_all_namespaces.return_value.items = [pod_default, pod_kube]
        mock_apps = MagicMock()

        rows = scan(mock_v1, mock_apps)
        namespaces = {r["namespace"] for r in rows}
        assert "default" in namespaces
        assert "kube-system" in namespaces

    def test_exclude_multiple_namespaces(self):
        mock_v1 = MagicMock()
        mock_v1.list_pod_for_all_namespaces.return_value.items = [
            _make_pod("default", "w", [_make_container("c")]),
            _make_pod("monitoring", "p", [_make_container("c")]),
            _make_pod("prod", "a", [_make_container("c")]),
        ]
        mock_apps = MagicMock()

        rows = scan(mock_v1, mock_apps, exclude_namespaces=frozenset({"monitoring", "default"}))
        namespaces = {r["namespace"] for r in rows}
        assert namespaces == {"prod"}
