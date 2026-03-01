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
