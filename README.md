# Kubernetes Pod Resource Scanner

[![Build and Push](https://github.com/clouddrove/pod-resource-scanner/actions/workflows/docker-build-push.yaml/badge.svg)](https://github.com/clouddrove/pod-resource-scanner/actions/workflows/docker-build-push.yaml)

> **Kubernetes resource monitoring made simple.** Scan CPU, memory, and disk usage across all namespaces and nodes. Export human-readable CSV and Google Sheets with scaling recommendations—perfect for **capacity planning**, **cost optimization**, and **Kubernetes cluster visibility**.

A lightweight, **read-only** Kubernetes tool that runs as a CronJob on **AKS**, **GKE**, **EKS**, or any Kubernetes cluster. Get a single append-only CSV (raw values for parsing) and optional Google Sheet with **one new tab per run** (**Run &lt;timestamp&gt;** for historical data) and a **Dashboard** tab that visualizes the latest run.

---

## Table of Contents

- [✨ Features](#-features)
- [🎯 Why Use This](#-why-use-this)
- [📦 What It Collects](#-what-it-collects)
- [📊 Output](#-output)
- [🚀 Quick Start](#-quick-start)
- [📥 Installation (Helm)](#-installation-helm)
- [⚙️ Configuration](#configuration)
- [📋 Google Sheet (Optional)](#-google-sheet-optional)
- [💻 Running Locally](#-running-locally)
- [🧪 Testing](#-testing)
- [✅ Production Checklist](#-production-checklist)
- [🐛 Troubleshooting](#-troubleshooting)
- [📡 Grafana Dashboard](#-grafana-dashboard)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## ✨ Features

- ☁️ **Cluster-agnostic** — Works on AKS, GKE, EKS, and any Kubernetes (1.21+)
- 🔒 **Read-only** — No cluster changes; lists pods, nodes, namespaces, workloads
- 📁 **Single CSV** — One append-only file (`all-resources.csv`) with `scan_date` for long-term history
- 👁️ **Human-readable** — Memory/CPU/disk in Mi, Gi, cores, and % (no raw bytes or millicores)
- 💡 **Recommendations** — Scale up/down, limit changes, OOM risk, and growth alerts
- 📈 **Week-over-Week Comparison** — Tracks resource changes per namespace with growth alerts
- 📊 **Actual Usage Metrics** — CPU/memory actual usage via metrics-server (optional, degrades gracefully)
- 💀 **OOM Kill Detection** — Flags containers that were OOM-killed and emits `oom_risk` recommendations
- 📋 **ResourceQuota Reporting** — Scans namespace quotas (hard vs used) into `resource-quotas.csv`
- 🔄 **HPA Awareness** — Marks HPA-managed containers; annotates scale-down recs accordingly
- 💰 **Cost Estimation** — Estimates monthly cost per container based on CPU/memory requests
- 📡 **Prometheus Textfile Export** — Writes `pod-scanner.prom` for node_exporter scraping
- 🚫 **Namespace Exclusion** — Skip specific namespaces (e.g. `kube-system,monitoring`)
- 🧪 **Dry-Run Mode** — Full scan with no file writes; logs recommendations only
- 📋 **Optional Google Sheet** — Same data appended to one sheet for dashboards and sharing
- ⏰ **Helm + CronJob** — Deploy once; runs on a schedule (e.g. weekly)

---

## 🎯 Why Use This

| Use case | How it helps |
|----------|--------------|
| **Capacity planning** | See requested vs allocatable CPU/memory/disk per node and namespace. |
| **Cost visibility** | Export to CSV/Sheets for billing, showback, or chargeback. |
| **Right-sizing** | Get recommendations when limits are much higher than requests. |
| **Multi-cluster** | Set `cluster` name per cluster; one CSV or sheet for all. |
| **Compliance & audit** | Append-only history with `scan_date` for trend and audit. |

---

## 📦 What It Collects

| Area | Data |
|------|------|
| **Pods / Containers** | Namespace, pod, container, node, workload kind/name, replicas, CPU/memory/ephemeral-storage request & limit, status |
| **Actual Usage** | Per-container CPU/memory actual usage from metrics-server (`cpu_usage`, `memory_usage`) — optional |
| **OOM Kills** | Whether each container was OOM-killed in its last termination (`oom_killed` 0/1) |
| **HPA** | Whether each container's workload is managed by an HPA (`hpa_managed` 0/1) |
| **Cost** | Estimated monthly cost per container based on CPU/memory requests (`est_monthly_cost_usd`) |
| **Nodes** | Per-node CPU, memory, and disk (ephemeral-storage) capacity and allocatable |
| **Node Usage** | Actual CPU/memory usage per node from metrics-server (when available) |
| **Utilization** | Requested vs allocatable per node (CPU, memory, disk %) |
| **Namespace** | Pod count, container count, CPU/memory requested per namespace |
| **ResourceQuotas** | Hard and used values for CPU, memory, and pod count per namespace |
| **Week-over-Week** | CPU/memory/pod count changes vs previous scan with % growth |
| **Recommendations** | Scale up/down nodes, change limits (set or lower), OOM risk, growth alerts |

---

## 📊 Output

| File | Description |
|------|-------------|
| `all-resources.csv` | Single append-only file; each run adds rows with `scan_date`. Contains pod/container/node/namespace data, usage, OOM, HPA, cost, and recommendations. |
| `resource-quotas.csv` | Append-only; namespace ResourceQuota hard and used values per run. |
| `pod-scanner.prom` | Prometheus textfile format for node_exporter scraping. Includes namespace CPU/memory requested, node utilization %, usage % (if metrics-server available), and recommendation counts. |
| `last_success.txt` | Timestamp and cluster name of the last successful scan (for monitoring). |

- 📋 **Google Sheet (optional)** — **One new tab per run** (historical data) + **Dashboard:** Each run creates **"Run &lt;timestamp&gt;"** with summary tables (namespace, node utilization, recommendations, and 13-column container details including usage, OOM, HPA, and cost); only the last **N** run tabs are kept (configurable). **Dashboard** shows KPIs including total estimated monthly cost.

---

## 🚀 Quick Start

```bash
# Clone and install from chart
helm install pod-resource-scanner ./chart \
  --namespace pod-resource-scanner \
  --create-namespace \
  --set fullnameOverride=pod-resource-scanner \
  --set image.repository=ghcr.io/clouddrove/pod-resource-scanner \
  --set image.tag=latest
```

The CronJob runs weekly by default (Sunday 00:00 UTC). To run once manually:

```bash
kubectl create job --from=cronjob/pod-resource-scanner manual-$(date +%s) -n pod-resource-scanner
kubectl logs -n pod-resource-scanner job/manual-<timestamp> -f
```

---

## 📥 Installation (Helm)

### 1. Image

Use the pre-built image from [GitHub Container Registry](https://github.com/clouddrove/pod-resource-scanner/pkgs/container/pod-resource-scanner), or build and push your own:

```bash
docker build -t ghcr.io/clouddrove/pod-resource-scanner:latest .
docker push ghcr.io/clouddrove/pod-resource-scanner:latest
```

### 2. Install

```bash
helm install pod-resource-scanner ./chart \
  --namespace pod-resource-scanner \
  --create-namespace \
  --set fullnameOverride=pod-resource-scanner \
  --set image.repository=ghcr.io/clouddrove/pod-resource-scanner \
  --set image.tag=latest
```

### 3. Override schedule and config

```bash
helm upgrade pod-resource-scanner ./chart -n pod-resource-scanner \
  --set config.clusterName=prod-us-east-1 \
  --set cronjob.schedule="0 9 * * 1"
```

See **Configuration** and `chart/values.yaml` for all options.

**Useful commands**

- 🔼 Upgrade: `helm upgrade pod-resource-scanner ./chart -n pod-resource-scanner [--set ...]`
- 🗑️ Uninstall: `helm uninstall pod-resource-scanner -n pod-resource-scanner`
- ✔️ Lint: `helm lint ./chart`

---

## ⚙️ Configuration

| Env var / Helm value | Description | Default |
|----------------------|-------------|--------|
| `POD_SCANNER_OUTPUT_DIR` | Directory for CSV output | `/output` |
| `POD_SCANNER_CLUSTER_NAME` | Cluster identifier (for multi-cluster CSV/Sheet) | (empty) |
| `POD_SCANNER_EXCLUDE_NAMESPACES` | Comma-separated namespaces to skip (e.g. `kube-system,monitoring`) | (empty) |
| `POD_SCANNER_DRY_RUN` | `true`/`1` — scan fully but write no files | `false` |
| `POD_SCANNER_METRICS_ENABLED` | `false` to skip metrics-server calls | `true` |
| `POD_SCANNER_COST_CPU_CORE_HOUR` | Estimated cost per CPU core per hour (USD) | `0.048` |
| `POD_SCANNER_COST_MEM_GB_HOUR` | Estimated cost per GiB memory per hour (USD) | `0.006` |
| `POD_SCANNER_UPDATE_GOOGLE_SHEET` | Set to `true`/`1` to update Google Sheet | unset |
| `POD_SCANNER_SHEET_ID` | Google Sheet ID (or use secret) | - |
| `POD_SCANNER_SHEET_RUN_TABS_KEEP` | Number of **Run &lt;timestamp&gt;** tabs to keep | `10` |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to service account JSON | - |
| `POD_SCANNER_UTIL_SCALE_UP_PCT` | Utilization % above which to recommend scale up | `75` |
| `POD_SCANNER_UTIL_SCALE_DOWN_PCT` | Utilization % below which to recommend scale down | `25` |
| `POD_SCANNER_GROWTH_ALERT_PCT` | Namespace growth % to trigger alert (week-over-week) | `20` |
| `POD_SCANNER_RETENTION_DAYS` | Delete snapshot CSVs older than N days (`0` = keep all) | `0` |
| `POD_SCANNER_LOG_LEVEL` | Logging level | `INFO` |

RBAC: the chart creates a **ClusterRole** and **ClusterRoleBinding** (read-only) for pods, nodes, namespaces, workloads, resourcequotas, horizontalpodautoscalers, and metrics.k8s.io (for metrics-server).

---

## 📋 Google Sheet (Optional)

1. **Google Cloud** — Enable Google Sheets API; create a Service Account and download JSON key.
2. **Sheet** — Create a sheet and share it with the service account email as **Editor**. Copy the Sheet ID from the URL: `https://docs.google.com/spreadsheets/d/<SHEET_ID>/edit`.
3. **Secret** (with `fullnameOverride=pod-resource-scanner`):

   ```bash
   kubectl create secret generic pod-resource-scanner-google -n pod-resource-scanner \
     --from-literal=sheet-id="YOUR_SHEET_ID" \
     --from-file=credentials.json=/path/to/service-account-key.json
   ```

4. **Enable in Helm**

   ```bash
   helm upgrade pod-resource-scanner ./chart -n pod-resource-scanner --set googleSheet.enabled=true
   ```

The job appends to `all-resources.csv` and updates the sheet: a new **Run &lt;timestamp&gt;** tab each run (namespace summary, node utilization, recommendations, container details—keeps last N for history) and **Dashboard** (KPIs for the latest run). Set `POD_SCANNER_SHEET_RUN_TABS_KEEP` (default 10) to control how many run tabs are retained.

---

## 💻 Running Locally

Without deploying to a cluster:

```bash
pip install -r requirements.txt
export POD_SCANNER_OUTPUT_DIR=./output
python scanner.py
```

Output goes to `./output/all-resources.csv`. For Google Sheet, set `GOOGLE_APPLICATION_CREDENTIALS`, `POD_SCANNER_SHEET_ID`, and `POD_SCANNER_UPDATE_GOOGLE_SHEET=true`.

**Docker (local kubeconfig)**

```bash
docker build -t pod-resource-scanner:local .
docker run --rm \
  -v ~/.kube:/home/appuser/.kube:ro \
  -v "$(pwd)/output":/output \
  pod-resource-scanner:local
```

Builds the image and runs the scanner using your local kubeconfig; CSV is written to `./output`.

---

## 🧪 Testing

```bash
pip install pytest
python3 -m pytest tests/ -v
```

No cluster or Google Sheets account required — all tests run with mocked dependencies.

---

## ✅ Production Checklist

- [ ] 🏷️ Use a tagged image (e.g. `image.tag=0.1.0`); avoid `:latest` in production.
- [ ] ☁️ Set `config.clusterName` for multi-cluster visibility.
- [ ] 📐 Override `resources` and `cronjob.activeDeadlineSeconds` for large clusters.
- [ ] 📡 Monitor CronJob failure (e.g. Prometheus or `last_success.txt` age).
- [ ] 🔑 For Google Sheet: use a dedicated service account; rotate keys periodically.

---

## 🐛 Troubleshooting

| Issue | What to do |
|-------|------------|
| **Permission denied on /output** | Ensure `podSecurityContext.fsGroup: 1000` and image runs as UID 1000. |
| **Google Sheet 403 / 404** | Share the sheet with the service account email; check Sheet ID. |
| **API timeout / connection refused** | Increase `cronjob.activeDeadlineSeconds` or retry; check network policies. |
| **Out of memory** | Increase `resources.limits.memory` in Helm values. |

**Logs and one-off run**

```bash
kubectl get jobs -n pod-resource-scanner --sort-by=.metadata.creationTimestamp
kubectl logs -n pod-resource-scanner job/<job-name> --tail=200
kubectl create job --from=cronjob/pod-resource-scanner manual-test -n pod-resource-scanner
kubectl logs -n pod-resource-scanner job/manual-test -f
```

The scanner writes `last_success.txt` in the output directory (`timestamp=`, `cluster=`) for monitoring.

---

## 📡 Grafana Dashboard

A pre-built Grafana dashboard is included at [`grafana/dashboard.json`](grafana/dashboard.json). Import it in seconds — no manual panel setup required.

### Prerequisites

Configure Prometheus **node_exporter** textfile collector to scrape `pod-scanner.prom`:

```yaml
# values.yaml (kube-prometheus-stack or node-exporter chart)
extraArgs:
  - --collector.textfile.directory=/output

extraVolumeMounts:
  - name: pod-scanner-output
    mountPath: /output
    readOnly: true
```

Or if running node_exporter directly:
```bash
node_exporter --collector.textfile.directory=/path/to/output
```

The scanner and node_exporter must share the same output directory (PVC or hostPath).

### Import

1. Open Grafana → **Dashboards** → **Import**
2. Upload `grafana/dashboard.json` or paste its contents
3. Select your **Prometheus** data source
4. Pick your **cluster** from the variable drop-down

### Dashboard Panels

| Panel | Metric |
|---|---|
| Last Scan Age | `pod_scanner_last_scan_timestamp_seconds` |
| Namespaces / Nodes / Recommendations / Cost | Stat cards |
| CPU Requested by Namespace | `pod_scanner_namespace_cpu_requested_millicores` |
| Memory Requested by Namespace | `pod_scanner_namespace_memory_requested_bytes` |
| CPU Week-over-Week Change % | `pod_scanner_namespace_cpu_change_pct` |
| Node CPU / Memory Utilization % | `pod_scanner_node_cpu_util_pct`, `pod_scanner_node_memory_util_pct` |
| Node CPU / Memory Actual Usage % | `pod_scanner_node_cpu_usage_pct`, `pod_scanner_node_memory_usage_pct` |
| Recommendations by Type | `pod_scanner_recommendations_total` |
| Namespace Cost, OOM Kills & CPU Change | `pod_scanner_namespace_est_monthly_cost_usd`, `pod_scanner_namespace_oom_killed_total`, `pod_scanner_namespace_cpu_change_pct` |

> **Note:** Node actual usage panels are only populated when metrics-server is enabled (`POD_SCANNER_METRICS_ENABLED=true`).

---

## 🤝 Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/clouddrove/pod-resource-scanner).

---

## 📄 License

See [LICENSE](LICENSE) in this repository.

---

**Repository:** [github.com/clouddrove/pod-resource-scanner](https://github.com/clouddrove/pod-resource-scanner) · **Maintained by [CloudDrove](https://clouddrove.com)**
