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
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## ✨ Features

- ☁️ **Cluster-agnostic** — Works on AKS, GKE, EKS, and any Kubernetes (1.21+)
- 🔒 **Read-only** — No cluster changes; lists pods, nodes, namespaces, workloads
- 📁 **Single CSV** — One append-only file (`all-resources.csv`) with `scan_date` for long-term history
- 👁️ **Human-readable** — Memory/CPU/disk in Mi, Gi, cores, and % (no raw bytes or millicores)
- 💡 **Recommendations** — Suggests scale up/down and limit changes (e.g. limit >> request)
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
| **Nodes** | Per-node CPU, memory, and disk (ephemeral-storage) capacity and allocatable |
| **Utilization** | Requested vs allocatable per node (CPU, memory, disk %) |
| **Namespace** | Pod count and container count per namespace |
| **Recommendations** | Scale up (add nodes), scale down (consolidate), change limits (set or lower limits) |

---

## 📊 Output

- 📄 **CSV (always)** — Single file: **`all-resources.csv`**. Each run **appends** rows with a **scan_date** column. Raw column names (e.g. `cpu_request`, `memory_limit`, `node_cpu_util_pct`) and values (e.g. `100m`, `128Mi`, `38.9`) for easy parsing and tools.

- 📋 **Google Sheet (optional)** — **One new tab per run** (historical data) + **Dashboard:** Each run creates **"Run &lt;timestamp&gt;"** with that run’s summary tables; only the last **N** run tabs are kept (configurable). **"All Resources"** holds the latest container-level metrics. **"Dashboard"** shows KPIs and charts for the **latest** run; you can open any **Run &lt;timestamp&gt;** tab to compare history.

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
| `POD_SCANNER_UPDATE_GOOGLE_SHEET` | Set to `true`/`1` to update Google Sheet | unset |
| `POD_SCANNER_SHEET_ID` | Google Sheet ID (or use secret) | - |
| `POD_SCANNER_SHEET_RUN_TABS_KEEP` | Number of **Run &lt;timestamp&gt;** tabs to keep (older ones deleted); use for historical data | `10` |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to service account JSON | - |
| `POD_SCANNER_UTIL_SCALE_UP_PCT` | Utilization % above which to recommend scale up | `75` |
| `POD_SCANNER_UTIL_SCALE_DOWN_PCT` | Utilization % below which to recommend scale down | `25` |
| `POD_SCANNER_LOG_LEVEL` | Logging level | `INFO` |

RBAC: the chart creates a **ClusterRole** and **ClusterRoleBinding** (read-only) so the scanner can list nodes, namespaces, pods, and workloads.

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

The job appends to `all-resources.csv` and updates the sheet: **All Resources** (metrics × containers for latest run), a new **Run &lt;timestamp&gt;** tab each run (namespace, node utilization, recommendations—keeps last N for history), and **Dashboard** (KPIs and charts for the latest run). Set `POD_SCANNER_SHEET_RUN_TABS_KEEP` (default 10) to control how many run tabs are retained.

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
./scripts/docker-test.sh
```

Builds the image and runs the scanner with `KUBECONFIG` mounted; CSV under `./output` by default.

---

## 🧪 Testing

```bash
pip install -r requirements.txt
python3 -m pytest tests/ -v
```

No cluster required for the quantity and formatting tests.

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

## 🤝 Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/clouddrove/pod-resource-scanner).

---

## 📄 License

See [LICENSE](LICENSE) in this repository.

---

**Repository:** [github.com/clouddrove/pod-resource-scanner](https://github.com/clouddrove/pod-resource-scanner) · **Maintained by [CloudDrove](https://clouddrove.com)**
