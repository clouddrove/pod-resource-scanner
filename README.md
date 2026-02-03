# Pod Resource Scanner

A Kubernetes-native tool that works on **any cluster** (AKS, GKE, EKS, on-prem). It scans **all namespaces**, **pods**, and **nodes** for CPU, memory, and disk (ephemeral-storage) requests/limits and capacity, then produces **recommendations** for scaling (up/down) and changing limits. Output is **CSV** and optionally a **Google Sheet**, on a weekly schedule.

**Deployment is via Helm.** The chart is in `chart/`; install with `helm install` and override values in `chart/values.yaml` or with `--set`.

## What it collects

- **Pods/containers**: namespace, pod, container, **node**, workload kind/name, replicas, **CPU / memory / ephemeral-storage** request and limit, status  
- **Nodes**: per-node **CPU, memory, and disk** (ephemeral-storage) **capacity** and **allocatable**  
- **Node utilization**: requested CPU/memory/disk per node vs allocatable (percentage)  
- **Per namespace**: pod count, container count  
- **Recommendations**: suggest **scale up** (add nodes), **scale down** (remove/consolidate), or **change limits** (set limits, or reduce limit when >> request)  
- **History**: each run appends timestamped rows for weekly trends  

## Outputs

1. **CSV (always)**  
   - **`all-resources.csv`** – **single file**: each run **appends** rows with a **`scan_date`** column. One row per container per scan (pod/container details, node capacity/utilization, namespace counts, recommendations). Use this one file for a year or more of history.

2. **Google Sheet (optional)**  
   - **All Resources** – **single sheet**: each run **appends** rows with **`scan_date`** (same columns as the CSV). One place for long-term history.  

## Deploy with Helm

The chart is in `chart/`. You need the scanner image (build and push, or use the one from GHCR) and then install/upgrade with Helm.

### 1. Image

Build and push your image, or use the one from GHCR:

```bash
# From repo root (pod-resource-scanner)
docker build -t ghcr.io/cloud-wizz/pod-resource-scanner:latest .
docker push ghcr.io/cloud-wizz/pod-resource-scanner:latest
```

### 2. Install (CSV only)

```bash
helm install pod-resource-scanner ./chart \
  --namespace pod-resource-scanner \
  --create-namespace \
  --set fullnameOverride=pod-resource-scanner \
  --set image.repository=ghcr.io/cloud-wizz/pod-resource-scanner \
  --set image.tag=latest
```
Using `fullnameOverride=pod-resource-scanner` keeps resource names short (e.g. CronJob `pod-resource-scanner`). Omit it to use the default `<release-name>-pod-resource-scanner`.

The CronJob runs **weekly** (default: Sunday 00:00 UTC). To run once manually (with `fullnameOverride=pod-resource-scanner`):

```bash
kubectl create job --from=cronjob/pod-resource-scanner manual-$(date +%s) -n pod-resource-scanner
kubectl logs -n pod-resource-scanner job/manual-<timestamp> -f
```

Without `fullnameOverride`, the CronJob name is `<release-name>-pod-resource-scanner`.

### 3. Override config

```bash
helm upgrade pod-resource-scanner ./chart -n pod-resource-scanner \
  --set config.clusterName=prod-us-east-1 \
  --set config.retentionDays=90 \
  --set cronjob.schedule="0 9 * * 1"
```

See `chart/values.yaml` for all options (image, resources, schedule, config, persistence, googleSheet, etc.).

**Upgrade:** `helm upgrade pod-resource-scanner ./chart -n pod-resource-scanner [--set ...]`  
**Uninstall:** `helm uninstall pod-resource-scanner -n pod-resource-scanner`  
**Lint/template:** `helm lint ./chart` and `helm template test ./chart -n pod-resource-scanner`

GitHub Actions (`.github/workflows/`) runs **Helm lint + template** and **Docker build + push** to GHCR on push to `main` (see workflow "Build, Push, and Helm").

### 4. Optional: Google Sheet

1. **Google Cloud**  
   - Create a project (or use existing).  
   - Enable **Google Sheets API**.  
   - Create a **Service Account**, download JSON key.  

2. **Google Sheet**  
   - Create a new Sheet.  
   - Share it with the service account email (e.g. `...@....iam.gserviceaccount.com`) as **Editor**.  
   - Copy the **Sheet ID** from the URL:  
     `https://docs.google.com/spreadsheets/d/<SHEET_ID>/edit`  

3. **Create a Kubernetes Secret**  
   With `fullnameOverride=pod-resource-scanner`, the chart expects a Secret named `pod-resource-scanner-google`:

   ```bash
   kubectl create secret generic pod-resource-scanner-google -n pod-resource-scanner \
     --from-literal=sheet-id="YOUR_SHEET_ID" \
     --from-file=credentials.json=/path/to/service-account-key.json
   ```

   Without `fullnameOverride`, the secret name must be `<release-name>-pod-resource-scanner-google`. Or set `googleSheet.existingSecret` to your existing secret name.

4. **Enable Google Sheet in the chart**

   ```bash
   helm upgrade pod-resource-scanner ./chart -n pod-resource-scanner \
     --set googleSheet.enabled=true
   ```

   The job will append to `all-resources.csv` and to the Google Sheet "All Resources" every week.

### 5. CSV output

CSV files are written to the PVC. With `fullnameOverride=pod-resource-scanner` the PVC name is `pod-resource-scanner-output`. To copy them out, run a debug pod that mounts the same PVC, or use a sidecar/job that syncs to S3/GCS.

## Configuration (Helm)

All configuration is via the Helm chart. Set values in `chart/values.yaml` or with `--set` / `-f`. Scanner env vars are driven by `config.*`, `image.*`, `cronjob.*`, `googleSheet.*`, `persistence`, and `resources`. Key mappings:

| Env var / Helm value | Description | Default |
|--------|-------------|--------|
| `POD_SCANNER_OUTPUT_DIR` | Directory for CSV output | `/output` |
| `POD_SCANNER_CLUSTER_NAME` | Cluster identifier (all CSVs/sheets get a `cluster` column) | (empty) |
| `POD_SCANNER_UPDATE_GOOGLE_SHEET` | Set to `true`/`1` to update Google Sheet | unset |
| `POD_SCANNER_SHEET_ID` | Google Sheet ID (or use secret) | - |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to service account JSON | - |
| `POD_SCANNER_UTIL_SCALE_UP_PCT` | Utilization % above which to recommend scale up | `75` |
| `POD_SCANNER_UTIL_SCALE_DOWN_PCT` | Utilization % below which to recommend scale down | `25` |
| `POD_SCANNER_LOG_LEVEL` | Logging level: DEBUG, INFO, WARNING, ERROR | `INFO` |
| `POD_SCANNER_RETENTION_DAYS` | Unused; all data is in one append-only CSV (no files are deleted). | `0` |

RBAC: the chart creates a **ClusterRole** and **ClusterRoleBinding** (when `rbac.create: true`) so the scanner can list **nodes**, namespaces, pods, replicasets, deployments, statefulsets, and daemonsets across the cluster (read-only).

## Production checklist

- [ ] **Image**: Use a tagged image and set `image.repository` and `image.tag` (or `imageTag`) in Helm values; avoid `:latest` in prod.
- [ ] **Cluster name**: Set `config.clusterName` in values so multi-cluster dashboards/sheets can filter by cluster.
- [ ] **Retention**: All data is in one append-only file; retention is not used. Plan backup/archival if the CSV grows very large.

- [ ] **Resources**: Override `resources` in values (default 128Mi–512Mi, 50m–500m CPU). Increase for very large clusters if needed.
- [ ] **Timeout**: Override `cronjob.activeDeadlineSeconds` (default 900). Increase if scans regularly run longer.
- [ ] **Monitoring**: Alert on CronJob job failure (e.g. Prometheus `kube_job_failed` or check `last_success.txt` age – see Runbook).
- [ ] **Secrets**: For Google Sheet, use a dedicated service account with minimal scope (Sheets + Drive). Rotate keys periodically.
- [ ] **Security**: Chart sets `podSecurityContext` (runAsNonRoot, runAsUser 1000, fsGroup 1000); image runs as non-root.

## Runbook: Job failed or no recent data

1. **List recent jobs and see if the last one failed**
   ```bash
   kubectl get jobs -n pod-resource-scanner --sort-by=.metadata.creationTimestamp
   kubectl describe job -n pod-resource-scanner <job-name>
   ```

2. **Fetch logs from the failed job’s pod**
   ```bash
   kubectl logs -n pod-resource-scanner job/<job-name> --tail=200
   ```

3. **Check last success marker**  
   The scanner writes `last_success.txt` to the output directory with `timestamp=` and `cluster=`. You can expose this via a sidecar or periodic job that copies it to a place Prometheus/node_exporter can scrape (e.g. textfile collector), or mount the PVC in a pod that checks file age and alerts if older than 7 days.

4. **Common failures**
   - **Permission denied on /output**: Ensure chart `podSecurityContext` has `fsGroup: 1000` and image runs as UID 1000 (default).
   - **Google Sheet 403 / 404**: Verify the Sheet is shared with the service account email and Sheet ID is correct.
   - **Kubernetes API timeout / connection refused**: Cluster may be overloaded or network policy blocking; increase `cronjob.activeDeadlineSeconds` in values or retry later.
   - **Out of memory**: Increase `resources.limits.memory` in Helm values for very large clusters.

5. **Run a one-off job to test**
   ```bash
   kubectl create job --from=cronjob/<release-name>-pod-resource-scanner manual-test -n pod-resource-scanner
   kubectl logs -n pod-resource-scanner job/manual-test -f
   ```
   Or install with `oneShotJob.install: true` in values to create a one-off Job resource (then run it manually).

## Schedule

Default: `0 0 * * 0` (every Sunday at 00:00 UTC). Override with `cronjob.schedule` (e.g. `--set cronjob.schedule="0 9 * * 1"` for Monday 09:00 UTC).

## Tests

Run unit tests (no Kubernetes cluster or deps required for quantity parsing tests):

```bash
pip install -r requirements.txt   # optional for quantity tests only
python3 -m pytest tests/ -v
```

## Test with Docker only

No Kubernetes deploy: build the image and run the scanner in a container using your local kubeconfig. Requires Docker and a working `kubeconfig` (e.g. `~/.kube/config`).

```bash
cd pod-resource-scanner
./scripts/docker-test.sh
```

This will:

1. Build the image `pod-resource-scanner:latest`
2. Run the scanner with your `KUBECONFIG` (default `~/.kube/config`) mounted read-only
3. Write CSVs and `last_success.txt` to `./output` (override with `POD_SCANNER_OUTPUT=/path/to/dir`)

Optional env vars for the run:

- `POD_SCANNER_OUTPUT` – output directory on the host (default: `./output`)
- `POD_SCANNER_CLUSTER_NAME` – cluster label in CSVs (default: `docker-test`)
- `KUBECONFIG` – path to kubeconfig (default: `~/.kube/config`)
- `POD_SCANNER_IMAGE` – image name to build/run (default: `pod-resource-scanner:latest`)

Example with custom cluster name and output:

```bash
POD_SCANNER_CLUSTER_NAME=my-aks ./scripts/docker-test.sh
```

## Local run (outside cluster)

Install deps and run with your kubeconfig:

```bash
pip install -r requirements.txt
export POD_SCANNER_OUTPUT_DIR=./output
python scanner.py
```

Output appears under `./output/` (or `POD_SCANNER_OUTPUT_DIR`). For Google Sheet, set `GOOGLE_APPLICATION_CREDENTIALS` and `POD_SCANNER_SHEET_ID` and `POD_SCANNER_UPDATE_GOOGLE_SHEET=true`. A successful run also creates `last_success.txt` with the scan timestamp and cluster name for monitoring.
