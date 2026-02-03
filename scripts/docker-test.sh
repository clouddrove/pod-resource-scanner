#!/usr/bin/env bash
# Test the pod-resource-scanner using Docker only (no Kubernetes deploy).
# Requires: Docker, a kubeconfig that can list pods/nodes (e.g. ~/.kube/config).

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_NAME="${POD_SCANNER_IMAGE:-pod-resource-scanner:latest}"
OUTPUT_DIR="${POD_SCANNER_OUTPUT:-$ROOT_DIR/output}"
KUBECONFIG_PATH="${KUBECONFIG:-$HOME/.kube/config}"

echo "Building image: $IMAGE_NAME"
docker build -t "$IMAGE_NAME" "$ROOT_DIR"

mkdir -p "$OUTPUT_DIR"
OUTPUT_ABS="$(cd "$OUTPUT_DIR" && pwd)"

# Ensure kubeconfig exists
if [ ! -f "$KUBECONFIG_PATH" ]; then
  echo "Error: KUBECONFIG not found at $KUBECONFIG_PATH"
  echo "Set KUBECONFIG to your config path or ensure ~/.kube/config exists."
  exit 1
fi

KUBE_DIR="$(cd "$(dirname "$KUBECONFIG_PATH")" && pwd)"
KUBE_FILE="$(basename "$KUBECONFIG_PATH")"

echo "Running scanner (output -> $OUTPUT_ABS, kubeconfig -> $KUBE_DIR/$KUBE_FILE)"
docker run --rm \
  -v "$KUBE_DIR:/kube:ro" \
  -e "KUBECONFIG=/kube/$KUBE_FILE" \
  -v "$OUTPUT_ABS:/output" \
  -e "POD_SCANNER_OUTPUT_DIR=/output" \
  -e "POD_SCANNER_CLUSTER_NAME=${POD_SCANNER_CLUSTER_NAME:-docker-test}" \
  --user "$(id -u):$(id -g)" \
  "$IMAGE_NAME"

echo "Done. Check output: $OUTPUT_ABS"
ls -la "$OUTPUT_ABS"
