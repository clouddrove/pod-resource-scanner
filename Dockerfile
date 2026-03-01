# Pin to a specific patch release + distro for reproducible builds.
# Update this tag (and re-run pip-compile) when you need OS/Python security patches.
FROM python:3.11.11-slim-bookworm

# Run as non-root (UID 1000) so pod securityContext runAsUser/fsGroup match
RUN adduser --disabled-password --gecos "" --uid 1000 appuser

WORKDIR /app

COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir -q -r requirements.lock

COPY quantity.py scanner.py .

# /output is mounted and must be writable by appuser
RUN mkdir -p /output && chown -R appuser:appuser /app /output

USER appuser

# Unbuffered stdout so logs stream in real time (e.g. kubectl logs -f)
CMD ["python", "-u", "scanner.py"]
