FROM python:3.11-slim

# Run as non-root (UID 1000) so pod securityContext runAsUser/fsGroup match
RUN adduser --disabled-password --gecos "" --uid 1000 appuser

WORKDIR /app

RUN pip install --no-cache-dir -q kubernetes gspread google-auth google-auth-oauthlib

COPY quantity.py scanner.py .

# /output is mounted and must be writable by appuser
RUN mkdir -p /output && chown -R appuser:appuser /app /output

USER appuser

# Unbuffered stdout so logs stream in real time (e.g. kubectl logs -f)
CMD ["python", "-u", "scanner.py"]
