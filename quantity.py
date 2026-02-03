"""Parse Kubernetes resource quantities (no K8s dependency). Used by scanner and tests."""
import re


def parse_quantity(s: str) -> str:
    """Return quantity as-is for CSV (e.g. '100m', '512Mi')."""
    return (s or "").strip()


def quantity_to_millicores(s: str) -> float:
    """Parse Kubernetes CPU quantity to millicores (1000m = 1 core). Returns 0 if invalid."""
    s = (s or "").strip()
    if not s:
        return 0.0
    if s.endswith("m"):
        try:
            return float(s[:-1])
        except ValueError:
            return 0.0
    try:
        return float(s) * 1000
    except ValueError:
        return 0.0


def quantity_to_bytes(s: str) -> float:
    """Parse Kubernetes memory/storage quantity to bytes. Returns 0 if invalid."""
    s = (s or "").strip()
    if not s:
        return 0.0
    m = re.match(r"^([0-9]+\.?[0-9]*)\s*([KMGTPE]i?)?$", s.strip(), re.IGNORECASE)
    if not m:
        return 0.0
    try:
        val = float(m.group(1))
    except ValueError:
        return 0.0
    suffix = (m.group(2) or "").lower()
    if suffix == "ki":
        return val * 1024
    if suffix == "mi":
        return val * (1024 ** 2)
    if suffix == "gi":
        return val * (1024 ** 3)
    if suffix == "ti":
        return val * (1024 ** 4)
    if suffix == "pi":
        return val * (1024 ** 5)
    if suffix == "ei":
        return val * (1024 ** 6)
    if suffix == "k":
        return val * 1000
    if suffix == "m":
        return val * (1000 ** 2)
    if suffix == "g":
        return val * (1000 ** 3)
    if suffix == "t":
        return val * (1000 ** 4)
    if suffix == "p":
        return val * (1000 ** 5)
    if suffix == "e":
        return val * (1000 ** 6)
    return val


def format_bytes(n: float) -> str:
    """Format byte count as human-readable (e.g. 268435456 -> '256 Mi', 0 -> '')."""
    if n is None or (isinstance(n, float) and (n != n or n <= 0)):
        return ""
    n = float(n)
    if n <= 0:
        return ""
    for unit, scale in [("Pi", 1024**5), ("Ti", 1024**4), ("Gi", 1024**3), ("Mi", 1024**2), ("Ki", 1024)]:
        if n >= scale:
            val = n / scale
            return f"{val:.1f} {unit}" if val != int(val) else f"{int(val)} {unit}"
    return f"{int(n)} B"


def format_millicores(m: float) -> str:
    """Format millicores as human-readable (e.g. 200 -> '200m', 1500 -> '1.5 cores', 0 -> '')."""
    if m is None or (isinstance(m, float) and (m != m or m < 0)):
        return ""
    m = float(m)
    if m <= 0:
        return ""
    if m < 1000:
        return f"{int(m)}m" if m == int(m) else f"{m:.0f}m"
    cores = m / 1000
    return f"{cores:.1f} cores" if cores != int(cores) else f"{int(cores)} cores"
