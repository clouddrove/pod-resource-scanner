"""Unit tests for Kubernetes quantity parsing (used for utilization and recommendations)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from quantity import (
    quantity_to_millicores,
    quantity_to_bytes,
    parse_quantity,
    format_bytes,
    format_millicores,
)


def test_parse_quantity():
    assert parse_quantity("100m") == "100m"
    assert parse_quantity("512Mi") == "512Mi"
    assert parse_quantity("") == ""
    assert parse_quantity(None) == ""


def test_quantity_to_millicores():
    assert quantity_to_millicores("100m") == 100.0
    assert quantity_to_millicores("1") == 1000.0
    assert quantity_to_millicores("0.5") == 500.0
    assert quantity_to_millicores("") == 0.0
    assert quantity_to_millicores("250m") == 250.0


def test_quantity_to_bytes():
    assert quantity_to_bytes("1Ki") == 1024
    assert quantity_to_bytes("1Mi") == 1024 ** 2
    assert quantity_to_bytes("1Gi") == 1024 ** 3
    assert quantity_to_bytes("512Mi") == 512 * (1024 ** 2)
    assert quantity_to_bytes("1G") == 1000 ** 3
    assert quantity_to_bytes("") == 0.0
    assert quantity_to_bytes("100") == 100.0


def test_format_bytes():
    assert format_bytes(0) == ""
    assert format_bytes(1024) == "1 Ki"
    assert format_bytes(512 * (1024 ** 2)) == "512 Mi"
    assert format_bytes(268435456) == "256 Mi"
    assert format_bytes(1024 ** 3) == "1 Gi"
    assert format_bytes(4919918592) == "4.6 Gi"
    assert format_bytes(100) == "100 B"


def test_format_millicores():
    assert format_millicores(0) == ""
    assert format_millicores(100) == "100m"
    assert format_millicores(1000) == "1 cores"
    assert format_millicores(3115) == "3.1 cores"
    assert format_millicores(500) == "500m"
