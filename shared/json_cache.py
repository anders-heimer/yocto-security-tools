# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Gzip-compressed JSON cache with backward compatibility.

Reads both compressed (.json.gz) and plain (.json) files transparently.
Always writes compressed (.json.gz) to save disk space.
"""
import gzip
import json
import os


def cache_load(path: str):
    """Load JSON from cache, trying .gz first then plain.

    Returns None if file is missing or corrupted.
    """
    gz_path = path + '.gz' if not path.endswith('.gz') else path
    plain_path = path.removesuffix('.gz') if path.endswith('.gz') else path

    try:
        if os.path.isfile(gz_path):
            with gzip.open(gz_path, 'rt', encoding='utf-8') as f:
                return json.load(f)
        if os.path.isfile(plain_path):
            with open(plain_path, encoding='utf-8') as f:
                return json.load(f)
    except (json.JSONDecodeError, gzip.BadGzipFile, OSError):
        import logging
        logging.warning("Corrupted cache file: %s", gz_path or plain_path)
    return None


def cache_dump(data, path: str) -> None:
    """Write JSON to cache atomically as gzip-compressed file."""
    gz_path = path + '.gz' if not path.endswith('.gz') else path
    os.makedirs(os.path.dirname(gz_path) or '.', exist_ok=True)
    tmp_path = gz_path + '.tmp'
    with gzip.open(tmp_path, 'wt', encoding='utf-8') as f:
        json.dump(data, f)
    os.replace(tmp_path, gz_path)


def cache_exists(path: str) -> bool:
    """Check if a cache file exists (compressed or plain)."""
    gz_path = path + '.gz' if not path.endswith('.gz') else path
    plain_path = path.removesuffix('.gz') if path.endswith('.gz') else path
    return os.path.isfile(gz_path) or os.path.isfile(plain_path)
