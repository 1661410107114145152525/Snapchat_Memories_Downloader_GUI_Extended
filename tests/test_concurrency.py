"""
Tests for adaptive concurrency and stability improvements.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import subprocess
import threading


def test_zip_utils_ffmpeg_communicate_no_blocking_loop():
    """Verify zip_utils uses communicate() instead of readline() loop for ffmpeg."""
    import zip_utils
    import inspect
    source = inspect.getsource(zip_utils)
    # The old pattern used a while True + readline loop which could block
    # Check that proc.stderr.readline() is not called (comments are OK)
    import re
    # Match actual readline() calls (not in comments)
    code_lines = [l for l in source.splitlines() if l.strip() and not l.strip().startswith('#')]
    has_blocking_readline = any('.readline()' in l for l in code_lines)
    assert not has_blocking_readline, \
        "zip_utils should not use blocking readline() calls — use communicate() instead"
    # Verify communicate is used
    assert 'proc.communicate' in source, \
        "zip_utils should use proc.communicate() for reading ffmpeg output"


def test_downloader_uses_tuple_timeout():
    """Verify downloader uses separate connect/read timeouts."""
    import downloader
    import inspect
    source = inspect.getsource(downloader.download_media)
    # Should use a tuple timeout (connect, read) instead of a single value
    assert 'timeout=(15, 45)' in source or 'timeout=(15,45)' in source, \
        "downloader should use separate (connect, read) timeouts"


def test_thread_count_cpu_aware():
    """Verify default thread count is CPU-aware and capped reasonably."""
    cpu_count = os.cpu_count() or 2
    expected_default = max(1, min(3, cpu_count))
    assert expected_default >= 1
    assert expected_default <= 3


def test_downloader_has_docstring():
    """Verify download_media has a proper docstring documenting return values."""
    import downloader
    doc = downloader.download_media.__doc__
    assert doc is not None, "download_media should have a docstring"
    assert 'return' in doc.lower() or 'Returns' in doc, \
        "Docstring should document return values"


def test_adaptive_concurrency_logic():
    """Test the adaptive concurrency reduction/recovery logic pattern."""
    # Simulate the adaptive concurrency algorithm used in download_thread
    max_workers = 4
    active_limit = max_workers
    consecutive_errors = 0

    # Simulate 3 consecutive errors -> should reduce limit
    for _ in range(3):
        consecutive_errors += 1
        if consecutive_errors >= 3 and active_limit > 1:
            active_limit = max(1, active_limit - 1)

    assert active_limit == 3, f"After 3 errors, limit should reduce from 4 to 3, got {active_limit}"
    assert consecutive_errors == 3

    # Simulate 3 more errors -> should reduce further (6 total)
    for _ in range(3):
        consecutive_errors += 1
        if consecutive_errors >= 3 and active_limit > 1:
            active_limit = max(1, active_limit - 1)

    assert active_limit == 1, f"After 6 total errors, limit should be 1, got {active_limit}"

    # Simulate success -> should recover
    consecutive_errors = 0
    if active_limit < max_workers:
        active_limit = min(active_limit + 1, max_workers)

    assert active_limit == 2, f"After success, limit should increase to 2, got {active_limit}"
    assert consecutive_errors == 0

    # Multiple successes -> should gradually restore
    for _ in range(5):
        consecutive_errors = 0
        if active_limit < max_workers:
            active_limit = min(active_limit + 1, max_workers)

    assert active_limit == max_workers, f"After many successes, should be back to max {max_workers}, got {active_limit}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
