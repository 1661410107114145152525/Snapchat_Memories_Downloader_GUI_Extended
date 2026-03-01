"""
Test ZIP path traversal (Zip Slip) protection.

Ensures that malicious ZIP entries with path traversal sequences
like '../' are rejected and cannot write files outside the target directory.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from pathlib import Path
import tempfile
import zipfile
import zip_utils


def test_is_safe_zip_member_normal_paths():
    """Test that normal ZIP member paths are allowed."""
    with tempfile.TemporaryDirectory() as tmpdir:
        assert zip_utils._is_safe_zip_member("photo.jpg", tmpdir)
        assert zip_utils._is_safe_zip_member("subdir/photo.jpg", tmpdir)
        assert zip_utils._is_safe_zip_member("a/b/c/video.mp4", tmpdir)


def test_is_safe_zip_member_rejects_traversal():
    """Test that path traversal attempts are rejected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        assert not zip_utils._is_safe_zip_member("../etc/passwd", tmpdir)
        assert not zip_utils._is_safe_zip_member("../../secret.txt", tmpdir)
        assert not zip_utils._is_safe_zip_member("subdir/../../outside.txt", tmpdir)
        assert not zip_utils._is_safe_zip_member("../../../tmp/evil.sh", tmpdir)


def test_is_safe_zip_member_rejects_absolute_paths():
    """Test that absolute paths in ZIP members are rejected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        assert not zip_utils._is_safe_zip_member("/etc/passwd", tmpdir)
        assert not zip_utils._is_safe_zip_member("/tmp/evil.txt", tmpdir)


def test_safe_extractall_skips_traversal():
    """Test that _safe_extractall skips malicious entries but extracts safe ones."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a ZIP with both safe and unsafe entries
        zip_path = os.path.join(tmpdir, "test.zip")
        extract_dir = os.path.join(tmpdir, "extract")
        os.makedirs(extract_dir)

        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("safe_file.txt", "safe content")
            zf.writestr("subdir/also_safe.txt", "also safe")
            # Malicious entry with path traversal
            zf.writestr("../outside.txt", "malicious content")

        with zipfile.ZipFile(zip_path, 'r') as zf:
            zip_utils._safe_extractall(zf, extract_dir)

        # Safe files should be extracted
        assert os.path.exists(os.path.join(extract_dir, "safe_file.txt"))
        assert os.path.exists(os.path.join(extract_dir, "subdir", "also_safe.txt"))

        # Malicious file should NOT exist outside extract_dir
        assert not os.path.exists(os.path.join(tmpdir, "outside.txt"))


def test_extract_media_from_zip_rejects_traversal():
    """Test that extract_media_from_zip rejects entries with path traversal."""
    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, "test.zip")
        output_path = os.path.join(tmpdir, "output.jpg")

        # Create a ZIP with only a malicious entry
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("../../evil.jpg", b'\xff\xd8\xff' + b'\x00' * 200)

        result = zip_utils.extract_media_from_zip(zip_path, output_path)
        assert result is False, "Should reject ZIP with only traversal paths"
        assert not os.path.exists(output_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
