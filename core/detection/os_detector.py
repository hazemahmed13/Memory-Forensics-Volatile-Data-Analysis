"""
Early target-OS detection before plugin workflows.

Runs lightweight Volatility probes without Linux symbol preflight so Windows dumps
are never blocked by Linux ISF validation during detection.
"""

from __future__ import annotations

import os
import re

_DETECTED_OS_CACHE: dict = {}


def clear_detected_os_cache():
    """Invalidate cached OS detection (call when loading a different memory image)."""
    global _DETECTED_OS_CACHE
    _DETECTED_OS_CACHE.clear()


def _score_from_metadata(memory_file: str) -> dict:
    scores = {"windows": 0, "linux": 0, "mac": 0}
    name = (memory_file or "").lower()
    if any(tag in name for tag in ("lime", "kali", "linux", "ubuntu", "debian")):
        scores["linux"] += 1
    if any(tag in name for tag in ("win", "windows", "nt", ".dmp", ".vmem")):
        scores["windows"] += 1
    if any(tag in name for tag in ("darwin", "mac", "osx", "xnu")):
        scores["mac"] += 1
    return scores


def detect_target_os(memory_image: str) -> str:
    """
    Detect Windows vs Linux vs Mac from the memory image path and banners.

    Does not initialize Linux automagic or Linux symbol validation.

    Returns:
        "windows", "linux", or "mac"
    """
    # Deferred import: volatility_runner must not import this module at load time.
    from volatility_runner import (
        _dump_mtime_sig,
        _extract_linux_kernel_version,
        _is_runner_error,
        _run_volatility3,
        log_volatility,
    )

    sig = _dump_mtime_sig(memory_image)
    if sig in _DETECTED_OS_CACHE:
        return _DETECTED_OS_CACHE[sig]

    default_os = "windows"
    if not memory_image or not os.path.isfile(memory_image):
        _DETECTED_OS_CACHE[sig] = default_os
        log_volatility("detect_os", memory_image or "", "[INFO] Detected OS: windows (no dump file)")
        return default_os

    meta = _score_from_metadata(memory_image)

    # Banners only — use Windows symbol path filtering so Linux ISF repos cannot skew probes.
    banner_out = _run_volatility3("banners.Banners", memory_image, [], os_type="windows")
    kernel_ver = _extract_linux_kernel_version(banner_out)
    if kernel_ver:
        _DETECTED_OS_CACHE[sig] = "linux"
        log_volatility("detect_os", memory_image, "[INFO] Detected OS: linux")
        return "linux"

    low = (banner_out or "").lower()
    if "darwin" in low or "mac os" in low or "xnu" in low:
        _DETECTED_OS_CACHE[sig] = "mac"
        log_volatility("detect_os", memory_image, "[INFO] Detected OS: mac")
        return "mac"

    winfo = _run_volatility3("windows.info.Info", memory_image, [], os_type="windows")
    if not _is_runner_error(winfo):
        _DETECTED_OS_CACHE[sig] = "windows"
        log_volatility("detect_os", memory_image, "[INFO] Detected OS: windows")
        return "windows"

    best = max(meta, key=lambda k: meta[k])
    if meta.get(best, 0) > 0:
        if best == "linux":
            _DETECTED_OS_CACHE[sig] = "linux"
            log_volatility("detect_os", memory_image, "[INFO] Detected OS: linux (filename hint)")
            return "linux"
        if best == "mac":
            _DETECTED_OS_CACHE[sig] = "mac"
            log_volatility("detect_os", memory_image, "[INFO] Detected OS: mac (filename hint)")
            return "mac"

    _DETECTED_OS_CACHE[sig] = default_os
    log_volatility("detect_os", memory_image, "[INFO] Detected OS: windows (fallback)")
    return default_os
