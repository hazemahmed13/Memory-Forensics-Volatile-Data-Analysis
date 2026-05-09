from volatility_runner import run_first_available


PROFILE_PLUGINS = {
    "windows": ["windows.info.Info", "windows.pslist.PsList"],
    "linux": ["banners.Banners", "linux.pslist.PsList"],
    "mac": ["mac.pslist.PsList", "mac.ifconfig.Ifconfig"],
}


def detect_os_profile(memory_file):
    """
    Best-effort OS profiling by trying lightweight plugins and matching markers.
    """
    marker_scores = {"windows": 0, "linux": 0, "mac": 0}
    metadata_scores = _score_from_metadata(memory_file)
    for k, v in metadata_scores.items():
        marker_scores[k] += v

    for os_name, plugins in PROFILE_PLUGINS.items():
        output = run_first_available(plugins, memory_file, os_type=os_name)
        if output.startswith("[volatility error]") or output.startswith("[runner error]"):
            continue

        low = output.lower()
        if "windows" in low or "ntkrnlmp" in low:
            marker_scores["windows"] += 2
        if "linux" in low or "systemd" in low or "/bin/" in low:
            marker_scores["linux"] += 2
        if "darwin" in low or "xnu" in low or "macos" in low:
            marker_scores["mac"] += 2

        marker_scores[os_name] += 2

    guessed = max(marker_scores, key=marker_scores.get)
    if marker_scores[guessed] == 0:
        guessed = "linux"
        confidence = "low"
    elif marker_scores[guessed] < 3:
        confidence = "medium"
    else:
        confidence = "high"

    return {
        "guessed_os": guessed,
        "confidence": confidence,
        "scores": marker_scores,
    }


def _score_from_metadata(memory_file):
    """
    Lightweight metadata scan: extensions do not control logic, but filenames often
    contain useful hints for OS routing before symbol-dependent plugins run.
    """
    scores = {"windows": 0, "linux": 0, "mac": 0}
    name = (memory_file or "").lower()
    if any(tag in name for tag in ("lime", "kali", "linux", "ubuntu", "debian")):
        scores["linux"] += 1
    if any(tag in name for tag in ("win", "windows", "nt")):
        scores["windows"] += 1
    if any(tag in name for tag in ("darwin", "mac", "osx", "xnu")):
        scores["mac"] += 1
    return scores
