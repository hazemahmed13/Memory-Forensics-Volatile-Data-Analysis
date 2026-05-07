from volatility_runner import run_first_available


PROFILE_PLUGINS = {
    "windows": ["windows.info", "windows.banner"],
    "linux": ["linux.banner", "linux.bash"],
    "mac": ["mac.banner", "mac.ifconfig"],
}


def detect_os_profile(memory_file):
    """
    Best-effort OS profiling by trying lightweight plugins and matching markers.
    """
    marker_scores = {"windows": 0, "linux": 0, "mac": 0}

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

        marker_scores[os_name] += 1

    guessed = max(marker_scores, key=marker_scores.get)
    if marker_scores[guessed] == 0:
        guessed = "windows"
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
