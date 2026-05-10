from core.detection.os_detector import detect_target_os


def detect_os_profile(memory_file):
    """
    Resolve target OS before kernel-heavy plugins run.

    Uses early banner/metadata detection only — does not invoke Linux symbol validation
    or iterate linux.* plugins against Windows dumps.
    """
    guessed = detect_target_os(memory_file)
    return {
        "guessed_os": guessed,
        "confidence": "high",
        "scores": {"windows": 0, "linux": 0, "mac": 0},
    }
