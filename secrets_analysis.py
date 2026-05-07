import re

from volatility_runner import run_first_available


STRINGS_PLUGIN = {
    "windows": ["windows.strings"],
    "linux": ["linux.bash", "linux.envars"],
    "mac": ["mac.bash", "mac.ifconfig"],
}


def _scan_text_patterns(text):
    patterns = {
        "possible_aes_key_hex": r"\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{64}\b",
        "possible_password": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*[^\s'\";]+",
        "possible_token": r"(?i)(?:token|apikey|api_key|secret)\s*[:=]\s*[^\s'\";]+",
        "possible_private_key_header": r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----",
    }

    findings = {}
    for name, pattern in patterns.items():
        matches = [m.group(0) for m in re.finditer(pattern, text)]
        if matches:
            findings[name] = list(dict.fromkeys(matches))[:20]
    return findings


def _extract_printable_strings(memory_file, min_len=6):
    strings = []
    current = []

    with open(memory_file, "rb") as mem_file:
        while True:
            chunk = mem_file.read(1024 * 1024)
            if not chunk:
                break

            for byte in chunk:
                if 32 <= byte <= 126:
                    current.append(chr(byte))
                else:
                    if len(current) >= min_len:
                        strings.append("".join(current))
                    current = []

    if len(current) >= min_len:
        strings.append("".join(current))

    return "\n".join(strings)


def detect_keys_and_credentials(memory_file, os_type="windows"):
    plugins = STRINGS_PLUGIN.get(os_type.lower(), STRINGS_PLUGIN["windows"])
    text = run_first_available(plugins, memory_file, os_type=os_type.lower())

    if (
        text.startswith("[volatility error]")
        or text.startswith("[volatility warning]")
        or text.startswith("[runner error]")
    ):
        # Fallback: parse printable bytes from dump directly.
        try:
            text = _extract_printable_strings(memory_file)
        except Exception as exc:
            return {"error": f"Could not read memory dump directly: {exc}"}

    findings = _scan_text_patterns(text)
    if not findings:
        return {"info": "No obvious keys/credentials patterns found."}
    return findings
