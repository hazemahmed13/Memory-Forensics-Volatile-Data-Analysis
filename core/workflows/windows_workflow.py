"""Windows memory workflow — Volatility 3 Windows plugins with Windows-safe symbol paths."""

from volatility_runner import run_volatility


def run_windows_volatility(plugin: str, memory_file: str, extra_args=None):
    """Execute a Volatility plugin on a Windows-class memory image (routing uses OS detection)."""
    return run_volatility(plugin, memory_file, extra_args=extra_args or [], os_type="windows")
