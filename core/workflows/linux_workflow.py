"""Linux memory workflow — linux.* plugins after Linux ISF validation (detection-driven routing)."""

from volatility_runner import run_volatility


def run_linux_volatility(plugin: str, memory_file: str, extra_args=None):
    """Execute a Volatility plugin on a Linux-class memory image (routing uses OS detection)."""
    return run_volatility(plugin, memory_file, extra_args=extra_args or [], os_type="linux")
