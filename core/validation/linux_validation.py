"""Linux-only ISF / kernel symbol prerequisites."""

from volatility_runner import validate_linux_symbols as _impl


def validate_linux_symbols(memory_file: str) -> str:
    return _impl(memory_file)
