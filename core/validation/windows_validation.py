"""Windows/mac environment checks — intentionally minimal (no Linux artifact dependencies)."""

from volatility_runner import validate_windows_environment as _impl


def validate_windows_environment(memory_file: str) -> str:
    return _impl(memory_file)
