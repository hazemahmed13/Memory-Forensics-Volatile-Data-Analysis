from volatility_runner import run_first_available
from parsers import parse_volatility_table


NETWORK_PLUGIN = {
    "windows": ["windows.netscan"],
    "linux": ["linux.netstat", "linux.sockstat"],
    "mac": ["mac.netstat", "mac.ifconfig"],
}


def get_connections(memory_file, os_type="windows"):
    plugins = NETWORK_PLUGIN.get(os_type.lower(), NETWORK_PLUGIN["windows"])
    output = run_first_available(plugins, memory_file, os_type=os_type.lower())

    connections = []
    for line in output.splitlines():
        if ":" in line or "tcp" in line.lower() or "udp" in line.lower():
            connections.append(line)

    return connections


def get_connection_records(memory_file, os_type="windows"):
    output = run_first_available(
        NETWORK_PLUGIN.get(os_type.lower(), NETWORK_PLUGIN["windows"]),
        memory_file,
        os_type=os_type.lower(),
    )
    if output.startswith("[volatility error]") or output.startswith("[runner error]"):
        return []
    return parse_volatility_table(output, min_columns=3)