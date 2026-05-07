def parse_volatility_table(output, min_columns=3):
    """
    Parse common volatility table-like output into structured records.
    Returns a list of dictionaries.
    """
    records = []
    lines = [line.rstrip() for line in output.splitlines() if line.strip()]
    if not lines:
        return records

    header_idx = None
    headers = []
    for idx, line in enumerate(lines):
        if line.startswith("Volatility") or line.startswith("Progress:"):
            continue
        if "  " in line:
            candidate = [part.strip() for part in line.split("  ") if part.strip()]
            if len(candidate) >= min_columns:
                header_idx = idx
                headers = candidate
                break

    if header_idx is None:
        return records

    for line in lines[header_idx + 1 :]:
        if set(line.strip()) == {"-"}:
            continue
        cols = [part.strip() for part in line.split("  ") if part.strip()]
        if len(cols) < min_columns:
            continue

        if len(cols) > len(headers):
            cols = cols[: len(headers) - 1] + [" ".join(cols[len(headers) - 1 :])]
        elif len(cols) < len(headers):
            cols += [""] * (len(headers) - len(cols))

        records.append(dict(zip(headers, cols)))

    return records
