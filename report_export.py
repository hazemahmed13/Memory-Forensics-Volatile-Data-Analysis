import html
import json
import os
from datetime import datetime

_TXT_SAMPLE_LIMIT = 8
_SECRETS_PREVIEW_KEYS = 3
_HTML_SECRETS_JSON_MAX = 12000


def _normalize_yara_matches_for_report(yara_matches):
    """Keep structured dict hits; flatten legacy yara.Match or bare rule names to JSON-safe dicts."""
    if isinstance(yara_matches, str):
        return yara_matches
    if not isinstance(yara_matches, list):
        return yara_matches
    if not yara_matches:
        return []
    if isinstance(yara_matches[0], dict):
        return list(yara_matches)
    out = []
    for m in yara_matches:
        rule = getattr(m, "rule", None)
        if rule is not None:
            out.append({"rule": rule, "rule_file": "", "category": "legacy", "strings": []})
        else:
            out.append({"rule": str(m), "rule_file": "", "category": "legacy", "strings": []})
    return out


def _report_pipeline_debug(message: str):
    """Set FORENSICS_REPORT_PIPELINE_DEBUG=1 to trace report build/export stages in forensics_tool.log."""
    if not (os.environ.get("FORENSICS_REPORT_PIPELINE_DEBUG", "").strip()):
        return
    try:
        from forensics_logging import setup_forensics_logging

        setup_forensics_logging().info("report_pipeline %s", message)
    except Exception:
        pass


def build_report(
    memory_file,
    os_profile,
    process_records,
    process_tree_records,
    thread_records,
    dll_records,
    suspicious_injection,
    connection_records,
    secrets,
    yara_matches,
    volatility_meta=None,
):
    out = {
        "generated_at_utc": datetime.utcnow().isoformat() + "Z",
        "memory_file": memory_file,
        "os_profile": os_profile,
        "counts": {
            "processes": len(process_records),
            "process_tree_nodes": len(process_tree_records),
            "threads": len(thread_records),
            "dll_or_module_records": len(dll_records),
            "suspicious_injection_lines": len(suspicious_injection),
            "connections": len(connection_records),
            "yara_matches": len(yara_matches) if isinstance(yara_matches, list) else 0,
        },
        "process_records": process_records,
        "process_tree_records": process_tree_records,
        "thread_records": thread_records,
        "dll_records": dll_records,
        "suspicious_injection": suspicious_injection,
        "connection_records": connection_records,
        "secrets_findings": secrets,
        "yara_matches": _normalize_yara_matches_for_report(yara_matches),
    }
    if volatility_meta:
        out["volatility"] = volatility_meta
    _report_pipeline_debug(
        "build_report done keys=%s yara_type=%s"
        % (list(out.keys()), type(out.get("yara_matches")).__name__)
    )
    return out


def export_report_json(report_data, out_path):
    _report_pipeline_debug("export_report_json start path=%r" % (out_path,))
    with open(out_path, "w", encoding="utf-8", newline="\n", errors="replace") as fp:
        json.dump(report_data, fp, indent=2, ensure_ascii=False)
    _report_pipeline_debug("export_report_json done bytes=%s" % os.path.getsize(out_path))


def _format_record_rows(records, limit=_TXT_SAMPLE_LIMIT):
    rows = []
    for rec in records[:limit]:
        if isinstance(rec, dict):
            parts = [f"{k}={v}" for k, v in list(rec.items())[:8]]
            rows.append("  " + " | ".join(parts))
        else:
            rows.append(f"  {rec}")
    return rows


def _secrets_summary(secrets):
    if not isinstance(secrets, dict):
        return [f"  (non-dict payload): {secrets!s}"[:200]]
    lines = []
    for key, val in list(secrets.items())[:_SECRETS_PREVIEW_KEYS]:
        if isinstance(val, list):
            lines.append(f"  {key}: {len(val)} item(s), sample: {val[0]!s}"[:200])
        elif isinstance(val, dict):
            lines.append(f"  {key}: {len(val)} key(s)")
        else:
            lines.append(f"  {key}: {val!s}"[:200])
    if len(secrets) > _SECRETS_PREVIEW_KEYS:
        lines.append(f"  … plus {len(secrets) - _SECRETS_PREVIEW_KEYS} more key(s)")
    return lines


def export_report_txt(report_data, out_path):
    lines = []
    os_profile = report_data.get("os_profile") or {}
    lines.append("Memory Forensics Report")
    lines.append("=" * 40)
    lines.append(f"Generated: {report_data.get('generated_at_utc', '')}")
    lines.append(f"Memory File: {report_data.get('memory_file', '')}")
    lines.append(f"OS Guess: {os_profile.get('guessed_os', 'unknown')}")
    lines.append(f"OS Confidence: {os_profile.get('confidence', 'unknown')}")
    vol_meta = report_data.get("volatility")
    if vol_meta:
        lines.append("")
        lines.append("Volatility backend")
        lines.append("-" * 40)
        for k, v in vol_meta.items():
            lines.append(f"{k}: {v}")
    lines.append("")
    lines.append("SECURITY NOTE")
    lines.append("-" * 40)
    lines.append("This report may contain credentials, key material, and host indicators.")
    lines.append("Handle like sensitive evidence; redact before sharing.")
    lines.append("")
    lines.append("Counts")
    lines.append("-" * 40)
    for key, value in report_data.get("counts", {}).items():
        lines.append(f"{key}: {value}")
    lines.append("")
    lines.append("Process coverage")
    lines.append("-" * 40)
    lines.append(f"process_records: {len(report_data.get('process_records', []))}")
    lines.append(f"process_tree_records: {len(report_data.get('process_tree_records', []))}")
    lines.append(f"thread_records: {len(report_data.get('thread_records', []))}")
    lines.append(f"dll_records: {len(report_data.get('dll_records', []))}")
    proc_sample = report_data.get("process_records") or []
    if proc_sample:
        lines.append("Sample process records (first rows):")
        lines.extend(_format_record_rows(proc_sample))
    lines.append("")
    lines.append("Injection / malfind (suspicious lines)")
    lines.append("-" * 40)
    inj = report_data.get("suspicious_injection") or []
    if inj:
        for item in inj[:_TXT_SAMPLE_LIMIT]:
            lines.append(f"  {item}"[:500])
        if len(inj) > _TXT_SAMPLE_LIMIT:
            lines.append(f"  … {len(inj) - _TXT_SAMPLE_LIMIT} more line(s)")
    else:
        lines.append("  (none captured in this export)")
    lines.append("")
    lines.append("Network connection records")
    lines.append("-" * 40)
    conns = report_data.get("connection_records") or []
    lines.append(f"Total parsed records: {len(conns)}")
    if conns:
        lines.append("Sample:")
        lines.extend(_format_record_rows(conns))
    lines.append("")
    lines.append("Secrets / pattern findings (summary)")
    lines.append("-" * 40)
    secrets = report_data.get("secrets_findings") or {}
    lines.extend(_secrets_summary(secrets) if secrets else ["  (none or empty)"])
    lines.append("")
    lines.append("YARA")
    lines.append("-" * 40)
    yara_matches = report_data.get("yara_matches", [])
    if isinstance(yara_matches, list) and yara_matches:
        if isinstance(yara_matches[0], dict):
            for item in yara_matches[:20]:
                lines.append("  Rule: %s" % item.get("rule", ""))
                lines.append("  File: %s" % item.get("rule_file", ""))
                lines.append("  Category: %s" % item.get("category", ""))
                strs = item.get("strings") or []
                if strs:
                    lines.append("  Strings (sample):")
                    for s in strs[:5]:
                        lines.append("    - %s" % s)
                lines.append("")
            if len(yara_matches) > 20:
                lines.append("  … %s more match record(s)" % (len(yara_matches) - 20))
        else:
            for item in yara_matches:
                lines.append(f"- {item}")
    else:
        lines.append(str(yara_matches))

    _report_pipeline_debug("export_report_txt start path=%r lines=%s" % (out_path, len(lines)))
    with open(out_path, "w", encoding="utf-8", newline="\n", errors="replace") as fp:
        fp.write("\n".join(lines))
    _report_pipeline_debug("export_report_txt done bytes=%s" % os.path.getsize(out_path))


def export_report_html(report_data, out_path):
    os_profile = report_data.get("os_profile") or {}
    title = html.escape("Memory Forensics Report")
    mem = html.escape(str(report_data.get("memory_file", "")))
    gen = html.escape(str(report_data.get("generated_at_utc", "")))
    og = html.escape(str(os_profile.get("guessed_os", "unknown")))
    oc = html.escape(str(os_profile.get("confidence", "unknown")))

    counts_html = "".join(
        f"<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(v))}</td></tr>"
        for k, v in report_data.get("counts", {}).items()
    )

    def pre_block(label, text):
        return (
            f"<h2>{html.escape(label)}</h2><pre>{html.escape(text)}</pre>"
        )

    inj = report_data.get("suspicious_injection") or []
    inj_text = "\n".join(inj[:_TXT_SAMPLE_LIMIT]) if inj else "(none)"
    conns = report_data.get("connection_records") or []
    conn_text = "\n".join(
        " | ".join(f"{k}={v}" for k, v in list(rec.items())[:8]) for rec in conns[:_TXT_SAMPLE_LIMIT]
    ) or "(none)"
    yara_matches = report_data.get("yara_matches", [])
    if isinstance(yara_matches, list):
        if yara_matches and isinstance(yara_matches[0], dict):
            yara_text = json.dumps(yara_matches, indent=2, ensure_ascii=False)
        else:
            yara_text = "\n".join(yara_matches) if yara_matches else "(none)"
    else:
        yara_text = str(yara_matches)

    secrets = report_data.get("secrets_findings") or {}
    secrets_json = json.dumps(secrets, indent=2, ensure_ascii=False) if secrets else "{}"
    # Never slice raw JSON: a byte/char cut mid-structure yields invalid JSON inside HTML (looks "corrupted").
    if len(secrets_json) > _HTML_SECRETS_JSON_MAX:
        secrets_esc = html.escape(
            "(Secrets JSON omitted in HTML preview: payload exceeds %s characters. "
            "Open the exported *_forensics_report.json for the complete, valid secrets_findings object.)"
            % _HTML_SECRETS_JSON_MAX
        )
    else:
        secrets_esc = html.escape(secrets_json)

    vm = report_data.get("volatility")
    vol_block = ""
    if vm:
        vol_block = (
            "<h2>Volatility backend</h2><pre>"
            + html.escape(json.dumps(vm, indent=2, ensure_ascii=False))
            + "</pre>"
        )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>{title}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 1.5rem; max-width: 960px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 0.35rem 0.5rem; text-align: left; }}
pre {{ background: #f6f6f6; padding: 0.75rem; overflow-x: auto; font-size: 0.85rem; }}
.note {{ background: #fff8e6; border: 1px solid #e6c200; padding: 0.75rem; margin: 1rem 0; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p><strong>Generated:</strong> {gen}<br/>
<strong>Memory file:</strong> {mem}<br/>
<strong>OS guess:</strong> {og} ({oc})</p>
{vol_block}
<div class="note"><strong>Sensitive data.</strong> This report may contain credentials and indicators. Redact before sharing.</div>
<h2>Counts</h2>
<table><tbody>{counts_html}</tbody></table>
{pre_block("Injection / malfind (sample)", inj_text)}
{pre_block("Network records (sample)", conn_text)}
<h2>Secrets findings (JSON)</h2><pre>{secrets_esc}</pre>
{pre_block("YARA", yara_text)}
</body>
</html>"""
    _report_pipeline_debug("export_report_html start path=%r doc_chars=%s" % (out_path, len(doc)))
    with open(out_path, "w", encoding="utf-8", newline="\n", errors="replace") as fp:
        fp.write(doc)
    _report_pipeline_debug("export_report_html done bytes=%s" % os.path.getsize(out_path))
