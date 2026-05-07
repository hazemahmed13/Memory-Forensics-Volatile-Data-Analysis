import yara
import os


def scan_memory(memory_file, rule_file="rules.yar"):
    try:
        if not os.path.isabs(rule_file):
            base_dir = os.path.dirname(os.path.abspath(__file__))
            rule_file = os.path.join(base_dir, rule_file)
        rules = yara.compile(filepath=rule_file)
        matches = rules.match(memory_file)
        return matches
    except Exception as e:
        return str(e)


def format_yara_matches(matches):
    if isinstance(matches, str):
        return matches
    if not matches:
        return "No YARA matches found."
    return "\n".join([f"- {match.rule}" for match in matches])