"""Bounded, local-only parsing of Ansible default callback evidence."""
from datetime import datetime
import json
import re
from itertools import chain, islice

from deployment_evidence_profiles import PROFILE_TASKS, validate

MAX_BYTES = 2_000_000
MAX_LINE = 16_384
MAX_BLOCK = 256_000
MAX_TASKS = 10_000
MAX_RESULTS = 20_000
MAX_RECAP_HOSTS = 10_000
MAX_LINES = 100_000
RANGE_STATES = frozenset({"SUCCESS", "ERROR", "DEPLOYING"})
ISSUE_CODES = frozenset({"input_truncated", "unsupported_callback", "malformed_payload", "malformed_report", "report_missing", "recap_missing", "recap_duplicate", "recap_invalid", "recap_coverage_missing", "recap_mismatch", "status_contradiction", "identity_mismatch", "task_unknown", "task_contradiction", "task_limit", "result_limit"})
_TASK = re.compile(r"TASK \[(.{1,256})\](?: \*{3,})?\Z")
_RESULT = re.compile(r"(ok|changed|skipping|fatal|unreachable|failed)\s*:\s*\[([^\]]{1,260})\](.*)\Z")
_RECAP = re.compile(r"([^ :\[\]]{1,128})\s+:\s+(.+)\Z")
_COUNTER = re.compile(r"(ok|changed|unreachable|failed|skipped|rescued|ignored)=(\d{1,10})\Z")
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z", re.ASCII)
_TASK_RESULT = {"ok": "ok", "changed": "changed", "skipping": "skipped", "fatal": "failed", "unreachable": "unreachable", "failed": "failed"}


class EvidenceError(ValueError):
    """Raised with a fixed message for invalid caller-supplied structures."""


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _strict_json(text):
    def bad_constant(_value):
        raise ValueError
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=bad_constant)


def _valid_timestamp(value):
    if not isinstance(value, str) or len(value) > 32 or not value.endswith("Z"):
        return False
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return True


def _valid_status(status):
    if not isinstance(status, dict):
        return False
    range_id = status.get("rangeID")
    deployment = status.get("lastDeployment")
    state = status.get("rangeState")
    return (isinstance(range_id, str) and bool(_IDENTITY.fullmatch(range_id))
            and _valid_timestamp(deployment) and isinstance(state, str) and state in RANGE_STATES)


def _valid_allowlist(allowlist):
    if not isinstance(allowlist, dict) or set(allowlist) != {"hosts", "tasks"}:
        return False
    for key in ("hosts", "tasks"):
        values = allowlist[key]
        if not isinstance(values, list) or len(values) > 1000:
            return False
        if any(not isinstance(value, str) or not value or len(value) > 256
               or any(ord(char) < 32 or ord(char) == 127 for char in value) for value in values):
            return False
        if len(values) != len(set(values)):
            return False
    return True


def _outcome_line(line):
    match = _RESULT.fullmatch(line)
    if not match:
        return None
    outcome, bracket_identity, suffix = match.groups()
    origin, separator, delegated = bracket_identity.partition(" -> ")
    if not _IDENTITY.fullmatch(origin):
        return None
    if separator and not _IDENTITY.fullmatch(delegated):
        return None
    # Task output syntax after the bracket is untrusted except the callback delimiter.
    payload = suffix.strip()
    item_result = False
    if payload.startswith(": UNREACHABLE!"):
        outcome = "unreachable"
        payload = payload[len(": UNREACHABLE!"):].strip()
    elif payload.startswith(": FAILED!"):
        outcome = "failed"
        payload = payload[len(": FAILED!"):].strip()
    if payload.startswith("=>"):
        payload = payload[2:].strip()
    elif payload and not payload.startswith("("):
        return {"outcome": _TASK_RESULT[outcome], "host": origin,
                "delegated_host": delegated if separator else None, "payload": None,
                "recognized": False, "item_result": item_result}
    # `=> (item=...) => {}` is supported, but item text is never retained or parsed.
    if payload.startswith("("):
        item_result = True
        arrow = payload.find("=>")
        payload = payload[arrow + 2:].strip() if arrow >= 0 else ""
    if payload and not payload.startswith("{"):
        return {"outcome": _TASK_RESULT[outcome], "host": origin,
                "delegated_host": delegated if separator else None, "payload": None,
                "recognized": False, "item_result": item_result}
    return {"outcome": _TASK_RESULT[outcome], "host": origin,
            "delegated_host": delegated if separator else None,
            "payload": payload if payload.startswith("{") else None, "recognized": True,
            "item_result": item_result}


def _json_block(first, following):
    """Decode one bounded JSON object, returning object and lines consumed."""
    block = first
    depth = 0
    quoted = False
    escaped = False
    started = False
    for line_offset, text in enumerate(chain((first,), following)):
        if line_offset:
            block += "\n" + text
        if len(block.encode("utf-8", "replace")) > MAX_BLOCK:
            return None, line_offset + 1, True
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char == "{":
                started = True
                depth += 1
            elif char == "}" and started:
                depth -= 1
                if depth == 0:
                    try:
                        return _strict_json(block), line_offset + 1, False
                    except Exception:
                        return None, line_offset + 1, False
        if line_offset >= MAX_BLOCK // 2:
            return None, line_offset + 1, True
    return None, line_offset + 1 if "line_offset" in locals() else 1, False


def _recap(line):
    match = _RECAP.fullmatch(line)
    if not match:
        return None
    host, raw_counts = match.groups()
    counts = {}
    for item in raw_counts.split():
        parsed = _COUNTER.fullmatch(item)
        if not parsed:
            return host, None
        key, raw_value = parsed.groups()
        if key in counts:
            return host, None
        counts[key] = int(raw_value)
    required = {"ok", "changed", "unreachable", "failed", "skipped", "rescued", "ignored"}
    return host, counts if set(counts) == required else None


def _read_bounded_text(stream):
    chunks = []
    total = 0
    truncated = False
    while total < MAX_BYTES:
        chunk = stream.read(min(65536, MAX_BYTES - total + 1))
        if not chunk:
            break
        accepted = []
        for character in chunk:
            size = len(character.encode("utf-8", "replace"))
            if total + size > MAX_BYTES:
                truncated = True
                break
            accepted.append(character)
            total += size
        chunks.append("".join(accepted))
        if truncated:
            break
    else:
        if stream.read(1):
            truncated = True
    return "".join(chunks), truncated


def collect_evidence(stream, status, allowlist, *, range_id, deployment):
    if not _valid_status(status) or not _valid_allowlist(allowlist):
        raise EvidenceError("invalid input")
    if not isinstance(range_id, str) or not _IDENTITY.fullmatch(range_id) or not _valid_timestamp(deployment):
        raise EvidenceError("invalid input")

    try:
        raw, truncated = _read_bounded_text(stream)
    except Exception:
        raise EvidenceError("invalid input") from None
    lines = raw.splitlines()
    overlong_indexes = [i for i, line in enumerate(lines) if len(line) > MAX_LINE]
    overlong = bool(overlong_indexes)
    if overlong:
        lines = lines[:overlong_indexes[0]]
    if len(lines) > MAX_LINES:
        lines = lines[:MAX_LINES]
        truncated = True
    issues = set()
    if truncated or overlong:
        issues.add("input_truncated")
    if status["rangeID"] != range_id or status["lastDeployment"] != deployment:
        issues.add("identity_mismatch")

    tasks = []
    reports = []
    recaps = {}
    all_recap_counts = []
    recap_hosts_seen = set()
    selected_hosts = set()
    recap_rows = 0
    state = {"name": None, "occurrence": 0, "results": [], "last_outcomes": {},
             "had_result": False, "selected_result": False, "profile": None}
    occurrence_count = {}
    task_count = 0
    result_count = 0
    recognized_lines = 0
    saw_recap = False

    def finalize_task():
        if state["name"] is None:
            return
        name = state["name"]
        allowed_task = name in allowlist["tasks"]
        if not allowed_task:
            return
        if not state["had_result"]:
            tasks.append({"name": name, "occurrence": state["occurrence"], "host": None,
                          "delegated_host": None, "outcome": "unknown"})
            issues.add("task_unknown")
            if state["profile"]:
                issues.add("report_missing")
        elif state["selected_result"] and not state["results"]:
            tasks.append({"name": name, "occurrence": state["occurrence"], "host": None,
                          "delegated_host": None, "outcome": "unknown"})
            issues.add("task_unknown")
        for row in state["results"]:
            tasks.append(row)
            if row["outcome"] == "unknown":
                issues.add("task_unknown")

    index = 0
    while index < len(lines):
        line = lines[index]
        heading = _TASK.fullmatch(line)
        if heading:
            finalize_task()
            name = heading.group(1)
            task_count += 1
            occurrence_count[name] = occurrence_count.get(name, 0) + 1
            state = {"name": name, "occurrence": occurrence_count[name], "results": [], "last_outcomes": {},
                     "had_result": False, "selected_result": False,
                     "profile": next((p for p, t in PROFILE_TASKS.items() if t == name), None)}
            if task_count > MAX_TASKS:
                issues.add("task_limit")
                break
            recognized_lines += 1
            index += 1
            continue

        if line.startswith("PLAY RECAP"):
            saw_recap = True
            recognized_lines += 1
        recap_item = _recap(line)
        if recap_item:
            saw_recap = True
            recap_rows += 1
            host, counts = recap_item
            if recap_rows > MAX_RECAP_HOSTS:
                issues.add("result_limit")
                index += 1
                continue
            if host in recap_hosts_seen:
                issues.add("recap_duplicate")
            recap_hosts_seen.add(host)
            if counts is not None:
                all_recap_counts.append((host, counts))
            else:
                issues.add("recap_invalid")
            if host in allowlist["hosts"]:
                if counts is not None and host not in recaps:
                    recaps[host] = counts
            recognized_lines += 1
            index += 1
            continue

        parsed = _outcome_line(line)
        if parsed and state["name"] is not None:
            recognized_lines += 1
            result_count += 1
            state["had_result"] = True
            if result_count > MAX_RESULTS:
                issues.add("result_limit")
                break
            origin = parsed["host"]
            delegate = parsed["delegated_host"]
            task_allowed = state["name"] in allowlist["tasks"]
            host_allowed = origin in allowlist["hosts"] and (delegate is None or delegate in allowlist["hosts"])
            row_outcome = parsed["outcome"] if task_allowed and host_allowed and parsed["recognized"] else "unknown"
            selected_event = task_allowed and host_allowed
            if selected_event:
                state["selected_result"] = True
                selected_hosts.add(origin)
            if parsed["payload"]:
                data, consumed, too_large = _json_block(parsed["payload"], islice(lines, index + 1, None))
                if too_large:
                    issues.add("input_truncated")
                    index = len(lines)
                    break
                if data is None:
                    issues.add("malformed_payload")
                    if selected_event and state["profile"] and parsed["outcome"] in {"ok", "changed"}:
                        issues.add("malformed_report")
                elif selected_event and state["profile"] and parsed["outcome"] in {"ok", "changed"}:
                    if not isinstance(data, dict):
                        issues.add("malformed_report")
                    elif "msg" not in data:
                        issues.add("report_missing")
                    else:
                        report = data["msg"]
                        if validate(state["profile"], report) is None:
                            issues.add("malformed_report")
                        else:
                            reports.append({"profile": state["profile"], "occurrence": state["occurrence"],
                                            "host": origin, "report": report})
                index += max(0, consumed - 1)
            elif selected_event and state["profile"] and parsed["outcome"] in {"ok", "changed"}:
                issues.add("report_missing")
            if not parsed["recognized"]:
                issues.add("unsupported_callback")
            row = {"name": state["name"], "occurrence": state["occurrence"],
                   "host": origin if host_allowed else None,
                   "delegated_host": delegate if host_allowed else None, "outcome": row_outcome}
            identity = (origin, delegate)
            prior = state["last_outcomes"].get(identity)
            if (prior is not None and prior[0] != row_outcome
                    and not (prior[1] and parsed["item_result"])):
                issues.add("task_contradiction")
            state["last_outcomes"][identity] = (row_outcome, parsed["item_result"])
            if selected_event:
                state["results"].append(row)
            index += 1
            continue

        if (line.startswith("TASK [")
                or re.match(r"[A-Za-z_]+\s*:\s*\[", line)):
            issues.add("unsupported_callback")
        index += 1
    finalize_task()

    if not saw_recap or recap_rows == 0:
        issues.add("recap_missing")
    if not recognized_lines:
        issues.add("unsupported_callback")

    for host in selected_hosts:
        if host not in recaps:
            issues.add("recap_coverage_missing")

    # Repeated loop-item result lines are retained above, but count once per
    # task occurrence and inventory host when checking recap lower bounds.
    grouped_outcomes = {}
    for row in tasks:
        if row["host"] is None or row["outcome"] == "unknown":
            continue
        key = (row["name"], row["occurrence"], row["host"])
        grouped_outcomes.setdefault(key, set()).add(row["outcome"])
    observed_counts = {}
    for (_task, _occurrence, host), outcomes in grouped_outcomes.items():
        host_counts = observed_counts.setdefault(host, {})
        if "failed" in outcomes:
            categories = ("failed",)
        elif "unreachable" in outcomes:
            categories = ("unreachable",)
        elif "changed" in outcomes:
            categories = ("ok", "changed")
        elif "ok" in outcomes:
            categories = ("ok",)
        elif "skipped" in outcomes:
            categories = ("skipped",)
        else:
            continue
        for category in categories:
            host_counts[category] = host_counts.get(category, 0) + 1
    for host, lower_bounds in observed_counts.items():
        recap_counts = recaps.get(host)
        if recap_counts is None:
            continue
        for category, lower_bound in lower_bounds.items():
            if category == "failed":
                available = recap_counts["failed"] + recap_counts["rescued"] + recap_counts["ignored"]
            elif category == "unreachable":
                available = recap_counts["unreachable"] + recap_counts["ignored"]
            else:
                available = recap_counts[category]
            if lower_bound > available:
                issues.add("recap_mismatch")

    if status["rangeState"] == "SUCCESS":
        if any(counts["failed"] > 0 or counts["unreachable"] > 0
               for _host, counts in all_recap_counts):
            issues.add("status_contradiction")

    return {
        "expected": {"range": range_id, "deployment": deployment},
        "observed": {"range": status["rangeID"], "deployment": status["lastDeployment"]},
        "deployment_state": status["rangeState"],
        "attribution": "status_matches_expected; supplied_log_stream_unverified" if "identity_mismatch" not in issues else "status_identity_mismatch; supplied_log_stream_unverified",
        "tasks": tasks,
        "recap": recaps,
        "reports": reports,
        "issues": sorted(issues),
    }
