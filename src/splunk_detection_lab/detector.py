from __future__ import annotations

import argparse
import ipaddress
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class AuthEvent:
    timestamp: str
    src_ip: str
    user: str
    host: str
    action: str
    logon_type: str
    privileged: bool


def load_events(path: str | Path = ROOT / "sample_data" / "auth_events.json") -> list[AuthEvent]:
    rows = json.loads(Path(path).read_text(encoding="utf-8"))
    return [AuthEvent(**row) for row in rows]


def detect_bruteforce(
    events: list[AuthEvent], threshold: int = 4, window_minutes: int = 15
) -> list[dict[str, object]]:
    failures: dict[tuple[str, str, str], list[AuthEvent]] = defaultdict(list)
    successes: dict[tuple[str, str, str], list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.action == "failure":
            failures[(event.src_ip, event.user, event.host)].append(event)
        elif event.action == "success":
            successes[(event.src_ip, event.user, event.host)].append(event)

    findings = []
    for (src_ip, user, host), items in failures.items():
        window = _largest_window(items, window_minutes)
        if len(window) >= threshold:
            first_failure = _time(window[0])
            last_failure = _time(window[-1])
            success_after = any(
                last_failure < _time(event) <= last_failure + timedelta(minutes=window_minutes)
                for event in successes[(src_ip, user, host)]
            )
            findings.append(
                {
                    "type": "BRUTE_FORCE",
                    "src_ip": src_ip,
                    "user": user,
                    "host": host,
                    "failures": len(window),
                    "window_start": first_failure.isoformat(),
                    "window_end": last_failure.isoformat(),
                    "success_after_failures": success_after,
                    "severity": "critical" if success_after else "high",
                }
            )
    return findings


def detect_password_spray(
    events: list[AuthEvent], unique_user_threshold: int = 5, window_minutes: int = 15
) -> list[dict[str, object]]:
    attempts: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.action == "failure":
            attempts[event.src_ip].append(event)

    findings = []
    for src_ip, items in attempts.items():
        window = _largest_window(items, window_minutes, score=lambda rows: len({row.user for row in rows}))
        users = sorted({event.user for event in window})
        if len(users) >= unique_user_threshold:
            findings.append(
                {
                    "type": "PASSWORD_SPRAY",
                    "src_ip": src_ip,
                    "unique_users": len(users),
                    "attempted_users": users,
                    "window_start": _time(window[0]).isoformat(),
                    "window_end": _time(window[-1]).isoformat(),
                    "severity": "high",
                }
            )
    return findings


def detect_privileged_unusual_source(events: list[AuthEvent], internal_cidr: str = "10.0.0.0/8") -> list[dict[str, object]]:
    internal = ipaddress.ip_network(internal_cidr)
    findings = []
    for event in events:
        if event.action != "success" or not event.privileged:
            continue
        try:
            external = ipaddress.ip_address(event.src_ip) not in internal
        except ValueError:
            external = True
        if external:
            findings.append(
                {
                    "type": "PRIVILEGED_UNUSUAL_SOURCE",
                    "src_ip": event.src_ip,
                    "user": event.user,
                    "host": event.host,
                    "logon_type": event.logon_type,
                    "severity": "critical",
                }
            )
    return findings


def run_all(events: list[AuthEvent]) -> list[dict[str, object]]:
    findings = []
    findings.extend(detect_bruteforce(events))
    findings.extend(detect_password_spray(events))
    findings.extend(detect_privileged_unusual_source(events))
    return findings


def write_report(findings: list[dict[str, object]], path: str | Path) -> None:
    rows = "\n".join(
        f"| {item['severity'].upper()} | {item['type']} | {item['src_ip']} | {_evidence(item)} |"
        for item in findings
    )
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(
        "# Splunk Detection Validation Report\n\n"
        "Generated from `sample_data/auth_events.json` using the Python validation harness.\n\n"
        "| Severity | Detection | Source | Evidence |\n"
        "| --- | --- | --- | --- |\n"
        f"{rows or '| - | No detections | - | - |'}\n",
        encoding="utf-8",
    )


def _time(event: AuthEvent) -> datetime:
    return datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))


def _largest_window(
    events: list[AuthEvent], window_minutes: int, score=lambda rows: len(rows)
) -> list[AuthEvent]:
    ordered = sorted(events, key=_time)
    duration = timedelta(minutes=window_minutes)
    candidates = [
        [event for event in ordered if _time(start) <= _time(event) <= _time(start) + duration]
        for start in ordered
    ]
    return max(candidates, key=score, default=[])


def _evidence(item: dict[str, object]) -> str:
    if item["type"] == "BRUTE_FORCE":
        return f"{item['failures']} failures against {item['user']}; success_after={item['success_after_failures']}"
    if item["type"] == "PASSWORD_SPRAY":
        return f"{item['unique_users']} users attempted"
    return f"privileged user {item['user']} on {item['host']}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Splunk authentication detections against synthetic events.")
    parser.add_argument("--events", default=str(ROOT / "sample_data" / "auth_events.json"))
    parser.add_argument("--report", default="docs/examples/example_detection_report.md")
    args = parser.parse_args()
    findings = run_all(load_events(args.events))
    write_report(findings, args.report)
    for finding in findings:
        if finding["type"] == "BRUTE_FORCE":
            print(f"BRUTE_FORCE: {finding['src_ip']} against {finding['user']} on {finding['host']}")
        elif finding["type"] == "PASSWORD_SPRAY":
            print(f"PASSWORD_SPRAY: {finding['src_ip']} attempted {finding['unique_users']} users")
        elif finding["type"] == "PRIVILEGED_UNUSUAL_SOURCE":
            print(f"PRIVILEGED_UNUSUAL_SOURCE: {finding['user']} from {finding['src_ip']}")
    print(f"Report: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
