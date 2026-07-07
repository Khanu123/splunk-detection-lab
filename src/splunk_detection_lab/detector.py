from __future__ import annotations

import ipaddress
import json
from collections import defaultdict
from dataclasses import dataclass
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


def detect_bruteforce(events: list[AuthEvent], threshold: int = 4) -> list[dict[str, object]]:
    failures: dict[tuple[str, str, str], list[AuthEvent]] = defaultdict(list)
    successes = {(event.src_ip, event.user, event.host) for event in events if event.action == "success"}
    for event in events:
        if event.action == "failure":
            failures[(event.src_ip, event.user, event.host)].append(event)

    findings = []
    for (src_ip, user, host), items in failures.items():
        if len(items) >= threshold:
            findings.append(
                {
                    "type": "BRUTE_FORCE",
                    "src_ip": src_ip,
                    "user": user,
                    "host": host,
                    "failures": len(items),
                    "success_after_failures": (src_ip, user, host) in successes,
                    "severity": "critical" if (src_ip, user, host) in successes else "high",
                }
            )
    return findings


def detect_password_spray(events: list[AuthEvent], unique_user_threshold: int = 5) -> list[dict[str, object]]:
    attempts: dict[str, set[str]] = defaultdict(set)
    for event in events:
        if event.action == "failure":
            attempts[event.src_ip].add(event.user)

    return [
        {
            "type": "PASSWORD_SPRAY",
            "src_ip": src_ip,
            "unique_users": len(users),
            "attempted_users": sorted(users),
            "severity": "high",
        }
        for src_ip, users in attempts.items()
        if len(users) >= unique_user_threshold
    ]


def detect_privileged_unusual_source(events: list[AuthEvent], internal_cidr: str = "10.0.0.0/8") -> list[dict[str, object]]:
    internal = ipaddress.ip_network(internal_cidr)
    findings = []
    for event in events:
        if event.action != "success" or not event.privileged:
            continue
        if ipaddress.ip_address(event.src_ip) not in internal:
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


def main() -> int:
    findings = run_all(load_events())
    for finding in findings:
        if finding["type"] == "BRUTE_FORCE":
            print(f"BRUTE_FORCE: {finding['src_ip']} against {finding['user']} on {finding['host']}")
        elif finding["type"] == "PASSWORD_SPRAY":
            print(f"PASSWORD_SPRAY: {finding['src_ip']} attempted {finding['unique_users']} users")
        elif finding["type"] == "PRIVILEGED_UNUSUAL_SOURCE":
            print(f"PRIVILEGED_UNUSUAL_SOURCE: {finding['user']} from {finding['src_ip']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
