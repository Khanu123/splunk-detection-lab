# Splunk Detection Validation Report

Generated from `sample_data/auth_events.json` using the Python validation harness.

| Severity | Detection | Source | Evidence |
| --- | --- | --- | --- |
| CRITICAL | BRUTE_FORCE | 198.51.100.44 | 4 failures against admin; success_after=True |
| HIGH | PASSWORD_SPRAY | 203.0.113.77 | 6 users attempted |
| CRITICAL | PRIVILEGED_UNUSUAL_SOURCE | 198.51.100.44 | privileged user admin on web-01 |
