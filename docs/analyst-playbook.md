# Analyst Playbook

## Brute-Force Login Attempts

Evidence to collect:

- Source IP, target user, target host, and time range.
- Number of failures and whether a success followed.
- GeoIP or VPN context if available.
- Recent password reset or admin maintenance ticket.

False-positive checks:

- User forgot their password.
- Approved vulnerability scanner or authentication test.
- Misconfigured service account repeatedly retrying.

Suggested action:

- Escalate quickly if a privileged account succeeds after repeated failures.
- Reset credentials and review endpoint activity if compromise is likely.

## Password Spraying

Evidence to collect:

- Source IP.
- Number of unique usernames attempted.
- Whether attempts target VPN, email, or identity provider.
- Any successful logins after the spray.

False-positive checks:

- Identity provider outage.
- SSO migration or test automation.
- Misconfigured application attempting old credentials.

Suggested action:

- Block or challenge the source where appropriate.
- Review MFA status and successful sign-ins.

## Privileged Login From Unusual Source

Evidence to collect:

- Privileged user, source IP, host, logon type, and time.
- Expected admin jump box or VPN source ranges.
- Change ticket or emergency access record.

False-positive checks:

- Approved remote admin access.
- Break-glass account use with a valid incident ticket.

Suggested action:

- Treat unexpected privileged access from external IPs as high priority until validated.
