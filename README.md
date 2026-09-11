# SOC Open Redirect Detection & Response

A blue-team SOC exercise: detecting and responding to Open Redirect
exploitation on a UGC Creator platform. Includes detection rules
(Sigma, Wazuh, converted Splunk SPL / Elastic queries), a Python
reference detector, an alert-triage checklist, a full incident-response
playbook, and validation against both synthetic logs and a real
exploit against a live OWASP Juice Shop instance.

## Structure

- `SOC_Runbook_Open_Redirect.md` — main deliverable: background, detection logic, triage checklist, IR playbook, blind spots, and real test results.
- `rules/` — Sigma rule, native Wazuh rule, and converted Splunk/Elastic queries.
- `scripts/detect_open_redirect.py` — standalone Python reference detector (URL-decoding + real hostname parsing).
- `samples/` — synthetic attack and benign log samples used for initial rule tuning.
- `results/` — real access log and detector output from a live OWASP Juice Shop test, including a genuine open-redirect bypass of the app's own allowlist check.

## Key finding

Testing against a real OWASP Juice Shop instance uncovered that its
built-in redirect allowlist check uses `url.includes(allowedUrl)`
instead of exact host matching — allowing an attacker to embed an
allowlisted string anywhere in a malicious URL to bypass it. The
detection rule in this repo correctly flagged that bypass even though
the application's own control missed it. See Section 8 of the runbook
for full details.

## Lab/authorization note

All testing was performed against infrastructure I control (a local
Docker container running OWASP Juice Shop). No third-party systems
were scanned or exploited.
