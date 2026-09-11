```
# SOC Open Redirect Detection & Response

**A blue-team SOC exercise — detecting and responding to Open Redirect exploitation, validated against a real, live vulnerability.**

This isn't a purely theoretical detection rule. It was built, tuned, and then proven against a real, reproducible open-redirect bypass in a live [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) instance — the kind of finding an actual SOC analyst would want to see before trusting a rule in production.

---

## What's in here

| | |
|---|---|
| 🕵️ **Detection rule** | Three equivalent implementations — Sigma (vendor-agnostic), native Wazuh, and a Python reference detector — so the logic can be dropped into whatever stack is on hand |
| ⚙️ **Config-driven allowlist** | Detection logic is environment-agnostic. Point it at any protected asset with `--profile <name>`, no code changes needed |
| 🧪 **Real-world validation** | Correctly caught a real allowlist-bypass vulnerability in a live app that fooled the app's *own* security control |
| 📋 **Triage checklist** | A concrete, step-by-step guide for disposing of an alert in under 10 minutes |
| 🚨 **Incident-response playbook** | Severity guide, containment, notification, and root-cause remediation |
| 🔍 **Documented blind spots** | Honest accounting of what this rule can't see, and why |

---

## Quick start

```bash
# Run against the fictional UGC Creator scenario
python3 scripts/detect_open_redirect.py samples/attack_sample.log --profile ugc
python3 scripts/detect_open_redirect.py samples/benign_sample.log --profile ugc

# Run against the real OWASP Juice Shop validation target
python3 scripts/detect_open_redirect.py results/juice_shop_access.log --profile juiceshop
```

Or point it at your own environment with a custom allowlist:

```bash
python3 scripts/detect_open_redirect.py your_access.log --allowlist path/to/your_allowlist.txt
```

---

## 🔑 The key finding

Testing against a real, live Juice Shop container uncovered that its built-in redirect allowlist check does this:

```js
allowed = allowed || url.includes(allowedUrl)
```

That's a **substring check**, not a **host check** — meaning an attacker can smuggle a trusted-looking string anywhere inside a malicious URL and sail straight through the app's own defense:

```
http://evil.com/?x=https://github.com/juice-shop/juice-shop
```

The app allowed it. **This repo's detection rule caught it** — because it parses the actual destination host instead of pattern-matching on substrings.

Full writeup, requests tested, and raw log evidence: [Section 8 of the runbook](./SOC_Runbook_Open_Redirect.md#8-real-world-validation--owasp-juice-shop).

---

## Repo structure

```
├── SOC_Runbook_Open_Redirect.md      # main deliverable — the full SOC runbook
├── rules/
│   ├── open_redirect.sigma.yml       # vendor-agnostic Sigma rule
│   ├── wazuh_open_redirect_rules.xml # native Wazuh local rule set
│   └── converted_*.txt               # Splunk SPL / Elastic Lucene / ES|QL conversions
├── configs/
│   ├── allowlist_ugc.txt             # trusted domains — fictional UGC Creator scenario
│   └── allowlist_juiceshop.txt       # trusted domains — real Juice Shop validation target
├── scripts/
│   └── detect_open_redirect.py       # reference detector (--profile <name> or --allowlist <path>)
├── samples/
│   ├── attack_sample.log             # 12 synthetic attack requests
│   └── benign_sample.log             # 12 synthetic legitimate requests
└── results/
    ├── test_output.txt               # detector output against both samples
    ├── juice_shop_access.log         # real access log from the live Juice Shop container
    └── juice_shop_test_results.txt   # real detector output against that log
```

---

## Lab & authorization note

All live testing was performed against infrastructure I control — a local Docker container running OWASP Juice Shop, an intentionally vulnerable app built for security training. No third-party systems were scanned or exploited.

---

## Read the full runbook

👉 **[SOC_Runbook_Open_Redirect.md](./SOC_Runbook_Open_Redirect.md)** — detection logic, tuning notes, triage checklist, full IR playbook, blind spots, and the complete Juice Shop validation writeup.
```
