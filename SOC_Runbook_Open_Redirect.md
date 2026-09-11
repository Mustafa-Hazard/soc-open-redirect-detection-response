# SOC Runbook: Open Redirect Detection & Response
**Organization type:** UGC Creator platform (user profiles, share links, creator-to-brand redirects, OAuth login)
**Author:** SOC Blue Team — Week 4 Exercise
**Last updated:** 2026-09-11

---

## 1. Background — What is Open Redirect?

Open Redirect is a web vulnerability where an application takes a
user-supplied value (usually a query parameter like `redirect=`,
`next=`, or `url=`) and sends the browser to that destination without
verifying it stays on the site's own domain. It's not a memory-corruption
or auth-bypass bug — it's a **trust bug**: the app vouches for a link
that actually points somewhere else.

On a UGC Creator platform this matters more than usual because the whole
product is built around shareable links (creator profile links, "watch
on our site" redirects, brand-campaign click-throughs, OAuth login
callbacks). Every one of those is a candidate abuse vector.

### What an attacker uses it for
- **Phishing with a trusted domain in the URL bar** — `https://ugc-creator-hub.com/login?redirect=http://evil-phish.ru` looks legitimate up to the point of redirection, which raises click-through rates in phishing campaigns.
- **OAuth/token theft** — chaining an open redirect into an OAuth `redirect_uri` or `continue` parameter to leak authorization codes or session tokens to an attacker-controlled host.
- **SSRF/CSRF pivot** — using the app's own trusted egress to reach internal or attacker infrastructure.
- **Malware/exploit-kit delivery** — bouncing traffic through a trusted domain to defeat simple reputation/URL filters in email or chat security tools.

### What an attack attempt looks like in logs
Common request shapes (see `samples/attack_sample.log` for real examples used in this exercise):
- `?redirect=http://evil.com/...` — plain absolute URL to an external host.
- `?next=//attacker.net/...` — protocol-relative (`//`) redirect; browsers treat this as "same scheme, different host."
- `?url=https://trusted.com@evil.com/...` — userinfo `@` trick; everything before `@` is cosmetic, the browser navigates to `evil.com`.
- `?dest=http:%2f%2fevil.tk/...` or double/triple URL-encoded slashes — encoding used to slip past naive string filters (e.g. a WAF rule that only checks for the literal substring `http://`).
- `?target=http:\\evil.com\...` — backslash-as-slash; some browsers/parsers normalize `\` to `/`.
- `?url=javascript:...` / `?url=data:text/html;base64,...` — non-http schemes used for redirect-based XSS rather than a network redirect at all.
- Lookalike domains: `ugc-creator-hub.com.evilproxy.io` — the real brand name appears as a **subdomain label** of an attacker-owned domain, which fools a human skimming the URL but not correct hostname parsing.
- Bursts of the above from a single IP or small IP set, often with non-browser user agents (`curl`, `python-requests`) — indicates scripted probing rather than a real user session.

### What a false alarm looks like
- `?redirect=/dashboard` — relative path. Cannot leave the site; not an open redirect regardless of what's in the parameter name.
- `?url=https://ugc-creator-hub.com/creator/janedoe` — absolute URL, but to the site's own domain.
- `?continue=https://accounts.google.com/o/oauth2/continue` — absolute URL to a legitimately allowlisted third party (this is the normal OAuth continuation flow, not an attack).
- A **tricky-looking but actually safe** case worth calling out explicitly, because it fooled a naive substring check during this exercise's own testing: `?redirect=https://accounts.ugc-creator-hub.com//.evil.co/login`. A rule that just greps for `evil.co` or for the substring `//` anywhere in the value would flag this. But parsed correctly, the **host** is `accounts.ugc-creator-hub.com` and `//.evil.co/login` is just an unusual-looking *path* on that legitimate host — the browser never leaves the site. This is why the detection logic in this runbook does real URL parsing (hostname extraction) rather than pure regex/substring matching. It's flagged as a documented example below (Test Case 9) precisely because it's the case most likely to generate analyst confusion.

---

## 2. Detection Rule

Three equivalent implementations are provided so the rule can be dropped
into whatever stack is available:

| File | Purpose |
|---|---|
| `rules/open_redirect.sigma.yml` | Vendor-agnostic Sigma rule — convert with `sigma-cli` to Splunk SPL, Elastic Query DSL, etc. |
| `rules/wazuh_open_redirect_rules.xml` | Native Wazuh local rule, layered (base match → pattern match → high-confidence `@`-trick → allowlist suppression → same-IP frequency correlation). |
| `scripts/detect_open_redirect.py` | Standalone Python reference implementation used to actually test the logic in this exercise (does full URL-decode + hostname parsing, which the regex-only rules approximate). Allowlist is supplied externally via `--profile ugc\|juiceshop` or `--allowlist <path>` — not hardcoded — so the same detection logic can be pointed at different protected assets without editing the script. |

### Rule logic (plain language)
1. Match requests where a known redirect-carrying parameter is present (`redirect`, `redir`, `url`, `next`, `return`, `return_url`, `dest`, `continue`, `target`, `out`, `forward`, `to`).
2. Fully URL-decode the value (handles single and double/triple encoding).
3. Classify the decoded value:
   - Starts with `/` and not `//` → **benign** (relative path).
   - Absolute URL (`scheme://host/...`) → extract the **hostname** and check it against an allowlist of owned/trusted domains. Allowlisted → benign. Not allowlisted → **alert**.
   - Starts with `//` or `///` (protocol-relative) → **alert**.
   - Contains `\\` immediately after/instead of `//` → **alert** (backslash bypass).
   - Scheme is `javascript:`, `data:`, or `vbscript:` → **alert** (highest severity — this isn't even a network redirect, it's redirect-parameter-based script injection).
   - Contains a control character (`\t`, `\n`, etc.) immediately before the host → **alert** (filter-bypass attempt).
   - `@` present in the authority component of an otherwise-allowlisted-looking absolute URL → **alert, high confidence** (classic phishing trick).
   - Anything that doesn't cleanly fit the above → **review** (fail open to a human, not silently dropped).

### Why an allowlist instead of a denylist
Denylisting known-bad domains doesn't scale — attackers register a new
domain per campcampaign. Allowlisting the organization's own domains
(and a short, deliberately-maintained list of trusted third parties like
the OAuth and payment providers) means the rule doesn't need to know
what "bad" looks like; it only needs to know what "ours" looks like,
which changes far less often.

---

## 3. Test Results

Both sample logs were run through `scripts/detect_open_redirect.py --profile ugc`
(loading `configs/allowlist_ugc.txt`, the fictional UGC Creator platform's
trusted domains). Full raw output is in `results/test_output.txt`; key lines below.

### Attack sample (`samples/attack_sample.log`) — 12 redirect requests

| # | Source IP | Param | Value (truncated) | Verdict | Reason |
|---|---|---|---|---|---|
| 1 | 203.0.113.44 | redirect | `http://evil-phish.ru/steal` | **ALERT** | external absolute URL |
| 2 | 203.0.113.44 | next | `//attacker.net/creds` | **ALERT** | protocol-relative |
| 3 | 198.51.100.9 | url | `https://ugc-creator-hub.com@evil-lookalike.com/payload` | **ALERT** | `@` userinfo trick |
| 4 | 198.51.100.9 | dest | `http://evil.tk/finalize-login` | **ALERT** | external absolute URL |
| 5 | 198.51.100.9 | to | `\t//malicious-cdn.top/asset.js` | **ALERT** | protocol-relative + control-char prefix |
| 6 | 45.146.164.22 | return_url | `https://ugc-creator-hub.com.evilproxy.io/verify` | **ALERT** | lookalike subdomain of attacker domain |
| 7 | 45.146.164.22 | continue | `//evil-payload-host.xyz/harvest` | **ALERT** | protocol-relative |
| 8 | 45.146.164.22 | target | `http:\\evil-backslash-trick.com\phish` | **ALERT** | backslash bypass |
| 9 | 45.146.164.22 | redirect | `https://accounts.ugc-creator-hub.com//.evil.co/login` | **ok (benign)** | correctly parsed: host is the real, allowlisted domain — `.evil.co` is only a path segment, not a host. See discussion above. |
| 10 | 91.219.237.5 | url | `data:text/html;base64,...` | **ALERT** | non-http scheme |
| 11 | 91.219.237.5 | next | `javascript:alert(document.domain)` | **ALERT** | non-http scheme |
| 12 | 91.219.237.5 | url | `///evil-triple-slash.net/x` | **ALERT** | protocol-relative |

**Result: 11/12 correctly alerted, 1/12 correctly identified as benign (not 12/12 "alerts" — see below).**

Line 9 deserves a second look rather than being called a miss. It was
deliberately included as a "looks scary, isn't" test case. `accounts.ugc-creator-hub.com//.evil.co/login`
parses to host `accounts.ugc-creator-hub.com` with path `//.evil.co/login`
— a browser sends the request to the real site, full stop. A naive
detection rule (plain regex for `//` anywhere in the value, or a
substring search for competitor/lookalike keywords) would have false-alarmed
on this. Correct URL parsing is what avoids that false positive. This
is called out explicitly because an analyst unfamiliar with URL parsing
could easily mis-triage it as a miss — it isn't.

### Benign sample (`samples/benign_sample.log`) — 12 redirect requests

All 12 relative-path and allowlisted-domain requests (dashboard links,
own-domain share links, Google OAuth continuation, Stripe checkout,
partner subdomain campaign links) were correctly classified **benign**,
producing **zero false positives**.

```
--- Summary ---
Total redirect-param requests examined : 12
  Suspicious (would fire SOC alert)     : 0
  Needs manual review                   : 0
  Benign                                : 12
```

### Tuning performed
- Initial draft of the rule flagged any value containing `//` at all, which caught legitimate double-slash paths on the org's own domain (e.g., CDN paths with `//`) as false positives. Fixed by requiring the `//` to appear at the **start** of the value (i.e., actually be protocol-relative) rather than anywhere in it.
- Added the allowlist check *before* the bypass-pattern checks for absolute URLs, so a fully-qualified `https://accounts.ugc-creator-hub.com/...` isn't flagged just because it's an absolute URL.
- Added the `@`-trick check as a distinct high-confidence sub-case rather than folding it into the generic "external host" check, because it's a much stronger phishing signal.

---

## 4. Alert Triage Checklist

Use this when a `950101` / `950102` (Wazuh) or "Possible Open Redirect"
(Sigma) alert fires. Target: get to a disposition in under 10 minutes for a
single alert.

1. **Read the raw redirect parameter value in full (decoded).** Don't trust the truncated SIEM preview — copy the full query string and URL-decode it in a scratch tool (not a browser) to see the real destination host.
2. **Identify the destination host and check it against the current allowlist** (`configs/allowlist_ugc.txt` in production; confirm which `--profile` is in use if unsure). If it should be allowlisted (e.g., a newly launched partner domain), this is a tuning task, not an incident — update the allowlist file and suppress this alert instance.
3. **Check the source IP reputation and volume.** How many requests from this IP/ASN in the last hour? A single request from a residential IP with a normal browser UA is lower priority than a burst from a datacenter IP with `curl`/`python-requests` as the user agent.
4. **Check whether the request reached a live user session.** Was this endpoint actually hit by a real, authenticated session (potential victim), or is it an unauthenticated scan hitting the redirect endpoint directly? Pull the session/user ID if present in the log.
5. **Check the HTTP response code and whether the redirect was actually served.** A `302`/`301` response means the redirect fired. If the app already validates and returned `400`/`403`, the exploit attempt failed at the app layer — downgrade severity but still log it (attacker is probing).
6. **Check for the `@` userinfo trick or a lookalike-domain pattern specifically** (rule `950102`). These are near-zero false-positive patterns — treat as high confidence phishing/credential-theft attempts, not scanning noise.
7. **Correlate against the campaign rule (`950104`)** — is this one of many attempts from the same source in a short window? If yes, this is likely automated scanning/a phishing kit test-run rather than a targeted, one-off probe.
8. **Check if any real users clicked through** — search web logs / CDN logs for requests to the *destination* domain referred from your platform in the same time window, if that visibility exists (see blind spots, Section 6).
9. **Disposition:**
   - Confirmed exploitation attempt, no evidence of user impact → log, block source, proceed to containment (Section 5) at reduced urgency.
   - Confirmed exploitation attempt with evidence of a real user reaching the malicious destination → escalate immediately per Section 5 notification steps.
   - False positive (allowlist gap) → update allowlist, document, close.
   - Ambiguous / `review` verdict from the tool → escalate to a senior analyst rather than closing on your own judgment.

---

## 5. Incident Response Playbook

### Severity guide
| Condition | Severity |
|---|---|
| Single scan attempt, no successful redirect served, no user impact evidence | Low |
| Successful redirect served (302 to external host) but no confirmed user click-through | Medium |
| Confirmed user click-through to attacker infrastructure, or `@`-trick / lookalike-domain pattern targeting the login or OAuth flow | High |
| Evidence of session token / OAuth code / credentials observed leaving via the redirect (e.g., token visible in the destination URL) | Critical |

### Containment
1. **Block the destination domain** at the egress/DNS filtering layer and, if available, at email/chat link-scanning tools, so any already-sent phishing links are neutralized in transit.
2. **Rate-limit or block the source IP(s) / ASN** at the WAF/CDN edge for the affected redirect endpoint(s).
3. **If a specific redirect endpoint is confirmed exploitable** (not just probed), disable or hot-patch that endpoint — e.g., temporarily hard-code it to only accept relative paths — rather than waiting for a full code fix to ship.
4. **If credentials or session tokens may have been exposed** (Critical severity): force session invalidation / password reset for any affected accounts, and rotate any OAuth client secrets involved in the flow.
5. **Preserve evidence** — export the relevant raw access logs, WAF logs, and (if available) the destination domain's WHOIS/registration data before any takedown/blocking activity potentially triggers attacker awareness.

### Notification
| Who | When | Why |
|---|---|---|
| On-call SOC lead / IC | Medium severity and above, immediately | Own the incident timeline and coordinate response |
| Application/Platform engineering team owning the affected redirect endpoint | Medium and above | They need to ship the code-level fix (see Remediation) |
| Trust & Safety / Creator Support | High and above | Creators are often the ones whose share links get abused for phishing; they need to warn affected creators and moderate any malicious content using the platform's redirect as a vector |
| Legal / Privacy | Critical, or any confirmed credential/token exposure | Breach-notification obligations may apply depending on jurisdiction and what was exposed |
| End users / affected creators | Critical, once containment is stable | Direct notice with clear guidance (reset password, don't click old links) — coordinate wording with Legal and Comms first |
| External — domain registrar / hosting provider abuse contact for the attacker's domain | Medium and above | Request takedown of phishing infrastructure impersonating the brand |

### Remediation (root cause, not just symptom)
- Enforce redirect-target validation **server-side, at the code level**, not just at the SIEM/WAF: only allow relative paths, or absolute URLs whose host exactly matches an allowlist maintained in application config (mirrors the detection rule's own allowlist — keep them in sync).
- For OAuth/SSO flows specifically, validate `redirect_uri` / `continue` against the **exact, pre-registered** callback URL for that client — not a substring or prefix match.
- Add automated regression tests (e.g., a lightweight DAST/SAST check in CI) that specifically try the bypass patterns in this document (protocol-relative, `@`-trick, backslash, encoded slashes, non-http schemes) against every redirect-capable endpoint before each release.
- Keep the SIEM allowlist and the application-code allowlist in the same source of truth (or auto-generate one from the other) so they can't silently drift apart. In this project, `configs/allowlist_ugc.txt` is that source of truth for the detection side — application engineering's code-level allowlist should be reviewed against it on the same change cadence.
- Track **MTTD** (mean time to detect — alert fire time minus request time, should be near-zero for real-time SIEM ingestion) and **MTTR** (mean time to remediate — alert fire time to confirmed fix/containment) for this alert class, and review both monthly.

---

## 6. Detection Coverage & Known Blind Spots

**Covered:**
- Query-string-based redirect parameters using the recognized parameter name list.
- Protocol-relative, backslash, `@`-trick, non-http-scheme, and single/double/triple-URL-encoded bypasses.
- Lookalike domains where the real brand appears as a subdomain label of an attacker domain.
- Volumetric/scanning behavior via the same-source-IP frequency correlation rule.

**Blind spots (documented, not solved by this rule alone):**
1. **Fragment-based (`#`) redirects.** Anything after `#` in a URL is never sent to the server, so a client-side JS redirect driven by `window.location.hash` is completely invisible to server access logs. Requires client-side telemetry (RUM, CSP violation reports, or browser extension telemetry) to catch — out of scope for a log-based SIEM rule.
2. **POST-body redirect parameters.** This rule only inspects the query string. If a redirect target is submitted via a POST body (e.g., a form field), standard access logs won't show it. Requires either app-level logging of that field or WAF body inspection.
3. **Unlisted/renamed parameter names.** The rule depends on knowing the parameter name conventions (`redirect`, `next`, etc.). A custom or obscure parameter name (`u`, `go_to`, a single letter, or an app-specific name not yet added to the list) bypasses detection entirely. Mitigation: periodic manual review of new endpoints/parameters added by engineering; keep this list synced with the app-level allowlist changelog.
4. **IDN/punycode homograph domains.** A domain using look-alike Unicode characters (rendering visually similar to the real brand) that isn't a literal subdomain string won't be caught by the current allowlist/lookalike logic, since it operates on ASCII substrings. Needs a dedicated homograph-detection check (NFKC normalization + confusable-character mapping) as a follow-up enhancement.
5. **Allowlist drift.** Every new legitimate partner/subdomain requires a manual allowlist update on both the SIEM rule and the app code. Until that update happens, legitimate new integrations will generate false positives (safe failure mode) — but if the *code-level* allowlist is updated without a matching SIEM update, real attacks against the new pattern could go undetected until the SIEM allowlist catches up. Keep a change-log/ticket requirement tying the two together.
6. **CDN/proxy layers that strip or rewrite query strings before they reach origin logs.** If a CDN caches or rewrites redirect requests, the access log seen by the SIEM may not reflect the original attacker-supplied value. Verify logging is configured at the layer closest to the actual redirect logic (origin, not just edge cache).
7. **Wrong or missing `--profile`/`--allowlist` at run time.** The detector requires an explicit allowlist selection; if an analyst runs it against the wrong protected asset's log with the wrong profile (or a future integration forgets to pass one), it fails safe by erroring out rather than silently using a stale or wrong allowlist — but this still requires operational discipline (documented run commands, not ad-hoc invocation) to avoid analyst error at 2am during an incident.

---

## 7. Files in this exercise

```
soc_open_redirect/
├── SOC_Runbook_Open_Redirect.md      <- this document
├── rules/
│   ├── open_redirect.sigma.yml       <- vendor-agnostic Sigma rule
│   └── wazuh_open_redirect_rules.xml <- native Wazuh local rule set
├── configs/
│   ├── allowlist_ugc.txt             <- trusted domains for the fictional UGC Creator scenario
│   └── allowlist_juiceshop.txt       <- trusted domains for the real Juice Shop validation target
├── samples/
│   ├── attack_sample.log             <- 12 attack requests (test input)
│   └── benign_sample.log             <- 12 legitimate requests (test input)
├── scripts/
│   └── detect_open_redirect.py       <- reference detection implementation (--profile ugc|juiceshop or --allowlist <path>)
└── results/
    ├── test_output.txt               <- raw output of running the script against both samples
    ├── juice_shop_access.log         <- real access log pulled from the live Juice Shop container
    └── juice_shop_test_results.txt   <- real detector output against that log
```

**Allowlist is environment-specific, not hardcoded.** The detection
logic in `scripts/detect_open_redirect.py` is reused unchanged across
targets; only the allowlist file passed via `--profile` or `--allowlist`
changes. This avoids the failure mode discovered mid-project: an
earlier version hardcoded one target's allowlist directly into the
script, which silently broke detection (50% false-positive rate) the
moment the script was pointed at a different protected asset.

**Lab/authorization note:** the sample logs in `samples/` are synthetic,
generated for this exercise. All live testing (Section 8 below) was
performed exclusively against a self-hosted OWASP Juice Shop container
under my own control — no third-party systems were scanned or exploited.

**Scope decision — Wazuh/ELK deployment:** a full Wazuh/ELK stack was
deliberately not deployed for this exercise. The Sigma and Wazuh rules
(`rules/`) are authored and, for Sigma, mechanically converted to
Splunk/Elastic query syntax via `sigma-cli` — but neither has been
loaded into a live SIEM instance. Detection logic is instead validated
through the Python reference implementation (`scripts/detect_open_redirect.py`),
run against both synthetic samples and a real access log pulled from a
live, exploited OWASP Juice Shop container (Section 8). This is judged
sufficient validation for this exercise's scope: it proves the
detection *logic* works against a real, reproducible vulnerability,
which is the harder and more valuable thing to get right. Deploying an
actual SIEM instance is flagged as a natural next step, not a gap in
what was tested here.

---

## 8. Real-World Validation — OWASP Juice Shop

To go beyond synthetic logs, the detection rule was also validated
against a real, live target: OWASP Juice Shop, run locally via Docker
(`docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop`).

### The real vulnerability found

Juice Shop's own redirect allowlist check (`lib/insecurity.ts`,
`isRedirectAllowed`) does this:

```js
export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl)
  }
  return allowed
}
```

This checks whether the allowlisted string appears **anywhere in** the
supplied URL (`.includes()`), not whether the URL's **host** matches an
allowlisted host. That's a real, exploitable open-redirect bypass:
appending an allowlisted URL as a decoy query parameter on an
attacker-controlled domain satisfies the check.

### Requests tested against the live app

| # | Request | App's own verdict | Actual destination |
|---|---|---|---|
| 1 | `GET /redirect?to=http://evil.com` | `406` rejected | — (blocked) |
| 2 | `GET /redirect?to=/` | `406` rejected | — (blocked) |
| 3 | `GET /redirect?to=https://github.com/juice-shop/juice-shop` | `302` allowed | github.com — correct, legitimate |
| 4 | `GET /redirect?to=http://evil.com/?x=https://github.com/juice-shop/juice-shop` | **`302` allowed** | **evil.com — real bypass** |

Requests 1–2 were the app's own check working correctly (rejecting an
unrelated external domain and an underspecified relative value).
Request 4 is the interesting one: the app's own allowlist check passed
it because the string `github.com/juice-shop/juice-shop` appears
inside the value — but `urllib.parse` (and any browser) resolves the
actual host to `evil.com`. The application redirected the user there.

### Running the detector against the real access log

Real combined-format log lines were pulled directly from the container
(`docker cp juice-shop:/juice-shop/logs/access.log.<date> .`) and run
through `scripts/detect_open_redirect.py --profile juiceshop`, which loads
`configs/allowlist_juiceshop.txt` — Juice Shop's actual allowlist:
`github.com`, `blockchain.info`, `explorer.dash.org`, `etherscan.io`,
`spreadshirt.com`, `stickeryou.com`, `leanpub.com`:

```
[ALERT] line   1 | ::ffff:172.17.0.1 | param=to | value='http://evil.com'
   -> absolute URL to non-allowlisted external host (evil.com)
[ok]     line   2 | ::ffff:172.17.0.1 | param=to | value='/'
   -> relative path, cannot redirect off-site
[ok]     line   3 | ::ffff:172.17.0.1 | param=to | value='https://github.com/juice-shop/juice-shop'
   -> absolute URL to allowlisted host (github.com)
[ALERT] line   4 | ::ffff:172.17.0.1 | param=to | value='http://evil.com/?x=https://github.com/juice-shop/juice-shop'
   -> absolute URL to non-allowlisted external host (evil.com)

--- Summary ---
Total redirect-param requests examined : 4
  Suspicious (would fire SOC alert)     : 2
  Needs manual review                   : 0
  Benign                                : 2
```

**Key finding:** the detection rule correctly alerted on request 4 —
the same bypass that fooled the application's own security control.
This demonstrates the value of an independent, hostname-aware detection
layer at the SIEM level: it caught a real open-redirect exploit that
the target application's own substring-based allowlist check missed.
Full raw log and output are in `results/juice_shop_access.log` and
`results/juice_shop_test_results.txt`.
