#!/usr/bin/env python3
"""
detect_open_redirect.py
Open Redirect detection rule (log-pattern / regex based).
Simulates a SIEM correlation rule against web access logs.

Usage:
    python3 detect_open_redirect.py <logfile>

Exit behavior: prints one line per matched request with a verdict and reason.
"""

import re
import sys
import urllib.parse

# ---------------------------------------------------------------------------
# CONFIG - tune these for your environment
# ---------------------------------------------------------------------------

REDIRECT_PARAM_NAMES = {
    "redirect", "redir", "url", "next", "return", "return_url", "returnurl",
    "dest", "destination", "continue", "target", "out", "forward", "to",
    "callback", "checkout_url", "u",
}

ALLOWLISTED_DOMAINS = {
    "github.com",
    "blockchain.info",
    "explorer.dash.org",
    "etherscan.io",
    "spreadshirt.com",
    "stickeryou.com",
    "leanpub.com",
}

LOG_LINE_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) HTTP/[\d.]+" '
    r'(?P<status>\d+) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<ua>[^"]*)"'
)


def decode_fully(value: str, max_rounds: int = 3) -> str:
    prev = value
    for _ in range(max_rounds):
        decoded = urllib.parse.unquote(prev)
        if decoded == prev:
            break
        prev = decoded
    return prev


def hostname_is_allowlisted(hostname: str) -> bool:
    if not hostname:
        return False
    hostname = hostname.lower()
    for allowed in ALLOWLISTED_DOMAINS:
        if hostname == allowed or hostname.endswith("." + allowed):
            return True
    return False


def classify_redirect_target(raw_value: str):
    decoded = decode_fully(raw_value)
    stripped = decoded.strip()

    if re.match(r'^\s*(javascript|data|vbscript):', stripped, re.IGNORECASE):
        return "suspicious", f"non-http scheme in redirect target ({stripped[:40]})"

    if re.search(r'^(https?:)?\\\\', stripped, re.IGNORECASE) or "\\\\" in stripped:
        return "suspicious", "backslash-as-slash bypass pattern"

    if re.match(r'^/{2,}[^/]', stripped):
        return "suspicious", "protocol-relative (//) redirect to external host"

    if re.match(r'^[\s\x00-\x1f]+/{0,2}[a-zA-Z]', stripped):
        return "suspicious", "control-character prefix before host (filter-bypass attempt)"

    if stripped.startswith("/") and not stripped.startswith("//"):
        return "benign", "relative path, cannot redirect off-site"

    if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', stripped):
        parsed = urllib.parse.urlparse(stripped)
        host = parsed.hostname or ""
        at_trick = "@" in (parsed.netloc or "")

        if hostname_is_allowlisted(host):
            if at_trick:
                return "suspicious", f"@ userinfo trick against allowlisted-looking netloc ({parsed.netloc})"
            return "benign", f"absolute URL to allowlisted host ({host})"
        else:
            reason = f"absolute URL to non-allowlisted external host ({host or 'unresolvable'})"
            if at_trick:
                reason += " [contains @ userinfo trick]"
            return "suspicious", reason

    return "review", f"unrecognized redirect value pattern: {stripped[:60]!r}"


def scan_log(path: str):
    findings = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            m = LOG_LINE_RE.search(line)
            if not m:
                continue
            full_path = m.group("path")
            if "?" not in full_path:
                continue
            _, _, qs = full_path.partition("?")
            params = urllib.parse.parse_qs(qs, keep_blank_values=True)

            for pname, values in params.items():
                if pname.lower() not in REDIRECT_PARAM_NAMES:
                    continue
                for val in values:
                    verdict, reason = classify_redirect_target(val)
                    findings.append({
                        "line": lineno,
                        "ip": m.group("ip"),
                        "ts": m.group("ts"),
                        "status": m.group("status"),
                        "ua": m.group("ua"),
                        "param": pname,
                        "value": val,
                        "verdict": verdict,
                        "reason": reason,
                    })
    return findings


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 detect_open_redirect.py <logfile>")
        sys.exit(1)

    findings = scan_log(sys.argv[1])
    if not findings:
        print("No redirect-parameter requests found in log.")
        return

    counts = {"suspicious": 0, "review": 0, "benign": 0}
    for f in findings:
        counts[f["verdict"]] += 1
        tag = {"suspicious": "[ALERT]", "review": "[REVIEW]", "benign": "[ok]    "}[f["verdict"]]
        print(f'{tag} line {f["line"]:>3} | {f["ip"]:<15} | param={f["param"]:<12} '
              f'value={f["value"][:60]!r:<62} -> {f["reason"]}')

    print("\n--- Summary ---")
    print(f'Total redirect-param requests examined : {len(findings)}')
    print(f'  Suspicious (would fire SOC alert)     : {counts["suspicious"]}')
    print(f'  Needs manual review                   : {counts["review"]}')
    print(f'  Benign                                : {counts["benign"]}')


if __name__ == "__main__":
    main()
