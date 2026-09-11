#!/usr/bin/env python3
"""
detect_open_redirect.py
Open Redirect detection rule (log-pattern / regex based).
Simulates a SIEM correlation rule against web access logs.

Usage:
    python3 detect_open_redirect.py <logfile> --profile ugc
    python3 detect_open_redirect.py <logfile> --profile juiceshop
    python3 detect_open_redirect.py <logfile> --allowlist path/to/custom_allowlist.txt

The allowlist is environment-specific and must be supplied explicitly via
--profile (looks up configs/allowlist_<profile>.txt) or --allowlist (a
direct path to a newline-delimited hostname file, '#' comments allowed).
This keeps the detection logic reusable across different protected assets
instead of hardcoding one organization's trusted domains into the rule.

Exit behavior: prints one line per matched request with a verdict and reason.
"""

import argparse
import os
import re
import sys
import urllib.parse

# ---------------------------------------------------------------------------
# CONFIG - static detection tuning (NOT environment-specific; do not put
# allowlist domains here, use configs/allowlist_<profile>.txt instead)
# ---------------------------------------------------------------------------

REDIRECT_PARAM_NAMES = {
    "redirect", "redir", "url", "next", "return", "return_url", "returnurl",
    "dest", "destination", "continue", "target", "out", "forward", "to",
    "callback", "checkout_url", "u",
}

LOG_LINE_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) HTTP/[\d.]+" '
    r'(?P<status>\d+) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<ua>[^"]*)"'
)

CONFIGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "configs")


def load_allowlist(args) -> set:
    if args.allowlist:
        path = args.allowlist
    elif args.profile:
        path = os.path.join(CONFIGS_DIR, f"allowlist_{args.profile}.txt")
    else:
        print("ERROR: must supply --profile <name> or --allowlist <path>.")
        print("Example: --profile ugc   (loads configs/allowlist_ugc.txt)")
        print("Example: --profile juiceshop   (loads configs/allowlist_juiceshop.txt)")
        sys.exit(1)

    if not os.path.isfile(path):
        print(f"ERROR: allowlist file not found: {path}")
        sys.exit(1)

    domains = set()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domains.add(line.lower())
    if not domains:
        print(f"ERROR: allowlist file {path} loaded but contains no domains.")
        sys.exit(1)
    return domains


def decode_fully(value: str, max_rounds: int = 3) -> str:
    prev = value
    for _ in range(max_rounds):
        decoded = urllib.parse.unquote(prev)
        if decoded == prev:
            break
        prev = decoded
    return prev


def hostname_is_allowlisted(hostname: str, allowlisted_domains: set) -> bool:
    if not hostname:
        return False
    hostname = hostname.lower()
    for allowed in allowlisted_domains:
        if hostname == allowed or hostname.endswith("." + allowed):
            return True
    return False


def classify_redirect_target(raw_value: str, allowlisted_domains: set):
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

        if hostname_is_allowlisted(host, allowlisted_domains):
            if at_trick:
                return "suspicious", f"@ userinfo trick against allowlisted-looking netloc ({parsed.netloc})"
            return "benign", f"absolute URL to allowlisted host ({host})"
        else:
            reason = f"absolute URL to non-allowlisted external host ({host or 'unresolvable'})"
            if at_trick:
                reason += " [contains @ userinfo trick]"
            return "suspicious", reason

    return "review", f"unrecognized redirect value pattern: {stripped[:60]!r}"


def scan_log(path: str, allowlisted_domains: set):
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
                    verdict, reason = classify_redirect_target(val, allowlisted_domains)
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
    parser = argparse.ArgumentParser(description="Open Redirect detection rule against web access logs.")
    parser.add_argument("logfile", help="Path to the access log file to scan.")
    parser.add_argument("--profile", choices=["ugc", "juiceshop"],
                         help="Named allowlist profile (loads configs/allowlist_<profile>.txt).")
    parser.add_argument("--allowlist", help="Direct path to a custom allowlist file.")
    args = parser.parse_args()

    allowlisted_domains = load_allowlist(args)

    findings = scan_log(args.logfile, allowlisted_domains)
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
