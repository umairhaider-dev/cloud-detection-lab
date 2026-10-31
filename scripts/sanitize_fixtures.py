#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Account ID inside an ARN: arn:partition:service:region:ACCOUNT:resource
ARN_ACCOUNT_RE = re.compile(r"arn:aws[\w-]*:[\w-]*:[\w-]*:(\d{12})(?=:|/|$)")

# Access key IDs (AKIA/ASIA) and IAM unique IDs (AROA = role, AIDA = user, ...).
AWS_ID_PREFIXES = ("AKIA", "ASIA", "ABIA", "ACCA", "AROA", "AIDA", "AIPA",
                   "ANPA", "ANVA", "AGPA", "APKA", "ASCA")
AWS_ID_RE = re.compile(r"(?<![A-Za-z0-9])((?:%s)[A-Z0-9]{12,20})(?![A-Za-z0-9])"
                       % "|".join(AWS_ID_PREFIXES))

# IPv4. The boundaries skip version strings in user agents,
# e.g. "Linux/5.15.153.1-microsoft-standard-WSL2" is not an IP.
IPV4_RE = re.compile(r"(?<![\w./-])((?:\d{1,3}\.){3}\d{1,3})(?![\w-]|\.\d)")
# IPv6 candidates; each one is validated with the ipaddress module.
IPV6_RE = re.compile(r"(?<![0-9A-Za-z:.])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![0-9A-Za-z:])")

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# Keys whose values are secrets regardless of content.
SECRET_KEYS = {"sessiontoken", "secretaccesskey", "password", "passworddata",
               "privatekey", "keymaterial", "x-amz-security-token"}

DOC_V4_NETS = [ipaddress.ip_network(n) for n in
               ("203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24")]
DOC_V6_NET = ipaddress.ip_network("2001:db8::/32")
ACCOUNT_PLACEHOLDERS = ["111122223333", "444455556666", "777788889999"]
OWN_PLACEHOLDER = "444455556666"   # own account always maps here (%own_account% in tests)


def is_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def is_ipv6(s: str) -> bool:
    try:
        ipaddress.IPv6Address(s)
    except ValueError:
        return False
    return sum(1 for part in s.split(":") if part) >= 2  # skip "::", "::1"-like noise


def keep_ip(s: str) -> bool:
    """IPs that are already safe: documentation ranges and loopback/unspecified."""
    ip = ipaddress.ip_address(s)
    if ip.is_loopback or ip.is_unspecified:
        return True
    if ip.version == 4:
        return any(ip in n for n in DOC_V4_NETS)
    return ip in DOC_V6_NET


# ---------------------------------------------------------------------------
# Pass 1: discover every value that needs a placeholder
# ---------------------------------------------------------------------------

class Discovery:
    def __init__(self, known_accounts: list[str]):
        self.accounts: set[str] = set(known_accounts)
        self.aws_ids: set[str] = set()
        self.ipv4: set[str] = set()
        self.ipv6: set[str] = set()
        self.emails: set[str] = set()

    def walk(self, node, key: str | None = None) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                self.scan_string(k)
                self.walk(v, k)
        elif isinstance(node, list):
            for item in node:
                self.walk(item, key)
        elif isinstance(node, str):
            if key in ("accountId", "recipientAccountId", "vpcEndpointAccountId", "userId") \
                    and re.fullmatch(r"\d{12}", node):
                self.accounts.add(node)
            self.scan_string(node)

    def scan_string(self, s: str) -> None:
        self.accounts.update(ARN_ACCOUNT_RE.findall(s))
        for m in AWS_ID_RE.findall(s):
            if not m.endswith("EXAMPLE"):
                self.aws_ids.add(m)
        for m in IPV4_RE.findall(s):
            if is_ipv4(m) and not keep_ip(m):
                self.ipv4.add(m)
        for m in IPV6_RE.findall(s):
            if is_ipv6(m) and not keep_ip(m):
                self.ipv6.add(m)
        for m in EMAIL_RE.findall(s):
            if not m.lower().endswith("@example.com"):
                self.emails.add(m)


def build_mapping(d: Discovery, redact: list[str], own: str | None = None) -> dict[str, dict[str, str]]:
    """Assign placeholders in sorted order so re-runs give identical output."""
    m: dict[str, dict[str, str]] = {}

    # Own account is pinned; outside accounts get the rest in sorted order,
    # so re-runs stay identical and "own vs outside" is always distinguishable.
    m["account"] = {}
    if own:
        m["account"][own] = OWN_PLACEHOLDER
    pool = [p for p in ACCOUNT_PLACEHOLDERS if p != OWN_PLACEHOLDER]
    others = sorted(d.accounts - set(ACCOUNT_PLACEHOLDERS) - {own})
    for i, acct in enumerate(others):
        m["account"][acct] = pool[i] if i < len(pool) else f"{i + 1:012d}"

    m["aws_id"] = {}
    counters: dict[str, int] = {}
    for real in sorted(d.aws_ids):
        prefix = real[:4]
        counters[prefix] = counters.get(prefix, 0) + 1
        width = len(real) - 4 - len("EXAMPLE")  # keep the original length
        m["aws_id"][real] = f"{prefix}{counters[prefix]:0{width}d}EXAMPLE"

    v4_pool = [str(h) for net in DOC_V4_NETS for h in net.hosts()]
    if len(d.ipv4) > len(v4_pool):
        raise SystemExit(f"Too many distinct IPv4 addresses ({len(d.ipv4)})")
    m["ipv4"] = {real: v4_pool[i] for i, real in
                 enumerate(sorted(d.ipv4, key=lambda s: ipaddress.IPv4Address(s)))}
    m["ipv6"] = {real: f"2001:db8::{i + 1:x}" for i, real in
                 enumerate(sorted(d.ipv6, key=lambda s: ipaddress.IPv6Address(s)))}
    m["email"] = {real: f"user{i + 1}@example.com" for i, real in
                  enumerate(sorted(d.emails, key=str.lower))}
    m["redact"] = {real: f"redacted{i + 1}" for i, real in
                   enumerate(sorted({r for r in redact if r}, key=len, reverse=True))}
    return m


# ---------------------------------------------------------------------------
# Pass 2: replace
# ---------------------------------------------------------------------------

class Replacer:
    def __init__(self, mapping: dict[str, dict[str, str]]):
        self.m = mapping
        lower_email = {k.lower(): v for k, v in mapping["email"].items()}
        self.lower_email = lower_email
        self.redact_re = None
        if mapping["redact"]:
            alts = "|".join(re.escape(r) for r in mapping["redact"])  # longest first
            self.redact_re = re.compile(alts, re.IGNORECASE)
            self.redact_lookup = {k.lower(): v for k, v in mapping["redact"].items()}
        # Once an IP is known to be real, replace it in any context, not only
        # where the discovery pattern would have spotted it.
        self.known_ip_re = None
        self.ip_table = {**mapping["ipv4"], **mapping["ipv6"]}
        if self.ip_table:
            alts = "|".join(re.escape(ip) for ip in sorted(self.ip_table, key=len, reverse=True))
            self.known_ip_re = re.compile(r"(?<![0-9A-Fa-f.:])(%s)(?![0-9A-Fa-f:]|\.\d)" % alts)

    def sub(self, pattern: re.Pattern, table: dict[str, str], s: str) -> str:
        if not table:
            return s
        return pattern.sub(lambda mt: table.get(mt.group(1) if mt.groups() else mt.group(0),
                                                mt.group(0)), s)

    def string(self, s: str) -> str:
        s = EMAIL_RE.sub(lambda mt: self.lower_email.get(mt.group(0).lower(), mt.group(0)), s)
        if self.redact_re:
            s = self.redact_re.sub(lambda mt: self.redact_lookup[mt.group(0).lower()], s)
        s = self.sub(AWS_ID_RE, self.m["aws_id"], s)
        # Known account IDs are replaced wherever they occur, even glued to other
        # digits (e.g. inside an S3 key or a numeric ID). Safety beats fidelity here.
        for real, placeholder in self.m["account"].items():
            s = s.replace(real, placeholder)
        if self.known_ip_re:
            s = self.known_ip_re.sub(lambda mt: self.ip_table[mt.group(1)], s)
        return s

    def walk(self, node, key: str | None = None):
        if isinstance(node, dict):
            return {self.string(k): self.walk(v, k) for k, v in node.items()}
        if isinstance(node, list):
            return [self.walk(item, key) for item in node]
        if isinstance(node, str):
            if key is not None and key.lower() in SECRET_KEYS:
                return "REDACTED"
            return self.string(node)
        if isinstance(node, int) and not isinstance(node, bool):
            # An account ID stored as a JSON number instead of a string.
            replaced = self.string(str(node))
            return int(replaced) if replaced.isdigit() else replaced
        return node


def locate(rendered: dict[Path, str], needle: str) -> list[str]:
    """Where a leaked value sits: file:line and JSON path, without printing the record."""
    found: list[str] = []

    def walk(node, path: str, where: str):
        if isinstance(node, dict):
            for k, v in node.items():
                if needle in str(k):
                    found.append(f"{where} key {path}.{k}")
                walk(v, f"{path}.{k}", where)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, f"{path}[{i}]", where)
        elif needle.lower() in str(node).lower():
            kind = "" if isinstance(node, str) else f" (JSON {type(node).__name__})"
            found.append(f"{where} {path}{kind}")

    for out, text in rendered.items():
        for n, line in enumerate(text.splitlines(), 1):
            walk(json.loads(line), "$", f"{out}:{n}")
    return found


# ---------------------------------------------------------------------------
# Leak check on the final serialized text
# ---------------------------------------------------------------------------

def leak_check(text: str, mapping: dict, known_accounts: list[str],
               redact: list[str]) -> list[str]:
    problems: list[str] = []
    lowered = text.lower()

    for category, table in mapping.items():
        for real in table:
            if category in ("email", "redact"):
                found = real.lower() in lowered
            elif category in ("ipv4", "ipv6"):
                found = re.search(r"(?<![0-9A-Fa-f.:])%s(?![0-9A-Fa-f:]|\.\d)"
                                  % re.escape(real), text) is not None
            else:
                found = real in text
            if found:
                problems.append(f"original {category} value still present: {real}")

    for acct in known_accounts:
        if acct and acct in text:
            problems.append(f"--account-id value still present: {acct}")
    for word in redact:
        if word and word.lower() in lowered:
            problems.append(f"--redact value still present: {word}")

    for m in AWS_ID_RE.findall(text):
        if not m.endswith("EXAMPLE"):
            problems.append(f"AWS key/IAM ID not replaced: {m}")
    for m in IPV4_RE.findall(text):
        if is_ipv4(m) and not keep_ip(m):
            problems.append(f"IPv4 not replaced: {m}")
    for m in IPV6_RE.findall(text):
        if is_ipv6(m) and not keep_ip(m):
            problems.append(f"IPv6 not replaced: {m}")
    for m in EMAIL_RE.findall(text):
        if not m.lower().endswith("@example.com"):
            problems.append(f"email not replaced: {m}")
    return sorted(set(problems))


# ---------------------------------------------------------------------------

def load_jsonl(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", type=Path, default=Path("captures/raw/extracted"))
    ap.add_argument("--output", type=Path, default=Path("captures/fixtures"))
    ap.add_argument("--account-id", action="append", default=[],
                    help="real account ID that must not appear in the output (repeatable)")
    ap.add_argument("--redact", action="append", default=[],
                    help="extra literal string to replace, case-insensitive, e.g. your "
                         "username or hostname (repeatable)")
    ap.add_argument("--map-out", type=Path,
                    help="write the real->placeholder mapping here (must be under captures/raw/)")
    args = ap.parse_args()

    if args.map_out and "raw" not in args.map_out.parts:
        print("Refusing: --map-out contains your real values; put it under captures/raw/.",
              file=sys.stderr)
        return 2
    if "raw" in args.output.parts:
        print("Refusing: --output is inside captures/raw/, which git ignores. "
              "Sanitized fixtures belong somewhere you will commit, e.g. captures/fixtures.",
              file=sys.stderr)
        return 2

    inputs = sorted(args.input.rglob("*.jsonl"))
    if not inputs:
        print(f"No .jsonl files under {args.input}. Run extract_fixtures.py first.",
              file=sys.stderr)
        return 1
    data = {p: load_jsonl(p) for p in inputs}

    # Pass 1 over every file, so placeholders are consistent across files.
    disc = Discovery(args.account_id)
    for records in data.values():
        for rec in records:
            disc.walk(rec)
    mapping = build_mapping(disc, args.redact, args.account_id[0] if args.account_id else None)

    # Pass 2 in memory.
    rep = Replacer(mapping)
    rendered: dict[Path, str] = {}
    for path, records in data.items():
        lines = [json.dumps(rep.walk(rec), sort_keys=True) for rec in records]
        rendered[args.output / path.relative_to(args.input)] = "\n".join(lines) + "\n"

    # Leak check BEFORE writing anything.
    problems = leak_check("\n".join(rendered.values()), mapping,
                          args.account_id, args.redact)
    if problems:
        print("LEAK CHECK FAILED, nothing written:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        needles = set(args.account_id) | set(args.redact)
        for table in mapping.values():
            needles.update(table)
        all_text = "\n".join(rendered.values()).lower()
        for needle in sorted(n for n in needles if n and n.lower() in all_text):
            spots = locate(rendered, needle)
            print(f"\n  Found {needle} at {len(spots)} place(s):", file=sys.stderr)
            for spot in spots[:15]:
                print(f"    {spot}", file=sys.stderr)
        return 1

    for out, text in rendered.items():
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")

    if args.map_out:
        args.map_out.parent.mkdir(parents=True, exist_ok=True)
        args.map_out.write_text(json.dumps(mapping, indent=2, sort_keys=True) + "\n")

    # ---- Summary -----------------------------------------------------------
    print("Leak check passed. Replaced:")
    for category in ("account", "aws_id", "ipv4", "ipv6", "email", "redact"):
        print(f"  {category:8} {len(mapping[category])} distinct value(s)")
    print("\nWrote:")
    for out in rendered:
        print(f"  {out}  ({rendered[out].count(chr(10))} records)")

    # Things a regex cannot judge. Eyeball these before committing.
    identities, agents = set(), set()
    for text in rendered.values():
        for line in text.splitlines():
            rec = json.loads(line)
            ui = rec.get("userIdentity") or {}
            identities.add(ui.get("arn") or ui.get("invokedBy") or ui.get("type"))
            agents.add(rec.get("userAgent"))
    print("\nReview by eye: identities (role session names can contain your name):")
    for i in sorted(x for x in identities if x):
        print(f"  {i}")
    print("\nReview by eye: user agents (can contain your hostname or OS user):")
    for a in sorted(x for x in agents if x):
        print(f"  {a}")
    print("\nIf anything above identifies you, re-run with --redact <that text>.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
