"""Shared preprocessing: turn raw input into a Context every engine reads.

Only transforms here (parse, NFC, IDNA A-label/U-label, Public Suffix List); no verdicts.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from functools import cache
from urllib.parse import unquote

import idna
from publicsuffixlist import PublicSuffixList


@dataclass
class Context:
    raw: str
    input_type: str                 # domain / email / url / name
    text: str                       # what a reader sees: the name, or the host with valid A-labels as U-labels
    host: str = ""                  # host as written: NFC, ASCII lower-cased (DNS ignores ASCII case)
    local: str = ""                 # email local part
    userinfo: str = ""              # URL userinfo, percent-decoded ('paypal.com' in 'https://paypal.com@evil.com')
    a_label: str = ""               # the domain DNS sees; "" when no resolver accepts the host
    resolved: str = ""              # U-label form of a_label (or the IP address): the destination actually visited
    strict_error: idna.IDNAError | None = None   # why the host is not IDNA2008 as written
    lookup_error: idna.IDNAError | None = None   # why even UTS #46 lookup rejects it
    parse_status: str = "ok"        # ok / rejected (invalid input) / unsupported (input exceeds a limit)
    parse_reason: str = ""          # why, when not ok: a key of REASONS
    ip: str = ""                    # the IP address a URL host denotes, canonical ('127.0.0.1' for '0x7f.1')
    ip_obfuscated: bool = False     # that IPv4 address is written in another form (hex, octal, short, one number)


MAX_INPUT_LENGTH = 272   # code points the engines scan: a host, a name, a URL userinfo or an email local part
MAX_RAW_LENGTH = 8192    # code points of a whole input before normalization: bounds parsing, not scoring
SPECIAL_SCHEMES = {"http", "https", "ws", "wss", "ftp", "file"}   # WHATWG "special" URL schemes
SCHEME = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*):")
# WHATWG forbidden domain code points: checked after UTS #46 mapping, so fullwidth '＠' counts as '@'
FORBIDDEN_DOMAIN = set("\x00\t\n\r #/:<>?@[\\]^|%\x7f") | {chr(c) for c in range(0x20)}
REASONS = {
    "too_long": f"a host, name, user name or local part exceeds {MAX_INPUT_LENGTH} Unicode characters, "
                f"or the whole input exceeds {MAX_RAW_LENGTH}",
    "empty": "there is no host",
    "invalid_port": "the port is not a number from 0 to 65535",
    "forbidden_code_point": "the host contains a character a host cannot have (such as @ : / % or a space)",
    "disallowed_code_point": "the host contains a character IDNA does not allow",
    "invalid_punycode": "an 'xn--' label is not valid Punycode",
    "invalid_label": "a label starts with a combining mark",
    "invalid_joiner": "a zero-width joiner or non-joiner is outside the context IDNA allows",
    "invalid_bidi": "a label breaks the IDNA bidi rule",
    "invalid_ipv4": "the host ends in a number but is not a valid IPv4 address",
    "invalid_ipv6": "the host is not a valid IPv6 address in brackets",
}


def _strip_port(host: str) -> str:
    return re.sub(r":\d*$", "", host)


def _authority(raw: str) -> tuple[str, str] | None:
    """(scheme, authority) of a URL read as a browser reads it, or None when `raw` is not such a URL.
    Special schemes ignore any number of slashes or backslashes: 'https:/x', 'https:///x' and 'https:x' go to x."""
    match = SCHEME.match(raw)
    scheme = match.group(1).lower() if match else ""
    rest = raw[match.end():] if match else raw
    if scheme == "file":       # 'file:///etc/x' has an empty host, 'file://server/x' has one
        return scheme, re.split(r"[/\\?#]", rest[2:], maxsplit=1)[0] if re.match(r"[/\\]{2}", rest) else ""
    if scheme in SPECIAL_SCHEMES or (not match and raw.startswith("//")):   # '//host' is read as http
        return scheme or "http", re.split(r"[/\\?#]", rest.lstrip("/\\"), maxsplit=1)[0]
    if match and rest.startswith("//"):
        return scheme, re.split(r"[/?#]", rest[2:], maxsplit=1)[0]
    return None


def _split_port(hostport: str) -> tuple[str, str | None]:
    """The host ends at the first ':' outside an IPv6 '[...]'."""
    inside = False
    for i, ch in enumerate(hostport):
        inside = (inside or ch == "[") and ch != "]"
        if ch == ":" and not inside:
            return hostport[:i], hostport[i + 1:]
    return hostport, None


def _ipv4_number(part: str) -> int | None:
    base, digits = (16, part[2:]) if part[:2].lower() == "0x" else (8, part[1:]) if part[:1] == "0" and part[1:] \
        else (10, part)
    allowed = {16: "0123456789abcdef", 10: "0123456789", 8: "01234567"}[base]
    return int(digits or "0", base) if all(ch in allowed for ch in digits.lower()) else None


def _ipv4(host: str) -> str | None:
    """WHATWG IPv4 parser: '0x7f.1', '2130706433', '0177.0.0.1' and '127.1' are all 127.0.0.1."""
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts.pop()
    numbers = [_ipv4_number(part) if part else None for part in parts]
    if len(parts) > 4 or None in numbers or any(n > 255 for n in numbers[:-1]) \
            or numbers[-1] >= 256 ** (5 - len(numbers)):
        return None
    return str(ipaddress.IPv4Address(numbers[-1] + sum(n << 8 * (3 - i) for i, n in enumerate(numbers[:-1]))))


def _plain_host_reason(host: str) -> str:
    """Why a domain or email host is unusable as written: nothing to look up, or a control character (C0, DEL,
    C1) that no resolver accepts. The full URL host parser is not applied here: it would change how domains are
    scored ('a\u200db.com' would no longer be scored)."""
    if not host.rstrip("."):
        return "empty"
    return "forbidden_code_point" if any(unicodedata.category(ch) == "Cc" for ch in host) else ""


def _ends_in_number(host: str) -> bool:
    """Only one trailing empty label is dropped: 'foo.09..' is a domain, 'foo.09.' is an invalid IPv4."""
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts.pop()
    return bool(re.fullmatch(r"[0-9]+|0x[0-9a-f]*", parts[-1]))


def _parse_host(raw_host: str) -> tuple[str, str]:
    """WHATWG host parser for special schemes: ('' or a REASONS key, canonical IP or '')."""
    if raw_host.startswith("["):
        try:
            if raw_host.endswith("]") and "%" not in raw_host:   # no zone id ('[::%31]') in a URL
                return "", str(ipaddress.IPv6Address(raw_host[1:-1]))
        except ValueError:
            pass
        return "invalid_ipv6", ""
    host = unquote(raw_host)
    try:
        mapped = idna.uts46_remap(host, std3_rules=False, transitional=False)
    except idna.IDNAError:
        return "disallowed_code_point", ""
    if not mapped:
        return "empty", ""
    if FORBIDDEN_DOMAIN.intersection(mapped):
        return "forbidden_code_point", ""
    for label in mapped.split("."):
        if label.startswith("xn--"):
            try:
                label = label[4:].encode("ascii").decode("punycode")
            except (UnicodeError, ValueError):
                return "invalid_punycode", ""
        if label and unicodedata.category(label[0]).startswith("M"):
            return "invalid_label", ""
        if any(ch in "\u200c\u200d" and not idna.valid_contextj(label, i) for i, ch in enumerate(label)):
            return "invalid_joiner", ""
        try:
            idna.check_bidi(label)
        except idna.IDNABidiError:
            return "invalid_bidi", ""
    if _ends_in_number(mapped):
        ip = _ipv4(mapped)
        return ("", ip) if ip else ("invalid_ipv4", "")
    return "", ""


def classify(raw: str) -> tuple[str, str, str, str, str]:
    """Return (input_type, host_or_name, email_local_part_or_url_userinfo, parse_reason, ip).
    URLs are read the way browsers (WHATWG) do; parse_reason is '' unless a browser would refuse the input."""
    raw = unicodedata.normalize("NFC", raw.strip())
    if not raw:
        return "name", "", "", "empty", ""
    url = _authority(re.sub(r"[\t\n\r]", "", raw))   # browsers drop tabs and newlines anywhere in a URL
    if url:
        scheme, authority = url
        userinfo, _, hostport = authority.rpartition("@")   # the host follows the last '@'
        raw_host, port = _split_port(hostport)
        host = unquote(raw_host)   # .hostname would lower-case non-ASCII; browsers percent-decode the host
        if port is not None and not re.fullmatch(r"[0-9]*", port) or port and int(port) > 65535:
            reason, ip = "invalid_port", ""
        elif not raw_host:
            reason, ip = ("" if scheme == "file" else "empty"), ""
        elif scheme not in SPECIAL_SCHEMES:
            reason, ip = "", ""   # an opaque host: no IDNA, no IP parsing
        else:
            reason, ip = _parse_host(raw_host)
        return "url", host, unquote(userinfo), reason, ip
    if "@" in raw and " " not in raw:
        local, _, host = raw.rpartition("@")
        if re.search(r"[/?#\\]", host):   # 'paypal.com@evil.com/login' is a URL without a scheme, not an email
            return classify("http://" + raw)
        return "email", host, local, _plain_host_reason(host), ""
    if "." in raw and " " not in raw:
        host = _strip_port(re.split(r"[/?#]", raw, maxsplit=1)[0])   # 'paypal.com/login'
        return "domain", host, "", _plain_host_reason(host), ""
    return "name", raw, "", "", ""


def _shown(host: str) -> str:
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = idna.decode(label)
            except idna.IDNAError:
                pass  # not a real IDN: show it as written
        labels.append(label)
    return ".".join(labels)


def prepare(raw: str) -> Context:
    # A long URL is fine (tracking links, return URLs): only what the engines scan is bounded
    if len(raw) > MAX_RAW_LENGTH:
        return Context("", "unknown", "", parse_status="unsupported", parse_reason="too_long")
    input_type, target, before_at, reason, ip = classify(raw)
    if max(len(target), len(before_at)) > MAX_INPUT_LENGTH:
        return Context("", "unknown", "", parse_status="unsupported", parse_reason="too_long")
    status = "rejected" if reason else "ok"
    if input_type == "name":
        return Context(raw, input_type, target, parse_status=status, parse_reason=reason)
    host = "".join(ch.lower() if ch.isascii() else ch for ch in target).rstrip(".")
    email = input_type == "email"
    ctx = Context(raw, input_type, _shown(host), host=host,
                  local=before_at if email else "", userinfo="" if email else before_at,
                  parse_status=status, parse_reason=reason, ip=ip)
    if ip:   # an address, not a domain: no IDNA ('[::1]', '127.0.0.1')
        ctx.resolved, ctx.ip_obfuscated = ip, ":" not in ip and host != ip
        return ctx
    if not host or reason:
        return ctx
    try:
        ctx.a_label = idna.encode(host).decode("ascii")                  # strict RFC 5891, no mapping
    except idna.IDNAError as strict:
        ctx.strict_error = strict
        try:
            ctx.a_label = idna.encode(host, uts46=True).decode("ascii")   # browser lookup mapping
        except idna.IDNAError as error:
            ctx.lookup_error = error
            return ctx
    ctx.resolved = idna.decode(ctx.a_label)
    return ctx


@cache
def _psl() -> PublicSuffixList:
    return PublicSuffixList()  # bundled list incl. private suffixes (github.io, blogspot.com, ...)


def userinfo_domain(userinfo: str) -> str:
    """The domain a URL's userinfo pretends to be ('paypal.com' from 'paypal.com', 'paypal.com:x', the
    fullwidth 'paypal.com／' or a decoded 'paypal.com/login'), or "" when it does not end in a known public
    suffix ('john.doe', 'user')."""
    name = unicodedata.normalize("NFKC", userinfo).strip("/\\ ")
    name = re.split(r"[:/\\?#]", name, maxsplit=1)[0].lower().rstrip(".")
    if "." not in name or not _psl().privatesuffix(name, accept_unknown=False):
        return ""
    return _shown(name)


def registrable(host: str) -> tuple[str, str]:
    """Public Suffix List: ('paypal.com', 'paypal') from 'login.paypal.com',
    ('vietcombank.com.vn', 'vietcombank'), ('x.github.io', 'x')."""
    rd = _psl().privatesuffix(host) or host
    suffix = _psl().publicsuffix(rd)
    return rd, (rd[: -len(suffix) - 1] if suffix and rd != suffix else rd.split(".")[0])
