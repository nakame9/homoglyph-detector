"""Shared preprocessing: turn raw input into a Context every engine reads.

Only transforms here (parse, NFC, IDNA A-label/U-label, Public Suffix List); no verdicts.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import cache
from urllib.parse import unquote, urlsplit

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
    resolved: str = ""              # U-label form of a_label: the domain actually visited
    strict_error: idna.IDNAError | None = None   # why the host is not IDNA2008 as written
    lookup_error: idna.IDNAError | None = None   # why even UTS #46 lookup rejects it


SPECIAL_SCHEMES = {"http", "https", "ws", "wss", "ftp", "file"}   # WHATWG "special" URL schemes


def _strip_port(host: str) -> str:
    return re.sub(r":\d*$", "", host)


def classify(raw: str) -> tuple[str, str, str]:
    """Return (input_type, host_or_name, email_local_part_or_url_userinfo).
    URLs are read the way browsers (WHATWG) do."""
    raw = unicodedata.normalize("NFC", raw.strip())
    if "://" in raw or raw.startswith("//"):
        scheme = raw.split("://", 1)[0].lower() if "://" in raw else ""
        if not scheme or scheme in SPECIAL_SCHEMES:
            raw = raw.replace("\\", "/")   # 'https://evil.com\\@paypal.com' goes to evil.com in a browser
        try:
            netloc = urlsplit(raw if "://" in raw else "http:" + raw).netloc
        except ValueError:   # Python refuses netlocs that NFKC-normalise to '/', '@', ... or a stray '['
            netloc = re.split(r"[/?#]", raw.split("//", 1)[1], maxsplit=1)[0]
        # .hostname would lower-case non-ASCII; browsers percent-decode the host ('%2e' is a dot)
        userinfo, _, host = netloc.rpartition("@")
        return "url", _strip_port(unquote(host)), unquote(userinfo)
    if "@" in raw and " " not in raw:
        local, _, host = raw.rpartition("@")
        if re.search(r"[/?#\\]", host):   # 'paypal.com@evil.com/login' is a URL without a scheme, not an email
            return classify("http://" + raw)
        return "email", host, local
    if "." in raw and " " not in raw:
        return "domain", _strip_port(re.split(r"[/?#]", raw, maxsplit=1)[0]), ""   # 'paypal.com/login'
    return "name", raw, ""


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
    input_type, target, before_at = classify(raw)
    if input_type == "name":
        return Context(raw, input_type, target)
    host = "".join(ch.lower() if ch.isascii() else ch for ch in target).rstrip(".")
    email = input_type == "email"
    ctx = Context(raw, input_type, _shown(host), host=host,
                  local=before_at if email else "", userinfo="" if email else before_at)
    if not host:
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
    """The domain a URL's userinfo pretends to be ('paypal.com' from 'paypal.com', 'paypal.com:x' or the
    fullwidth 'paypal.com／'), or "" when it does not end in a known public suffix ('john.doe', 'user')."""
    name = unicodedata.normalize("NFKC", userinfo).split(":")[0].strip("/\\ ").lower().rstrip(".")
    return name if "." in name and _psl().privatesuffix(name, accept_unknown=False) else ""


def registrable(host: str) -> tuple[str, str]:
    """Public Suffix List: ('paypal.com', 'paypal') from 'login.paypal.com',
    ('vietcombank.com.vn', 'vietcombank'), ('x.github.io', 'x')."""
    rd = _psl().privatesuffix(host) or host
    suffix = _psl().publicsuffix(rd)
    return rd, (rd[: -len(suffix) - 1] if suffix and rd != suffix else rd.split(".")[0])
