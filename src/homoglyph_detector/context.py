"""Shared preprocessing: turn raw input into a Context every engine reads.

Only transforms here (parse, NFC, IDNA A-label/U-label, Public Suffix List); no verdicts.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import cache
from urllib.parse import urlsplit

import idna
from publicsuffixlist import PublicSuffixList


@dataclass
class Context:
    raw: str
    input_type: str                 # domain / email / url / name
    text: str                       # what a reader sees: the name, or the host with valid A-labels as U-labels
    host: str = ""                  # host as written: NFC, ASCII lower-cased (DNS ignores ASCII case)
    local: str = ""                 # email local part
    a_label: str = ""               # the domain DNS sees; "" when no resolver accepts the host
    resolved: str = ""              # U-label form of a_label: the domain actually visited
    strict_error: idna.IDNAError | None = None   # why the host is not IDNA2008 as written
    lookup_error: idna.IDNAError | None = None   # why even UTS #46 lookup rejects it


def classify(raw: str) -> tuple[str, str, str]:
    """Return (input_type, host_or_name, email_local_part)."""
    raw = unicodedata.normalize("NFC", raw.strip())
    if "://" in raw:
        # .hostname would lower-case non-ASCII too; only drop user-info and port.
        return "url", re.sub(r":\d*$", "", urlsplit(raw).netloc.rpartition("@")[2]), ""
    if "@" in raw and " " not in raw:
        local, _, host = raw.rpartition("@")
        return "email", host, local
    if "." in raw and " " not in raw:
        return "domain", raw, ""
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
    input_type, target, local = classify(raw)
    if input_type == "name":
        return Context(raw, input_type, target)
    host = "".join(ch.lower() if ch.isascii() else ch for ch in target).rstrip(".")
    ctx = Context(raw, input_type, _shown(host), host=host, local=local)
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


def registrable(host: str) -> tuple[str, str]:
    """Public Suffix List: ('paypal.com', 'paypal') from 'login.paypal.com',
    ('vietcombank.com.vn', 'vietcombank'), ('x.github.io', 'x')."""
    rd = _psl().privatesuffix(host) or host
    suffix = _psl().publicsuffix(rd)
    return rd, (rd[: -len(suffix) - 1] if suffix and rd != suffix else rd.split(".")[0])
