# homoglyph-detector

Detect look-alike (homoglyph / IDN homograph) domains, emails, URLs and names — offline, zero dependencies, based on the Unicode [UTS #39](https://www.unicode.org/reports/tr39/) confusables data.

```
$ homoglyph-detector "pаypal.com" xn--80ak6aa92e.com rnicrosoft.com tiếngviệt.vn

🚨 MALICIOUS  pаypal.com  [domain]
    skeleton: paypal.corn
    - [medium] 'pаypal' mixes scripts: Cyrillic, Latin
    - [medium] 'pаypal' renders like ASCII 'paypal'
    - [low] Position 1: 'а' U+0430 (Cyrillic) looks like 'a'
    - [critical] Impersonates PayPal: renders like 'paypal.com'

🚨 MALICIOUS  xn--80ak6aa92e.com  [domain]
    decoded : аррӏе.com
    ...
    - [critical] Impersonates Apple: renders like 'apple.com'

🚨 MALICIOUS  rnicrosoft.com  [domain]
    skeleton: rnicrosoft.corn
    - [critical] Impersonates Microsoft: renders like 'microsoft.com'

✅ SAFE       tiếngviệt.vn  [domain]
```

## Why

Attackers register domains that *look* like a brand: `pаypal.com` (Cyrillic `а`), `аррӏе.com` (every letter Cyrillic), `rnicrosoft.com` (`rn` ≈ `m`), `paypa1.com`. Browsers already show mixed-script domains as `xn--…`, but **whole-script** look-alikes and pure-ASCII tricks still get through, and filters that compare strings byte-by-byte miss all of them.

ATT&CK: [T1583.001 Acquire Infrastructure: Domains](https://attack.mitre.org/techniques/T1583/001/), used for [T1566 Phishing](https://attack.mitre.org/techniques/T1566/).

## How it works

1. **Parse** the input: domain, email (`user@host`), URL (`https://host/...`) or free-text name.
2. **Decode punycode** (`xn--…`). Labels that decode to nothing, to plain ASCII or to invisible/control characters are flagged as invalid IDNs.
3. **Character checks** per label:
   - *mixed script* (e.g. Latin + Cyrillic), allowing normal combinations such as Han + Hiragana;
   - *whole-script look-alike*: a non-ASCII label whose skeleton is plain ASCII (`аррӏе` → `apple`);
   - each confusable character, with position, code point and script;
   - compatibility forms such as fullwidth `ｐａｙｐａｌ`.
4. **Skeleton** (UTS #39): `NFD → map every char to its prototype → NFD`, then lower-cased because domains are case-insensitive. Two strings that look the same get the same skeleton. Note the skeleton itself can look odd — `m` maps to `rn`, so `paypal.com` → `paypal.corn` — that is expected.
5. **Brand matching** against `data/brands.json`, comparing skeletons on *both* sides:
   - official domain or subdomain → allow-listed;
   - registrable domain has the same skeleton as an official domain → **critical**;
   - name label has the same skeleton as a brand keyword → high (homograph) / medium (brand name on an unofficial domain);
   - one edit away from a keyword, or keyword inside the host → medium.
6. **Verdict** = worst finding: `SAFE` (info/low), `SUSPICIOUS` (medium), `MALICIOUS` (high/critical).

Vietnamese text is a first-class test case: `tiếngviệt.vn` and `Nguyễn Văn A` are Latin with diacritics and must not be flagged.

## Install & use

```bash
pip install -e .            # or: pip install -e ".[dev]" for pytest

homoglyph-detector paypa1.com "user@pаypal.com" "https://аpple.com/login"
homoglyph-detector -f examples/sample_domains.txt
cat domains.txt | homoglyph-detector -f -
homoglyph-detector g00gle.com --json
homoglyph-detector suspicious.com --brands my_brands.json
python -m homoglyph_detector ...   # same thing
```

Exit code: `0` all safe, `1` something suspicious, `2` something malicious — handy in scripts and CI.

As a library:

```python
from homoglyph_detector import analyze, skeleton

report = analyze("pаypal.com")
report.verdict            # 'MALICIOUS'
report.to_dict()          # JSON-ready
skeleton("pаypal") == skeleton("paypal")   # True
```

## How is this different from dnstwist?

[dnstwist](https://github.com/elceef/dnstwist) *generates* look-alike permutations of **your** domain so you can monitor them. This tool goes the other way: it takes **any** input — a sender address, a URL from a log, a username — and tells you whether it imitates something. The two complement each other.

## Project layout

```
src/homoglyph_detector/
  unicode_data.py   skeleton() and script_of() from the Unicode data files
  analyzer.py       parsing, checks, brand matching, verdict
  cli.py            command line
  data/
    confusables.txt  UTS #39 confusables, Unicode 18.0.0
    Scripts.txt      Unicode script property, Unicode 18.0.0
    brands.json      brands to protect — edit freely
tests/              pytest suite (malicious / suspicious / safe cases)
```

## Roadmap

- [x] v0.1 — punycode, skeleton, mixed/whole-script, brand matching with allow-list, CLI, JSON, tests, CI
- [ ] Real public-suffix handling (`tldextract`) instead of the built-in guess for `*.com.vn`-style TLDs
- [ ] Flag invisible characters (zero-width space/joiner) anywhere in the input
- [ ] Use Script_Extensions for characters shared between scripts
- [ ] HTML report for batch runs
- [ ] `.eml` mode: check From / Reply-To / Return-Path and every link in a phishing email
- [ ] Optional online checks: DNS resolution, domain age (RDAP), VirusTotal — off by default
- [ ] Small web UI (Streamlit) for demos

## Data & license

Code: MIT (see `LICENSE`). `confusables.txt` and `Scripts.txt` are © Unicode, Inc., distributed under the [Unicode License v3](https://www.unicode.org/license.txt). To update them, replace the two files with the latest versions from `https://www.unicode.org/Public/security/latest/confusables.txt` and `https://www.unicode.org/Public/UCD/latest/ucd/Scripts.txt`.
