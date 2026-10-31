# homoglyph-detector

Detect look-alike (homoglyph / IDN homograph) domains, emails, URLs and names — offline, zero dependencies.

**Technique: Unicode [UTS #39](https://www.unicode.org/reports/tr39/) Confusable Detection** — skeletons, confusable classification (single / mixed / whole-script), restriction levels, mixed numbers and hidden characters, implemented from the standard on the official Unicode 18 data files.

```
$ homoglyph-detector "pаypal.com" xn--80ak6aa92e.com rnicrosoft.com tiếngviệt.vn

🚨 MALICIOUS  pаypal.com  [domain]
    skeleton: paypal.corn
    level   : Minimally Restrictive
    - [medium] 'pаypal' mixes scripts: Cyrillic, Latin (level: Minimally Restrictive)
    - [medium] 'pаypal' renders like ASCII 'paypal' (mixed-script confusable)
    - [low] Position 1: 'а' U+0430 (Cyrillic) looks like 'a'
    - [critical] Impersonates PayPal: renders like 'paypal.com' (mixed-script confusable)

🚨 MALICIOUS  xn--80ak6aa92e.com  [domain]
    decoded : аррӏе.com
    skeleton: apple.corn
    level   : Single Script
    ...
    - [critical] Impersonates Apple: renders like 'apple.com' (whole-script confusable)

🚨 MALICIOUS  rnicrosoft.com  [domain]
    skeleton: rnicrosoft.corn
    level   : ASCII-Only
    - [critical] Impersonates Microsoft: renders like 'microsoft.com' (single-script confusable)

✅ SAFE       tiếngviệt.vn  [domain]
    skeleton: tiếngviệt.vn
    level   : Single Script
```

## Why

Attackers register domains that *look* like a brand: `pаypal.com` (Cyrillic `а`), `аррӏе.com` (every letter Cyrillic), `rnicrosoft.com` (`rn` ≈ `m`), `paypa1.com`, `pay<U+200B>pal.com` (hidden zero-width space). Browsers already show mixed-script domains as `xn--…`, but **whole-script** look-alikes, pure-ASCII tricks and invisible characters still get through, and filters that compare strings byte-by-byte miss all of them.

ATT&CK: [T1583.001 Acquire Infrastructure: Domains](https://attack.mitre.org/techniques/T1583/001/), used for [T1566 Phishing](https://attack.mitre.org/techniques/T1566/).

## Technique: Unicode UTS #39 Confusable Detection

[UTS #39 *Unicode Security Mechanisms*](https://www.unicode.org/reports/tr39/) is the standard browsers, registries and ICU's SpoofChecker use against look-alike text. This project implements its detection mechanisms directly, in [`unicode_data.py`](src/homoglyph_detector/unicode_data.py):

| UTS #39 | What it does | Function | Example |
|---|---|---|---|
| §4 Confusable Detection — *skeleton* | NFD → drop default-ignorables → map each char to its prototype from `confusables.txt` → NFD. Two strings are confusable when their skeletons are equal. | `skeleton()` | `skeleton("pаypal") == skeleton("paypa1") == skeleton("paypal")` |
| §4 — *single-script confusables* | Confusable, and the two strings together still fit one script | `confusable_type()` | `rnicrosoft` ↔ `microsoft` |
| §4 — *mixed-script confusables* | Confusable, but they need more than one script | `confusable_type()` | `pаypal` ↔ `paypal` |
| §4 — *whole-script confusables* | Mixed-script confusables where **each** string is single-script — the hardest kind to spot, browsers show it decoded | `confusable_type()` | `аррӏе` (Cyrillic) ↔ `apple` |
| §5.1 Mixed-Script Detection | *Resolved script set*: intersection of every character's Script_Extensions, augmented for CJK (Han + Hiragana = Japanese). Empty = mixed-script. | `resolved_script_set()`, `is_single_script()` | `東京とうきょう` is single-script (Japanese) |
| §5.2 Restriction Levels | ASCII-Only → Single Script → Highly → Moderately → Minimally Restrictive → Unrestricted, using the General Security Profile (`IdentifierStatus.txt`) | `restriction_level()` | `abcلعربية` = Moderately, `pаypal` = Minimally, `pay<U+200B>pal` = Unrestricted |
| §5.3 Mixed-Number Detection | Decimal digits from different numbering systems | `numbering_systems()` | `ab1٣` (ASCII 1 + Arabic-Indic 3) |
| §5.4 Optional Detection — *hidden overlays* | The same nonspacing mark stacked twice on one letter | `repeated_marks()` | `café́` |
| Default-ignorable characters | Characters that render as nothing (`Default_Ignorable_Code_Point`, from `DerivedCoreProperties.txt`): removed from the skeleton and reported | `is_default_ignorable()` | `pay<U+200B>pal`, `pay<U+00AD>pal` |
| Bidi controls | `Bidi_Control` characters (from `PropList.txt`) reorder how text is displayed — the [Trojan Source](https://trojansource.codes/) / RLO file-name trick. Reported as **high** | `is_bidi_control()` | `invoice<U+202E>fdp.exe` shows as `invoiceexe.pdf` |

On top of the standard, the analyzer adds what a SOC needs: punycode decoding with invalid-IDN detection, brand matching on skeletons with an allow-list of official domains, a severity per finding and a verdict. The text report prints hidden and bidi characters as `<U+XXXX>`, so a malicious input cannot rearrange the report itself.

## Unicode data: official files, updates and compatibility tests

The tool never hand-builds a Unicode table: every mapping and property comes from the official Unicode data files, bundled in `src/homoglyph_detector/data/` (all **Unicode 18.0.0**, check with `homoglyph-detector --version`).

| File | Source | Used for |
|---|---|---|
| `confusables.txt` | UTS #39 security data | skeleton |
| `IdentifierStatus.txt` | UTS #39 security data | General Security Profile (restriction levels) |
| `Scripts.txt`, `ScriptExtensions.txt` | UCD | scripts, resolved script sets |
| `ScriptAliases.txt` | UCD `PropertyValueAliases.txt`, `sc` lines only | script code → name |
| `DefaultIgnorable.txt` | UCD `DerivedCoreProperties.txt`, `Default_Ignorable_Code_Point` only | invisible characters |
| `BidiControl.txt` | UCD `PropList.txt`, `Bidi_Control` only | bidi controls |

**Updating** — one command downloads every file from unicode.org, refuses to write anything unless all of them report the same Unicode version, and extracts the needed properties:

```bash
python scripts/update_unicode_data.py                    # latest release
python scripts/update_unicode_data.py --version 18.0.0   # a specific release
pytest                                                   # then the compatibility tests
```

**Compatibility tests** (`tests/test_unicode_data.py`) fail if an update breaks an assumption: files on different versions, a confusable prototype that is itself remapped, a script code without a name, a script name used by the spec that disappeared, a property file in a new format, or a well-known confusable that stopped matching.

**Monthly check** — the `Unicode data` GitHub Actions workflow runs the update script and the tests every month and fails when new data is available, so you get notified.

**Self-check** — a test scans this repository with the tool's own bidi / default-ignorable detection, so no Trojan-Source-style character can slip into the code or docs.

## How it works

1. **Parse** the input: domain, email (`user@host`), URL (`https://host/...`) or free-text name.
2. **Decode punycode** (`xn--…`). Labels that decode to nothing, to plain ASCII or to invisible/control characters are flagged as invalid IDNs.
3. **UTS #39 checks** per domain label / word: restriction level and mixed scripts, whole-label look-alike of ASCII (with its confusable type), mixed numbers, hidden overlays. Then per character: bidi controls (high), default-ignorable characters, confusable characters (position, code point, script), characters outside the identifier profile, and compatibility forms such as fullwidth `ｐａｙｐａｌ`.
4. **Brand matching** against `data/brands.json`, comparing skeletons on *both* sides:
   - official domain or subdomain → allow-listed;
   - registrable domain has the same skeleton as an official domain → **critical**;
   - name label has the same skeleton as a brand keyword → high (homograph) / medium (brand name on an unofficial domain);
   - one edit away from a keyword, or keyword inside the host → medium.
5. **Verdict** = worst finding: `SAFE` (info/low), `SUSPICIOUS` (medium), `MALICIOUS` (high/critical).

The skeleton is lower-cased because domains are case-insensitive, so `0` (prototype `O`) collides with `o`. It can look odd — `m` maps to `rn`, so `paypal.com` → `paypal.corn` — that is expected.

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
from homoglyph_detector import analyze, skeleton, confusable_type, restriction_level

report = analyze("pаypal.com")
report.verdict                     # 'MALICIOUS'
report.restriction_level           # 'Minimally Restrictive'
report.to_dict()                   # JSON-ready
confusable_type("аррӏе", "apple")  # 'whole-script'
restriction_level("東京とうきょう")  # 'Single Script'
```

## How is this different from dnstwist?

[dnstwist](https://github.com/elceef/dnstwist) *generates* look-alike permutations of **your** domain so you can monitor them. This tool goes the other way: it takes **any** input — a sender address, a URL from a log, a username — and tells you whether it imitates something. The two complement each other.

## Project layout

```
src/homoglyph_detector/
  unicode_data.py   UTS #39: skeleton, scripts, restriction levels, confusable types, properties
  analyzer.py       parsing, punycode, checks, brand matching, verdict
  cli.py            command line
  data/             official Unicode data files (see above) + brands.json (edit freely)
scripts/
  update_unicode_data.py   refresh the Unicode data files from unicode.org
tests/
  test_analyzer.py         malicious / suspicious / safe cases, one test per UTS #39 mechanism
  test_unicode_data.py     compatibility checks for the bundled Unicode data
.github/workflows/
  ci.yml                   tests on every push
  unicode-data.yml         monthly check for new Unicode data
```

## Roadmap

- [x] v0.1 — punycode, skeleton, brand matching with allow-list, CLI, JSON, tests, CI
- [x] v0.2 — full UTS #39 confusable detection: Script_Extensions, resolved script sets, restriction levels, single/mixed/whole-script confusable types, mixed numbers, invisible characters, hidden overlays
- [x] v0.3 — official Default_Ignorable and Bidi_Control data, bidi control detection, update script with version check, data compatibility tests, monthly data workflow, safe report output
- [ ] Real public-suffix handling (`tldextract`) instead of the built-in guess for `*.com.vn`-style TLDs
- [ ] HTML report for batch runs
- [ ] `.eml` mode: check From / Reply-To / Return-Path and every link in a phishing email
- [ ] Optional online checks: DNS resolution, domain age (RDAP), VirusTotal — off by default
- [ ] Small web UI (Streamlit) for demos

## Data & license

Code: MIT (see `LICENSE`). The files in `src/homoglyph_detector/data/` except `brands.json` are © Unicode, Inc., distributed under the [Unicode License v3](https://www.unicode.org/license.txt) — Unicode 18.0.0. Refresh them with `python scripts/update_unicode_data.py`.
