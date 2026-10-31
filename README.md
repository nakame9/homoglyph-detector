# homoglyph-detector

Detect look-alike (homoglyph / IDN homograph) domains, emails, URLs and names — offline, two small pure-Python dependencies.

**Techniques**
- **Unicode [UTS #39](https://www.unicode.org/reports/tr39/) Confusable Detection** — skeletons, single / mixed / whole-script confusables, restriction levels, mixed numbers, bidi controls and default-ignorable characters, on the official Unicode 18 data files.
- **ASCII Visual Confusable Detection** — look-alikes made only of ordinary characters: single (`5hopee`, `paypai`) and multi-character substitutions (`vvhatsapp`, `clropbox`, `nnicrosoft`) with a visual similarity score.
- **IDNA2008 validation** ([RFC 5890–5893](https://www.rfc-editor.org/rfc/rfc5891)) with [UTS #46](https://www.unicode.org/reports/tr46/) lookup mapping via [`idna`](https://pypi.org/project/idna/), and **Public Suffix List** parsing via [`publicsuffixlist`](https://pypi.org/project/publicsuffixlist/).

```
$ homoglyph-detector "pаypal.com" xn--80ak6aa92e.com rnicrosoft.com "ｐａｙｐａｌ.com" tiếngviệt.vn

🚨 MALICIOUS  pаypal.com  [domain]
    a-label : xn--pypal-4ve.com
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
    - [low] A-label 'xn--80ak6aa92e' is the U-label 'аррӏе'
    ...
    - [critical] Impersonates Apple: renders like 'apple.com' (whole-script confusable)

🚨 MALICIOUS  rnicrosoft.com  [domain]
    level   : ASCII-Only
    - [critical] Impersonates Microsoft: renders like 'microsoft.com' (single-script confusable)

⚠️  SUSPICIOUS ｐａｙｐａｌ.com  [domain]
    a-label : paypal.com
    - [low] Not valid IDNA2008 as written (Codepoint U+FF50 ... not allowed); browsers map it to 'paypal.com'
    - [medium] Contains compatibility characters (e.g. fullwidth) that normalise to other text
    ...
    - [info] 'paypal.com' is an official brand domain

✅ SAFE       tiếngviệt.vn  [domain]
    a-label : xn--tingvit-5t4cyc.vn
    level   : Single Script
```

The fullwidth case shows why the pipeline separates *what the reader sees* from *what is resolved*: a browser maps `ｐａｙｐａｌ.com` to the real `paypal.com`, so it is obfuscation (suspicious), not a fake domain (malicious).

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

## Technique: ASCII Visual Confusable Detection

Many phishing domains use no Unicode at all. UTS #39 only lists pairs that look *identical* (`0`/`o`, `1`/`l`, `m`/`rn` among domain characters), so `5hopee` or `vvhatsapp` are not confusable in the standard sense — but a reader in a hurry sees `shopee` and `whatsapp`. [`visual.py`](src/homoglyph_detector/visual.py) covers that gap:

| | What | Examples |
|---|---|---|
| **A. Character substitution** | one domain character for a similar one | `5hopee` (5→s), `paypai` (i→l), `qoogle` (q→g), `g00gle` (0→o) |
| **B. Multi-character substitution** | several characters drawn like one | `vvhatsapp` (vv→w), `clropbox` (cl→d), `nnicrosoft` (nn→m), `rnicrosoft` (rn→m) |
| **C. Visual similarity scoring** | weighted edit distance: a look-alike substitution costs `1 − similarity`, any other edit costs 1; score = `1 − distance / length` | `5hopee`/`shopee` = 0.95, `vvhatsapp`/`whatsapp` = 0.99 |

- **Where the weights come from:** pairs UTS #39 calls identical are read from `confusables.txt` and cost 0. Only the *near* pairs (similar, not identical) live in the small `NEAR` table, restricted to `a-z 0-9 -`, so there is no Unicode version to track. A test fails if a `NEAR` pair ever becomes identical in the official data.
- **Typos are not look-alikes:** a substitution outside the table costs a full character, so `paypak` or `shoppe` (distance 1.0) stay ordinary *typosquats* (medium), while a visual look-alike (distance ≤ 0.5, i.e. at most half a character of visible difference) is **high**: `brand_visual`.
- Each hyphen-separated part of a name is compared too (`paypai-login.com`), and display names / usernames get the same check (`5hopee Official`).
- Checked against 50+ popular legitimate domains (Vietnamese banks and news sites, `mono`, `memo`, `nomo` near `momo`, ...) without a single `brand_visual` false positive.

## Technique: IDNA2008 validation and Public Suffix List

Every host (from a domain, an email address or a URL) goes through this pipeline in [`analyzer.py`](src/homoglyph_detector/analyzer.py):

| # | Step | How | Finding kinds |
|---|---|---|---|
| 1 | Raw domain input | host taken from the domain / `user@host` / URL authority (without lower-casing non-ASCII) | |
| 2 | Unicode normalization | **NFC only** (canonical equivalence, same meaning) and ASCII case folding (DNS is ASCII-case-insensitive). No NFKC or ad-hoc mapping. | `not_nfc` |
| 3 | IDNA2008 validation | `idna.encode()` strict ([RFC 5891](https://www.rfc-editor.org/rfc/rfc5891)): code point classes ([RFC 5892](https://www.rfc-editor.org/rfc/rfc5892)), CONTEXTJ / CONTEXTO rules, the bidi rule ([RFC 5893](https://www.rfc-editor.org/rfc/rfc5893)), hyphen rules, label ≤ 63 and domain ≤ 253 octets. If strict fails, [UTS #46](https://www.unicode.org/reports/tr46/) mapping tells what a browser would resolve instead. | `idna_bidi`, `idna_context`, `idna_disallowed`, `idna_length`, `idna_invalid`, `idna_mapped` |
| 4 | A-label / U-label conversion | `xn--` labels are shown as U-labels only if `idna` accepts them, so a successful Punycode decode alone never counts as a valid IDN. A-label → U-label → A-label must round-trip. | `punycode`, `idna_roundtrip` |
| 5 | Public Suffix List parsing | `publicsuffixlist` (bundled list, ICANN **and private** section) finds the registrable domain: `login.vietcombank.com.vn` → `vietcombank.com.vn`, `pаypal.github.io` → `pаypal.github.io` (on hosting platforms each site is its own domain) | |
| 6 | Unicode skeleton comparison | UTS #39 checks on the host as the reader sees it, then skeleton brand matching on the domain that is actually resolved (see the UTS #39 section) | `mixed_script`, `whole_lookalike`, `brand_*`, ... |
| 7 | Risk scoring | every finding has a severity; verdict = worst: `SAFE` (info/low), `SUSPICIOUS` (medium), `MALICIOUS` (high/critical); CLI exit code 0/1/2 | |

Brand matching, step 6, in detail — comparing skeletons on *both* sides against `data/brands.json`:
- official domain or subdomain → allow-listed;
- registrable domain has the same skeleton as an official domain → **critical**;
- site name has the same skeleton as a brand keyword → high (homograph) / medium (brand name on an unofficial domain);
- one edit away from a keyword, or keyword inside the host → medium.

The skeleton is lower-cased because domains are case-insensitive, so `0` (prototype `O`) collides with `o`. It can look odd — `m` maps to `rn`, so `paypal.com` → `paypal.corn` — that is expected.

Vietnamese text is a first-class test case: `tiếngviệt.vn` and `Nguyễn Văn A` are Latin with diacritics and must not be flagged.

## Install & use

```bash
pip install -e .            # or: pip install -e ".[dev]" for pytest
                            # dependencies: idna, publicsuffixlist (pure Python, no network at runtime)

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
from homoglyph_detector import analyze, skeleton, confusable_type, restriction_level, visual_similarity

report = analyze("pаypal.com")
report.verdict                     # 'MALICIOUS'
report.restriction_level           # 'Minimally Restrictive'
report.to_dict()                   # JSON-ready
confusable_type("аррӏе", "apple")  # 'whole-script'
restriction_level("東京とうきょう")  # 'Single Script'
visual_similarity("vvhatsapp", "whatsapp")  # VisualMatch(score=0.989, distance=0.1, edits=['vv->w'])
```

## How is this different from dnstwist?

[dnstwist](https://github.com/elceef/dnstwist) *generates* look-alike permutations of **your** domain so you can monitor them. This tool goes the other way: it takes **any** input — a sender address, a URL from a log, a username — and tells you whether it imitates something. The two complement each other.

## Project layout

```
src/homoglyph_detector/
  unicode_data.py   UTS #39: skeleton, scripts, restriction levels, confusable types, properties
  visual.py         ASCII visual confusables: substitution table and similarity scoring
  analyzer.py       parsing, punycode, checks, brand matching, verdict
  cli.py            command line
  data/             official Unicode data files (see above) + brands.json (edit freely)
scripts/
  update_unicode_data.py   refresh the Unicode data files from unicode.org
tests/
  test_analyzer.py         malicious / suspicious / safe cases, one test per UTS #39 mechanism
  test_unicode_data.py     compatibility checks for the bundled Unicode data
  test_visual.py           ASCII look-alikes, typos vs look-alikes, table consistency
.github/workflows/
  ci.yml                   tests on every push
  unicode-data.yml         monthly check for new Unicode data
```

## Roadmap

- [x] v0.1 — punycode, skeleton, brand matching with allow-list, CLI, JSON, tests, CI
- [x] v0.2 — full UTS #39 confusable detection: Script_Extensions, resolved script sets, restriction levels, single/mixed/whole-script confusable types, mixed numbers, invisible characters, hidden overlays
- [x] v0.3 — official Default_Ignorable and Bidi_Control data, bidi control detection, update script with version check, data compatibility tests, monthly data workflow, safe report output
- [x] v0.4 — IDNA2008 validation (strict + UTS #46), A-label/U-label round-trip, length / bidi / contextual rules, Public Suffix List with private suffixes
- [x] v0.5 — ASCII visual confusable detection: character and multi-character substitutions, visual similarity scoring, WhatsApp and Dropbox brands
- [ ] HTML report for batch runs
- [ ] `.eml` mode: check From / Reply-To / Return-Path and every link in a phishing email
- [ ] Optional online checks: DNS resolution, domain age (RDAP), VirusTotal — off by default
- [ ] Small web UI (Streamlit) for demos

## Data & license

Code: MIT (see `LICENSE`). The files in `src/homoglyph_detector/data/` except `brands.json` are © Unicode, Inc., distributed under the [Unicode License v3](https://www.unicode.org/license.txt) — Unicode 18.0.0. Refresh them with `python scripts/update_unicode_data.py`. The IDNA tables come with `idna` and the Public Suffix List with `publicsuffixlist` (a new release follows every PSL change): refresh both with `pip install -U idna publicsuffixlist`; a test checks that `idna` uses the same Unicode version as the bundled data.
