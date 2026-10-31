# homoglyph-detector

Detect look-alike (homoglyph / IDN homograph) domains, emails, URLs and names — offline, two small pure-Python dependencies.

**Techniques**
- **Multi-layer detection engine** — five independent engines (Unicode, IDNA, brand, combosquat, visual) each return a score and their evidence; a fusion layer turns them into a **calibrated probability**, fitted on a 15,805-domain benchmark instead of hand-set rules.
- **Unicode [UTS #39](https://www.unicode.org/reports/tr39/) Confusable Detection** — skeletons, single / mixed / whole-script confusables, restriction levels, mixed numbers, bidi controls and default-ignorable characters, on the official Unicode 18 data files.
- **ASCII Visual Confusable Detection** — look-alikes made only of ordinary characters: single (`5hopee`, `paypai`) and multi-character substitutions (`vvhatsapp`, `clropbox`, `nnicrosoft`) with a visual similarity score.
- **IDNA2008 validation** ([RFC 5890–5893](https://www.rfc-editor.org/rfc/rfc5891)) with [UTS #46](https://www.unicode.org/reports/tr46/) lookup mapping via [`idna`](https://pypi.org/project/idna/), and **Public Suffix List** parsing via [`publicsuffixlist`](https://pypi.org/project/publicsuffixlist/).

```
$ homoglyph-detector "pаypal.com" 5hopee.vn paypal-login.com "tiếngviệt.vn"

🚨 MALICIOUS  pаypal.com  [domain]
    a-label : xn--pypal-4ve.com
    skeleton: paypal.corn
    level   : Minimally Restrictive
    risk    : 100/100   engines: unicode 0.75  idna 0.00  brand 0.95  combosquat 0.00  visual 0.00
    - [unicode/medium] 'pаypal' mixes scripts: Cyrillic, Latin (level: Minimally Restrictive)
    - [unicode/medium] 'pаypal' renders like ASCII 'paypal' (mixed-script confusable)
    - [unicode/info] Position 1: 'а' U+0430 (Cyrillic) looks like 'a'
    - [brand/critical] Impersonates PayPal: renders like 'paypal.com' (mixed-script confusable)

🚨 MALICIOUS  5hopee.vn  [domain]
    skeleton: 5hopee.vn
    level   : ASCII-Only
    risk    : 100/100   engines: unicode 0.00  idna 0.00  brand 0.50  combosquat 0.00  visual 0.70
    - [brand/medium] '5hopee' is one edit away from Shopee keyword 'shopee'
    - [visual/high] '5hopee' looks like Shopee keyword 'shopee' (visual similarity 0.95: 5->s)

⚠️  SUSPICIOUS paypal-login.com  [domain]
    skeleton: paypal-login.corn
    level   : ASCII-Only
    risk    : 81/100   engines: unicode 0.00  idna 0.00  brand 0.00  combosquat 0.50  visual 0.00
    - [combosquat/medium] Contains PayPal keyword 'paypal' on unofficial domain 'paypal-login.com'

✅ SAFE       tiếngviệt.vn  [domain]
    a-label : xn--tingvit-5t4cyc.vn
    skeleton: tiếngviệt.vn
    level   : Single Script
    risk    : 13/100   engines: unicode 0.00  idna 0.00  brand 0.00  combosquat 0.00  visual 0.00
```

Every result carries a calibrated risk (0–100), the raw score of each engine and the evidence behind it, tagged with the engine that produced it — not just a yes/no.

## Why

Attackers register domains that *look* like a brand: `pаypal.com` (Cyrillic `а`), `аррӏе.com` (every letter Cyrillic), `rnicrosoft.com` (`rn` ≈ `m`), `paypa1.com`, `pay<U+200B>pal.com` (hidden zero-width space). Browsers already show mixed-script domains as `xn--…`, but **whole-script** look-alikes, pure-ASCII tricks and invisible characters still get through, and filters that compare strings byte-by-byte miss all of them.

ATT&CK: [T1583.001 Acquire Infrastructure: Domains](https://attack.mitre.org/techniques/T1583/001/), used for [T1566 Phishing](https://attack.mitre.org/techniques/T1566/).

## Detection engine: multi-layer, calibrated by benchmark

```
input ─► prepare (context.py): parse, NFC, IDNA A-label/U-label, Public Suffix List   ← transforms only
           ├─► unicode     UTS #39 scripts, restriction level, bidi / invisible characters ─┐
           ├─► idna        IDNA2008 validity, UTS #46 mapping, round-trip                  │ each: score 0..1
           ├─► brand       skeleton homographs, one-edit typosquats of protected brands    ├ + findings
           ├─► combosquat  brand name on an unofficial domain (paypal-login, google.ca)    │
           └─► visual      ASCII / accent look-alikes, continuous visual similarity        ─┘
         ─► fusion (scoring.py): p = sigmoid(bias + Σ weight·score)  ─►  risk 0-100, verdict, evidence
```

- **Independent engines** ([`engines.py`](src/homoglyph_detector/engines.py)): each reads only the shared context, never another engine's output, and can be run on its own; a test checks that every engine gives the same result alone as inside the pipeline. Scores are a noisy-OR of an engine's findings, counting repeats of one kind once (six confusable letters are one piece of evidence, not six); the visual engine reports its best similarity directly.
- **Calibrated fusion** ([`scoring.py`](src/homoglyph_detector/scoring.py)): a logistic regression whose weights, bias and thresholds come from [`calibration.json`](src/homoglyph_detector/data/calibration.json), fitted by [`benchmark/calibrate.py`](benchmark/calibrate.py). Weights are constrained ≥ 0, so more evidence never lowers the risk. Verdict: `SUSPICIOUS` at p ≥ 0.5 (more likely than not), `MALICIOUS` at p ≥ 0.9 (9 in 10).
- **Fitted weights:** unicode 17.0816, idna 0.0, brand 11.5037, combosquat 6.6264, visual 7.798, bias -1.8926. The idna engine gets weight 0: an invalid domain cannot be visited, so it explains rather than predicts; its findings stay in the report.

### Benchmark

[`benchmark/build_dataset.py`](benchmark/build_dataset.py) builds 15,805 labelled domains from sources independent of this tool: **10,065 benign** (the [OpenDNS top 10,000](https://github.com/opendns/public-domain-lists) plus Vietnamese sites, legitimate IDNs in both forms and real words close to brands) and **5,740 attacks** (every [dnstwist](https://github.com/elceef/dnstwist) fuzzer on each protected brand domain, including combosquats, IDN homoglyphs of 150 unprotected popular domains, and a curated set of bidi / invisible / fullwidth tricks). The split keeps all permutations of one domain on the same side, so the test set is made of domains the model never saw.

Results on the test split (4,799 rows) — full report with per-category detection, a reliability table and the hardest errors in [`benchmark/RESULTS.md`](benchmark/RESULTS.md):

| | precision | recall | F1 | false positive rate |
|---|---|---|---|---|
| calibrated, p ≥ 0.5 | 0.9667 | 0.8698 | 0.9157 | 0.016 |
| calibrated, p ≥ 0.9 | 0.9926 | 0.6395 | 0.7778 | 0.0026 |
| severity rules, no calibration | 0.9624 | 0.7522 | 0.8444 | 0.0156 |

ROC-AUC 0.9302, Brier score 0.0585, expected calibration error 0.0609.

**What the benchmark caught** — each found by reading the errors, fixed in the engines, then re-measured:
1. *Data leakage:* every attack in DNS (`xn--`) form and no benign one, so the first model learned "punycode = attack" (idna weight 21.8). Fix: punycode conversion is `info`, and benign IDNs are included in both forms.
2. *Bug:* typosquat distance was measured on skeletons, where `amazon` becomes `arnazon`, hiding `aazon.com`; transposition typos (`amaozn`) had **0 %** recall. Fix: optimal-string-alignment distance on the raw and skeleton forms, also against official domain names (`office` from office.com).
3. *Conflated evidence:* brand-owned sites (`amazon.co.uk`, `google-analytics.com`) and real combosquats shared one score. Fix: a separate **combosquat** engine, with dnstwist dictionary combosquats in the data, so its weight is learned on its own.
4. *Missed homoglyphs:* `amažoṉ`, `gmăįl` use accented Latin letters that UTS #39 does not call confusable (homoglyph recall 63 %). Fix: the visual engine also reads the skeleton without accents, at a cost per dropped accent (now ~90 %).
5. *Count bias:* a legitimate Russian IDN scored 1.00 because each of its six Cyrillic letters counted as evidence. Fix: repeated evidence counts once, and single confusable letters are `info`; the evidence is at label level.

**Limits, measured:** a domain with no evidence still gets ~13/100 — the share of attacks in the benchmark that leave no trace (the probabilities follow the benchmark's mix of about one attack per two benign domains; real traffic has far fewer, so read the score as a ranking and the thresholds as review cut-offs). One-edit typos of a short brand name are rated high even for real words (`apply.com`, `ymail.com`), and brand-owned domains missing from `brands.json` show up as combosquats. Accented look-alikes of *unprotected* domains are out of reach (about half detected) because accents are normal in Vietnamese and European names.

`CI` re-runs the calibration and fails if `calibration.json` no longer matches the committed engines and benchmark; tests also check the dataset hash and minimum quality (ROC-AUC ≥ 0.9, precision ≥ 0.98 at the malicious threshold).

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
| 7 | Risk scoring | the five engine scores go through the calibrated fusion layer (see *Detection engine*): probability, risk 0–100, verdict; CLI exit code 0/1/2 | |

Brand matching, step 6, in detail — comparing skeletons on *both* sides against `data/brands.json`:
- official domain or subdomain → allow-listed;
- registrable domain has the same skeleton as an official domain → **critical**;
- site name has the same skeleton as a brand keyword → high (homograph) / medium (brand name on an unofficial domain);
- one edit away from a keyword, or keyword inside the host → medium.

The skeleton is lower-cased because domains are case-insensitive, so `0` (prototype `O`) collides with `o`. It can look odd — `m` maps to `rn`, so `paypal.com` → `paypal.corn` — that is expected.

Vietnamese text is a first-class test case: `tiếngviệt.vn` and `Nguyễn Văn A` are Latin with diacritics and must not be flagged.

## Install & use

```bash
pip install -e .            # or: pip install -e ".[dev]" for pytest, ".[bench]" to rebuild the benchmark
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
report.risk_score                  # 100 (calibrated probability x 100)
report.engine_scores               # {'unicode': 0.75, 'idna': 0.0, 'brand': 0.95, 'combosquat': 0.0, 'visual': 0.0}
report.restriction_level           # 'Minimally Restrictive'
report.to_dict()                   # JSON-ready
confusable_type("аррӏе", "apple")  # 'whole-script'
restriction_level("東京とうきょう")  # 'Single Script'
visual_similarity("vvhatsapp", "whatsapp")  # VisualMatch(score=0.989, distance=0.1, edits=['vv->w'])
```

## How is this different from dnstwist?

[dnstwist](https://github.com/elceef/dnstwist) *generates* look-alike permutations of **your** domain so you can monitor them. This tool goes the other way: it takes **any** input — a sender address, a URL from a log, a username — and tells you whether it imitates something. The two complement each other, and dnstwist is what generates the attacks in this project's benchmark, so the detector is measured against a tool it was not written with.

## Project layout

```
src/homoglyph_detector/
  context.py        shared preprocessing: parse, NFC, IDNA A-label/U-label, Public Suffix List
  engines.py        the five independent detection engines
  scoring.py        calibrated fusion: probability, risk score, verdict
  analyzer.py       orchestrator: prepare -> engines -> fusion -> Report
  unicode_data.py   UTS #39: skeleton, scripts, restriction levels, confusable types, properties
  visual.py         ASCII visual confusables: substitution table and similarity scoring
  cli.py            command line
  data/             official Unicode data files (see above) + brands.json (edit freely)
scripts/
  update_unicode_data.py   refresh the Unicode data files from unicode.org
benchmark/
  build_dataset.py         labelled dataset from independent sources (dnstwist, OpenDNS top 10k)
  dataset.jsonl            the benchmark (pure ASCII, JSON-escaped)
  calibrate.py             fit the fusion layer, write calibration.json and RESULTS.md
  RESULTS.md               test-split metrics, reliability, per-category detection, hardest errors
tests/
  test_analyzer.py         malicious / suspicious / safe cases, one test per UTS #39 mechanism
  test_unicode_data.py     compatibility checks for the bundled Unicode data
  test_visual.py           ASCII look-alikes, typos vs look-alikes, table consistency
  test_engines.py          engine independence, calibrated output, monotonicity, calibration vs dataset
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
- [x] v0.6 — multi-layer detection engine: five independent engines, calibrated logistic fusion, benchmark from dnstwist + OpenDNS top 10k, reproducible calibration checked in CI
- [ ] HTML report for batch runs
- [ ] `.eml` mode: check From / Reply-To / Return-Path and every link in a phishing email
- [ ] Optional online checks: DNS resolution, domain age (RDAP), VirusTotal — off by default
- [ ] Small web UI (Streamlit) for demos

## Data & license

Code: MIT (see `LICENSE`). The files in `src/homoglyph_detector/data/` except `brands.json` are © Unicode, Inc., distributed under the [Unicode License v3](https://www.unicode.org/license.txt) — Unicode 18.0.0. Refresh them with `python scripts/update_unicode_data.py`. The IDNA tables come with `idna` and the Public Suffix List with `publicsuffixlist` (a new release follows every PSL change): refresh both with `pip install -U idna publicsuffixlist`; a test checks that `idna` uses the same Unicode version as the bundled data.
