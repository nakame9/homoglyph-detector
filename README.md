# homoglyph-detector

[![CI](https://github.com/nakame9/homoglyph-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/nakame9/homoglyph-detector/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Phát hiện tên miền, email, URL và tên hiển thị **giả mạo bằng ký tự trông giống nhau**: homoglyph Unicode (`pаypal.com` với chữ `а` Cyrillic), ký tự ASCII trông giống (`5hopee.vn`, `rnicrosoft.com`), typosquat, combosquat, ký tự ẩn và ký tự đảo chiều. Chạy offline, chỉ cần 2 thư viện Python thuần.

## Tính năng

- **Ba loại bằng chứng tách bạch** — mỗi bằng chứng là Unicode confusable, visual similarity hoặc brand impersonation (kèm cơ sở: `unicode` / `visual` / `spelling` / `name`). Độ giống hình ảnh phụ thuộc font nên chỉ hỗ trợ chấm điểm: **một mình nó không bao giờ dẫn tới MALICIOUS**.
- **Detection engine nhiều lớp** — 5 engine độc lập (unicode, idna, brand, combosquat, visual), mỗi engine trả điểm và bằng chứng; tầng hợp nhất cho ra **xác suất đã hiệu chỉnh** trên benchmark 15.805 tên miền, không đặt điểm bằng tay.
- **Unicode UTS #39** — skeleton, single / mixed / whole-script confusable, restriction level, ký tự ẩn, ký tự đảo chiều (bidi), trên dữ liệu Unicode 18 chính thức.
- **ASCII Visual Confusable** — thay ký tự (`5`→`s`), thay cụm ký tự (`vv`→`w`, `cl`→`d`), chữ có dấu, kèm điểm độ giống hình ảnh.
- **IDNA2008 + Public Suffix List** — kiểm tra theo RFC 5891–5893, mapping UTS #46 như trình duyệt, tách tên miền đúng (`vietcombank.com.vn`, `x.github.io`).
- **Domain Risk Scoring theo môi trường** — cùng một điểm rủi ro, ngưỡng kết luận khác nhau: profile `default`, `banking` (chặn mọi bằng chứng), `browser` (chỉ cảnh báo bằng chứng mạnh) hoặc ngân sách báo nhầm riêng (`--max-fpr`), chọn từ benchmark theo tỷ lệ báo nhầm.
- **Brand Intelligence Database** — thương hiệu nằm trong JSON có version; tổ chức nạp thêm database riêng; mọi dữ liệu được ghim SHA-256, dữ liệu bị sửa thì công cụ dừng.

## Ví dụ

```
$ homoglyph-detector "pаypal.com" 5hopee.vn paypal-login.com "tiếngviệt.vn"

🚨 MALICIOUS  pаypal.com  [domain]
    a-label : xn--pypal-4ve.com
    skeleton: paypal.corn
    level   : Minimally Restrictive
    risk    : 100/100   engines: unicode 0.75  idna 0.00  brand 0.95  combosquat 0.00  visual 0.00
    profile : default (SUSPICIOUS >= 0.50, MALICIOUS >= 0.90)
    evidence: unicode medium,  visual -,  brand critical (basis: unicode),  idna -
    - [unicode/medium] 'pаypal' mixes scripts: Cyrillic, Latin (level: Minimally Restrictive)
    - [unicode/medium] 'pаypal' renders like ASCII 'paypal' (mixed-script confusable)
    - [unicode/info] Position 1: 'а' U+0430 (Cyrillic) looks like 'a'
    - [brand/critical, unicode] Impersonates PayPal: renders like 'paypal.com' (mixed-script confusable)

⚠️  SUSPICIOUS 5hopee.vn  [domain]
    skeleton: 5hopee.vn
    level   : ASCII-Only
    risk    : 100/100   engines: unicode 0.00  idna 0.00  brand 0.50  combosquat 0.00  visual 0.70
    profile : default (SUSPICIOUS >= 0.50, MALICIOUS >= 0.90)
    evidence: unicode -,  visual high,  brand medium (basis: visual),  idna -
    note    : capped at SUSPICIOUS: the only evidence is visual similarity, which depends on font and rendering
    - [brand/medium, visual] '5hopee' is one edit away from Shopee keyword 'shopee'
    - [visual/high] '5hopee' looks like Shopee keyword 'shopee' (visual similarity 0.95: 5->s)

⚠️  SUSPICIOUS paypal-login.com  [domain]
    skeleton: paypal-login.corn
    level   : ASCII-Only
    risk    : 81/100   engines: unicode 0.00  idna 0.00  brand 0.00  combosquat 0.50  visual 0.00
    profile : default (SUSPICIOUS >= 0.50, MALICIOUS >= 0.90)
    evidence: unicode -,  visual -,  brand medium (basis: name),  idna -
    - [combosquat/medium, name] Contains PayPal keyword 'paypal' on unofficial domain 'paypal-login.com'

✅ SAFE       tiếngviệt.vn  [domain]
    a-label : xn--tingvit-5t4cyc.vn
    skeleton: tiếngviệt.vn
    level   : Single Script
    risk    : 13/100   engines: unicode 0.00  idna 0.00  brand 0.00  combosquat 0.00  visual 0.00
    profile : default (SUSPICIOUS >= 0.50, MALICIOUS >= 0.90)
    evidence: unicode -,  visual -,  brand -,  idna -
```

Mỗi kết quả có điểm rủi ro 0–100, điểm của từng engine, bằng chứng theo loại (Unicode / hình ảnh / thương hiệu, kèm cơ sở), profile đã dùng, và lý do khi kết luận bị giới hạn: `5hopee.vn` chỉ trông giống `shopee` nên dừng ở SUSPICIOUS, còn `pаypal.com` có bằng chứng Unicode nên là MALICIOUS.

## Cài đặt

```bash
git clone https://github.com/nakame9/homoglyph-detector
cd homoglyph-detector
pip install -e .                 # thêm ".[dev]" để chạy test (pytest, Hypothesis), ".[bench]" để tạo lại benchmark
```

Yêu cầu Python 3.10+. Thư viện phụ thuộc được khai báo trong `pyproject.toml` và pip tự cài:

| Gói | Phiên bản | Ghi chú |
|---|---|---|
| `idna` | ≥ 3.20 | 3.20 là bản đầu tiên có bảng IDNA Unicode 18, khớp dữ liệu UTS #39 đi kèm (3.19 dùng Unicode 17, bị test chặn) |
| `publicsuffixlist` | ≥ 1.0 | có sẵn PSL, không cần mạng khi chạy |
| `pytest`, `hypothesis` (`.[dev]`) | ≥ 7, ≥ 6.100 | chỉ để chạy test |

Đã kiểm thử cài sạch trên Python 3.10, 3.11, 3.12, 3.13, với cả phiên bản thư viện mới nhất lẫn thấp nhất cho phép; CI chạy lại cả hai trường hợp ở mỗi lần push.

## Sử dụng

```bash
homoglyph-detector paypa1.com "user@pаypal.com" "https://аpple.com/login"   # domain, email, URL
homoglyph-detector "5hopee Official"                                    # tên hiển thị
homoglyph-detector -f examples/sample_domains.txt                       # mỗi dòng một đầu vào
cat domains.txt | homoglyph-detector -f -                               # đọc từ stdin
homoglyph-detector g00gle.com --json                                    # JSON cho SIEM / script
homoglyph-detector paypal-login.com --profile banking                  # profile: default, banking, browser
homoglyph-detector paypal-login.com --max-fpr 0.01,0.001                # ngân sách báo nhầm riêng
homoglyph-detector --profiles                                           # các profile và số liệu đo được
homoglyph-detector paypal-login.com --base-rate 0.001                   # xác suất khi 1/1.000 đầu vào là tấn công
homoglyph-detector x.vn --brands "org.json#sha256=<mã>"                 # thêm thương hiệu của tổ chức
homoglyph-detector --verify                                             # kiểm tra toàn vẹn dữ liệu
homoglyph-detector --version                                            # phiên bản công cụ và dữ liệu
```

| Mã thoát | Ý nghĩa |
|---|---|
| 0 | tất cả SAFE |
| 1 | có SUSPICIOUS |
| 2 | có MALICIOUS (cần bằng chứng ngoài độ giống hình ảnh) |
| 3 | dữ liệu không qua kiểm tra toàn vẹn / hợp lệ, không đưa ra kết luận |

Dùng như thư viện:

```python
from homoglyph_detector import analyze

report = analyze("pаypal.com", policy="browser")   # policy: tên profile, mặc định 'default'
report.verdict          # 'MALICIOUS'
report.risk_score       # 100
report.engine_scores    # {'unicode': 0.75, 'idna': 0.0, 'brand': 0.95, 'combosquat': 0.0, 'visual': 0.0}
report.profile          # 'browser'; report.thresholds: ngưỡng SUSPICIOUS / MALICIOUS đã dùng
report.findings         # bằng chứng, mỗi cái có engine, kind, severity, message
report.to_dict()        # sẵn sàng xuất JSON
```

## Kiến trúc

```
đầu vào ─► context.py (parse, NFC, IDNA, PSL)
             ├─► engines/unicode_engine.py      ─┐
             ├─► engines/idna_engine.py          │ mỗi engine: điểm 0..1 + bằng chứng
             ├─► engines/brand_engine.py         ├ (độc lập, không đọc kết quả của nhau)
             ├─► engines/combosquat_engine.py    │
             └─► engines/visual_engine.py       ─┘
          ─► scoring.py (trọng số từ calibration.json) ─► Report: xác suất, risk, verdict, bằng chứng
```

Chi tiết từng module, các khái niệm chính và bảng **"muốn sửa gì thì mở file nào"**: [docs/kien-truc.md](docs/kien-truc.md).

## Chất lượng

Có hai loại số liệu, đo những thứ khác nhau. Đừng đọc số của benchmark tổng hợp như hiệu quả khi triển khai.

**1. Phishing thật và web thật** ([benchmark/REAL_WORLD.md](benchmark/REAL_WORLD.md)): 271.231 host phishing từ lịch sử feed OpenPhish (10/2024 → 11/2026) và 41.620 domain hợp lệ từ Chrome UX Report top 1 triệu, profile `default`:

| | kết quả |
|---|---|
| phishing thật thuộc phạm vi của công cụ (nhắc thương hiệu được bảo vệ, hoặc IDN) | **3,5%** — phần lớn phishing nhắm thương hiệu khác (Telegram, USPS, Ledger, Coinbase...) hoặc không giả mạo tên miền |
| phát hiện trên **toàn bộ** phishing thật | **3,4%** |
| phát hiện phishing nhắc thương hiệu được bảo vệ | 99,6% (gần như tự chứng minh, xem báo cáo); chỉ 0,8% có bằng chứng giả mạo *trông giống* (profile `browser`, bỏ qua combosquat), còn lại là ghép tên thương hiệu |
| homograph IDN trong phishing thật | 166 / 271.231 host (0,06%) |
| báo nhầm trên web thật | 0,1–0,3% mọi khu vực, 0% Việt Nam, 0,1% trên 1.678 IDN hợp lệ; 0% ở profile `browser` trừ vài domain của chính thương hiệu |
| ổn định theo thời gian | recall trong phạm vi 91–100% mỗi tháng suốt 25 tháng; mô hình fit trên quá khứ không xếp hạng tốt hơn mô hình hiện tại |
| precision khi 1 / 1.000 domain là tấn công | 23% trong phạm vi, 1,7% trên mọi phishing |

Kết luận: đây là **một lớp phòng thủ chuyên biệt** cho giả mạo các thương hiệu được bảo vệ, không phải bộ lọc phishing tổng quát. Hiệu quả phụ thuộc trước hết vào **độ phủ của brand database**. Muốn biết xác suất trong lưu lượng của bạn, dùng `--base-rate`.

**2. Benchmark tổng hợp** ([docs/benchmark.md](docs/benchmark.md)): tấn công do [dnstwist](https://github.com/elceef/dnstwist) sinh từ domain thương hiệu, domain hợp lệ từ [OpenDNS top 10.000](https://github.com/opendns/public-domain-lists), tập test 4.799 domain mô hình chưa thấy. Dùng để hiệu chỉnh tầng hợp nhất và so sánh các phiên bản, **không** đại diện phân bố phishing thật:

| | precision | recall | F1 | tỷ lệ báo nhầm |
|---|---|---|---|---|
| p ≥ 0,5 (SUSPICIOUS trở lên) | 96,6% | 86,5% | 91,3% | 1,6% |
| p ≥ 0,9 (MALICIOUS) | 99,3% | 63,5% | 77,4% | 0,26% |

Ngưỡng là của profile `default`; mỗi môi trường chọn điểm vận hành riêng: [docs/risk-scoring.md](docs/risk-scoring.md).

**3. Kiểm thử**: golden corpus 142 ca cho 10 nhóm bắt buộc, Hypothesis (property-based, fuzzing Unicode), differential testing IDNA, regression snapshot, 203 biến thể adversarial với kỹ thuật chưa từng dùng khi phát triển. Độ trễ p50 4,3 ms, p99 14 ms mỗi domain: [docs/testing.md](docs/testing.md).

## Tài liệu

| Tài liệu | Nội dung |
|---|---|
| [docs/kien-truc.md](docs/kien-truc.md) | luồng xử lý, bản đồ thư mục, muốn sửa gì thì mở file nào, các trường kết quả |
| [docs/ky-thuat.md](docs/ky-thuat.md) | UTS #39, ASCII visual, IDNA2008 + PSL, typosquat / combosquat, ba loại bằng chứng và quy tắc visual-only |
| [docs/brand-database.md](docs/brand-database.md) | định dạng brand database, các lớp, kiểm tra hợp lệ, toàn vẹn, version, dữ liệu Unicode |
| [docs/benchmark.md](docs/benchmark.md) | benchmark tổng hợp và **đánh giá thực tế** (phishing thật, temporal, adversarial, calibration), giới hạn |
| [benchmark/REAL_WORLD.md](benchmark/REAL_WORLD.md) | báo cáo đánh giá thực tế đầy đủ (tự sinh) |
| [docs/testing.md](docs/testing.md) | kỹ thuật kiểm thử, golden corpus 10 nhóm, precision / recall / FPR / FNR / độ trễ, các lỗi đã tìm ra |
| [docs/risk-scoring.md](docs/risk-scoring.md) | profile rủi ro theo môi trường, ngân sách báo nhầm, điểm vận hành |
| [docs/bao-tri.md](docs/bao-tri.md) | **hướng dẫn bảo trì**: thêm thương hiệu, sửa báo nhầm, thêm engine, cập nhật dữ liệu, phát hành, **tra cứu lỗi** |
| [CHANGELOG.md](CHANGELOG.md) | lịch sử phiên bản |
| [CONTRIBUTING.md](CONTRIBUTING.md) | quy trình đóng góp, kiểm tra trước khi mở PR |

## Lộ trình

- Mở rộng brand database theo thương hiệu bị giả mạo nhiều nhất ngoài thực tế (Telegram, USPS, Ledger, Coinbase, Netflix, Instagram, MetaMask) và domain của chính thương hiệu (`cloud.microsoft`, `amazon.co.jp`).
- Thay chữ bằng số chưa có trong bảng (`3`→e, `4`→a, `7`→t, `8`→b): chỉ bắt được 47% ở kiểm thử adversarial.
- Engine combosquat chỉ có trọng số nhờ loại `dictionary` của benchmark (bỏ loại này khi fit thì recall về 0%): cần dữ liệu combosquat đa dạng hơn, ví dụ từ phishing thật.
- Bổ sung domain quốc gia của các thương hiệu (`amazon.co.jp`).
- Điểm số mịn hơn (đặc trưng liên tục như độ dài từ khóa, mức phổ biến của domain) để có nhiều điểm vận hành hơn ba bậc hiện tại.
- Tập test từ domain lừa đảo thật (PhishTank, OpenPhish) bên cạnh tấn công do dnstwist sinh.
- Chế độ `.eml`: kiểm tra From / Reply-To / Return-Path và mọi liên kết trong email lừa đảo.
- Ký số brand database (Ed25519) để chống sửa cả `MANIFEST.json`.
- Báo cáo HTML cho chạy hàng loạt; giao diện web để demo.
- Kiểm tra trực tuyến tùy chọn (DNS, tuổi tên miền qua RDAP), tắt mặc định.

## Giấy phép

Code: MIT (xem `LICENSE`). Các file dữ liệu Unicode trong `src/homoglyph_detector/data/` (mọi file `.txt`) thuộc © Unicode, Inc., phân phối theo [Unicode License v3](https://www.unicode.org/license.txt).
