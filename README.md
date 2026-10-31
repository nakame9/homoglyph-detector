# homoglyph-detector

[![CI](https://github.com/nakame9/homoglyph-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/nakame9/homoglyph-detector/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Phát hiện tên miền, email, URL và tên hiển thị **giả mạo bằng ký tự trông giống nhau**: homoglyph Unicode (`pаypal.com` với chữ `а` Cyrillic), ký tự ASCII trông giống (`5hopee.vn`, `rnicrosoft.com`), typosquat, combosquat, ký tự ẩn và ký tự đảo chiều. Chạy offline, chỉ cần 2 thư viện Python thuần.

## Tính năng

- **Detection engine nhiều lớp** — 5 engine độc lập (unicode, idna, brand, combosquat, visual), mỗi engine trả điểm và bằng chứng; tầng hợp nhất cho ra **xác suất đã hiệu chỉnh** trên benchmark 15.805 tên miền, không đặt điểm bằng tay.
- **Unicode UTS #39** — skeleton, single / mixed / whole-script confusable, restriction level, ký tự ẩn, ký tự đảo chiều (bidi), trên dữ liệu Unicode 18 chính thức.
- **ASCII Visual Confusable** — thay ký tự (`5`→`s`), thay cụm ký tự (`vv`→`w`, `cl`→`d`), chữ có dấu, kèm điểm độ giống hình ảnh.
- **IDNA2008 + Public Suffix List** — kiểm tra theo RFC 5891–5893, mapping UTS #46 như trình duyệt, tách tên miền đúng (`vietcombank.com.vn`, `x.github.io`).
- **Brand Intelligence Database** — thương hiệu nằm trong JSON có version; tổ chức nạp thêm database riêng; mọi dữ liệu được ghim SHA-256, dữ liệu bị sửa thì công cụ dừng.

## Ví dụ

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

Mỗi kết quả có điểm rủi ro 0–100, điểm của từng engine và bằng chứng gắn tên engine tạo ra nó, không chỉ đúng / sai.

## Cài đặt

```bash
git clone https://github.com/nakame9/homoglyph-detector
cd homoglyph-detector
pip install -e .                 # thêm ".[dev]" để chạy test, ".[bench]" để tạo lại benchmark
```

Yêu cầu Python 3.10+. Thư viện phụ thuộc: `idna`, `publicsuffixlist` (không cần mạng khi chạy).

## Sử dụng

```bash
homoglyph-detector paypa1.com "user@pаypal.com" "https://аpple.com/login"   # domain, email, URL
homoglyph-detector "5hopee Official"                                    # tên hiển thị
homoglyph-detector -f examples/sample_domains.txt                       # mỗi dòng một đầu vào
cat domains.txt | homoglyph-detector -f -                               # đọc từ stdin
homoglyph-detector g00gle.com --json                                    # JSON cho SIEM / script
homoglyph-detector x.vn --brands "org.json#sha256=<mã>"                 # thêm thương hiệu của tổ chức
homoglyph-detector --verify                                             # kiểm tra toàn vẹn dữ liệu
homoglyph-detector --version                                            # phiên bản công cụ và dữ liệu
```

| Mã thoát | Ý nghĩa |
|---|---|
| 0 | tất cả SAFE |
| 1 | có SUSPICIOUS |
| 2 | có MALICIOUS |
| 3 | dữ liệu không qua kiểm tra toàn vẹn / hợp lệ, không đưa ra kết luận |

Dùng như thư viện:

```python
from homoglyph_detector import analyze

report = analyze("pаypal.com")
report.verdict          # 'MALICIOUS'
report.risk_score       # 100
report.engine_scores    # {'unicode': 0.75, 'idna': 0.0, 'brand': 0.95, 'combosquat': 0.0, 'visual': 0.0}
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

Đo trên tập test (4.799 tên miền mô hình chưa từng thấy) của benchmark gồm tấn công do [dnstwist](https://github.com/elceef/dnstwist) sinh ra và [OpenDNS top 10.000](https://github.com/opendns/public-domain-lists):

| | precision | recall | F1 | tỷ lệ báo nhầm |
|---|---|---|---|---|
| p ≥ 0.5 (SUSPICIOUS trở lên) | 0.9667 | 0.8698 | 0.9157 | 0.016 |
| p ≥ 0.9 (MALICIOUS) | 0.9926 | 0.6395 | 0.7778 | 0.0026 |
| luật mức độ, không hiệu chỉnh | 0.9624 | 0.7522 | 0.8444 | 0.0156 |

ROC-AUC 0.9302. Cách xây dựng, những gì benchmark đã phát hiện và các giới hạn: [docs/benchmark.md](docs/benchmark.md).

## Tài liệu

| Tài liệu | Nội dung |
|---|---|
| [docs/kien-truc.md](docs/kien-truc.md) | luồng xử lý, bản đồ thư mục, muốn sửa gì thì mở file nào, các trường kết quả |
| [docs/ky-thuat.md](docs/ky-thuat.md) | UTS #39, ASCII visual, IDNA2008 + PSL, typosquat / combosquat |
| [docs/brand-database.md](docs/brand-database.md) | định dạng brand database, các lớp, kiểm tra hợp lệ, toàn vẹn, version, dữ liệu Unicode |
| [docs/benchmark.md](docs/benchmark.md) | bộ dữ liệu, hiệu chỉnh, kết quả, giới hạn |
| [docs/bao-tri.md](docs/bao-tri.md) | **hướng dẫn bảo trì**: thêm thương hiệu, sửa báo nhầm, thêm engine, cập nhật dữ liệu, phát hành, **tra cứu lỗi** |
| [CHANGELOG.md](CHANGELOG.md) | lịch sử phiên bản |
| [CONTRIBUTING.md](CONTRIBUTING.md) | quy trình đóng góp, kiểm tra trước khi mở PR |

## Lộ trình

- Tập test từ domain lừa đảo thật (PhishTank, OpenPhish) bên cạnh tấn công do dnstwist sinh.
- Chế độ `.eml`: kiểm tra From / Reply-To / Return-Path và mọi liên kết trong email lừa đảo.
- Ký số brand database (Ed25519) để chống sửa cả `MANIFEST.json`.
- Báo cáo HTML cho chạy hàng loạt; giao diện web để demo.
- Kiểm tra trực tuyến tùy chọn (DNS, tuổi tên miền qua RDAP), tắt mặc định.

## Giấy phép

Code: MIT (xem `LICENSE`). Các file dữ liệu Unicode trong `src/homoglyph_detector/data/` (mọi file `.txt`) thuộc © Unicode, Inc., phân phối theo [Unicode License v3](https://www.unicode.org/license.txt).
