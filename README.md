# homoglyph-detector

[![CI](https://github.com/nakame9/homoglyph-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/nakame9/homoglyph-detector/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Phát hiện tên miền, email, URL và tên hiển thị **giả mạo thương hiệu bằng ký tự trông giống nhau**: homoglyph Unicode (`pаypal.com` với `а` Cyrillic), ký tự ASCII trông giống (`5hopee.vn`, `rnicrosoft.com`), typosquat, combosquat, ký tự ẩn và ký tự đảo chiều. Chạy offline, chỉ cần 2 thư viện Python.

## Bắt đầu nhanh

```bash
git clone https://github.com/nakame9/homoglyph-detector
cd homoglyph-detector
pip install -e .            # ".[dev]" để chạy test, ".[bench]" để dựng lại benchmark
homoglyph-detector "pаypal.com" 5hopee.vn
```

```
🚨 MALICIOUS  pаypal.com  [domain]
    a-label : xn--pypal-4ve.com
    risk    : 100/100   engines: unicode 0.75  idna 0.00  brand 0.95  combosquat 0.00  visual 0.00
    evidence: unicode medium,  visual -,  brand critical (basis: unicode),  idna -
    - [brand/critical, unicode] Impersonates PayPal: renders like 'paypal.com' (mixed-script confusable)

⚠️  SUSPICIOUS 5hopee.vn  [domain]
    risk    : 100/100   engines: unicode 0.00  idna 0.00  brand 0.50  combosquat 0.00  visual 0.70
    note    : capped at SUSPICIOUS: the only evidence is visual similarity, which depends on font and rendering
    - [visual/high] '5hopee' looks like Shopee keyword 'shopee' (visual similarity 0.95: 5->s)
```

(Đã rút gọn: báo cáo đầy đủ có thêm skeleton, restriction level, profile và mọi bằng chứng.)

## Công cụ làm gì

- **5 engine độc lập**: `unicode` (UTS #39, Unicode 18), `idna` (IDNA2008 và UTS #46, đọc URL như trình duyệt theo WHATWG), `brand`, `combosquat`, `visual`. Mỗi engine trả điểm 0–1 kèm bằng chứng. Tầng hợp nhất cho ra **xác suất đã hiệu chỉnh** trên benchmark, không đặt điểm bằng tay.
- **Ba loại bằng chứng tách bạch**: Unicode, hình ảnh, thương hiệu. Độ giống hình ảnh phụ thuộc font, nên **một mình nó không bao giờ dẫn tới MALICIOUS**.
- **Ngưỡng theo môi trường**: profile `default`, `banking`, `browser`, hoặc ngân sách báo nhầm riêng (`--max-fpr`).
- **Brand database có version và ghim SHA-256**: tổ chức nạp thêm thương hiệu của mình; dữ liệu bị sửa thì công cụ dừng.

**Phạm vi:** đây là lớp phòng thủ chuyên cho giả mạo **các thương hiệu được bảo vệ**, không phải bộ lọc phishing tổng quát. Hiệu quả phụ thuộc trước hết vào độ phủ của brand database.

## Sử dụng

```bash
homoglyph-detector paypa1.com "user@pаypal.com" "https://аpple.com/login"   # domain, email, URL
homoglyph-detector "5hopee Official"                 # tên hiển thị
homoglyph-detector -f domains.txt                    # mỗi dòng một đầu vào ('-' = stdin)
homoglyph-detector g00gle.com --json                 # báo cáo JSON đầy đủ
homoglyph-detector --integration-json -f domains.txt # JSON đã lược dữ liệu nhạy cảm, schema v1
homoglyph-detector x.com --profile banking           # hoặc --max-fpr 0.01,0.001; xem --profiles
homoglyph-detector x.com --base-rate 0.001           # thêm xác suất theo tỷ lệ tấn công của bạn
homoglyph-detector x.vn --brands "org.json#sha256=<mã>"   # thêm brand database của tổ chức
homoglyph-detector --verify                          # kiểm tra toàn vẹn dữ liệu đi kèm
```

| Mã thoát | Ý nghĩa |
|---|---|
| 0 | tất cả SAFE |
| 1 | có SUSPICIOUS, gồm cả đầu vào không chấm được (`parse_status` khác `ok`) |
| 2 | có MALICIOUS |
| 3 | dữ liệu không qua kiểm tra, file không phải UTF-8, hoặc lô vượt giới hạn; không đưa kết luận |

Dùng như thư viện:

```python
from homoglyph_detector import analyze

report = analyze("pаypal.com", policy="browser")
report.verdict                  # 'MALICIOUS'
report.findings                 # bằng chứng: engine, kind, severity, message
report.to_integration_dict()    # bản lược cho tích hợp; report.to_dict() là bản đầy đủ
```

**Giới hạn:** phần được quét (host, tên hiển thị, userinfo, phần local của email) tối đa 272 điểm mã, cả đầu vào tối đa 8.192; một lô CLI tối đa 256 đầu vào và 65.536 điểm mã. Đầu vào công cụ không đọc được (quá dài, scheme như `git://`, ký tự mới hơn Unicode của Python) ra SUSPICIOUS với `parse_status=unsupported`; URL mà trình duyệt từ chối ra `parse_status=rejected`. Chi tiết: [docs/integration.md](docs/integration.md).

## Chất lượng

| Đo trên | Kết quả chính | Báo cáo |
|---|---|---|
| 271.231 host phishing thật (OpenPhish) và 41.620 domain hợp lệ (CrUX) | báo nhầm tối đa 0,3% ở mọi khu vực (profile `default`); phát hiện 99,6% phishing nhắc thương hiệu được bảo vệ | [benchmark/REAL_WORLD.md](benchmark/REAL_WORLD.md) |
| benchmark tổng hợp (dnstwist + OpenDNS), tập test | F1 92,5%, báo nhầm 1,6% ở p ≥ 0,5 | [benchmark/RESULTS.md](benchmark/RESULTS.md) |

Đọc đúng các con số này:
- **Con số 99,6% gần như tự đúng.** "Trong phạm vi" được định nghĩa bằng việc có nhắc tên thương hiệu, và phần lớn số đó là ghép tên thương hiệu, không phải ký tự trông giống.
- **Chỉ 3,4% phishing thật nhắc tới thương hiệu được bảo vệ**, nên tỷ lệ phát hiện trên toàn bộ phishing là 3,4%.

Các file báo cáo do script sinh ra; cách đọc số liệu: [docs/benchmark.md](docs/benchmark.md).

## Tài liệu

| Tài liệu | Nội dung |
|---|---|
| [docs/kien-truc.md](docs/kien-truc.md) | luồng xử lý, bản đồ thư mục, **muốn sửa gì thì mở file nào** |
| [docs/ky-thuat.md](docs/ky-thuat.md) | UTS #39, ASCII visual, IDNA2008 + PSL, typosquat / combosquat, các loại bằng chứng |
| [docs/brand-database.md](docs/brand-database.md) | định dạng brand database, các lớp, toàn vẹn, version |
| [docs/risk-scoring.md](docs/risk-scoring.md) | profile rủi ro, ngân sách báo nhầm, điểm vận hành |
| [docs/integration.md](docs/integration.md) | schema tích hợp v1, trạng thái parse |
| [docs/benchmark.md](docs/benchmark.md), [docs/testing.md](docs/testing.md) | cách đo, kỹ thuật kiểm thử, giới hạn |
| [docs/bao-tri.md](docs/bao-tri.md) | **bảo trì**: thêm thương hiệu, sửa báo nhầm, thêm engine, cập nhật dữ liệu, phát hành, tra cứu lỗi |
| [CHANGELOG.md](CHANGELOG.md), [CONTRIBUTING.md](CONTRIBUTING.md) | lịch sử phiên bản, quy trình đóng góp |

## Lộ trình

- Mở rộng brand database theo thương hiệu bị giả mạo nhiều nhất ngoài thực tế (Telegram, USPS, Ledger, Coinbase, MetaMask...).
- Bảo vệ thương hiệu tên ngắn (`zalo-login.com`, `momo-wallet.com`) và lookalike nằm ở subdomain.
- Sửa ngữ nghĩa chữ hoa/thường của `skeleton()`.
- Thay chữ bằng số chưa có trong bảng (`3`→e, `4`→a, `7`→t): mới bắt được 47% ở kiểm thử adversarial.
- Chế độ `.eml`, ký số brand database (Ed25519), báo cáo HTML cho chạy hàng loạt.

Mọi thay đổi về phát hiện phải qua cổng chất lượng: không làm thêm quá 5 domain hợp lệ bị gắn cờ trên web thật, không mất tấn công đã bắt được, và tăng recall trên nhóm mục tiêu.

## Giấy phép

Code: [MIT](LICENSE). Các file dữ liệu Unicode trong `src/homoglyph_detector/data/` (mọi file `.txt`) thuộc © Unicode, Inc., phân phối theo [Unicode License v3](https://www.unicode.org/license.txt).
