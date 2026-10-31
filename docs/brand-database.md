# Brand Intelligence Database và dữ liệu

Danh sách thương hiệu cần bảo vệ là **dữ liệu, không phải code**. `brands.py` nạp các *brand database* (file JSON có schema, phiên bản và nguồn gốc), kiểm tra hợp lệ, xác minh toàn vẹn rồi gộp lại.

## Định dạng

```json
{
  "schema": 1,
  "name": "ACME Bank brands",
  "version": "1.2.0",
  "updated": "2026-10-31",
  "brands": [
    {"id": "acmebank", "name": "ACME Bank", "category": "banking", "country": "VN",
     "domains": ["acmebank.vn", "acme-bank.com.vn"], "keywords": ["acmebank"]}
  ]
}
```

| Trường | Bắt buộc | Ý nghĩa |
|---|---|---|
| `schema` | có | luôn là `1` |
| `name` | có | tên database, hiện trong mọi báo cáo |
| `version` | có | `MAJOR.MINOR.PATCH`; **phải tăng khi nội dung đổi** |
| `updated` | có | `YYYY-MM-DD` |
| `brands[].id` | có | định danh duy nhất (`a-z 0-9 -`), dùng để gộp và ghi đè |
| `brands[].name` | có | tên hiển thị |
| `brands[].domains` | có | domain **chính thức** (allowlist). Mọi subdomain của chúng cũng được coi là chính thức |
| `brands[].keywords` | có | từ khóa để so typosquat / combosquat / hình ảnh: ASCII thường, ≥ 3 ký tự |
| `brands[].category`, `country` | không | thông tin phân loại |

Database đi kèm (`src/homoglyph_detector/data/brands.json`, version 1.0.0) có 13 thương hiệu: Apple, PayPal, Microsoft, Google, Facebook, Amazon, WhatsApp, Dropbox (toàn cầu) và Vietcombank, Techcombank, MoMo, Shopee, Zalo (Việt Nam).

## Các lớp database

| Lớp | Ở đâu | Mức tin cậy |
|---|---|---|
| đi kèm | `data/brands.json` | ghim SHA-256 trong `data/MANIFEST.json` |
| biến môi trường | `HOMOGLYPH_BRANDS=/etc/acme/brands.json` (nhiều file ngăn bởi `:`, trên Windows là `;`) | ghim được nếu viết `path#sha256=HEX` |
| dòng lệnh | `--brands FILE[#sha256=HEX]`, dùng được nhiều lần | như trên |

Các lớp gộp theo `id`, lớp sau ghi đè lớp trước (đi kèm < biến môi trường < dòng lệnh). Nhờ vậy một tổ chức có thể thêm thương hiệu của mình hoặc mở rộng một thương hiệu có sẵn mà không phải sửa package. File mẫu: [`examples/org_brands.json`](../examples/org_brands.json).

```bash
# dùng database của tổ chức, ghim đúng phiên bản đã review
homoglyph-detector acrnebank.vn --brands "examples/org_brands.json#sha256=$(sha256sum examples/org_brands.json | cut -d' ' -f1)"

# kiểm tra toàn vẹn mọi dữ liệu và mọi database đang dùng
homoglyph-detector --verify --brands examples/org_brands.json

# xem phiên bản công cụ, dữ liệu Unicode và từng brand database
homoglyph-detector --version
```

Database không ghim vẫn được dùng nhưng có cảnh báo, kèm sẵn mã SHA-256 để ghim.

## Kiểm tra hợp lệ

Database bị từ chối (mã thoát 3, không đưa ra kết luận) khi nó làm yếu khả năng phát hiện:
- **domain chính thức là hậu tố công cộng** (`github.io`, `com.vn`): allowlist nó nghĩa là tin mọi site bên dưới;
- **một domain thuộc hai thương hiệu**, xét trên mọi database đang nạp: database của tổ chức không thể âm thầm chiếm `paypal.com`;
- domain không phải chữ thường hoặc không hợp lệ theo IDNA2008; từ khóa không phải ASCII thường (engine visual so sánh với nó); `id` trùng; thiếu hoặc sai `version` / `updated` / `schema`.

## Toàn vẹn dữ liệu

`integrity.py` kiểm tra **mọi file trong `data/`** (brand database, dữ liệu Unicode, calibration) với SHA-256 trong `data/MANIFEST.json` trước khi đọc. File bị sửa hoặc không có trong manifest làm công cụ dừng (mã thoát 3), thay vì để một allowlist bị đầu độc quyết định kết luận.

Ví dụ đã kiểm thử: chèn `paypal-secure-login.com` vào allowlist của PayPal trong `brands.json` → công cụ từ chối chạy.

Giới hạn: kiểm tra này chỉ mạnh bằng độ tin cậy của chính bản cài đặt. Kẻ sửa được cả `MANIFEST.json` trong thư mục cài đặt sẽ qua được. Muốn chống cả trường hợp đó cần chữ ký số (ví dụ Ed25519); đây là việc trong lộ trình.

## Đánh phiên bản

- Mỗi database có `version` (semver) và `updated`.
- `scripts/seal_data.py` ghim lại dữ liệu sau một thay đổi đã review, và **từ chối niêm phong `brands.json` đã đổi nội dung mà version không tăng**. CI chạy `seal_data.py --check`.
- Mỗi báo cáo ghi các database đã dùng trong trường `brand_db` (tên, version, sha256, cách xác minh, nguồn), nên mọi kết luận truy vết được đến đúng phiên bản dữ liệu.
- `calibration.json` ghi brand database được dùng khi hiệu chỉnh; một test kiểm tra đó là bản đi kèm. Đổi thương hiệu đi kèm nghĩa là phải chạy lại benchmark (xem [bảo trì](bao-tri.md#thêm-hoặc-sửa-một-thương-hiệu-được-bảo-vệ)).

## Dữ liệu Unicode

Mọi bảng Unicode đều là file chính thức (Unicode 18.0.0), không tự xây.

| File | Nguồn | Dùng cho |
|---|---|---|
| `confusables.txt` | dữ liệu bảo mật UTS #39 | skeleton |
| `IdentifierStatus.txt` | dữ liệu bảo mật UTS #39 | General Security Profile (restriction level) |
| `Scripts.txt`, `ScriptExtensions.txt` | UCD | script, resolved script set |
| `ScriptAliases.txt` | UCD `PropertyValueAliases.txt`, chỉ dòng `sc` | mã script → tên |
| `DefaultIgnorable.txt` | UCD `DerivedCoreProperties.txt`, chỉ `Default_Ignorable_Code_Point` | ký tự vô hình |
| `BidiControl.txt` | UCD `PropList.txt`, chỉ `Bidi_Control` | ký tự điều khiển chiều |

`scripts/update_unicode_data.py` tải tất cả từ unicode.org, **không ghi gì nếu các file lệch phiên bản**, rồi tự niêm phong. `tests/test_unicode_data.py` là bộ kiểm tra tương thích: cùng phiên bản, nguyên mẫu confusable không bị ánh xạ lại, mọi mã script có tên, `idna` dùng cùng phiên bản Unicode. Workflow `Unicode data` trên GitHub chạy hằng tháng và báo lỗi khi có bản mới.

Bảng IDNA đi kèm thư viện `idna`, PSL đi kèm `publicsuffixlist`: cập nhật bằng `pip install -U idna publicsuffixlist`.
