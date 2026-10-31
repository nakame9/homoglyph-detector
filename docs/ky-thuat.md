# Các kỹ thuật phát hiện

Mục lục:
1. [Unicode UTS #39 Confusable Detection](#1-unicode-uts-39-confusable-detection) — engine `unicode`, `brand`
2. [ASCII Visual Confusable Detection](#2-ascii-visual-confusable-detection) — engine `visual`
3. [IDNA2008 và Public Suffix List](#3-idna2008-và-public-suffix-list) — `context.py`, engine `idna`
4. [Typosquat và combosquat](#4-typosquat-và-combosquat) — engine `brand`, `combosquat`

Bối cảnh tấn công: kẻ gian đăng ký tên miền *trông giống* thương hiệu, như `pаypal.com` (chữ `а` Cyrillic), `аррӏе.com` (toàn bộ là chữ Cyrillic), `rnicrosoft.com` (`rn` ≈ `m`), `5hopee.vn` hay `pay<U+200B>pal.com` (có ký tự vô hình). MITRE ATT&CK: [T1583.001 Acquire Infrastructure: Domains](https://attack.mitre.org/techniques/T1583/001/), dùng cho [T1566 Phishing](https://attack.mitre.org/techniques/T1566/).

---

## 1. Unicode UTS #39 Confusable Detection

[UTS #39 *Unicode Security Mechanisms*](https://www.unicode.org/reports/tr39/) là chuẩn mà trình duyệt, nhà đăng ký tên miền và ICU SpoofChecker dùng để chống chữ trông giống nhau. Dự án cài đặt trực tiếp các cơ chế của chuẩn trong `unicode_data.py`, trên dữ liệu Unicode 18 chính thức.

| Mục UTS #39 | Làm gì | Hàm | Ví dụ |
|---|---|---|---|
| §4 *skeleton* | NFD → bỏ ký tự default-ignorable → thay mỗi ký tự bằng "nguyên mẫu" trong `confusables.txt` → NFD. Hai chuỗi trông giống nhau khi skeleton bằng nhau | `skeleton()` | `pаypal`, `paypa1`, `paypal` có cùng skeleton |
| §4 *single-script confusable* | giống nhau và gộp lại vẫn chỉ dùng một script | `confusable_type()` | `rnicrosoft` ↔ `microsoft` |
| §4 *mixed-script confusable* | giống nhau nhưng cần nhiều script | `confusable_type()` | `pаypal` ↔ `paypal` |
| §4 *whole-script confusable* | mỗi chuỗi chỉ một script, nhưng khác script nhau; khó phát hiện nhất vì trình duyệt vẫn hiển thị bình thường | `confusable_type()` | `аррӏе` (Cyrillic) ↔ `apple` |
| §5.1 phát hiện trộn script | *resolved script set*: giao Script_Extensions của mọi ký tự, có mở rộng cho CJK (Hán + Hiragana = tiếng Nhật). Rỗng nghĩa là trộn script | `resolved_script_set()` | `東京とうきょ` là một script (tiếng Nhật) |
| §5.2 restriction level | 6 mức từ ASCII-Only đến Unrestricted, dùng General Security Profile (`IdentifierStatus.txt`) | `restriction_level()` | `abcلعربية` = Moderately, `pаypal` = Minimally |
| §5.3 trộn hệ chữ số | chữ số từ các hệ đếm khác nhau | `numbering_systems()` | `ab1٣` (1 ASCII + 3 Ả Rập) |
| §5.4 hidden overlay | cùng một dấu chồng hai lần lên một chữ | `repeated_marks()` | `café́` |
| default-ignorable | ký tự hiển thị như không có gì (`DerivedCoreProperties.txt`): bị bỏ khỏi skeleton và báo cáo | `is_default_ignorable()` | `pay<U+200B>pal`, `pay<U+00AD>pal` |
| bidi control | ký tự đảo chiều hiển thị (`PropList.txt`), kiểu tấn công Trojan Source / đổi tên file bằng RLO | `is_bidi_control()` | `invoice<U+202E>fdp.exe` hiển thị thành `invoiceexe.pdf` |

Một số chi tiết:
- Skeleton được chuyển thành chữ thường vì tên miền không phân biệt hoa thường, nên `0` (nguyên mẫu `O`) trùng với `o`. Skeleton có thể trông lạ: `m` thành `rn`, nên `paypal.com` → `paypal.corn`; đó là đúng chuẩn.
- Từng chữ "trông giống" riêng lẻ chỉ ở mức `info`: chữ `а` trong một từ tiếng Nga thì đơn giản là tiếng Nga. Bằng chứng thật nằm ở cấp nhãn (trộn script, cả nhãn trông như ASCII, khớp thương hiệu).
- Tiếng Việt là trường hợp kiểm thử bắt buộc: `tiếngviệt.vn` và `Nguyễn Văn A` là chữ Latin có dấu, không được bị gắn cờ.

Dữ liệu Unicode và cách cập nhật: xem [brand database và dữ liệu](brand-database.md#dữ-liệu-unicode) và [bảo trì](bao-tri.md#cập-nhật-dữ-liệu-unicode).

---

## 2. ASCII Visual Confusable Detection

Nhiều tên miền lừa đảo không dùng Unicode. UTS #39 chỉ liệt kê các cặp *giống hệt* (`0`/`o`, `1`/`l`, `m`/`rn` trong số ký tự tên miền), nên `5hopee` hay `vvhatsapp` không phải "confusable" theo chuẩn, nhưng người đọc vội vẫn thấy `shopee` và `whatsapp`. `visual.py` lấp khoảng trống này:

| | Làm gì | Ví dụ |
|---|---|---|
| **A. Thay một ký tự** | một ký tự tên miền bằng một ký tự trông giống | `5hopee` (5→s), `paypai` (i→l), `qoogle` (q→g) |
| **B. Thay cụm ký tự** | nhiều ký tự viết liền trông như một | `vvhatsapp` (vv→w), `clropbox` (cl→d), `nnicrosoft` (nn→m) |
| **C. Chấm điểm độ giống** | khoảng cách sửa chuỗi có trọng số: thay bằng ký tự trông giống tốn `1 − độ giống`, sửa khác tốn 1; điểm = `1 − khoảng cách / độ dài` | `5hopee`/`shopee` = 0.95 |
| **Chữ có dấu** | đọc skeleton bỏ dấu, mỗi dấu bị bỏ tốn 0.2 | `gmăįl` ~ `gmail`, `amažoṉ` ~ `amazon` |

- **Trọng số lấy từ đâu:** cặp giống hệt lấy tự động từ `confusables.txt` (chi phí 0). Chỉ các cặp *gần giống* nằm trong bảng `NEAR` nhỏ, giới hạn ở `a-z 0-9 -`, nên không phụ thuộc phiên bản Unicode. Test báo lỗi nếu một cặp `NEAR` trở thành "giống hệt" trong dữ liệu chính thức.
- **Gõ sai không phải giả mạo hình ảnh:** thay ký tự ngoài bảng tốn trọn 1, nên `paypak`, `shoppe` (khoảng cách 1.0) chỉ là typosquat. Khoảng cách ≤ 0.5 (tối đa "nửa ký tự" khác biệt) được báo `brand_visual`.
- So sánh cả từng phần tách theo dấu `-` (`paypai-login.com`) và tên hiển thị (`5hopee Official`).
- Điểm liên tục `1 − khoảng cách` là đầu vào của fusion; ngưỡng thật do benchmark quyết định.

---

## 3. IDNA2008 và Public Suffix List

Mọi host (từ domain, email, URL) đi qua pipeline trong `context.py`, sau đó engine `idna` ghi bằng chứng:

| # | Bước | Cách làm | Loại bằng chứng |
|---|---|---|---|
| 1 | Đầu vào thô | lấy host từ domain / `user@host` / URL (không tự hạ chữ hoa non-ASCII) | |
| 2 | Chuẩn hóa Unicode | **chỉ NFC** (tương đương chính tắc, không đổi nghĩa) và hạ chữ hoa ASCII; không NFKC hay mapping tự chế | `not_nfc` |
| 3 | Kiểm tra IDNA2008 | `idna.encode()` strict ([RFC 5891](https://www.rfc-editor.org/rfc/rfc5891)): lớp code point (RFC 5892), CONTEXTJ / CONTEXTO, bidi rule ([RFC 5893](https://www.rfc-editor.org/rfc/rfc5893)), dấu gạch nối, nhãn ≤ 63 và domain ≤ 253 octet. Nếu strict thất bại, mapping [UTS #46](https://www.unicode.org/reports/tr46/) cho biết trình duyệt thật sự truy cập domain nào | `idna_bidi`, `idna_context`, `idna_disallowed`, `idna_length`, `idna_invalid`, `idna_mapped` |
| 4 | A-label ↔ U-label | nhãn `xn--` chỉ hiển thị thành U-label nếu `idna` chấp nhận: giải mã punycode thành công **không** có nghĩa là IDN hợp lệ. A → U → A phải khớp | `punycode`, `idna_roundtrip` |
| 5 | Public Suffix List | `publicsuffixlist` (có sẵn PSL, cả phần ICANN lẫn **private**) tìm domain đăng ký: `login.vietcombank.com.vn` → `vietcombank.com.vn`; `pаypal.github.io` là một site riêng | |
| 6 | So sánh skeleton | kiểm tra ký tự trên **chuỗi người đọc thấy**, so khớp thương hiệu trên **domain thật sự được truy cập** | |
| 7 | Chấm điểm | fusion đã hiệu chỉnh (xem [benchmark](benchmark.md)) | |

Engine `idna` có trọng số 0 sau hiệu chỉnh: một chuỗi không hợp lệ theo IDNA thì không truy cập được, nên nó giải thích chứ không dự đoán tấn công. Bằng chứng của nó vẫn có trong báo cáo.

---

## 4. Typosquat và combosquat

**Engine `brand`** — giả mạo danh tính thương hiệu:
- domain đăng ký có cùng skeleton với domain chính thức → `brand_homograph` (critical);
- tên site có cùng skeleton với từ khóa thương hiệu → `brand_homograph` (high);
- cách đúng một lần sửa so với từ khóa hoặc tên domain chính thức (`office` từ `office.com`) → `brand_typosquat`. Khoảng cách dùng *optimal string alignment* (tính cả hoán vị hai ký tự kề nhau như `amaozn`), trên cả dạng gốc lẫn skeleton.

**Engine `combosquat`** — tên thương hiệu đặt trên domain không chính thức:
- tên site đúng bằng từ khóa nhưng khác đuôi → `brand_unofficial` (`google.ca`);
- từ khóa nằm trong host, kể cả khi bị chia bởi dấu chấm / gạch → `brand_in_host` (`paypal-login.com`, `am.azon.com`).

Tách combosquat thành engine riêng là một phát hiện từ benchmark: domain thật của chính thương hiệu (`amazon.co.uk`, `google-analytics.com`) và combosquat lừa đảo có cùng dạng, nên cần một trọng số riêng học từ dữ liệu.

**So với dnstwist:** [dnstwist](https://github.com/elceef/dnstwist) *sinh* biến thể của domain **của bạn** để theo dõi. Công cụ này làm chiều ngược lại: nhận **bất kỳ** đầu vào nào (địa chỉ người gửi, URL trong log, tên người dùng) và cho biết nó có giả mạo ai không. dnstwist cũng chính là nguồn sinh tấn công cho benchmark của dự án.
