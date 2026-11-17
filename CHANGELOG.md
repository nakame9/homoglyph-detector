# Nhật ký thay đổi

Định dạng theo [Keep a Changelog](https://keepachangelog.com/vi/1.1.0/), đánh số theo [Semantic Versioning](https://semver.org/lang/vi/).

## [Chưa phát hành]
### Sửa
- **Brand DB chuẩn hóa A-label và U-label** trước khi so allowlist, đối chiếu Public Suffix List và kiểm tra domain trùng.
- **Đọc URL như browser (WHATWG).** Scheme đặc biệt bỏ qua mọi dấu `/` và `\` sau dấu `:`. Vì vậy `https:///paypаl.com/`, `https:/…` và `https:…` (chữ `а` Cyrillic) không còn mất host. `paypаl.com/?q=https://x.org/` không còn bị coi là URL có scheme. Tab và xuống dòng trong URL bị bỏ qua. Ba ca này trước đây ra SAFE, nay ra MALICIOUS.
- Port được tách trên authority gốc, trước khi giải mã host. `https://paypal.com%3A443/` không còn được nhận là domain chính thức của PayPal.
- Userinfo chứa đường dẫn đã giải mã (`https://paypal.com%2Flogin@evil.com/`, cả `%3F` và `%5C`) trước đây ra SAFE. Nay vẫn nhận ra `paypal.com` và ra MALICIOUS, finding nêu đúng thương hiệu và đích `evil.com`.
- **Userinfo mang thương hiệu khác host đích (P2).** Allowlist chỉ miễn kiểm tra giả mạo trên host đích. `https://paypal.com@apple.com/` trước đây ra SAFE, nay có finding `brand_in_userinfo` (medium, `detail.destination_brand`) và ra SUSPICIOUS ở `default`, MALICIOUS ở `banking` (một ngưỡng chung), SAFE ở `browser`. Userinfo cùng thương hiệu (`www.paypal.com@paypal.com`) và username thường (`john.doe@`, `user:pass@`) không bị báo.
- **Đầu vào không còn điều khiển được terminal.** Báo cáo văn bản hiển thị ký tự điều khiển (C0 như ESC, CR, LF; DEL; C1), ký tự định dạng (bidi, zero-width, tag), ký tự ngắt dòng hay đoạn Unicode và mọi ký tự default-ignorable dưới dạng `<U+XXXX>`. Quy tắc này áp dụng cho mọi trường lấy từ đầu vào hoặc Brand DB: input, decoded, a-label, `skeleton` (trước đây in thô), finding, thông báo lỗi và dòng `brands:` của `--version`. Vì vậy chuỗi ANSI CSI, OSC 8 hay CRLF chèn vào input không thể xóa màn hình, tạo link giả hay giả một dòng kết luận. `--json` thay các ký tự này bằng escape `\uXXXX`. JSON vẫn hợp lệ và `json.loads` trả về đúng giá trị gốc.
### Thêm
- **`Report.parse_status` / `parse_reason`.** URL mà browser từ chối (port sai, `%40` hay `%3A` trong host, IPv4 hoặc IPv6 không hợp lệ, ký tự IDNA không cho phép, ZWJ/ZWNJ sai ngữ cảnh) và đầu vào rỗng có trạng thái `rejected`. Đích của các đầu vào này không được chấm điểm. Verdict là SUSPICIOUS ("cần xem lại"), mã thoát `1`, không bao giờ SAFE. Lỗi cú pháp không còn làm tăng verdict: `https://g00gle.com:abc/` đổi từ MALICIOUS sang SUSPICIOUS. CLI in dòng `parse`.
- Ngoại lệ: ký tự điều khiển định dạng bidi (U+202A–U+202E, U+2066–U+2069) trong host bị từ chối vẫn được chấm, chỉ từ bằng chứng đó và theo ngưỡng của policy đang dùng. URL `https://apple.com/` có U+202E chèn trước host vẫn là MALICIOUS ở cả ba profile.
- **Host là địa chỉ IP** không đi qua các engine tên miền. Dạng chuẩn (`192.168.1.1`, `[::1]`) có finding `ip_host` (info). IPv4 viết lạ (`0x7f.1`, `2130706433`, `0177.0.0.1`, `127.1`) được chuẩn hóa về `127.0.0.1`, có finding `ip_obfuscated` và ra SUSPICIOUS.
- Test đối chiếu với 418 ca URL tuyệt đối trong `urltestdata.json` của web-platform-tests (commit `bff876f9`). Kết quả khớp toàn bộ.
- `--base-rate`: `probability_at_base_rate` là `null` với đầu vào chưa chấm điểm. Trước đây CLI dạng văn bản có thể gặp `TypeError`.
- **Giới hạn từng đầu vào ở 272 điểm mã Unicode.** Đầu vào dài hơn được gửi xem lại (`unsupported/too_long`) trước khi chạy các engine. CLI bỏ phần dư của dòng dài khi đọc file hoặc stdin và không đưa đầu vào dài vào báo cáo.

## [0.13.0] - 2026-11-08
### Thêm
- **Phát hiện lừa bằng userinfo của URL** (`https://paypal.com@evil.com/`, cả dạng `paypal.com:x@`, `paypal.com／@` với gạch chéo fullwidth): finding `brand_in_userinfo` (combosquat, high) khi phần trước `@` là domain hoặc tên của thương hiệu; `userinfo_domain` (idna, medium) khi phần đó trông như một host khác host thật. `Context.userinfo` giữ phần userinfo đã percent-decode.
### Sửa
- URL không có scheme nhưng có userinfo (`paypal.com@evil.com/login`) bị coi là email với host `evil.com/login`; nay đọc như URL, host `evil.com`, giống thanh địa chỉ của browser.
- Golden corpus: bỏ 2 `known_issue` userinfo, thêm 4 ca (`url_edge` 9/9 trên profile default).

## [0.12.0] - 2026-11-03
### Thay đổi
- **Visual similarity không còn tự quyết định MALICIOUS.** MALICIOUS cần ít nhất một bằng chứng mức medium trở lên không dựa trên hình ảnh; nếu không, kết luận dừng ở SUSPICIOUS (`Report.verdict_note`). Áp dụng ở mọi profile.
- Cặp ASCII trong `confusables.txt` (`rn`/`m`, `0`/`o`, `1`/`l`) được xếp là bằng chứng hình ảnh (phụ thuộc font), không phải bằng chứng Unicode. `rnicrosoft.com`, `g00gle.com`, `5hopee.vn`, `vvhatsapp.com` chuyển từ MALICIOUS sang SUSPICIOUS.
### Thêm
- Mỗi finding có `evidence` (`unicode_confusable`, `visual_similarity`, `brand_impersonation`, `protocol`); bằng chứng thương hiệu có `detail.basis` (`unicode`, `visual`, `spelling`, `name`). `Report.evidence` tóm tắt theo loại; CLI in dòng `evidence` và `note`.
- Đo chi phí và lợi ích: benchmark tổng hợp (recall MALICIOUS default 63,5% → 55,9%, FPR không đổi) và web thật (báo nhầm MALICIOUS banking 122 → 119 trên 41.620 domain, 2–3 / 9.377 phishing trong phạm vi hạ xuống SUSPICIOUS).

## [0.11.0] - 2026-11-03
### Thêm
- Đánh giá thực tế (`benchmark/real_world.py`, `benchmark/REAL_WORLD.md`): 271.231 host phishing thật từ lịch sử OpenPhish (10/2024 → 11/2026), 41.620 domain hợp lệ quốc tế từ Chrome UX Report top 1 triệu, temporal validation (mốc 01/05/2026), leave-one-technique-out, 203 biến thể adversarial từ 11 kỹ thuật mới, Brier / ECE / reliability diagram.
- Hiệu chỉnh theo tỷ lệ tấn công của môi trường (Bayes prior shift): `--base-rate`, `analyze(base_rate=...)`, `Report.probability_at_base_rate`; `calibration.json` lưu `train_prior`.
- README tách số liệu thực tế khỏi số liệu benchmark tổng hợp; lộ trình theo các lỗ hổng đo được.
### Sửa
- Chữ Latin có dấu / chữ ghép (`mæglerhuset.dk`, `borsaekranı.com`) bị coi là whole-script look-alike: báo nhầm trên IDN hợp lệ từ 0,3% xuống 0,1% (profile `browser`: 0,2% → 0%). Phát hiện nhờ dữ liệu thật.

## [0.10.1] - 2026-11-03
### Sửa
- Test `test_documented_differences[Ⱥ.com]` thất bại trên Python 3.10.20 và 3.12.3: codec IDNA2003 của CPython cho kết quả khác nhau theo bản vá với ký tự thêm sau Unicode 3.2. Thay bằng test chấp nhận cả hai hành vi và kiểm tra engine báo đúng theo bản đang chạy.
### Thêm
- CI chạy đủ Python 3.10, 3.11, 3.12, 3.13 (trước đây chỉ 3.10 và 3.13), và một job cài đúng phiên bản thấp nhất cho phép của mọi phụ thuộc (`uv --resolution lowest-direct`).
- README ghi bảng phiên bản phụ thuộc đã kiểm chứng và lý do của mức tối thiểu `idna>=3.20`.

## [0.10.0] - 2026-10-31
### Thêm
- Property-based testing và fuzzing Unicode với Hypothesis (`tests/test_properties.py`); profile `dev` / `ci` / `deep`.
- Differential testing IDNA2003 (codec của Python) và IDNA2008 + UTS #46 (`tests/test_idna_differential.py`).
- Golden corpus 142 ca cho 10 nhóm bắt buộc và regression snapshot (`tests/golden/`); lỗi đã biết chạy dưới dạng xfail nghiêm ngặt.
- Engine `idna` báo `idna_differential` khi phần mềm IDNA2003 và trình duyệt dẫn tới hai domain khác nhau (`faß.de`, `Ⱥ.com`).
- Đo FNR, độ trễ phát hiện (p50 / p95 / p99, thông lượng), kết quả golden theo nhóm và mục tiêu kỹ thuật trong `RESULTS.md`; test ngân sách độ trễ.
- `docs/testing.md`.
### Sửa
- URL `https://evil.com\@paypal.com/` được hiểu là `paypal.com` trong khi trình duyệt vào `evil.com` (vượt bộ lọc); host được tách theo WHATWG: `\` như `/`, giải mã `%2e`.
- URL chứa `／`, `＠`, `：` fullwidth hoặc `[` làm crash (từ chối dịch vụ khi xử lý hàng loạt).
- `paypal.com/login`, `paypal.com:443`, `//paypal.com/x` bị coi là domain không hợp lệ.
- Latin + chữ Nhật / Trung / Hàn (mức Highly Restrictive) bị coi là trộn script.
- Từ Cyrillic trông như Latin dưới TLD cùng script (`орех.рф`) bị chặn; nay theo chính sách IDN của Chromium.

## [0.9.0] - 2026-10-31
### Thêm
- Domain Risk Scoring theo môi trường: profile rủi ro `default`, `banking`, `browser`, chọn ngưỡng trên tập train theo mục tiêu tỷ lệ báo nhầm và đo lại trên tập test.
- Ngân sách báo nhầm riêng: `--max-fpr S,M` (CLI) và `custom_profile()` (thư viện), dựa trên đường cong vận hành lưu trong `calibration.json`.
- `--profile`, biến môi trường `HOMOGLYPH_PROFILE`, `--profiles`; trường `profile` và `thresholds` trong báo cáo.
- `docs/risk-scoring.md`; bảng profile và điểm vận hành trong `benchmark/RESULTS.md`.
### Thay đổi
- `analyze()` nhận tham số `policy`; `calibration.json` thay `thresholds` bằng `profiles`, `operating_points`, `operating_curve`.

## [0.8.0] - 2026-10-31
### Thay đổi
- Tổ chức lại repo để dễ quản lý: mỗi engine một file trong `src/homoglyph_detector/engines/` (trước đây gộp trong `engines.py`); hành vi và trọng số hiệu chỉnh giữ nguyên.
- README viết lại bằng tiếng Việt, ngắn gọn; tài liệu chi tiết chuyển sang `docs/` (kiến trúc, kỹ thuật, brand database, benchmark, hướng dẫn bảo trì và tra cứu lỗi).
- Báo cáo `benchmark/RESULTS.md` sinh bằng tiếng Việt.
### Thêm
- `CHANGELOG.md`, `CONTRIBUTING.md`, mẫu issue (báo lỗi, báo nhầm / bỏ lọt, đề xuất thương hiệu) và mẫu pull request có danh sách kiểm tra.

## [0.7.0] - 2026-10-31
### Thêm
- Brand Intelligence Database: thương hiệu nằm trong JSON có schema và version; database của tổ chức nạp qua `--brands` hoặc `HOMOGLYPH_BRANDS`, gộp theo `id`.
- Kiểm tra hợp lệ: cấm hậu tố công cộng làm domain chính thức, cấm một domain thuộc hai thương hiệu.
- Kiểm tra toàn vẹn: mọi file dữ liệu ghim SHA-256 trong `data/MANIFEST.json`; dữ liệu bị sửa thì dừng với mã thoát 3. Ghim database ngoài bằng `path#sha256=HEX`.
- `scripts/seal_data.py` bắt buộc tăng version khi `brands.json` đổi; `--verify`, `--version`; trường `brand_db` trong báo cáo.

## [0.6.0] - 2026-10-31
### Thêm
- Detection engine nhiều lớp: 5 engine độc lập (unicode, idna, brand, combosquat, visual), mỗi engine trả điểm và bằng chứng.
- Tầng hợp nhất logistic regression đã hiệu chỉnh: xác suất, risk 0–100, verdict.
- Benchmark 15.805 domain từ nguồn độc lập (dnstwist, OpenDNS top 10k); CI kiểm tra hiệu chỉnh tái tạo được.
### Sửa
- Rò rỉ "punycode = tấn công", khoảng cách typosquat trên skeleton, lỗi hoán vị, homoglyph có dấu, đếm trùng bằng chứng (phát hiện nhờ benchmark).

## [0.5.0] - 2026-10-31
### Thêm
- ASCII Visual Confusable Detection: thay ký tự (5→s), thay cụm ký tự (vv→w, cl→d), chấm điểm độ giống hình ảnh. Thêm WhatsApp, Dropbox.

## [0.4.0] - 2026-10-31
### Thêm
- Kiểm tra IDNA2008 (strict + UTS #46), round-trip A-label / U-label, độ dài, bidi rule, CONTEXTJ / CONTEXTO.
- Public Suffix List (`publicsuffixlist`) thay cho bảng đoán đuôi tên miền.

## [0.3.0] - 2026-10-31
### Thêm
- Phát hiện bidi control và default-ignorable từ dữ liệu Unicode chính thức.
- Script cập nhật dữ liệu Unicode có kiểm tra phiên bản, test tương thích dữ liệu, workflow kiểm tra hằng tháng.
- Báo cáo in ký tự ẩn dạng `<U+XXXX>`.

## [0.2.0] - 2026-10-31
### Thêm
- Đầy đủ UTS #39: Script_Extensions, resolved script set, restriction level, phân loại single / mixed / whole-script confusable, trộn hệ chữ số, hidden overlay.

## [0.1.0] - 2026-10-31
### Thêm
- Bản đầu tiên: giải mã punycode, skeleton UTS #39, so khớp thương hiệu có allowlist, CLI, JSON, test, CI.
