# Nhật ký thay đổi

Định dạng theo [Keep a Changelog](https://keepachangelog.com/vi/1.1.0/), đánh số theo [Semantic Versioning](https://semver.org/lang/vi/).

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
