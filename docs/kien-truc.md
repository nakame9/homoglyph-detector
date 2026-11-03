# Kiến trúc

Tài liệu này mô tả cách các phần của dự án ghép với nhau, để khi cần sửa bạn biết ngay phải mở file nào.

## Luồng xử lý

```
đầu vào (domain / email / URL / tên hiển thị)
   │
   ▼
prepare()            context.py      chỉ biến đổi, không kết luận:
                                     tách loại đầu vào, NFC, IDNA A-label/U-label, Public Suffix List
   │  Context (dùng chung, chỉ đọc)
   ├──► unicode      engines/unicode_engine.py     ─┐
   ├──► idna         engines/idna_engine.py         │  mỗi engine trả về EngineResult:
   ├──► brand        engines/brand_engine.py        ├─ điểm 0..1 + bằng chứng (findings)
   ├──► combosquat   engines/combosquat_engine.py   │  không engine nào đọc kết quả engine khác
   └──► visual       engines/visual_engine.py      ─┘
   │
   ▼
fusion               scoring.py      p = sigmoid(bias + Σ trọng_số × điểm)
                                     trọng số lấy từ data/calibration.json (do benchmark sinh ra)
   │
   ▼
chính sách           scoring.py      profile (default / banking / browser) hoặc --max-fpr
                                     -> hai ngưỡng -> SAFE / SUSPICIOUS / MALICIOUS
   │
   ▼
Report               analyzer.py     xác suất, risk 0–100, verdict, điểm từng engine,
                                     bằng chứng, brand database đã dùng
```

Mọi file dữ liệu đều được đọc qua `integrity.read_verified()`. Hàm này kiểm tra SHA-256 với `data/MANIFEST.json` trước khi trả nội dung.

## Bản đồ thư mục

```
homoglyph-detector/
├── src/homoglyph_detector/
│   ├── cli.py                  giao diện dòng lệnh, mã thoát, in báo cáo an toàn (<U+XXXX>)
│   ├── analyzer.py             điều phối: prepare -> engines -> fusion -> Report
│   ├── context.py              tiền xử lý dùng chung (parse, NFC, IDNA, PSL)
│   ├── engines/                5 engine độc lập, mỗi engine một file
│   │   ├── base.py             Finding, EngineResult, noisy-OR, is_official
│   │   ├── unicode_engine.py
│   │   ├── idna_engine.py
│   │   ├── brand_engine.py
│   │   ├── combosquat_engine.py
│   │   └── visual_engine.py
│   ├── scoring.py              hợp nhất điểm -> xác suất; profile rủi ro -> verdict
│   ├── brands.py               Brand Intelligence Database: nạp, kiểm tra, ghim, gộp
│   ├── integrity.py            kiểm tra SHA-256 mọi file dữ liệu theo MANIFEST.json
│   ├── unicode_data.py         thuật toán UTS #39: skeleton, script, restriction level
│   ├── visual.py               thuật toán độ giống hình ảnh ASCII (bảng NEAR, khoảng cách có trọng số)
│   └── data/                   dữ liệu, KHÔNG sửa tay rồi bỏ qua bước niêm phong
│       ├── *.txt               dữ liệu Unicode 18 chính thức
│       ├── brands.json         brand database đi kèm (có version)
│       ├── calibration.json    trọng số fusion do benchmark sinh ra
│       └── MANIFEST.json       SHA-256 + version của từng file trên
├── benchmark/
│   ├── build_dataset.py        tạo bộ dữ liệu có nhãn (dnstwist + OpenDNS top 10k)
│   ├── dataset.jsonl           bộ dữ liệu (ASCII thuần, escape JSON)
│   ├── calibrate.py            hiệu chỉnh fusion, ghi calibration.json + RESULTS.md, tự niêm phong
│   ├── real_world.py           đánh giá trên phishing thật / web thật, temporal, adversarial, calibration
│   ├── REAL_WORLD.md           báo cáo đánh giá thực tế (tự sinh)
│   ├── adversarial.jsonl       biến thể tấn công với kỹ thuật chưa từng dùng khi phát triển
│   └── RESULTS.md              báo cáo kết quả (tự sinh)
├── scripts/
│   ├── update_unicode_data.py  tải dữ liệu Unicode mới từ unicode.org, tự niêm phong
│   └── seal_data.py            ghim dữ liệu vào MANIFEST.json, bắt buộc tăng version brand
├── tests/                      pytest, Hypothesis, differential, golden corpus (xem testing.md)
│   ├── golden/corpus.jsonl     142 ca gán nhãn thủ công cho 10 nhóm bắt buộc
│   └── golden/snapshot.jsonl   kết quả đã review của từng ca (regression)
├── examples/                   domain mẫu, brand database mẫu cho tổ chức
├── docs/                       tài liệu (thư mục này)
└── .github/                    CI, kiểm tra dữ liệu Unicode hằng tháng, mẫu issue / PR
```

## Muốn sửa gì thì mở file nào

| Muốn | Sửa ở | Sau đó chạy |
|---|---|---|
| Thêm / sửa thương hiệu được bảo vệ | `data/brands.json` (tăng `version`) | `seal_data.py`, rồi build dataset + calibrate (xem [bảo trì](bao-tri.md)) |
| Dùng thương hiệu riêng của tổ chức | file JSON riêng + `--brands` | không cần sửa repo |
| Thêm cặp ký tự ASCII trông giống (5/s, vv/w) | `visual.py`, bảng `NEAR` | `pytest tests/test_visual.py`, calibrate |
| Sửa cách phát hiện trộn script, ký tự ẩn, bidi | `engines/unicode_engine.py` | pytest, calibrate |
| Sửa luật IDNA2008 | `engines/idna_engine.py`, `context.py` | pytest, calibrate |
| Sửa luật typosquat / homograph thương hiệu | `engines/brand_engine.py` | pytest, calibrate |
| Sửa luật combosquat | `engines/combosquat_engine.py` | pytest, calibrate |
| Thêm / sửa profile rủi ro (ngưỡng theo môi trường) | `PROFILES` trong `benchmark/calibrate.py` | calibrate (xem [risk scoring](risk-scoring.md)) |
| Dùng ngưỡng riêng cho một hệ thống | `--profile` / `--max-fpr` / `HOMOGLYPH_PROFILE` | không cần sửa repo |
| Thêm engine mới | file mới trong `engines/` + đăng ký trong `engines/__init__.py` | pytest, calibrate |
| Đổi cách in kết quả | `cli.py` (`render`) | pytest |
| Thêm trường vào kết quả JSON | `analyzer.py` (`Report`) | pytest |
| Cập nhật dữ liệu Unicode | `scripts/update_unicode_data.py` | pytest |

Quy tắc chung: **mọi thay đổi làm đổi điểm của engine đều phải hiệu chỉnh lại**. CI sẽ báo lỗi nếu `calibration.json` không khớp với code.

## Các khái niệm chính

**Context** (`context.py`) là kết quả tiền xử lý, dùng chung cho mọi engine:

| Trường | Ý nghĩa |
|---|---|
| `input_type` | `domain`, `email`, `url` hoặc `name` |
| `text` | thứ người đọc nhìn thấy (A-label đã hiện thành U-label) |
| `host` | host như được viết (NFC, chữ ASCII viết thường) |
| `a_label` | domain mà DNS thật sự thấy; rỗng nếu không resolver nào chấp nhận |
| `resolved` | dạng U-label của `a_label`: domain thật sự được truy cập |
| `strict_error`, `lookup_error` | lý do không hợp lệ theo IDNA2008 strict / UTS #46 |

**EngineResult** (`engines/base.py`): `score` từ 0 đến 1, danh sách `findings`, và `facts` (thông tin không tính điểm, ví dụ restriction level). Điểm là noisy-OR của các bằng chứng; nhiều bằng chứng cùng loại chỉ tính một lần.

**Finding**: `engine`, `kind`, `severity` (`info` / `low` / `medium` / `high` / `critical`), `message` và `detail`.

**Report** (`analyzer.py`), cũng là kết quả JSON:

| Trường | Ý nghĩa |
|---|---|
| `verdict` | `SAFE`, `SUSPICIOUS`, `MALICIOUS` |
| `probability`, `risk_score` | xác suất đã hiệu chỉnh, và cùng giá trị đó theo thang 0–100 (giống nhau ở mọi môi trường) |
| `profile`, `thresholds` | chính sách rủi ro đã dùng và hai ngưỡng của nó (khác nhau theo môi trường) |
| `engine_scores` | điểm thô của từng engine |
| `findings` | bằng chứng, gắn tên engine tạo ra nó |
| `target`, `a_label`, `skeleton`, `restriction_level` | thông tin phân tích |
| `brand_db` | các brand database đã dùng: tên, version, sha256, cách xác minh |

## Mã thoát của CLI

| Mã | Ý nghĩa |
|---|---|
| 0 | tất cả SAFE |
| 1 | có ít nhất một SUSPICIOUS |
| 2 | có ít nhất một MALICIOUS |
| 3 | dữ liệu không qua kiểm tra toàn vẹn hoặc hợp lệ: **không đưa ra kết luận** |

## Nguyên tắc thiết kế

- **Engine độc lập.** Engine chỉ đọc Context, không đọc kết quả engine khác. Test `test_engines_are_independent` kiểm tra điều này.
- **Không đặt điểm bằng tay.** Trọng số fusion được học từ benchmark; trọng số ≥ 0 nên thêm bằng chứng không bao giờ làm giảm rủi ro.
- **Dữ liệu chính thức, có ghim.** Dữ liệu Unicode lấy từ unicode.org; mọi file dữ liệu được ghim SHA-256; dữ liệu bị sửa thì công cụ dừng (fail closed).
- **Không tin chuỗi người dùng nhập.** Báo cáo in ký tự ẩn / bidi dưới dạng `<U+XXXX>`; repo không được chứa ký tự ẩn thật (test tự quét).
