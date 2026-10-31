# Hướng dẫn bảo trì và sửa lỗi

Mỗi mục là một tình huống thường gặp, kèm đúng các lệnh cần chạy. Mọi lệnh chạy từ thư mục gốc của repo.

## Chuẩn bị môi trường

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev,bench]"        # dev = pytest, bench = dnstwist (chỉ để tạo lại benchmark)
pytest -q                            # mọi test phải qua trước khi bắt đầu sửa
```

## Ba lệnh kiểm tra nhanh

```bash
pytest -q                               # toàn bộ test (khoảng 1 giây)
python scripts/seal_data.py --check     # mọi file dữ liệu khớp MANIFEST.json
homoglyph-detector --verify             # kiểm tra toàn vẹn dữ liệu đã cài
```

## Quy tắc vàng

1. **Đổi dữ liệu thì phải niêm phong.** Mọi file trong `src/homoglyph_detector/data/` được ghim SHA-256. Sửa xong chạy `python scripts/seal_data.py`, nếu không công cụ sẽ từ chối chạy (mã thoát 3).
2. **Đổi điểm thì phải hiệu chỉnh lại.** Sửa engine, `brands.json`, bảng `NEAR` hay dữ liệu Unicode đều có thể đổi điểm. Chạy `python benchmark/calibrate.py` (tự niêm phong) rồi commit `calibration.json`, `MANIFEST.json`, `benchmark/RESULTS.md`. CI chạy lại bước này và báo lỗi nếu bạn quên.
3. **Không để ký tự ẩn thật trong repo.** Trong code và test, viết ký tự đặc biệt bằng escape Unicode của Python thay vì dán ký tự thật. Test `test_repository_has_no_hidden_characters` sẽ chỉ đúng file và dòng vi phạm.

## Thêm hoặc sửa một thương hiệu được bảo vệ

1. Sửa `src/homoglyph_detector/data/brands.json`: thêm một mục trong `brands` (xem [brand database](brand-database.md) cho schema). **Tăng `version`** và cập nhật `updated`.
2. Niêm phong. Script sẽ kiểm tra hợp lệ và từ chối nếu chưa tăng version:
   ```bash
   python scripts/seal_data.py
   ```
3. Tạo lại benchmark (cần internet và `dnstwist`), vì tấn công được sinh từ danh sách thương hiệu:
   ```bash
   python benchmark/build_dataset.py
   python benchmark/calibrate.py
   ```
4. Kiểm tra rồi commit `brands.json`, `MANIFEST.json`, `benchmark/dataset.jsonl`, `calibration.json`, `benchmark/RESULTS.md`:
   ```bash
   pytest -q
   ```

Nếu chỉ cần bảo vệ thương hiệu cho **một tổ chức**, đừng sửa repo: viết một file JSON riêng và dùng `--brands` (xem [brand database](brand-database.md)).

## Xử lý một trường hợp báo nhầm hoặc bỏ lọt

1. Tái hiện và xem engine nào gây ra:
   ```bash
   homoglyph-detector "ten-mien-co-van-de.com" --json
   ```
   Xem `engine_scores` và trường `engine` của từng finding.
2. Viết test tái hiện **trước khi sửa**, đặt trong file test của engine liên quan (`tests/test_analyzer.py`, `tests/test_visual.py`, ...).
3. Sửa engine tương ứng (bảng "muốn sửa gì" trong [kiến trúc](kien-truc.md)).
4. Đo lại trên benchmark, để chắc bản sửa không làm hỏng chỗ khác:
   ```bash
   python benchmark/calibrate.py
   pytest -q
   ```
   So sánh `benchmark/RESULTS.md` trước và sau (`git diff benchmark/RESULTS.md`): recall theo từng loại, tỷ lệ báo nhầm, danh sách lỗi khó nhất.
5. Nếu ví dụ đó nên có trong benchmark, thêm vào `HARD_NEGATIVES` hoặc `CURATED_ATTACKS` trong `benchmark/build_dataset.py`, rồi chạy lại bước 4 sau `build_dataset.py`.

Đừng sửa trọng số trong `calibration.json` bằng tay: chúng sẽ bị ghi đè ở lần hiệu chỉnh tiếp theo, và CI sẽ báo lỗi.

## Thêm một cặp ký tự trông giống (ASCII)

1. Thêm cặp vào bảng `NEAR` trong `src/homoglyph_detector/visual.py`, với độ giống trong khoảng (0, 1). Chỉ dùng ký tự `a-z 0-9 -`.
2. Chạy `pytest tests/test_visual.py -q`. Test sẽ báo nếu cặp đó đã là "giống hệt" trong dữ liệu Unicode chính thức; khi đó không cần thêm.
3. Hiệu chỉnh lại: `python benchmark/calibrate.py`.

## Thêm một engine mới

1. Tạo `src/homoglyph_detector/engines/ten_engine.py` với hàm `ten_engine(ctx, brands) -> EngineResult`. Chỉ đọc `ctx` và `brands`, không gọi engine khác. Dùng `EngineResult("ten").add(...)` để ghi bằng chứng, rồi `.noisy_or()` hoặc tự đặt `score` trong khoảng 0..1.
2. Đăng ký trong `ENGINES` ở `src/homoglyph_detector/engines/__init__.py`.
3. Viết test riêng; `tests/test_engines.py` sẽ tự kiểm tra tính độc lập của engine mới.
4. Hiệu chỉnh lại (`python benchmark/calibrate.py`). Trọng số của engine mới được học từ benchmark. Nếu trọng số ra 0, nghĩa là engine chưa thêm thông tin nào mà các engine khác chưa có.

## Cập nhật dữ liệu Unicode

Workflow `Unicode data` trên GitHub chạy hằng tháng và báo lỗi khi Unicode có bản mới. Khi đó:

```bash
python scripts/update_unicode_data.py     # tải từ unicode.org, kiểm tra cùng phiên bản, tự niêm phong
pip install -U idna                       # bảng IDNA phải cùng phiên bản Unicode
pytest -q                                 # tests/test_unicode_data.py là bộ kiểm tra tương thích
python benchmark/calibrate.py             # dữ liệu mới có thể đổi điểm
```

Commit các file trong `data/` cùng `RESULTS.md`.

## Cập nhật Public Suffix List

PSL đi kèm thư viện `publicsuffixlist`: `pip install -U publicsuffixlist`. Sau đó chạy `python benchmark/calibrate.py` và xem `git diff`: PSL mới có thể đổi cách tách tên miền.

## Phát hành phiên bản mới

1. Tăng `version` ở `pyproject.toml` và `__version__` ở `src/homoglyph_detector/__init__.py` (hai chỗ phải giống nhau).
2. Ghi thay đổi vào [CHANGELOG.md](../CHANGELOG.md).
3. Kiểm tra: `pytest -q && python scripts/seal_data.py --check`.
4. Commit, gắn tag và đẩy lên:
   ```bash
   git tag v0.8.0
   git push origin main --tags
   ```

## Tra cứu lỗi

| Thông báo / test lỗi | Nguyên nhân | Cách sửa |
|---|---|---|
| `data error: data/X does not match its SHA-256` | file dữ liệu bị đổi sau lần niêm phong | nếu bạn cố ý sửa: `python scripts/seal_data.py`; nếu không: `git checkout -- src/homoglyph_detector/data/X` hoặc cài lại |
| `data/X is not listed in data/MANIFEST.json` | thêm file mới vào `data/` | `python scripts/seal_data.py` |
| `brands.json changed but its version ... is not above ...` | sửa brand database mà chưa tăng version | tăng `version` (và `updated`) trong `brands.json` |
| `... is a public suffix; allow-listing it would trust every site under it` | khai báo `github.io`, `com.vn`, ... là domain chính thức | xóa domain đó, chỉ khai báo domain đăng ký được |
| `domain '...' is claimed by both ...` | hai thương hiệu (có thể ở hai database) cùng nhận một domain | giữ domain ở đúng một thương hiệu |
| `SHA-256 is ..., expected ...` | brand database ngoài đã đổi so với mã ghim | kiểm tra file; nếu đúng là bản mới, cập nhật `#sha256=` |
| cảnh báo `brand database ... is not pinned` | dùng `--brands` mà không ghim | thêm `#sha256=<mã in trong cảnh báo>` |
| CI: bước `Calibration must match ...` lỗi | đổi engine / dữ liệu mà chưa hiệu chỉnh lại | `python benchmark/calibrate.py`, commit các file thay đổi |
| `test_calibration_was_fitted_on_the_committed_benchmark` | `dataset.jsonl` đổi | `python benchmark/calibrate.py` |
| `test_calibration_was_fitted_on_the_bundled_brands` | `brands.json` đổi | `build_dataset.py` rồi `calibrate.py` |
| `test_calibrated_quality_does_not_regress` | bản sửa làm chất lượng giảm dưới ngưỡng | xem `benchmark/RESULTS.md` theo từng loại để tìm chỗ hỏng |
| `test_idna_tables_match_bundled_unicode_data` | `idna` và dữ liệu Unicode lệch phiên bản | `pip install -U idna` hoặc cập nhật dữ liệu Unicode |
| `test_repository_has_no_hidden_characters` | có ký tự ẩn / bidi thật trong file (báo kèm file:dòng) | thay bằng escape Unicode của Python |
| `test_near_table_complements_the_official_data` | một cặp trong `NEAR` đã là "giống hệt" trong dữ liệu Unicode | xóa cặp đó khỏi `NEAR` |
| workflow `Unicode data` hằng tháng lỗi | Unicode có bản mới | làm theo mục *Cập nhật dữ liệu Unicode* |
