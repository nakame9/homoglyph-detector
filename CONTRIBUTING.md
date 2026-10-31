# Đóng góp

Cảm ơn bạn muốn cải thiện dự án. Hướng dẫn chi tiết theo từng tình huống nằm trong [docs/bao-tri.md](docs/bao-tri.md); trang này là phần tóm tắt.

## Bắt đầu

```bash
git clone https://github.com/nakame9/homoglyph-detector
cd homoglyph-detector
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev,bench]"
pytest -q
```

## Quy trình

1. Tạo nhánh mới từ `main`.
2. Với lỗi phát hiện (báo nhầm / bỏ lọt): **thêm ca vào golden corpus trước** (`tests/golden/corpus.jsonl`), rồi mới sửa. Xem [docs/testing.md](docs/testing.md).
3. Sửa đúng chỗ theo bảng "muốn sửa gì thì mở file nào" trong [docs/kien-truc.md](docs/kien-truc.md).
4. Chạy các bước kiểm tra bên dưới, rồi mở pull request (mẫu PR có sẵn danh sách kiểm tra).

## Trước khi mở pull request

```bash
pytest -q                               # mọi test qua
HYPOTHESIS_PROFILE=ci pytest -q         # như CI: property test tất định, 400 mẫu
UPDATE_GOLDEN=1 pytest tests/test_golden.py   # chỉ khi đổi hành vi có chủ ý; review git diff snapshot
python scripts/seal_data.py --check     # nếu có đổi dữ liệu trong src/homoglyph_detector/data/
python benchmark/calibrate.py           # nếu có đổi engine, brands.json, bảng NEAR hay dữ liệu Unicode
```

Nếu `calibrate.py` làm thay đổi `calibration.json`, hãy commit kèm `MANIFEST.json` và `benchmark/RESULTS.md`, và nêu trong PR các con số chính (F1, tỷ lệ báo nhầm) trước và sau.

## Quy ước

- Code, tên biến và thông báo của công cụ viết bằng tiếng Anh; tài liệu trong `docs/` và README viết bằng tiếng Việt.
- Một thay đổi, một mục đích. Ghi thay đổi người dùng thấy được vào [CHANGELOG.md](CHANGELOG.md).
- Không dán ký tự ẩn hay ký tự đảo chiều thật vào code, test hay tài liệu; dùng escape Unicode của Python. Một test tự quét toàn repo.
- Không sửa tay `calibration.json` hay `MANIFEST.json`: chúng do script sinh ra.
- Không thêm thư viện phụ thuộc mới nếu thư viện chuẩn làm được.
