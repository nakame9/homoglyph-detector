# Đóng góp

Trang này là bản tóm tắt. Hướng dẫn theo từng tình huống (thêm thương hiệu, sửa báo nhầm, thêm engine, cập nhật dữ liệu, phát hành, tra cứu lỗi) nằm trong [docs/bao-tri.md](docs/bao-tri.md).

## Cài môi trường

```bash
git clone https://github.com/nakame9/homoglyph-detector
cd homoglyph-detector
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate  (và đặt PYTHONUTF8=1)
pip install -e ".[dev,bench]"
pytest -q
```

## Quy trình

1. Tạo nhánh từ `main`, mỗi nhánh một mục đích.
2. **Viết test tái hiện trước, sửa sau.** Lỗi phát hiện (báo nhầm, bỏ lọt): thêm ca vào `tests/golden/corpus.jsonl`. Lỗi khác: thêm test vào file `tests/test_*.py` tương ứng.
3. Tìm đúng chỗ cần sửa trong bảng "muốn sửa gì thì mở file nào" của [docs/kien-truc.md](docs/kien-truc.md).
4. Chạy các bước kiểm tra bên dưới, ghi thay đổi người dùng thấy được vào [CHANGELOG.md](CHANGELOG.md), rồi mở PR theo mẫu.

## Kiểm tra trước khi mở PR

| Khi nào | Lệnh |
|---|---|
| luôn luôn | `HYPOTHESIS_PROFILE=ci pytest -q` (giống CI) |
| đổi dữ liệu trong `src/homoglyph_detector/data/` | `python scripts/seal_data.py`; sửa `brands.json` thì tăng `version` trước |
| đổi `brands.json` | `python benchmark/build_dataset.py`, rồi `python benchmark/calibrate.py` |
| đổi engine, bảng `NEAR` hoặc dữ liệu Unicode | `python benchmark/calibrate.py` |
| đổi kết luận của ca golden có chủ ý | `UPDATE_GOLDEN=1 pytest tests/test_golden.py`, rồi review `git diff` |
| đổi cách phát hiện | `python benchmark/real_world.py` (cần mạng lần đầu, khoảng 10 phút) |

Đổi cách chấm điểm thì commit kèm `calibration.json`, `MANIFEST.json`, `benchmark/RESULTS.md`, và ghi trong PR các con số trước và sau.

**Cổng chất lượng** cho mọi thay đổi về phát hiện, đo trên `benchmark/REAL_WORLD.md`:
- không quá 5 domain hợp lệ mới bị gắn cờ, và liệt kê từng domain đó trong PR;
- không mất tấn công nào đã phát hiện trước đó;
- recall trên nhóm mục tiêu của thay đổi tăng ít nhất 1 điểm phần trăm.

## Quy ước

- Code, tên biến và thông báo của công cụ viết bằng tiếng Anh; README và `docs/` viết bằng tiếng Việt.
- Không sửa tay `calibration.json` hay `MANIFEST.json`: chúng do script sinh ra.
- Thêm domain chính thức vào `brands.json` phải có nguồn chứng minh quyền sở hữu (trang của chính thương hiệu, bản ghi registry), ghi nguồn trong PR và CHANGELOG.
- Không dán ký tự ẩn hay ký tự đảo chiều thật vào code, test hay tài liệu; dùng escape Unicode của Python. Một test tự quét toàn repo.
- `rejected` là đầu vào trình duyệt từ chối, `unsupported` là đầu vào công cụ không đọc được. Thêm `parse_reason` mới thì sửa đồng bộ `REASONS`, analyzer, báo cáo tích hợp, tài liệu và test trong cùng PR.
- Không thêm thư viện phụ thuộc mới nếu thư viện chuẩn làm được.
