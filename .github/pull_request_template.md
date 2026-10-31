## Thay đổi gì và tại sao

## Loại thay đổi
- [ ] Sửa lỗi phát hiện (báo nhầm / bỏ lọt)
- [ ] Tính năng / engine mới
- [ ] Dữ liệu (brand database, Unicode, bảng NEAR)
- [ ] Tài liệu / cấu trúc, không đổi hành vi

## Danh sách kiểm tra
- [ ] `pytest -q` qua
- [ ] Có test mới cho thay đổi hành vi (với lỗi phát hiện: test tái hiện viết trước khi sửa)
- [ ] Đổi dữ liệu trong `data/`: đã chạy `python scripts/seal_data.py` (và tăng `version` nếu sửa `brands.json`)
- [ ] Đổi engine / dữ liệu ảnh hưởng điểm: đã chạy `python benchmark/calibrate.py` và commit `calibration.json`, `MANIFEST.json`, `benchmark/RESULTS.md`
- [ ] Đã ghi vào `CHANGELOG.md` nếu người dùng thấy được thay đổi

## Kết quả benchmark (nếu đổi điểm)
| | trước | sau |
|---|---|---|
| F1 (p ≥ 0.5) | | |
| tỷ lệ báo nhầm (p ≥ 0.5) | | |
| precision (p ≥ 0.9) | | |
