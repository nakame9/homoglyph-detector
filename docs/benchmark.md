# Benchmark và hiệu chỉnh

Điểm số của công cụ không đặt bằng tay: trọng số của tầng hợp nhất được **học và đo trên một benchmark** gồm 15.805 tên miền có nhãn. Báo cáo đầy đủ (theo từng loại tấn công, bảng độ tin cậy, các lỗi khó nhất) ở [`benchmark/RESULTS.md`](../benchmark/RESULTS.md); file đó được sinh tự động.

## Bộ dữ liệu

`benchmark/build_dataset.py` tạo `benchmark/dataset.jsonl` từ các nguồn **độc lập với công cụ**, để tránh "tự chấm bài mình":

| Nhãn | Nguồn | Số lượng |
|---|---|---|
| hợp lệ | [OpenDNS top 10.000](https://github.com/opendns/public-domain-lists) + mẫu âm khó: trang Việt Nam, IDN hợp lệ ở cả hai dạng (Unicode và `xn--`), từ thật gần tên thương hiệu | 10.065 |
| tấn công | mọi fuzzer của [dnstwist](https://github.com/elceef/dnstwist) trên từng domain thương hiệu (kể cả combosquat với từ điển `login`, `secure`, `verify`, ...), IDN homoglyph của 150 domain phổ biến không được bảo vệ, và một danh sách tuyển chọn các trò bidi / ký tự ẩn / fullwidth | 5.740 |

- Domain gốc có tên ngắn hơn 4 ký tự (`wa.me`) không được dùng để sinh biến thể: `aa.me`, `wz.me` là tên khác chứ không phải bản giả mạo.
- Domain lưu dạng escape JSON nên file là ASCII thuần, không chứa ký tự ẩn thật.
- Mỗi dòng có `group` (domain gốc): mọi biến thể của một domain nằm cùng phía train hoặc test.

## Hiệu chỉnh

`benchmark/calibrate.py`:
1. chạy 5 engine trên mọi domain để lấy điểm thô;
2. tách 70% train / 30% test theo `group` (SHA-256 của domain gốc), nên tập test gồm toàn domain mô hình chưa thấy;
3. học logistic regression (phương pháp Newton, L2) với **trọng số ≥ 0**: thêm bằng chứng không bao giờ làm giảm rủi ro;
4. chọn ngưỡng cho từng profile rủi ro trên đường cong của tập train;
5. đo trên tập test, ghi `data/calibration.json` + `benchmark/RESULTS.md`, rồi tự niêm phong `MANIFEST.json`.

Kết quả tái tạo được từng byte; CI chạy lại và báo lỗi nếu `calibration.json` không khớp code.

Trọng số hiện tại: unicode 17.0816, idna 0.0, brand 11.5037, combosquat 6.6264, visual 7.798, bias -1.8926. Ngưỡng của profile `default`: `SUSPICIOUS` khi p ≥ 0.5 (khả năng cao hơn không), `MALICIOUS` khi p ≥ 0.9 (9 trên 10). Các profile khác (`banking`, `browser`) và ngân sách báo nhầm riêng được chọn trên tập train theo mục tiêu tỷ lệ báo nhầm: xem [risk scoring](risk-scoring.md).

## Kết quả trên tập test (4.799 dòng)

| | precision | recall | F1 | tỷ lệ báo nhầm |
|---|---|---|---|---|
| đã hiệu chỉnh, p ≥ 0.5 | 0.9667 | 0.8698 | 0.9157 | 0.016 |
| đã hiệu chỉnh, p ≥ 0.9 | 0.9926 | 0.6395 | 0.7778 | 0.0026 |
| luật mức độ, không hiệu chỉnh | 0.9624 | 0.7522 | 0.8444 | 0.0156 |

ROC-AUC 0.9302, Brier score 0.0585, sai số hiệu chỉnh kỳ vọng (ECE) 0.0609.

## Benchmark đã phát hiện gì

Mỗi vấn đề được tìm ra khi đọc lỗi, sửa trong engine, rồi đo lại:

1. **Rò rỉ dữ liệu:** mọi tấn công đều ở dạng `xn--`, không mẫu hợp lệ nào như vậy, nên mô hình đầu tiên học sai thành "punycode = tấn công" (trọng số idna 21.8). Sửa: chuyển đổi punycode chỉ là `info`, và đưa IDN hợp lệ vào ở cả hai dạng.
2. **Lỗi code:** khoảng cách typosquat tính trên skeleton, nơi `amazon` thành `arnazon`, nên bỏ lọt `aazon.com`; lỗi hoán vị (`amaozn`) có recall **0%**. Sửa: khoảng cách optimal string alignment trên cả dạng gốc lẫn skeleton, so cả với tên domain chính thức (`office` từ `office.com`).
3. **Gộp nhầm bằng chứng:** domain thật của thương hiệu (`amazon.co.uk`, `google-analytics.com`) và combosquat lừa đảo dùng chung một điểm. Sửa: tách engine **combosquat** riêng, thêm combosquat của dnstwist vào dữ liệu để trọng số được học riêng.
4. **Bỏ lọt homoglyph có dấu:** chữ Latin có dấu (ž, ă, ľ) không là "confusable" trong UTS #39 (recall homoglyph 63%). Sửa: engine visual đọc thêm skeleton bỏ dấu, mỗi dấu tốn một chi phí nhỏ (sau sửa khoảng 90%).
5. **Đếm trùng:** một IDN tiếng Nga hợp lệ bị chấm 1.00 vì mỗi chữ Cyrillic được tính là một bằng chứng. Sửa: bằng chứng cùng loại chỉ tính một lần, chữ trông giống riêng lẻ là `info`.

## Giới hạn đã đo được

- Xác suất bám theo tỷ lệ của benchmark (khoảng 1 tấn công trên 2 mẫu hợp lệ). Domain không có bằng chứng gì vẫn nhận khoảng 13/100, tức tỷ lệ tấn công không để lại dấu vết trong benchmark. Lưu lượng thật có ít tấn công hơn nhiều: hãy dùng điểm như **thứ hạng** và ngưỡng như **mốc để xem xét**.
- Từ thật cách tên thương hiệu ngắn đúng một ký tự bị chấm cao (`apply.com`, `ymail.com`).
- Domain thật của thương hiệu nhưng chưa có trong `brands.json` bị coi là combosquat.
- Homoglyph có dấu của domain **không được bảo vệ** chỉ bắt được khoảng một nửa, vì dấu là bình thường trong tiếng Việt và các tiếng châu Âu.
- Tấn công trong benchmark là do dnstwist sinh ra; chưa có tập test từ domain lừa đảo thật (PhishTank, OpenPhish).

## Chạy lại

```bash
pip install -e ".[bench]"
python benchmark/build_dataset.py   # cần internet: tải OpenDNS top 10k, chạy dnstwist (~30 giây)
python benchmark/calibrate.py       # ~1 phút, ghi calibration.json + RESULTS.md, tự niêm phong
pytest -q
```
