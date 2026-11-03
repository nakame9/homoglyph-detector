# Benchmark và hiệu chỉnh

> Có **hai** bộ đánh giá. Benchmark tổng hợp (phần đầu tài liệu) dùng để hiệu chỉnh và so sánh phiên bản. [Đánh giá thực tế](#đánh-giá-thực-tế) (phishing thật, web thật, theo thời gian, adversarial) mới cho biết hiệu quả khi triển khai.

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

Ngoài ra: FNR (tỷ lệ bỏ lọt) = 1 − recall; kết quả theo 10 nhóm trên golden corpus, mục tiêu kỹ thuật theo profile và độ trễ phát hiện nằm trong `RESULTS.md` (xem [testing](testing.md#kết-quả-đo)).

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

## Đánh giá thực tế

Benchmark tổng hợp có giới hạn cơ bản: domain sinh bằng công cụ hoán vị (dnstwist) không đại diện cho phishing đang hoạt động. `benchmark/real_world.py` bổ sung năm hạng mục; báo cáo đầy đủ ở [`benchmark/REAL_WORLD.md`](../benchmark/REAL_WORLD.md).

| Hạng mục | Dữ liệu | Kết quả chính |
|---|---|---|
| 1. Phishing thật | 271.231 host từ toàn bộ lịch sử git của [OpenPhish Community Feed](https://github.com/openphish/public_feed), 10/2024 → 11/2026, mỗi host kèm thời điểm xuất hiện đầu tiên | chỉ **3,5%** thuộc phạm vi công cụ; phát hiện **3,4%** toàn bộ; trong phạm vi chủ yếu là combosquat, chỉ 0,8% có bằng chứng giả mạo trông giống (profile `browser`); homograph IDN chiếm 0,06% |
| 2. Domain hợp lệ quốc tế | 41.620 host từ [Chrome UX Report](https://github.com/zakird/crux-top-lists) top 1 triệu (phân bố thật theo quốc gia), gồm toàn bộ 1.678 IDN | FPR 0,1–0,3% mọi khu vực, 0% Việt Nam; báo nhầm còn lại chủ yếu là domain của chính thương hiệu chưa có trong database (`cloud.microsoft`, `hicloud.com`) |
| 3. Temporal validation | fit trên phishing trước 01/05/2026, test trên phishing sau mốc | xếp hạng không đổi (ROC-AUC 0,994 trong phạm vi cho cả mô hình hiện tại lẫn mô hình fit trên quá khứ); recall trong phạm vi ổn định 91–100% mỗi tháng; mô hình hiện tại **lệch calibration** trên dữ liệu thật (ECE 0,21 so với 0,06 trên benchmark) |
| 4. Adversarial | leave-one-technique-out trên benchmark; 203 biến thể từ 11 kỹ thuật chưa từng dùng | homoglyph Latin mở rộng / Armenia / chữ toán học / Cyrillic hoa: 100%; thay chữ bằng số ngoài bảng (`4ppl3`, `p4yp4l`): **47%**; bỏ loại `dictionary` khi fit thì engine combosquat mất trọng số (recall loại đó 81% → **0%**) |
| 5. Calibration | Brier, ECE, [reliability diagram](img/reliability.svg) | xem bên dưới |

**Đánh giá thực tế đã phát hiện một lỗi báo nhầm** mà benchmark tổng hợp và golden corpus đều bỏ sót: chữ Latin có dấu hoặc chữ ghép (`mæglerhuset.dk`, `borsaekranı.com`) bị coi là "cả nhãn trông như ASCII". Đã sửa: FPR trên IDN hợp lệ giảm từ 0,3% xuống 0,1%, ở profile `browser` từ 0,2% xuống 0%.

### Xác suất không phải tỷ lệ tấn công thật

Tầng hợp nhất là logistic regression fit trên benchmark có khoảng 37% tấn công. Xác suất của nó **chỉ đúng với tỷ lệ đó** và với kiểu tấn công giống benchmark. Khi triển khai có hai độ lệch khác nhau:

1. **Lệch tỷ lệ (prior shift)**: lưu lượng thật có ít tấn công hơn nhiều. Phần này sửa được bằng công thức Bayes: `--base-rate R` (CLI), `analyze(..., base_rate=R)` (thư viện), trả về `probability_at_base_rate`. Ví dụ `paypal-login.com`: 81% trên benchmark, **0,7%** khi 1/1.000 đầu vào là tấn công; `5hopee.vn`: 100% → 95%. Verdict không đổi, vì ngưỡng của profile là ngân sách tỷ lệ báo nhầm, không phụ thuộc tỷ lệ tấn công.
2. **Lệch phân bố (covariate shift)**: phishing thật phần lớn không có dấu hiệu giả mạo nào, nên ở mức dự đoán 13% thì 35% là tấn công thật (xem reliability diagram). Hiệu chỉnh base rate **không** sửa được độ lệch này (ECE 0,215 → 0,219). Chỉ fit lại trên dữ liệu thật mới giảm được (ECE 0,086).

Precision khi triển khai, tính từ recall và FPR đo trên phishing thật sau mốc thời gian:

| tỷ lệ tấn công trong lưu lượng | precision: phạm vi của công cụ | precision: mọi phishing |
|---|---|---|
| 1 / 10 | 97,1% | 66,3% |
| 1 / 100 | 75,4% | 15,2% |
| 1 / 1.000 | 23,3% | 1,7% |
| 1 / 10.000 | 2,9% | 0,2% |

Với DNS resolver hay email gateway (tỷ lệ tấn công rất thấp), dùng profile `browser` hoặc `--max-fpr` với ngân sách nhỏ, và coi kết quả SUSPICIOUS là tín hiệu để điều tra, không phải để chặn tự động.

### Chạy lại

```bash
pip install -e ".[dev,bench]"
python benchmark/real_world.py    # lần đầu cần mạng; ~45 phút trên 2 lõi (điểm được cache theo phiên bản engine)
```

Dữ liệu thô không nằm trong repo: OpenPhish Community Feed chỉ cho dùng phi thương mại ([điều khoản](https://openphish.com/terms.html)). Script tải lại từ đúng commit đã ghim, chỉ giữ hostname (không giữ URL đầy đủ, vốn có thể chứa email nạn nhân), và cache vào `benchmark/.cache/` (không commit).
