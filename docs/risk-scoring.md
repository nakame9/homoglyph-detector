# Domain Risk Scoring: chính sách rủi ro theo môi trường

Một ngưỡng cố định không phù hợp với mọi hệ thống. Cổng thanh toán của ngân hàng thà chặn nhầm một domain rồi yêu cầu xác thực thêm, còn hơn để lọt một trang lừa đảo. Trình duyệt cá nhân thì ngược lại: mỗi cảnh báo nhầm làm phiền một người dùng và dạy họ bỏ qua cảnh báo.

Vì vậy công cụ tách hai việc:

| | Là gì | Có đổi theo môi trường không |
|---|---|---|
| **Điểm rủi ro** | xác suất đã hiệu chỉnh (`probability`, `risk_score` 0–100) do 5 engine và tầng hợp nhất tính | không: cùng một domain luôn cùng một điểm |
| **Chính sách (profile)** | hai ngưỡng biến điểm thành `SAFE` / `SUSPICIOUS` / `MALICIOUS` | có: chọn theo mức báo nhầm môi trường chấp nhận được |

Mã nguồn: `scoring.py` (chọn ngưỡng), `benchmark/calibrate.py` (định nghĩa và đo các profile).

## Vì sao chính sách tính bằng tỷ lệ báo nhầm, không phải precision

Precision phụ thuộc vào **tỷ lệ tấn công** trong lưu lượng; tỷ lệ báo nhầm (FPR) và recall thì không. Ví dụ với profile `browser` (recall 0.64, FPR 0.0026):

- trên benchmark (khoảng 1 tấn công / 2 domain hợp lệ), precision là 0.99;
- trong lưu lượng có 1 tấn công trên 1.000 domain, mỗi 100.000 domain có 100 tấn công (bắt được khoảng 64) và 99.900 domain hợp lệ (báo nhầm khoảng 260): precision chỉ còn khoảng 20%.

Cùng một ngưỡng, precision khác hẳn nhau, nhưng "số báo nhầm trên 10.000 domain hợp lệ" vẫn giữ nguyên. Đó là đơn vị mà người vận hành lập kế hoạch được: số cảnh báo sai mỗi ngày = FPR × số domain hợp lệ mỗi ngày.

## Các profile có sẵn

Số liệu đo trên tập test của benchmark (domain mô hình chưa thấy). "Báo nhầm / 10k" là số cảnh báo sai trên 10.000 domain hợp lệ.

| Profile | Môi trường | Ngưỡng SUSPICIOUS | recall | báo nhầm / 10k | Ngưỡng MALICIOUS | recall | báo nhầm / 10k |
|---|---|---|---|---|---|---|---|
| `default` | dùng chung | 0.50 | 0.87 | 160 | 0.90 | 0.64 | 26 |
| `banking` | ngân hàng, thanh toán | 0.27 | 0.87 | 160 | 0.27 | 0.87 | 160 |
| `browser` | trình duyệt cá nhân | 0.84 | 0.64 | 26 | 0.98 | 0.18 | 6 |

- **`default`** — ngưỡng xác suất dễ hiểu: SUSPICIOUS khi khả năng tấn công cao hơn không (0.5), MALICIOUS khi 9 trên 10.
- **`banking`** — có bằng chứng là chặn (MALICIOUS), kể cả combosquat như `paypal-login.com`; báo nhầm được xử lý bằng xác thực bổ sung. Mục tiêu: FPR ≤ 5% / 2%.
- **`browser`** — chỉ cảnh báo khi có bằng chứng giả mạo mạnh (homograph, typosquat, giống hình ảnh), bỏ qua combosquat đứng một mình. Mục tiêu: FPR ≤ 0,2% / 0,05%.

Cùng một domain, ba kết luận:

```bash
homoglyph-detector paypal-login.com --profile default   # SUSPICIOUS: đưa vào hàng chờ xem xét
homoglyph-detector paypal-login.com --profile banking   # MALICIOUS: chặn, yêu cầu xác thực thêm
homoglyph-detector paypal-login.com --profile browser   # SAFE: không đáng làm phiền người dùng
```

Homograph thật (`pаypal.com`) bị chặn ở cả ba profile.

## Cách dùng

```bash
homoglyph-detector example.com --profile browser          # chọn profile
export HOMOGLYPH_PROFILE=banking                          # đặt mặc định cho cả hệ thống
homoglyph-detector example.com --max-fpr 0.01,0.001       # ngân sách báo nhầm riêng: SUSPICIOUS, MALICIOUS
homoglyph-detector --profiles                             # xem các profile và số liệu đo được
```

```python
from homoglyph_detector import analyze
from homoglyph_detector.scoring import custom_profile

analyze("paypal-login.com", policy="banking").verdict                  # 'MALICIOUS'
analyze("paypal-login.com", policy=custom_profile(0.01, 0.001)).verdict
```

Mỗi báo cáo ghi lại `profile` và `thresholds` đã dùng, nên biết được vì sao ra kết luận đó.

## Tự đặt ngân sách báo nhầm

1. Ước lượng lưu lượng: số domain hợp lệ khác nhau mỗi ngày (ví dụ email gateway thấy 50.000).
2. Quyết định số cảnh báo sai chấp nhận được mỗi ngày cho từng mức (ví dụ đội SOC xem được 20 SUSPICIOUS và chỉ chấp nhận 2 lần chặn nhầm).
3. Chia ra: FPR SUSPICIOUS = 20 / 50.000 = 0.0004; FPR MALICIOUS = 2 / 50.000 = 0.00004.
4. Chạy `--max-fpr 0.0004,0.00004`. Công cụ chọn ngưỡng có recall cao nhất mà FPR (trên tập train) không vượt ngân sách.

Các điểm vận hành hiện có (ngưỡng chọn trên tập train, số liệu đo trên tập test):

| Ngân sách FPR tối đa | Ngưỡng | recall | báo nhầm / 10k |
|---|---|---|---|
| 0.0005 | 0.98 | 0.18 | 6 |
| 0.002 | 0.84 | 0.64 | 26 |
| 0.02 | 0.27 | 0.87 | 160 |

## Giới hạn hiện tại

- **Điểm số còn thô.** Mỗi engine cho điểm theo vài mức cố định, nên toàn bộ benchmark chỉ có khoảng 30 mức điểm khác nhau, và đường đánh đổi chỉ có ba bậc như bảng trên: (1) mọi bằng chứng kể cả combosquat, (2) typosquat / homograph / hình ảnh, (3) chỉ bằng chứng mạnh nhất. Mọi ngân sách FPR đều rơi vào một trong ba bậc này. Muốn có nhiều lựa chọn hơn cần thêm đặc trưng liên tục cho engine (ví dụ độ dài từ khóa, mức phổ biến của domain); đây là việc trong lộ trình.
- FPR đo trên domain phổ biến (OpenDNS top 10.000). Domain "đuôi dài" ít người biết có thể cho FPR khác; nên kiểm tra lại trên lưu lượng thật của bạn.
- Ngân sách quá nhỏ không đạt được thì công cụ chọn mức nghiêm nhất có thể (ngưỡng 1.0: không gắn cờ gì).

## Thêm hoặc sửa một profile có sẵn

1. Sửa `PROFILES` trong `benchmark/calibrate.py`. Mỗi mức đặt `{"max_fpr": ...}` (ngân sách báo nhầm) hoặc `{"probability": ...}` (ngưỡng xác suất cố định).
2. Chạy `python benchmark/calibrate.py` (tự niêm phong) rồi `pytest -q`. Test kiểm tra mỗi profile đạt mục tiêu trên tập train và ngưỡng SUSPICIOUS ≤ MALICIOUS.
3. Commit `calibration.json`, `MANIFEST.json`, `benchmark/RESULTS.md`.
