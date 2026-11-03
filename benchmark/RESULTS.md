# Kết quả benchmark

Sinh tự động bởi `benchmark/calibrate.py` ngày 2026-11-03. Bộ dữ liệu: `benchmark/dataset.jsonl` (15805 dòng, 5740 tấn công), tạo bởi `benchmark/build_dataset.py`.
Train 11006 / test 4799 dòng, tách theo domain gốc. **Mọi con số đều đo trên tập test.**

## Mô hình hợp nhất (fusion)

| engine | trọng số |
|---|---|
| unicode | 17.0294 |
| idna | 0.0 |
| brand | 11.4845 |
| combosquat | 6.6039 |
| visual | 7.8093 |
| *bias* | -1.8808 |

## Mô hình đã hiệu chỉnh so với luật mức độ nghiêm trọng

| | precision | recall | F1 | tỷ lệ báo nhầm |
|---|---|---|---|---|
| đã hiệu chỉnh, p >= 0.5 (SUSPICIOUS trở lên) | 0.9665 | 0.865 | 0.9129 | 0.016 |
| đã hiệu chỉnh, p >= 0.9 (MALICIOUS) | 0.9915 | 0.5591 | 0.715 | 0.0026 |
| luật mức độ, không hiệu chỉnh: SUSPICIOUS trở lên | 0.9622 | 0.7475 | 0.8413 | 0.0156 |
| luật mức độ, không hiệu chỉnh: MALICIOUS | 1.0 | 0.0714 | 0.1333 | 0.0 |

ROC-AUC **0.9277**, Brier score 0.0599, sai số hiệu chỉnh kỳ vọng (ECE) 0.0604.

## Quy tắc visual-only

Độ giống hình ảnh (`rn`/`m`, `0`/`o`, `5`/`s`, `vv`/`w`, bỏ dấu) phụ thuộc font và cách hiển thị, nên chỉ hỗ trợ chấm điểm: MALICIOUS cần thêm ít nhất một bằng chứng độc lập (Unicode, chính tả, tên thương hiệu, IDNA). Bảng so sánh mức MALICIOUS trên tập test khi không và có quy tắc.

| profile | recall MALICIOUS (không / có quy tắc) | FPR MALICIOUS (không / có) | tấn công bị hạ xuống SUSPICIOUS |
|---|---|---|---|
| default | 63,47% / 55,91% | 0,26% / 0,26% | 126 |
| banking | 86,50% / 67,37% | 1,60% / 1,56% | 319 |
| browser | 17,88% / 13,38% | 0,06% / 0,06% | 75 |

Các tấn công bị hạ (profile default) vẫn được gắn cờ SUSPICIOUS; theo loại: brand/homoglyph 122, brand/replacement 3, curated/combosquat 1.

## Hồ sơ rủi ro (risk profiles)

Ngưỡng chọn trên tập train theo mục tiêu tỷ lệ báo nhầm, đo lại trên tập test. Báo nhầm / 10k = số cảnh báo sai trên 10.000 domain hợp lệ, không phụ thuộc tỷ lệ tấn công của môi trường.

| profile | ngưỡng SUSPICIOUS | recall | báo nhầm / 10k | ngưỡng MALICIOUS | recall | báo nhầm / 10k |
|---|---|---|---|---|---|---|
| default | 0.5000 | 0.865 | 160.0 | 0.9000 | 0.5591 | 26.0 |
| banking | 0.2766 | 0.865 | 160.0 | 0.2766 | 0.6737 | 156.0 |
| browser | 0.8444 | 0.6359 | 26.0 | 0.9805 | 0.1338 | 6.0 |

## Các điểm vận hành

Muốn tự đặt ngân sách báo nhầm: chọn một dòng (`--max-fpr`). Các mục tiêu cho cùng ngưỡng được gộp.

| mục tiêu FPR tối đa (train) | ngưỡng | recall (test) | FPR (test) | báo nhầm / 10k (test) |
|---|---|---|---|---|
| 0.0005 | 0.9805 | 0.1788 | 0.0006 | 6.0 |
| 0.002 | 0.8444 | 0.6359 | 0.0026 | 26.0 |
| 0.02 | 0.2766 | 0.865 | 0.016 | 160.0 |

## Golden corpus (10 nhóm test bắt buộc)

142 ca gán nhãn thủ công trong `tests/golden/corpus.jsonl`, profile `default` (gắn cờ = SUSPICIOUS trở lên). Recall / FNR tính trên ca tấn công, FPR trên ca hợp lệ.

| nhóm | recall | FNR | FPR | lỗi đã biết |
|---|---|---|---|---|
| ascii_lookalike | 100.0% (20/20) | 0.0% (0/20) | – |  |
| cyrillic_greek_homoglyph | 100.0% (14/14) | 0.0% (0/14) | – |  |
| mixed_script | 100.0% (5/5) | 0.0% (0/5) | 0.0% (0/3) |  |
| punycode_malformed | – | – | – |  |
| zero_width | 100.0% (9/9) | 0.0% (0/9) | – |  |
| bidi_override | 100.0% (7/7) | 0.0% (0/7) | – |  |
| vietnamese | – | – | 0.0% (0/15) |  |
| multilingual_legit | – | – | 0.0% (0/27) |  |
| multi_level_suffix | 100.0% (7/7) | 0.0% (0/7) | 14.3% (1/7) | 1 |
| url_edge | 71.4% (5/7) | 28.6% (2/7) | 0.0% (0/7) | 2 |

## Mục tiêu kỹ thuật: recall cao, báo nhầm thấp trên domain đa ngôn ngữ

| profile | recall: golden tấn công | recall: benchmark test | FPR: golden đa ngôn ngữ | FPR: mẫu âm khó (test) | FPR: top 10k (test) |
|---|---|---|---|---|---|
| default | 97.1% (67/69) | 86.5% (1442/1667) | 0.0% (0/45) | 22.7% (5/22) | 1.4% (45/3110) |
| banking | 97.1% (67/69) | 86.5% (1442/1667) | 0.0% (0/45) | 22.7% (5/22) | 1.4% (45/3110) |
| browser | 91.3% (63/69) | 63.6% (1060/1667) | 0.0% (0/45) | 13.6% (3/22) | 0.2% (5/3110) |

## Độ trễ phát hiện

Đo trên 15805 domain của benchmark, Python 3.13.18 (x86_64), một luồng, gồm cả 5 engine; số liệu thay đổi theo máy.

| p50 | p95 | p99 | lớn nhất | trung bình | thông lượng | lần gọi đầu (nạp dữ liệu) |
|---|---|---|---|---|---|---|
| 5.52 ms | 12.72 ms | 19.80 ms | 63.30 ms | 6.29 ms | 159 domain/giây | 137 ms |

## Độ tin cậy của xác suất (reliability)

Xác suất dự đoán so với tỷ lệ tấn công thật trong từng khoảng.

| khoảng dự đoán | số dòng | dự đoán trung bình | tỷ lệ tấn công thực tế |
|---|---|---|---|
| 0.1-0.2 | 3307 | 0.132 | 0.068 |
| 0.6-0.7 | 186 | 0.662 | 1.000 |
| 0.7-0.8 | 6 | 0.776 | 0.833 |
| 0.8-0.9 | 234 | 0.806 | 0.825 |
| 0.9-1.0 | 1066 | 0.983 | 0.992 |

## Phát hiện theo loại

Tỷ lệ bị gắn cờ SUSPICIOUS trở lên (p >= 0.5). Với tấn công đây là recall; với mẫu hợp lệ đây là tỷ lệ báo nhầm.

| loại | nhãn | số dòng | bị gắn cờ |
|---|---|---|---|
| brand/addition | tấn công | 175 | 100.0% |
| brand/bitsquatting | tấn công | 171 | 100.0% |
| brand/cyrillic | tấn công | 3 | 100.0% |
| brand/dictionary | tấn công | 175 | 85.7% |
| brand/homoglyph | tấn công | 175 | 89.7% |
| brand/hyphenation | tấn công | 48 | 100.0% |
| brand/insertion | tấn công | 175 | 100.0% |
| brand/omission | tấn công | 51 | 100.0% |
| brand/plural | tấn công | 14 | 78.6% |
| brand/repetition | tấn công | 33 | 100.0% |
| brand/replacement | tấn công | 172 | 100.0% |
| brand/subdomain | tấn công | 41 | 92.7% |
| brand/transposition | tấn công | 42 | 100.0% |
| brand/various | tấn công | 11 | 90.9% |
| brand/vowel-swap | tấn công | 39 | 100.0% |
| curated/combosquat | tấn công | 2 | 100.0% |
| curated/hidden-overlay | tấn công | 1 | 100.0% |
| curated/hosting | tấn công | 1 | 100.0% |
| curated/invisible | tấn công | 1 | 100.0% |
| curated/whole-script | tấn công | 1 | 100.0% |
| hard-negative | hợp lệ | 22 | 22.7% |
| top10k | hợp lệ | 3110 | 1.4% |
| unprotected/homoglyph | tấn công | 336 | 47.9% |

## Các lỗi khó nhất

Báo nhầm (hợp lệ nhưng bị gắn cờ):

- `hicloud.com` p=1.00 (top10k)
- `youtuber.net` p=1.00 (hard-negative)
- `ymail.com` p=0.98 (top10k)
- `mail.mil` p=0.98 (top10k)
- `ccloud.io` p=0.98 (top10k)
- `mail.com` p=0.98 (top10k)
- `email.com` p=0.98 (hard-negative)
- `shoplee.com` p=0.98 (hard-negative)
- `google-analytics.com` p=0.81 (top10k)
- `facebook.net` p=0.81 (top10k)
- `google.com.tr` p=0.81 (top10k)
- `images-amazon.com` p=0.81 (top10k)
- `ssl-images-amazon.com` p=0.81 (top10k)
- `google.ca` p=0.81 (top10k)
- `amazon.co.uk` p=0.81 (top10k)

Bỏ lọt (tấn công nhưng không bị gắn cờ):

- `xn--mzon-zmb94f.com` p=0.13 (brand/homoglyph)
- `xn--mazor-jwb.com` p=0.13 (brand/homoglyph)
- `amazeson.com` p=0.13 (brand/plural)
- `office-wallet.com` p=0.13 (brand/dictionary)
- `supportoffice.com` p=0.13 (brand/dictionary)
- `app-office.com` p=0.13 (brand/dictionary)
- `office-auth.com` p=0.13 (brand/dictionary)
- `billing-office.com` p=0.13 (brand/dictionary)
- `signin-office.com` p=0.13 (brand/dictionary)
- `secure-office.com` p=0.13 (brand/dictionary)
- `authoffice.com` p=0.13 (brand/dictionary)
- `office-verify.com` p=0.13 (brand/dictionary)
- `officebilling.com` p=0.13 (brand/dictionary)
- `office-security.com` p=0.13 (brand/dictionary)
- `billingoffice.com` p=0.13 (brand/dictionary)

## Lưu ý

- Xác suất được hiệu chỉnh theo tỷ lệ của bộ dữ liệu này (khoảng 1 tấn công trên 2 mẫu hợp lệ). Lưu lượng thật có ít tấn công hơn nhiều: hãy dùng điểm như thứ hạng và ngưỡng như mốc để xem xét.
- Tấn công lấy từ dnstwist và một danh sách tuyển chọn nhỏ; mẫu hợp lệ lấy từ OpenDNS top 10.000, bản thân danh sách này có thể lẫn vài domain giả mạo.
- Lỗi gõ ASCII của thương hiệu không có trong `brands.json` nằm ngoài phạm vi (không có gì để so sánh).
