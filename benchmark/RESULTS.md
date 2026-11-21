# Kết quả benchmark

Sinh tự động bởi `benchmark/calibrate.py` ngày 2026-11-21. Bộ dữ liệu: `benchmark/dataset.jsonl` (16156 dòng, 6091 tấn công), tạo bởi `benchmark/build_dataset.py`.
Train 11176 / test 4980 dòng, tách theo domain gốc. **Mọi con số đều đo trên tập test.**

## Mô hình hợp nhất (fusion)

| engine | trọng số |
|---|---|
| unicode | 16.2022 |
| idna | 0.0 |
| brand | 11.4372 |
| combosquat | 7.1554 |
| visual | 7.8006 |
| *bias* | -1.8614 |

## Mô hình đã hiệu chỉnh so với luật mức độ nghiêm trọng

| | precision | recall | F1 | tỷ lệ báo nhầm |
|---|---|---|---|---|
| đã hiệu chỉnh, p >= 0.5 (SUSPICIOUS trở lên) | 0.9708 | 0.8826 | 0.9246 | 0.0156 |
| đã hiệu chỉnh, p >= 0.9 (MALICIOUS) | 0.9926 | 0.5806 | 0.7327 | 0.0026 |
| luật mức độ, không hiệu chỉnh: SUSPICIOUS trở lên | 0.9675 | 0.7733 | 0.8595 | 0.0153 |
| luật mức độ, không hiệu chỉnh: MALICIOUS | 1.0 | 0.072 | 0.1343 | 0.0 |

ROC-AUC **0.9384**, Brier score 0.0572, sai số hiệu chỉnh kỳ vọng (ECE) 0.0644.

## Quy tắc visual-only

Độ giống hình ảnh (`rn`/`m`, `0`/`o`, `5`/`s`, `vv`/`w`, bỏ dấu) phụ thuộc font và cách hiển thị, nên chỉ hỗ trợ chấm điểm: MALICIOUS cần thêm ít nhất một bằng chứng độc lập (Unicode, chính tả, tên thương hiệu, IDNA). Bảng so sánh mức MALICIOUS trên tập test khi không và có quy tắc.

| profile | recall MALICIOUS (không / có quy tắc) | FPR MALICIOUS (không / có) | tấn công bị hạ xuống SUSPICIOUS |
|---|---|---|---|
| default | 65,37% / 58,06% | 0,26% / 0,26% | 135 |
| banking | 88,53% / 70,02% | 1,56% / 1,53% | 342 |
| browser | 18,83% / 14,23% | 0,06% / 0,06% | 85 |

Các tấn công bị hạ (profile default) vẫn được gắn cờ SUSPICIOUS; theo loại: brand/homoglyph 130, brand/replacement 4, curated/combosquat 1.

## Hồ sơ rủi ro (risk profiles)

Ngưỡng chọn trên tập train theo mục tiêu tỷ lệ báo nhầm, đo lại trên tập test. Báo nhầm / 10k = số cảnh báo sai trên 10.000 domain hợp lệ, không phụ thuộc tỷ lệ tấn công của môi trường.

| profile | ngưỡng SUSPICIOUS | recall | báo nhầm / 10k | ngưỡng MALICIOUS | recall | báo nhầm / 10k |
|---|---|---|---|---|---|---|
| default | 0.5000 | 0.8826 | 156.0 | 0.9000 | 0.5806 | 26.0 |
| banking | 0.2799 | 0.8853 | 156.0 | 0.2799 | 0.7002 | 153.0 |
| browser | 0.8662 | 0.6542 | 26.0 | 0.9819 | 0.1423 | 6.0 |

## Các điểm vận hành

Muốn tự đặt ngân sách báo nhầm: chọn một dòng (`--max-fpr`). Các mục tiêu cho cùng ngưỡng được gộp.

| mục tiêu FPR tối đa (train) | ngưỡng | recall (test) | FPR (test) | báo nhầm / 10k (test) |
|---|---|---|---|---|
| 0.0005 | 0.9819 | 0.1883 | 0.0006 | 6.0 |
| 0.002 | 0.8662 | 0.6542 | 0.0026 | 26.0 |
| 0.02 | 0.2799 | 0.8853 | 0.0156 | 156.0 |

## Golden corpus (10 nhóm test bắt buộc)

153 ca gán nhãn thủ công trong `tests/golden/corpus.jsonl`, profile `default` (gắn cờ = SUSPICIOUS trở lên). Recall / FNR tính trên ca tấn công, FPR trên ca hợp lệ. Cột *xem lại (P1)* đếm các ca có nhãn được gắn cờ chỉ vì đích không chấm được (URL bị browser từ chối, đầu vào rỗng hoặc quá dài), không phải vì có bằng chứng giả mạo; các ca này nằm trong recall và FPR như báo cáo thật.

| nhóm | recall | FNR | FPR | xem lại (P1) | lỗi đã biết |
|---|---|---|---|---|---|
| ascii_lookalike | 100.0% (20/20) | 0.0% (0/20) | – |  |  |
| cyrillic_greek_homoglyph | 100.0% (14/14) | 0.0% (0/14) | – |  |  |
| mixed_script | 100.0% (5/5) | 0.0% (0/5) | 0.0% (0/3) |  |  |
| punycode_malformed | – | – | – |  |  |
| zero_width | 100.0% (9/9) | 0.0% (0/9) | – |  |  |
| bidi_override | 100.0% (7/7) | 0.0% (0/7) | – |  |  |
| vietnamese | – | – | 0.0% (0/15) |  |  |
| multilingual_legit | – | – | 0.0% (0/27) |  |  |
| multi_level_suffix | 100.0% (9/9) | 0.0% (0/9) | 0.0% (0/8) |  |  |
| url_edge | 100.0% (11/11) | 0.0% (0/11) | 0.0% (0/10) |  |  |

## Mục tiêu kỹ thuật: recall cao, báo nhầm thấp trên domain đa ngôn ngữ

| profile | recall: golden tấn công | recall: benchmark test | FPR: golden đa ngôn ngữ | FPR: mẫu âm khó (test) | FPR: top 10k (test) |
|---|---|---|---|---|---|
| default | 100.0% (75/75) | 88.3% (1631/1848) | 0.0% (0/45) | 22.7% (5/22) | 1.4% (44/3110) |
| banking | 100.0% (75/75) | 88.5% (1636/1848) | 0.0% (0/45) | 22.7% (5/22) | 1.4% (44/3110) |
| browser | 90.7% (68/75) | 65.4% (1209/1848) | 0.0% (0/45) | 13.6% (3/22) | 0.2% (5/3110) |

## Độ trễ phát hiện

Đo trên 16156 domain của benchmark, Python 3.13.7 (AMD64), một luồng, gồm cả 5 engine; số liệu thay đổi theo máy.

| p50 | p95 | p99 | lớn nhất | trung bình | thông lượng | lần gọi đầu (nạp dữ liệu) |
|---|---|---|---|---|---|---|
| 0.80 ms | 1.34 ms | 1.90 ms | 3.87 ms | 0.86 ms | 1165 domain/giây | 99 ms |

## Độ tin cậy của xác suất (reliability)

Xác suất dự đoán so với tỷ lệ tấn công thật trong từng khoảng.

| khoảng dự đoán | số dòng | dự đoán trung bình | tỷ lệ tấn công thực tế |
|---|---|---|---|
| 0.1-0.2 | 3294 | 0.135 | 0.064 |
| 0.2-0.3 | 1 | 0.253 | 1.000 |
| 0.4-0.5 | 5 | 0.425 | 1.000 |
| 0.6-0.7 | 200 | 0.639 | 1.000 |
| 0.7-0.8 | 2 | 0.779 | 0.500 |
| 0.8-0.9 | 262 | 0.848 | 0.847 |
| 0.9-1.0 | 1216 | 0.984 | 0.993 |

## Phát hiện theo loại

Tỷ lệ bị gắn cờ SUSPICIOUS trở lên (p >= 0.5). Với tấn công đây là recall; với mẫu hợp lệ đây là tỷ lệ báo nhầm.

| loại | nhãn | số dòng | bị gắn cờ |
|---|---|---|---|
| brand/addition | tấn công | 200 | 100.0% |
| brand/bitsquatting | tấn công | 195 | 100.0% |
| brand/cyrillic | tấn công | 3 | 100.0% |
| brand/dictionary | tấn công | 200 | 87.5% |
| brand/homoglyph | tấn công | 200 | 88.0% |
| brand/hyphenation | tấn công | 53 | 100.0% |
| brand/insertion | tấn công | 200 | 100.0% |
| brand/omission | tấn công | 57 | 100.0% |
| brand/plural | tấn công | 15 | 73.3% |
| brand/repetition | tấn công | 35 | 100.0% |
| brand/replacement | tấn công | 197 | 100.0% |
| brand/subdomain | tấn công | 45 | 93.3% |
| brand/transposition | tấn công | 47 | 100.0% |
| brand/various | tấn công | 13 | 92.3% |
| brand/vowel-swap | tấn công | 46 | 100.0% |
| curated/combosquat | tấn công | 2 | 100.0% |
| curated/hidden-overlay | tấn công | 1 | 100.0% |
| curated/hosting | tấn công | 1 | 100.0% |
| curated/invisible | tấn công | 1 | 100.0% |
| curated/whole-script | tấn công | 1 | 100.0% |
| hard-negative | hợp lệ | 22 | 22.7% |
| top10k | hợp lệ | 3110 | 1.4% |
| unprotected/homoglyph | tấn công | 336 | 52.4% |

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
- `google-analytics.com` p=0.85 (top10k)
- `facebook.net` p=0.85 (top10k)
- `google.com.tr` p=0.85 (top10k)
- `images-amazon.com` p=0.85 (top10k)
- `ssl-images-amazon.com` p=0.85 (top10k)
- `google.ca` p=0.85 (top10k)
- `amazon.co.uk` p=0.85 (top10k)

Bỏ lọt (tấn công nhưng không bị gắn cờ):

- `annazor.co.jp` p=0.13 (brand/homoglyph)
- `anazor.co.jp` p=0.13 (brand/homoglyph)
- `anazom.co.jp` p=0.13 (brand/homoglyph)
- `amazeson.co.jp` p=0.13 (brand/plural)
- `amazeson.com` p=0.13 (brand/plural)
- `xn--gml-vta32m.com` p=0.13 (brand/homoglyph)
- `billingoffice.com` p=0.13 (brand/dictionary)
- `loginoffice.com` p=0.13 (brand/dictionary)
- `officelogin.com` p=0.13 (brand/dictionary)
- `office-alert.com` p=0.13 (brand/dictionary)
- `alertoffice.com` p=0.13 (brand/dictionary)
- `officeaccount.com` p=0.13 (brand/dictionary)
- `office-account.com` p=0.13 (brand/dictionary)
- `officesecure.com` p=0.13 (brand/dictionary)
- `officeonline.com` p=0.13 (brand/dictionary)

## Lưu ý

- Xác suất được hiệu chỉnh theo tỷ lệ của bộ dữ liệu này (khoảng 1 tấn công trên 2 mẫu hợp lệ). Lưu lượng thật có ít tấn công hơn nhiều: hãy dùng điểm như thứ hạng và ngưỡng như mốc để xem xét.
- Tấn công lấy từ dnstwist và một danh sách tuyển chọn nhỏ; mẫu hợp lệ lấy từ OpenDNS top 10.000, bản thân danh sách này có thể lẫn vài domain giả mạo.
- Lỗi gõ ASCII của thương hiệu không có trong `brands.json` nằm ngoài phạm vi (không có gì để so sánh).
