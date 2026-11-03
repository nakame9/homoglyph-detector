# Kiểm thử và đo lường

Mục tiêu kỹ thuật: **recall cao trên tập tấn công giả mạo đã gán nhãn, tỷ lệ báo nhầm thấp trên tập domain hợp lệ đa ngôn ngữ.** Tài liệu này mô tả cách dự án kiểm chứng mục tiêu đó.

## Các kỹ thuật kiểm thử

| Kỹ thuật | Ở đâu | Kiểm tra gì |
|---|---|---|
| Unit / integration (pytest) | `tests/test_analyzer.py`, `test_engines.py`, `test_brands.py`, `test_scoring.py`, `test_visual.py`, `test_unicode_data.py` | từng thành phần và toàn pipeline |
| Property-based testing (Hypothesis) | `tests/test_properties.py` | điều phải đúng với **mọi** đầu vào (xem bên dưới) |
| Fuzzing Unicode | `tests/test_properties.py` | chuỗi Unicode bất kỳ, domain ghép từ nhiều hệ chữ, URL ghép ngẫu nhiên, punycode hỏng |
| Differential testing IDNA | `tests/test_idna_differential.py` | IDNA2003 (codec có sẵn của Python, dùng trong `socket` / `urllib`) so với IDNA2008 + UTS #46 (thư viện `idna`, như trình duyệt) |
| Golden test corpus | `tests/golden/corpus.jsonl`, `tests/test_golden.py` | 142 ca gán nhãn thủ công, đủ 10 nhóm bắt buộc |
| Regression testing | `tests/golden/snapshot.jsonl` | kết luận và bằng chứng của từng ca golden dưới mọi profile; đổi gì cũng phải review |
| Benchmark | `benchmark/` | precision, recall, FPR, FNR, độ trễ trên 15.805 domain (xem [benchmark](benchmark.md)) |
| Đánh giá thực tế | `benchmark/real_world.py` | phishing thật (OpenPhish), web thật (CrUX), temporal validation, adversarial, calibration (xem [benchmark](benchmark.md#đánh-giá-thực-tế)) |
| Adversarial | `benchmark/adversarial.jsonl` | 203 biến thể từ 11 kỹ thuật chưa từng dùng khi phát triển, và leave-one-technique-out |

## Property test và fuzzing

Mỗi property là một mệnh đề phải luôn đúng; Hypothesis sinh hàng nghìn đầu vào để tìm phản ví dụ, rồi tự rút gọn phản ví dụ về dạng nhỏ nhất.

| Property | Ý nghĩa |
|---|---|
| mọi chuỗi đều cho báo cáo nhất quán | không bao giờ crash; verdict hợp lệ; `0 ≤ p ≤ 1`; điểm engine trong `[0, 1]`; JSON xuất được; báo cáo văn bản **không chứa ký tự ẩn / đảo chiều thật** |
| URL ghép ngẫu nhiên tìm đúng host | scheme, userinfo, cổng, đường dẫn bất kỳ quanh một domain |
| punycode hỏng được báo, không crash | `xn--` + chuỗi bất kỳ |
| đổi một chữ của domain thương hiệu sang chữ Cyrillic / Greek giống hệt → luôn MALICIOUS | phép biến đổi tấn công không bao giờ lọt |
| chèn ký tự vô hình vào bất kỳ đâu → không bao giờ SAFE | |
| chèn ký tự đảo chiều vào bất kỳ đâu → luôn MALICIOUS | |
| tiếng Việt không bao giờ bị coi là trộn script | điểm engine `unicode` luôn bằng 0 cho domain tiếng Việt |
| skeleton không đổi giữa NFC và NFD | |
| độ giống hình ảnh và khoảng cách sửa là đối xứng, có giới hạn | |
| thêm bằng chứng không bao giờ làm giảm rủi ro | |

Ba profile chạy (`HYPOTHESIS_PROFILE`): `dev` (mặc định, 150 mẫu mỗi property, ngẫu nhiên mỗi lần), `ci` (400 mẫu, tất định để lỗi trên CI tái hiện được), `deep` (2.000 mẫu, dùng trước khi phát hành). Lần đo gần nhất: 5 lượt `deep`, khoảng 210.000 đầu vào, không có phản ví dụ.

## Differential testing giữa các bản cài đặt IDNA

Cùng một chuỗi có thể dẫn tới **hai domain khác nhau** tùy phần mềm, và kẻ tấn công có thể lợi dụng chỗ lệch này:

| Đầu vào | IDNA2003 (Python `urllib`, phần mềm cũ) | UTS #46 (trình duyệt) |
|---|---|---|
| `faß.de` | `fass.de` | `xn--fa-hia.de` |
| `σοφος.gr` (sigma cuối) | `xn--0xaakcn.gr` | `xn--0xaajbq.gr` |
| `a<ZWJ>b.com` | `ab.com` | từ chối |
| `i❤.ws` | `xn--i-7iq.ws` | từ chối |
| `Ⱥ.com` | `xn--wma.com` hoặc `xn--cgj.com`, **tùy bản vá CPython** | `xn--cgj.com` |

Engine `idna` báo `idna_differential` cho mọi trường hợp như vậy. Test kiểm tra hai điều:
1. **Mọi khác biệt đều có nguyên nhân đã biết**, thuộc một trong ba nhóm: ký tự lệch của UTS #46 (ß, ς, ZWJ, ZWNJ), ký tự chưa có trong Unicode 3.2, hoặc ký tự có ánh xạ đổi từ Unicode 3.2. Ban đầu giả thuyết chỉ có nhóm thứ nhất; Hypothesis đã bác bỏ nó bằng các chữ hoa mới như `Ⱥ`, `ẞ`, `Ⱦ`, và giả thuyết đã sửa đứng vững qua 6.000 mẫu. Với các ký tự thêm sau Unicode 3.2, chính codec IDNA2003 của Python cũng cho kết quả khác nhau theo bản vá (3.10.20 và 3.12.3 ra `xn--cgj.com`, 3.11.18 và 3.13.18 ra `xn--wma.com`), nên test không cài cứng kết quả cũ cho các ký tự này; engine báo đúng theo bản Python đang chạy.
2. **Engine báo đúng mọi khác biệt**, dùng hai bản cài đặt làm "oracle".

## Golden corpus: 10 nhóm bắt buộc

`tests/golden/corpus.jsonl`, mỗi dòng một ca: `group`, `input`, `label` (`attack` / `benign` / `null` = chỉ kiểm tra hành vi), `host` (host trình duyệt thật sự kết nối, với URL), `known_issue` (lỗi đã biết). Nhãn ghi **bản chất** của ca, không phải điều công cụ đang trả lời.

| Nhóm | Ví dụ | Kiểm tra thêm |
|---|---|---|
| `ascii_lookalike` | `rnicrosoft.com`, `5hopee.vn`, `vvhatsapp.com` | |
| `cyrillic_greek_homoglyph` | `pаypal.com`, `аррӏе.com`, `ρaypal.com` | |
| `mixed_script` | `exаmple.com`; hợp lệ: `abcとうきょ.jp` | |
| `punycode_malformed` | `xn--a.com`, `xn--zz-.com`, `xn--ls8h.la` | không có A-label, có bằng chứng `idna_*` |
| `zero_width` | `pay<U+200B>pal.com`, `goo<U+00AD>gle.com` | có `default_ignorable` |
| `bidi_override` | `<U+202E>moc.lapyap`, `invoice<U+202E>fdp.exe` | có `bidi_control`, luôn MALICIOUS |
| `vietnamese` | `tiếngviệt.vn`, `đàlạt.vn`, `Nguyễn Văn A` | không bị coi là trộn script |
| `multilingual_legit` | `münchen.de`, `орех.рф`, `例子.测试`, `مثال.إختبار` | không bị coi là trộn script |
| `multi_level_suffix` | `vietcombank.com.vn`, `vietcornbank.com.vn`, `vietcombank.com.vn.evil.com` | |
| `url_edge` | `https://evil.com\@paypal.com/`, `https://paypal.com%2eevil.com/`, `paypal.com:443` | host đúng như trình duyệt |

Lỗi đã biết chạy dưới dạng `xfail` nghiêm ngặt: khi ai đó sửa được, test báo để xóa `known_issue`. Hiện có 3: `amazon.co.jp` (brand database thiếu domain quốc gia của Amazon) và hai URL lừa bằng phần userinfo (`https://paypal.com@evil.com/`: host thật `evil.com` không phải domain giả, nên công cụ chưa bắt).

## Kết quả đo

Golden corpus, profile `default` (gắn cờ = SUSPICIOUS trở lên):

| Nhóm | recall | FNR | FPR |
|---|---|---|---|
| ascii_lookalike | 100% (20/20) | 0% | – |
| cyrillic_greek_homoglyph | 100% (14/14) | 0% | – |
| mixed_script | 100% (5/5) | 0% | 0% (0/3) |
| zero_width | 100% (9/9) | 0% | – |
| bidi_override | 100% (7/7) | 0% | – |
| vietnamese | – | – | 0% (0/15) |
| multilingual_legit | – | – | 0% (0/27) |
| multi_level_suffix | 100% (7/7) | 0% | 14,3% (1/7, lỗi đã biết) |
| url_edge | 71,4% (5/7) | 28,6% (2 lỗi đã biết) | 0% (0/7) |

Mục tiêu kỹ thuật, theo profile:

| Profile | recall: golden tấn công | recall: benchmark (test) | FPR: golden đa ngôn ngữ | FPR: top 10k (test) |
|---|---|---|---|---|
| default | 97,1% | 87,0% | 0% (0/45) | 1,4% |
| banking | 97,1% | 87,0% | 0% (0/45) | 1,4% |
| browser | 91,3% | 64,1% | 0% (0/45) | 0,2% |

Độ trễ phát hiện (một luồng, cả 5 engine, 15.805 domain): **p50 4,3 ms, p95 10,2 ms, p99 14,1 ms**, khoảng 200 domain/giây; lần gọi đầu (nạp và xác minh dữ liệu) khoảng 100 ms. Test `test_detection_latency_budget` chặn mọi thay đổi làm p95 vượt 100 ms. Số liệu mới nhất luôn ở [`benchmark/RESULTS.md`](../benchmark/RESULTS.md).

**Đọc các con số cho đúng:** golden corpus đã được dùng để tìm và sửa lỗi, nên con số trên nó là **lạc quan**. Nó là bộ yêu cầu và chống hồi quy. Con số khách quan là tập test của benchmark (domain mô hình chưa thấy).

## Đợt kiểm thử này đã tìm ra gì

| Lỗi | Tìm bởi | Hậu quả nếu không sửa |
|---|---|---|
| `https://evil.com\@paypal.com/` được hiểu là `paypal.com` | golden `url_edge` | **vượt bộ lọc**: trình duyệt vào `evil.com` trong khi công cụ báo SAFE |
| host `paypal.com%2eevil.com` không được giải mã | golden `url_edge` | trình duyệt vào `paypal.com.evil.com` |
| URL có `／`, `＠`, `：` fullwidth hoặc `[` làm crash | fuzzing (phản ví dụ rút gọn `：.com`) | **từ chối dịch vụ**: một URL làm hỏng cả lô xử lý |
| `paypal.com/login`, `paypal.com:443`, `//paypal.com/x` bị coi là domain không hợp lệ | golden `url_edge` | đầu vào từ log bị phân tích sai |
| Latin + chữ Nhật / Trung / Hàn (`abcとうきょ.jp`) bị coi là trộn script | golden `mixed_script` | báo nhầm tên thương hiệu châu Á |
| từ Cyrillic trông như Latin dưới `.рф` (`орех.рф`) bị chặn | golden `multilingual_legit` | báo nhầm domain Nga hợp lệ (áp dụng chính sách IDN của Chromium) |
| `faß.de`, `Ⱥ.com`, ... dẫn tới hai domain khác nhau tùy phần mềm | differential testing | không cảnh báo được chỗ lệch giữa phần mềm cũ và trình duyệt |

## Chạy

```bash
pytest -q                                          # toàn bộ, profile Hypothesis 'dev'
HYPOTHESIS_PROFILE=ci pytest -q                    # như CI: tất định, 400 mẫu mỗi property
HYPOTHESIS_PROFILE=deep pytest tests/test_properties.py tests/test_idna_differential.py   # săn lỗi
pytest tests/test_golden.py -q                     # chỉ golden corpus + regression
python benchmark/calibrate.py                      # đo lại benchmark, golden theo nhóm, độ trễ
```

## Khi một test thất bại

- **Property test:** Hypothesis in phản ví dụ đã rút gọn (`Falsifying example`). Thêm phản ví dụ đó vào golden corpus như một ca cố định, rồi sửa code.
- **Regression snapshot:** test liệt kê ca đổi kết luận, kèm kết luận cũ → mới. Nếu thay đổi là chủ ý, review rồi tạo lại snapshot:
  ```bash
  UPDATE_GOLDEN=1 pytest tests/test_golden.py
  git diff tests/golden/snapshot.jsonl
  ```
- **Lỗi đã biết được sửa:** `test_known_issues_are_still_issues` báo; xóa `known_issue` khỏi ca đó trong `corpus.jsonl`.

## Thêm một ca golden

Thêm một dòng vào `tests/golden/corpus.jsonl` (giữ ký tự ẩn / đảo chiều ở dạng `\uXXXX`, các chữ khác viết thẳng), rồi chạy `UPDATE_GOLDEN=1 pytest tests/test_golden.py` và `pytest -q`. Nếu ca đó lộ ra lỗi chưa sửa ngay được, thêm `"known_issue": "<mô tả>"`.
