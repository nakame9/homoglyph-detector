# Baseline theo thời gian

`prepare-baseline` nhận URL đã được phép sử dụng, với nhãn do người đánh giá gán
trước khi xem verdict. Lệnh chạy offline, không tải feed và không gọi engine.

## Nguồn và nhãn

Ghi nguồn, phiên bản, quyền dùng và mục đích vào `--source`, đồng thời giữ bằng
chứng cấp phép riêng. Kiểm tra ngày 19/11/2026:

- [OpenPhish](https://openphish.com/terms.html) giới hạn nghiên cứu cá nhân, độc
  lập hoặc học thuật không phục vụ hoạt động kinh doanh của tổ chức. Sử dụng
  thương mại và chia sẻ thông tin với bên thứ ba cần đối chiếu yêu cầu chấp thuận
  bằng văn bản; không suy ra quyền dùng chỉ từ việc feed truy cập công khai.
- [PhreshPhish](https://huggingface.co/datasets/phreshphish/phreshphish) ghi
  CC BY 4.0 và mục đích nghiên cứu chống phishing. Nhãn `phish`/`benign` và brand
  mục tiêu không thay thế nhãn kỹ thuật bên dưới. Không dùng test split công khai
  để chọn ngưỡng. Công cụ này không tự tải dữ liệu từ hai nguồn trên.

Với ca dương đã xác nhận, chốt nhãn chính theo thứ tự dưới đây và lưu bằng chứng
đối chiếu riêng. Không dùng verdict của detector làm nhãn:

| Nhãn | Tiêu chí |
| --- | --- |
| `userinfo` | Domain trong phần trước `@` giả brand nhưng dẫn sang đích khác; ghi domain đã xem xét vào `userinfo_lure`. |
| `homoglyph` | Domain nhái thay ký tự bằng ký tự nhìn giống, có đối chiếu với brand mục tiêu. |
| `typosquat` | Domain nhái do lỗi chính tả như thêm, xóa, đổi chỗ hoặc thay chữ. |
| `combosquat` | Ghép tên brand với từ khác trên domain không chính chủ. |
| `other_phish` | Phishing đã xác nhận, ngoài bốn nhóm trên. |
| `benign` | Đầu vào hợp lệ đã xác nhận; tập dùng đo FPR phải đại diện kênh triển khai. |

## Định dạng và cách chạy

Một object JSON trên mỗi dòng; `userinfo_lure` bắt buộc với nhãn `userinfo`.

```json
{"url":"https://paypal.com@evil.com/login?token=EXAMPLE","observed_on":"2026-01-04","label":"userinfo","userinfo_lure":"paypal.com"}
```

```powershell
python benchmark/real_world.py prepare-baseline private/labeled.jsonl --output benchmark/.cache/baseline-v1 --source "authorized export v1; permission reviewed 2026-11-19" --validation-start 2026-07-01 --holdout-start 2026-10-01 --per-group 300 --coverage 500 --seed 2026
```

Đặt đầu vào và kết quả trong vùng dữ liệu riêng, không commit URL thật. Mỗi dòng
đọc tối đa 1 MiB. Lệnh từ chối nhãn/ngày sai và không ghi đè thư mục đã tồn tại.

## Lấy mẫu và khả năng tái tạo

- Gộp theo domain đăng ký với PSL, gồm private suffix như `github.io`. Giữ ca có
  ngày xuất hiện sớm nhất; cùng ngày dùng thứ tự nhãn, URL rồi độ dài nguồn để kết quả không
  phụ thuộc thứ tự dòng. Báo số domain có nhãn mâu thuẫn để rà thủ công.
- Ca trước `validation-start` vào development; từ mốc đó đến trước
  `holdout-start` vào validation; từ mốc holdout trở đi vào holdout. Một domain
  chỉ xuất hiện một lần, trong một tập. Không có nhãn chiến dịch, nên vẫn có thể
  trùng chiến dịch qua nhiều domain.
- Lấy mẫu coverage ngẫu nhiên từ ca dương đủ điều kiện trước, rồi lấy tối đa
  `--per-group` mỗi nhóm từ phần còn lại, trên tổng ba tập. Hai cohort không
  trùng domain. Giữ mọi benign đủ điều kiện.
- IP, public suffix, URL ngoài HTTP(S) hoặc host không chuẩn hóa được được đếm
  trong `without_registered_domain`, không đưa vào mẫu. Coverage này chỉ đại
  diện phần có domain đăng ký đủ điều kiện, chưa thể xem là độ bao phủ toàn feed.
- Giữ host **như được viết**, chỉ dùng A-label để gộp domain. Bỏ mật khẩu, path,
  query, fragment; chỉ giữ lure userinfo đã được người gán nhãn xác nhận và khớp
  userinfo gốc. Port sai được thay bằng giá trị sai cố định để không lộ dữ liệu.
- `source_length` ghi độ dài đầu vào gốc. URL rút gọn không tái hiện mọi giới hạn
  độ dài hay mọi tín hiệu trong userinfo đã bỏ; B2 phải kiểm tra hạn chế này trước
  khi dùng dữ liệu để nghiệm thu. Không coi ca rút gọn là bản gốc đầy đủ.
- Manifest ghi provenance, phiên bản Python/IDNA/PSL, SHA-256 đầu vào, mốc chia tập, seed, số mẫu và hash
  từng file. Báo thiếu mẫu theo nhóm; seed không biến một tập thiếu thành đủ.

Chỉ dùng development/validation để chọn thay đổi. Khóa ứng viên và ngưỡng trước
khi chấm holdout một lần. B1 vẫn cần 200–400 ca dương mỗi nhóm và tập benign đại
diện; việc công cụ chạy được trên dữ liệu tổng hợp chưa hoàn thành B1.
