# Hợp đồng JSON tích hợp v1

Dùng `homoglyph-detector --integration-json -f domains.txt`, hoặc
`analyze(value).to_integration_dict()` từ Python. CLI trả mảng theo thứ tự đầu vào
và giữ bảng mã thoát hiện có. `--json` và `Report.to_dict()` vẫn xuất báo cáo đầy đủ.

```json
{
  "schema_version": 1,
  "input": "https://apple.com:8443",
  "input_type": "url",
  "scheme": "https",
  "host": "apple.com",
  "port": 8443,
  "has_userinfo": true,
  "has_query": true,
  "parse_status": "ok",
  "parse_reason": "",
  "verdict": "SUSPICIOUS",
  "risk_score": 81,
  "findings": [{"kind": "brand_in_userinfo", "brand_id": "paypal"}]
}
```

- `input` là đích rút gọn: scheme, host và port chỉ định đối với URL; chỉ host đối
  với domain/email. Host dùng A-label hoặc IP chuẩn hóa; IPv6 có ngoặc vuông trong
  `input`, không có ngoặc trong `host`.
- `input`, `host`, `port` là `null` khi không có đích chuẩn hóa, gồm tên hiển thị và
  đầu vào bị từ chối. `scheme` là `null` với đầu vào ngoài dạng URL. `port` cũng là
  `null` nếu URL không chỉ định port.
- `has_userinfo` và `has_query` là cờ hiện diện, kể cả phần rỗng; cả hai là `null`
  khi `unsupported/too_long` vì không giữ chuỗi gốc để suy ra các cờ.
- `parse_status`: `ok`, `rejected`, `unsupported`; `parse_reason` rỗng khi `ok`.
  Trạng thái parse độc lập với verdict: nhánh bidi P1-b có thể là
  `rejected` và `MALICIOUS`.
- `findings` chỉ xuất mã `kind`; `brand_in_userinfo` thêm `brand_id` từ Brand DB.
  Ví dụ trên rút gọn danh sách finding. Không xuất message hoặc detail tự do.

Đánh giá diễn ra trước bước rút gọn, giữ bằng chứng userinfo và bidi. Schema bỏ
userinfo, path, query, fragment, tên hiển thị và phần local của email. Báo cáo đầy
đủ có thể chứa bí mật trong đầu vào. Giới hạn 272 áp cho phần engine quét, 8.192
cho toàn đầu vào; C1 dùng nguyên bộ đọc CLI và giới hạn lô hiện có.
