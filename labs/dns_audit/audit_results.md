# Kết quả Khảo sát Cấu hình Xác thực Email (DNS Audit)

> **Phụ trách:** Thành viên 3 — Nguyễn Lê Hữu Điền (`23120233`, *Auth & Simulation Engineer*)  
> **Công cụ sử dụng:** Script PowerShell [check_email_auth.ps1](check_email_auth.ps1), `Resolve-DnsName`, `nslookup`  
> **Thời điểm thực nghiệm:** `2026-11-25 14:15 +07:00` (trên mạng Internet thực tế)

---

## 1. Hướng dẫn Chạy Thực nghiệm

### Cách 1: Chạy kiểm thử logic offline (9 unit tests, không cần Internet)
```powershell
powershell -ExecutionPolicy Bypass -File .\check_email_auth.ps1 -SelfTest
```

### Cách 2: Chạy khảo sát trực tiếp trên máy có Internet (10 tên miền + DKIM selector mẫu)
```powershell
powershell -ExecutionPolicy Bypass -File .\check_email_auth.ps1
```
Hoặc xuất kết quả kèm bản ghi thô ra file Markdown tạm để đối chiếu:
```powershell
powershell -ExecutionPolicy Bypass -File .\check_email_auth.ps1 -ExportMarkdown .\live_audit_output.md
```

### Cách 3: Truy vấn thủ công bằng `nslookup` (đối chiếu với *Bài 7*)
```powershell
nslookup -type=mx vietcombank.com.vn
nslookup -type=txt vietcombank.com.vn
nslookup -type=txt _dmarc.vietcombank.com.vn
nslookup -type=txt selector1._domainkey.vietcombank.com.vn
```

---

## 2. Tiêu chí Đánh giá Mức độ Bảo vệ

| Mức đánh giá | Điều kiện kỹ thuật (`SPF` + `DMARC`) | Ý nghĩa chống giả mạo |
| :--- | :--- | :--- |
| **Mạnh** | Có SPF hiệu lực `-all` hoặc `~all` (**và** `DMARC p=reject`) | Máy nhận từ chối thẳng email giả mạo `Header From` khi sai xác thực/alignment. |
| **Trung bình** | Có DMARC `p=quarantine`/`reject`, hoặc chỉ có SPF `-all`/`~all` nhưng DMARC `p=none` hoặc chưa có DMARC | Mới dừng ở mức cách ly Spam, chỉ theo dõi báo cáo (`p=none`), hoặc chưa bảo vệ được trường `Header From`. |
| **Yếu / Chưa cấu hình** | Thiếu cả SPF & DMARC, hoặc dùng `+all`/`?all`, hoặc chỉ `p=none` thiếu SPF chặt | Nguy cơ cao bị lợi dụng giả mạo tên miền (*Email Spoofing*). |

---

## 3. Bảng Kết quả Khảo sát Thực tế (10 Tên miền)

> **Ghi nhận thực nghiệm ngày `25/11/2026` (`14:15 +07:00`):** Kết quả bên dưới được thu thập trực tiếp từ truy vấn DNS công khai thông qua `.\check_email_auth.ps1` (có đếm đệ quy cơ chế `include:` / `redirect=` theo RFC 7208).

| STT | Tên miền | Bản ghi MX chính | SPF (`v=spf1`), cơ chế cuối & số DNS lookup | DMARC (`_dmarc`) | Đánh giá | Ghi chú kỹ thuật |
| :-: | :--- | :--- | :--- | :--- | :---: | :--- |
| 1 | `microsoft.com` | `microsoft-com.mail.protection.outlook.com (10)` | `-all` (`4` top / `6` recursive lookups) | `p=reject; pct=100; rua=...; ruf=...; fo=1` | **Mạnh** | Chuẩn mực; bật cả RUA và RUF (`fo=1`) |
| 2 | `cloudflare.com` | `mxb-canary.global.inbound.cf-emailsecurity.net (5); mxa-canary... (5)` | `-all` (`6` top / `7` recursive lookups) | `p=reject; sp=reject; adkim=r; aspf=r; pct=100; rua=...` | **Mạnh** | Khóa chặt cả tên miền gốc lẫn subdomain (`sp=reject`) |
| 3 | `vietcombank.com.vn` | `vietcombank-com-vn.mail.protection.outlook.com (5)` | `~all` (`2` recursive lookups) | `p=reject; pct=100; rua=mailto:infosec@...; ruf=...; ri=86400; fo=1` | **Mạnh** | Ngân hàng VN tuân thủ nghiêm ngặt DMARC `p=reject` |
| 4 | `uit.edu.vn` | `aspmx.l.google.com (10); alt1.aspmx.l.google.com (20)` | `~all` (`1` recursive lookup) | `p=reject` | **Mạnh** | Điểm sáng khối giáo dục; đã cưỡng chế `p=reject` |
| 5 | `github.com` | `github-com.mail.protection.outlook.com (0)` | `~all` (`8` top / `10` recursive lookups) | `p=quarantine; sp=reject; pct=100; rua=mailto:dmarc@github.com; ruf=...` | **Trung bình** | **Chạm ngưỡng 10/10 DNS lookups** (`_spf.salesforce.com` + `ab.sendgrid.net`); gốc ở `quarantine` |
| 6 | `gmail.com` | `gmail-smtp-in.l.google.com (5); alt1.gmail-smtp-in.l.google.com (10)` | `redirect=_spf.google.com` → `~all` (`1` recursive lookup) | `p=none; sp=quarantine; rua=mailto:mailauth-reports@google.com` | **Trung bình** | Dùng `redirect=`; chính sách `p=none` để tránh gãy chuyển tiếp email người dùng |
| 7 | `vnexpress.net` | `vnexpress-net.mail.protection.outlook.com (0); mailgw01.fpt.com.vn (10)` | `-all` (`4` recursive lookups) | `p=none;` | **Trung bình** | Đã có SPF `-all` nhưng DMARC mới ở chế độ giám sát (`p=none`), chưa có `rua=` |
| 8 | `hust.edu.vn` | `hust-edu-vn.mail.protection.outlook.com (0)` | `-all` (`1` recursive lookup) | `p=none;` | **Trung bình** | Đã dùng SPF `-all` nhưng DMARC vẫn dừng ở `p=none`, chưa chặn giả mạo `From` |
| 9 | `hcmus.edu.vn` | `aspmx.l.google.com (1); alt1.aspmx.l.google.com (10)` | `~all` (`1` recursive lookup) | *Không có bản ghi `_dmarc`* | **Trung bình** | Có SPF `~all` qua Google Workspace nhưng thiếu hoàn toàn `_dmarc` bảo vệ `Header From` |
| 10 | `neverssl.com` | *Không có bản ghi MX* | *Không có bản ghi SPF* | *Không có bản ghi DMARC* | **Yếu / Chưa cấu hình** | Tên miền đối chứng không cấu hình bảo vệ email (dễ bị spoofing nếu không chặn) |

### Chi tiết Bản ghi Thô tiêu biểu (Raw Records)
- **`microsoft.com`**:
  - SPF: `v=spf1 include:_spf-a.microsoft.com include:_spf-b.microsoft.com include:_spf-ssg-a.msft.net include:_spf1-meo.microsoft.com -all`
  - DMARC: `v=DMARC1; p=reject; pct=100; rua=mailto:itex-rua@microsoft.com; ruf=mailto:itex-ruf@microsoft.com; fo=1`
- **`vietcombank.com.vn`**:
  - SPF: `v=spf1 include:spf.protection.outlook.com include:_spf-dc44.sapsf.com ip4:103.11.172.0/22 ip4:103.11.172.88 ... ~all`
  - DMARC: `v=DMARC1;p=reject;pct=100;rua=mailto:infosec@vietcombank.com.vn;ruf=mailto:infosec@vietcombank.com.vn;ri=86400;fo=1`
- **`github.com`**:
  - SPF: `v=spf1 ip4:192.30.252.0/22 ... include:spf.protection.outlook.com include:_netblocks.google.com include:_netblocks2.google.com include:mail.zendesk.com include:_spf.salesforce.com include:servers.mcsv.net include:mktomail.com include:sendgrid.net ... ~all`
  - DMARC: `v=DMARC1; p=quarantine; sp=reject; pct=100; rua=mailto:dmarc@github.com; ruf=mailto:dmarc@github.com; fo=1`
- **`gmail.com`**:
  - SPF: `v=spf1 redirect=_spf.google.com` *(phân giải `_spf.google.com` chứa dải `ip4`/`ip6` trực tiếp và kết thúc bằng `~all`)*
  - DMARC: `v=DMARC1; p=none; sp=quarantine; rua=mailto:mailauth-reports@google.com`

---

## 4. Minh họa Truy vấn Khóa Công khai DKIM trên DNS

Khác với SPF và DMARC nằm ở vị trí cố định, khóa công khai DKIM nằm tại `<selector>._domainkey.<domain>`. Kết quả truy vấn thực tế bằng `nslookup` cho thấy 3 trường hợp tiêu biểu trong thực tế triển khai:

1. **Ủy quyền qua bản ghi `CNAME` (Microsoft 365 — `vietcombank.com.vn`, selector `selector1`):**
   ```text
   > nslookup -type=txt selector1._domainkey.vietcombank.com.vn
   selector1._domainkey.vietcombank.com.vn canonical name = selector1-vietcombank-com-vn._domainkey.vcb365.onmicrosoft.com
   selector1-vietcombank-com-vn._domainkey.vcb365.onmicrosoft.com text =
       "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCZ5ktL/8GT0Vrm9HSOdInA7ZokvhUvRNN4Ra3qIMWvt5DCE4qtIBtQ4R4rrKjSo/+Or2vfRsUN7ksYQryy0EFy4JDHN0TlY48LLwj6XAchPa9iZZ9f6KoNgWiJO7bU/k4z7eH/xFbUV8gbjadc4oxw+aeQnpwxV9cSFIfI94jaSQIDAQAB;"
   ```
   *Nhận xét:* Doanh nghiệp chỉ cần trỏ `CNAME` một lần, việc xoay vòng khóa (*key rotation*) do nền tảng Microsoft 365 tự động quản lý.

2. **Khai báo khóa công khai RSA trực tiếp trên `TXT` (Google Workspace — `uit.edu.vn`, selector `google`):**
   ```text
   > nslookup -type=txt google._domainkey.uit.edu.vn
   google._domainkey.uit.edu.vn text =
       "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCv0GoeyqB4m/sjs66ZqzXgeERpK3qs6XbaeyBREb/T7lypW1+gW6bF11qQTBiTMdQf6o/fIYpQkWGjbYLf66lnwUh8YUsJZj17lcbDQSJ8szLyw29VugJBuGgAnxhvwRaUMj1O2s+dQldfObAoo+UC/5OiWx/YD/AXWWSj/CKzAwIDAQAB"
   ```

3. **Minh họa thu hồi khóa cũ theo RFC 6376 (`gmail.com`, selector `20230601`):**
   ```text
   > nslookup -type=txt 20230601._domainkey.gmail.com
   20230601._domainkey.gmail.com text =
       "v=DKIM1; k=rsa; p="
   ```
   *Nhận xét:* Giá trị `p=` rỗng là quy ước chuẩn của **RFC 6376 (Mục 3.6.1)** báo hiệu khóa đã bị thu hồi khi xoay vòng sang selector mới, giúp máy nhận không còn công nhận chữ ký dùng selector cũ.

---

## 5. Phân tích & Nhận xét Chuyên sâu (TV3)

- **Nhóm Tài chính & Công nghệ lớn (`vietcombank.com.vn`, `microsoft.com`, `cloudflare.com`):** Đều đã triển khai đồng bộ SPF, DKIM và DMARC ở mức cưỡng chế cao nhất (`p=reject`, `pct=100`), kết hợp nhận báo cáo `rua`/`ruf` về bộ phận An toàn thông tin (`infosec@vietcombank.com.vn`, `itex-rua@microsoft.com`) để giám sát liên tục các chiến dịch giả mạo thương hiệu.
- **Nhóm Báo chí & Giáo dục (`vnexpress.net`, `hust.edu.vn`, `hcmus.edu.vn` vs `uit.edu.vn`):** Có sự phân hóa rõ rệt. Trong khi `uit.edu.vn` đã nâng cấp thành công lên `p=reject`, thì `vnexpress.net` và `hust.edu.vn` mới cấu hình SPF `-all` kèm DMARC `p=none` (chỉ giám sát, không chặn) và chưa gán địa chỉ `rua=`; riêng `hcmus.edu.vn` mới chỉ có SPF `~all` của Google Workspace mà **chưa công bố bản ghi `_dmarc`**. Trên thực tế, bất kỳ tên miền nào thiếu `_dmarc` hoặc chỉ đặt `p=none` đều chưa bảo vệ được trường `Header From` trước kỹ thuật giả mạo trực tiếp như kịch bản Mẫu 3.
- **Bài học thiết kế SPF từ thực nghiệm `github.com` và `gmail.com`:**
  - `github.com` tích hợp nhiều dịch vụ bên thứ ba (Outlook, Google, Zendesk, Salesforce, Mailchimp, Marketo, SendGrid) khiến tổng số truy vấn đệ quy đạt đúng **`10 / 10` lookup** — chỉ cần thêm 1 `include:` nữa là vượt giới hạn RFC 7208 và phát sinh lỗi `PermError`.
  - `gmail.com` áp dụng `v=spf1 redirect=_spf.google.com` và làm phẳng (*SPF flattening*) toàn bộ dải IP trực tiếp trong `_spf.google.com`, giúp chỉ tốn `1` DNS lookup nhưng vẫn kế thừa đầy đủ cơ chế `~all`.
- **Minh chứng kèm theo:** Ảnh chụp kết quả chạy thực nghiệm lưu tại [ch3_dns_audit_terminal.png](../../report/assets/ch3_dns_audit_terminal.png) và tích hợp vào Mục 3.5 của [Chương 3](../../report/03_chuong3_spf_dkim_dmarc.md).

---

## 6. Checklist Hoàn thiện (TV3)

- [x] Chạy `.\check_email_auth.ps1 -SelfTest` (9/9 PASS) và chạy thực tế trên 10 tên miền vào ngày `25/11/2026`, cập nhật đầy đủ bảng Mục 3.
- [x] Lưu ảnh chụp kết quả chạy terminal tại `report/assets/ch3_dns_audit_terminal.png`.
- [x] Chạy `nslookup -type=txt` kiểm tra khóa công khai DKIM thực tế (`vietcombank.com.vn`, `uit.edu.vn`, `gmail.com`) và phân tích rõ `CNAME`, `TXT`, và khóa thu hồi (`p=` rỗng).
- [x] Viết nhận xét đối chiếu giữa nhóm công nghệ/ngân hàng, giáo dục/báo chí và tên miền chưa cấu hình để đưa sang Mục 3.5 của Chương 3.
