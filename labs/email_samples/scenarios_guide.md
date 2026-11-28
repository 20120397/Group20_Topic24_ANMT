# Bộ Mẫu Email `.eml` An toàn & Tài liệu Đáp án (Scenarios Guide)

> **Sinh viên thực hiện:** Nguyễn Gia Huy (`23120273`) — Thành viên 2 (*Threat & Malware Analyst*)  
> **Đối tượng bàn giao:** Thành viên 3 (*Auth & Simulation Engineer* — tích hợp vào `simulation/js/scenarios.js` và kiểm thử `header_analyzer.js`) & Thành viên 1 (đối chiếu báo cáo).  
> **Quy tắc an toàn & đạo đức:** Toàn bộ 6 mẫu `.eml` chỉ sử dụng tên miền dành riêng cho tài liệu `.example` (`RFC 2606`) và dải địa chỉ IP tài liệu `198.51.100.0/24`, `203.0.113.0/24` (`RFC 5737`); mọi tệp đính kèm chỉ là văn bản mô phỏng `text/plain` vô hại, **tuyệt đối không chứa mã độc, tệp thực thi `.exe`, VBA Macro hay đường dẫn độc hại thật**.  
> **Tài liệu tham chiếu:** `Bai 7 - Web - DHCP - DNS - Email Security.pptx` (S43–S45, S50–S52), `Bài 9 - Malicious Code.pptx` (S3–S8, S18, S25, S29–S38), `L1-Introduction to Cybersecurity.pptx` (S29, S33), cùng các chuẩn `RFC 5321`, `RFC 5322`, `RFC 3492`, `RFC 5891`, `RFC 7208`, `RFC 6376`, `RFC 7489`, `RFC 8601`.

---

## 1. Bảng Tổng quan 6 Kịch bản Mô phỏng

| STT | Tên file `.eml` | Loại kịch bản | Đáp án | Loại hình tấn công | Xác thực mẫu (`SPF / DKIM / DMARC`) | Chính sách DMARC (`p / dis`) | Mức độ rủi ro | Điểm `Header Analyzer` |
| :-: | :--- | :--- | :---: | :--- | :---: | :---: | :---: | :---: |
| **1** | `sample_01_legit_it.eml` | Thông báo bảo trì từ Phòng IT nội bộ (`corp-vn.example`) | **An toàn** | Hợp lệ (*Legitimate*) | `PASS / PASS / PASS` | `p=REJECT / dis=NONE` | Thấp (An toàn) | `0 / 100` (`safe`) |
| **2** | `sample_02_phishing_bank.eml` | Lừa đảo giả mạo Ngân hàng VCB Digibank | **Lừa đảo** | Phishing (Đánh cắp thông tin thẻ & OTP) | `FAIL / NONE / FAIL` | `p=QUARANTINE / dis=QUARANTINE` | Cao | `100 / 100` (`danger`) |
| **3** | `sample_03_spoofing_ceo_bec.eml` | Giả danh Tổng Giám đốc yêu cầu chuyển khoản gấp | **Lừa đảo** | Email Spoofing & BEC (*Display Name + Reply-To Spoofing*) | `SOFTFAIL / NONE / FAIL` | `p=NONE / dis=NONE` *(miền `external-mail.example`)* | Rất cao | `100 / 100` (`danger`) |
| **4** | `sample_04_lookalike_domain.eml` | Cảnh báo đăng nhập bất thường giả mạo Microsoft 365 | **Lừa đảo** | Giả mạo tên miền (*IDN Punycode Homograph & Subdomain Trick*) | `PASS* / NONE / NONE` | Chưa công bố DMARC | Cao | `100 / 100` (`danger`) |
| **5** | `sample_05_malicious_attachment.eml` | Giả danh đối tác vận tải gửi biên lai & hợp đồng độc hại | **Lừa đảo** | Phát tán Tệp đính kèm Độc hại (*Double Extension & Macro Virus*) | `FAIL / FAIL / FAIL` | `p=QUARANTINE / dis=QUARANTINE` | Rất cao | `100 / 100` (`danger`) |
| **6** | `sample_06_legit_hr.eml` | Thông báo lịch khám sức khỏe từ Phòng Nhân sự (`corp-vn.example`) | **An toàn** | Hợp lệ (*Legitimate*, kèm tệp `.pdf` sạch) | `PASS / PASS / PASS` | `p=REJECT / dis=NONE` | Thấp (An toàn) | `0 / 100` (`safe`) |

### Lưu ý kỹ thuật quan trọng về tính nhất quán RFC của bộ 6 mẫu
1. **Nhất quán chính sách DMARC nội bộ (`corp-vn.example`):** Cả Mẫu 01 và Mẫu 06 đều thể hiện tên miền nội bộ `corp-vn.example` đã triển khai DMARC ở mức nghiêm ngặt `p=REJECT sp=REJECT`. Do đó, ở Mẫu 03 (BEC), kẻ tấn công **không thể** giả mạo trực tiếp `From: <ceo@corp-vn.example>` để lọt vào hộp thư mà phải chuyển sang **Display Name Spoofing** bằng tên miền ngoài `<ceo.corpvn@external-mail.example>` (`p=NONE`) kết hợp đánh tráo `Reply-To`.
2. **Nhất quán giữa `dis=QUARANTINE` và sự kiện email lọt vào hộp thư mô phỏng:** Ở Mẫu 02 và Mẫu 05, tên miền bị giả mạo áp dụng `p=QUARANTINE sp=QUARANTINE dis=QUARANTINE` nên thư vẫn được tiếp nhận (`Delivered-To:`) vào thư mục Spam/hộp thư mô phỏng để người học phân tích (nếu để `dis=REJECT`, MTA đích đã từ chối ngay ở pha `SMTP DATA` và thư sẽ không tồn tại trong hộp thư).
3. **Cạm bẫy `SPF=PASS` tại Mẫu 04:** `SPF=PASS` vẫn xảy ra hợp lệ theo `RFC 7208` vì kẻ tấn công tự sở hữu và cấu hình bản ghi SPF cho chính tên miền giả mạo `xn--micrsoft-qbh.example` (giải mã Unicode ra `micrоsoft.example` với ký tự `о` Cyrillic `U+043E`). Điều này chứng minh `SPF=PASS` đơn lẻ **không bảo đảm email an toàn**.
4. **Tính chất mô phỏng tĩnh của `DKIM-Signature` (`bh=` và `b=`):** Các giá trị mã băm thân thư (`bh=`) và chữ ký (`b=`) trong tiêu đề `DKIM-Signature` tại Mẫu 01 và Mẫu 06 (cũng như chuỗi chữ ký không hợp lệ tại Mẫu 05) là **chuỗi mô phỏng tĩnh phục vụ môi trường huấn luyện offline**, không phải chữ ký mật mã RSA thực được sinh từ cặp khóa riêng/khóa công khai trên DNS. Cả nhóm cần nắm thống nhất chi tiết này khi trình bày demo và trả lời câu hỏi vấn đáp bảo vệ.

---

## 2. Phân tích Chi tiết Từng Mẫu (Đáp án & Dấu hiệu Nhận diện)

---

### Mẫu 01: `sample_01_legit_it.eml` — Thông báo bảo trì hệ thống từ Phòng IT
- **Đáp án:** **An toàn (*Legitimate*)**
- **Loại kịch bản:** Email thông báo nội bộ hợp lệ (không có tệp đính kèm).
- **Mức độ rủi ro:** Thấp (An toàn) — `EmailHeaderAnalyzer: 0 / 100 (safe)`.
- **Thông số Header trọng yếu:**
  - `From`: `"Phong Ky Thuat IT - CorpVN" <it-support@corp-vn.example>`
  - `Return-Path`: `<it-support@corp-vn.example>`
  - `Truyền tải`: 2 hop nội bộ chuẩn `ESMTPS` / `ESMTPSA` mã hóa `TLS 1.3`.
  - `Authentication-Results`: `spf=pass`, `dkim=pass (d=corp-vn.example; s=mail2026)`, `dmarc=pass (p=REJECT sp=REJECT dis=NONE)`.
  - `URL`: `<a href="https://status.corp-vn.example/maintenance">https://status.corp-vn.example/maintenance</a>`
- **Danh sách Dấu hiệu An toàn (*Green Flags* — 4 dấu hiệu):**
  1. **Vượt qua đầy đủ bộ ba xác thực:** Cả `SPF=PASS`, `DKIM=PASS` (có chữ ký `DKIM-Signature` hợp lệ ký bởi `d=corp-vn.example; s=mail2026`) và `DMARC=PASS` đều đạt chuẩn, với chính sách bảo vệ mạnh `p=REJECT`.
  2. **Khớp định danh (*Identifier Alignment*) hoàn toàn:** Tên miền của `Header From`, `Return-Path` (`smtp.mailfrom`) và miền ký DKIM (`header.d`) đều thống nhất là `corp-vn.example`, có đường truyền 2 hop nội bộ minh bạch mã hóa `TLS 1.3`.
  3. **Liên kết sạch, không ngụy trang:** Văn bản hiển thị (*anchor text*) trùng khớp 100% với đường dẫn đích `https://status.corp-vn.example/maintenance`, sử dụng giao thức `HTTPS` và trỏ đúng cổng nội bộ công ty.
  4. **Ngữ điệu chuyên nghiệp, không khai thác tâm lý:** Thông báo kế hoạch bảo trì rõ thời gian, không thúc ép hành động khẩn cấp và chủ động nhấn mạnh nhân viên *không cần cung cấp mật khẩu hay mã xác thực*.

---

### Mẫu 02: `sample_02_phishing_bank.eml` — Phishing giả mạo Ngân hàng (Đánh cắp thẻ & OTP)
- **Đáp án:** **Lừa đảo (*Phishing*)**
- **Loại hình tấn công:** *Bulk / Credential Harvesting Phishing* kết hợp *Email Spoofing*.
- **Mức độ rủi ro:** Cao — `EmailHeaderAnalyzer: 100 / 100 (danger)`.
- **Thông số Header trọng yếu:**
  - `From`: `"VCB Digibank Security" <no-reply@vcb-bank.example>`
  - `Return-Path`: `<bounce@promo-mailer-99.example>`
  - `Truyền tải`: 1 hop từ `host88.promo-mailer-99.example [203.0.113.88]` qua `SMTP` thuần (không mã hóa TLS).
  - `Authentication-Results`: `spf=fail` (IP `203.0.113.88` không được ủy quyền bởi `promo-mailer-99.example`), `dkim=none`, `dmarc=fail (p=QUARANTINE sp=QUARANTINE dis=QUARANTINE)`.
  - `URL`: Hiển thị `https://vcb-bank.example/verify` → đích thật `http://vcb-security-check.login-verify.example/auth`.
- **Danh sách Dấu hiệu Lừa đảo (*Red Flags* — 5 dấu hiệu):**
  1. **Thất bại xác thực `SPF`, `DKIM` và `DMARC`:** Máy chủ gửi `203.0.113.88` thất bại SPF đối với chính `smtp.mailfrom=bounce@promo-mailer-99.example` (`spf=fail`), email không có chữ ký số (`dkim=none`) và thất bại kiểm tra căn chỉnh định danh DMARC (`dmarc=fail`, xử lý `dis=QUARANTINE`).
  2. **Lệch `Envelope From` (`Return-Path`) và `Header From` + thiếu mã hóa đường truyền:** Hiển thị gửi từ `no-reply@vcb-bank.example` nhưng `Return-Path` và `Message-ID` lại thuộc miền quảng cáo/lạ `promo-mailer-99.example`; thư truyền bằng `SMTP` không bật TLS (*Bai 7*, Slide 51).
  3. **Liên kết ngụy trang (*Anchor Text vs `href` Mismatch*) & không dùng HTTPS:** Chữ hiển thị là `https://vcb-bank.example/verify` nhưng khi rê chuột vào, đường dẫn thật trỏ tới `http://vcb-security-check.login-verify.example/auth` — tên miền gốc lạ `login-verify.example` (kỹ thuật *Combosquatting* + *Subdomain Trick*) và dùng `http://` không mã hóa.
  4. **Đòn tâm lý *Social Engineering* (Khẩn cấp & Sợ hãi):** Tiêu đề gắn nhãn `[KHAN CAP]` và nội dung đe dọa tài khoản sẽ **"BỊ KHÓA VĨNH VIỄN SAU 02 GIỜ"** nhằm gây hoảng loạn, buộc nạn nhân bấm link ngay mà bỏ qua kiểm chứng.
  5. **Yêu cầu khai báo thông tin tài chính nhạy cảm:** Đòi hỏi khách hàng nhập trực tiếp *thông tin thẻ và mã OTP* qua một liên kết trong email — dấu hiệu đặc trưng của tấn công Phishing ngân hàng (*L1-Introduction to Cybersecurity*, Slide 33).

---

### Mẫu 03: `sample_03_spoofing_ceo_bec.eml` — Email Spoofing & BEC giả danh Giám đốc
- **Đáp án:** **Lừa đảo (*Email Spoofing / BEC*)**
- **Loại hình tấn công:** *Business Email Compromise (BEC)* sử dụng *Display Name Spoofing* + *Reply-To Spoofing* + lạm dụng *Open Relay*.
- **Mức độ rủi ro:** Rất cao — `EmailHeaderAnalyzer: 100 / 100 (danger)`.
- **Thông số Header trọng yếu:**
  - `From`: `"Giam doc Tran Minh Quan (CEO)" <ceo.corpvn@external-mail.example>`
  - `Return-Path`: `<mailer@relay-open88.example>`
  - `Reply-To`: `"Tran Minh Quan" <tranminhquan.private2026@freemail.example>`
  - `Truyền tải`: 1 hop từ `relay-open88.example [203.0.113.154]` qua `SMTP` thuần (không TLS).
  - `Authentication-Results`: `spf=softfail` (`relay-open88.example`), `dkim=none`, `dmarc=fail (p=NONE sp=NONE dis=NONE; spf alignment failed: smtp.mailfrom=relay-open88.example != header.from=external-mail.example)`.
- **Danh sách Dấu hiệu Lừa đảo (*Red Flags* — 5 dấu hiệu):**
  1. **Giả mạo tên hiển thị (*Display Name Spoofing*) để né DMARC `p=REJECT` của công ty:** Tên hiển thị mạo danh `"Giam doc Tran Minh Quan (CEO)"`, nhưng địa chỉ gửi thật bên trong `<...>` lại là `ceo.corpvn@external-mail.example` — hoàn toàn **không phải** tên miền nội bộ `@corp-vn.example`. Kẻ tấn công dùng miền ngoài có `p=NONE` để né chính sách `p=REJECT` mà `corp-vn.example` đang áp dụng.
  2. **Lệch `Return-Path`, đi qua máy chủ Open Relay và thất bại xác thực:** `Return-Path` và `Message-ID` thuộc máy chủ chuyển tiếp `relay-open88.example` (truyền `SMTP` không TLS), cho kết quả `spf=softfail` (`~all`), `dkim=none` và `dmarc=fail` do lệch định danh giữa `relay-open88.example` và `external-mail.example`.
  3. **Đánh tráo trường `Reply-To` (*Reply-To Spoofing*):** Header `Reply-To` bị trỏ sang hộp thư cá nhân miễn phí `tranminhquan.private2026@freemail.example`. Nếu nhân viên kế toán bấm *Reply*, toàn bộ trao đổi và xác nhận chuyển tiền sẽ rơi thẳng vào hộp thư của kẻ tấn công thay vì hệ thống nội bộ.
  4. **Đòn tâm lý Quyền lực (*Authority*) & Khẩn cấp (*Urgency*) trong BEC:** Mạo danh Tổng Giám đốc yêu cầu chuyển khoản số tiền lớn (`245.000.000 VND`) trước `11:00 trưa nay` sang một *số tài khoản mới* chưa qua quy trình duyệt chuẩn.
  5. **Cố ý cô lập nạn nhân khỏi xác minh đa kênh:** Viện cớ *"đang họp gấp với đối tác nước ngoài nên không tiện nghe điện thoại"* và yêu cầu *"tuyệt đối không trao đổi với các phòng ban khác"* — thủ thuật kinh điển nhằm ngăn kế toán gọi điện xác nhận lại với sếp thật.

---

### Mẫu 04: `sample_04_lookalike_domain.eml` — Giả mạo Tên miền (IDN Punycode & Subdomain Trick)
- **Đáp án:** **Lừa đảo (*Domain Spoofing / Lookalike*)**
- **Loại hình tấn công:** Tấn công giả mạo tên miền kết hợp *IDN Homograph Attack (Punycode)* và *Subdomain Trick*.
- **Mức độ rủi ro:** Cao — `EmailHeaderAnalyzer: 100 / 100 (danger)`.
- **Thông số Header trọng yếu:**
  - `From`: `"Microsoft 365 Account Team" <security@xn--micrsoft-qbh.example>`
  - `Return-Path`: `<bounce@xn--micrsoft-qbh.example>`
  - `Truyền tải`: `mail.xn--micrsoft-qbh.example [198.51.100.77]` qua `ESMTPS` (`TLS 1.2`).
  - `Authentication-Results`: `spf=pass` (hợp lệ trên miền giả `xn--micrsoft-qbh.example`), `dkim=none`, `dmarc=none`.
  - `URL`: Hiển thị `https://login.microsoft.example/verify` → đích thật `https://login.microsoft.example.account-reset-portal.example/oauth`.
- **Danh sách Dấu hiệu Lừa đảo (*Red Flags* — 4 dấu hiệu):**
  1. **Tên miền IDN Punycode (`xn--`) giả dạng bằng kỹ thuật *Homograph Attack*:** Địa chỉ gửi sử dụng chuỗi ACE (`RFC 3492` / `RFC 5891`) `xn--micrsoft-qbh.example`, khi hiển thị dạng Unicode là **`micrоsoft.example`** — trong đó ký tự thứ 5 là chữ **`о` bảng Cyrillic (`U+043E`)**, nhìn bằng mắt thường gần như giống hệt chữ **`o` bảng Latin (`U+006F`)**.
  2. **Thủ thuật *Subdomain Trick* kết hợp liên kết ngụy trang:** Văn bản hiển thị là `https://login.microsoft.example/verify` nhưng đường dẫn `href` thật là `https://login.microsoft.example.account-reset-portal.example/oauth`. Chuỗi tên miền 5 cấp đưa tên thương hiệu lên làm subdomain nhằm che giấu tên miền gốc thực sự ở cuối là **`account-reset-portal.example`**.
  3. **Cạm bẫy kỹ thuật `SPF=PASS` nhưng thiếu bảo chứng danh tính thực:** Kẻ tấn công tự mua tên miền giả và cấu hình bản ghi SPF cho IP `198.51.100.77` nên email vẫn vượt qua SPF (`spf=pass`) và có TLS (`TLS 1.2`); tuy nhiên miền giả không ký `DKIM` (`dkim=none`), không có `DMARC` (`dmarc=none`) và hoàn toàn không phải tên miền chính thức của nhà cung cấp.
  4. **Giả mạo thương hiệu & khai thác tâm lý sợ hãi (*Fear*):** Dùng tên hiển thị `"Microsoft 365 Account Team"`, cảnh báo đăng nhập từ IP nước ngoài và đe dọa *"mất quyền truy cập hộp thư công ty"* nhằm dụ người dùng nhập mật khẩu tài khoản doanh nghiệp vào trang giả mạo.

---

### Mẫu 05: `sample_05_malicious_attachment.eml` — Phát tán Tệp đính kèm Độc hại
- **Đáp án:** **Lừa đảo (*Malicious Attachment Delivery*)**
- **Loại hình tấn công:** Phát tán mã độc qua tệp đính kèm kết hợp *Double Extension* và *Macro Virus*.
- **Mức độ rủi ro:** Rất cao — `EmailHeaderAnalyzer: 100 / 100 (danger)`.
- **Thông số Header trọng yếu:**
  - `From`: `"Bo phan Thanh toan - Doi tac Van tai" <billing@partner-logistics.example>`
  - `Return-Path`: `<bounce@unknown-sender-44.example>`
  - `DKIM-Signature`: Có header ký `d=partner-logistics.example; s=mail2025` nhưng bị giả mạo/sai mã băm thân thư (`bh=`).
  - `Authentication-Results`: `spf=fail`, `dkim=fail reason="signature verification failed"`, `dmarc=fail (p=QUARANTINE sp=QUARANTINE dis=QUARANTINE)`.
  - `Tệp đính kèm (placeholder mô phỏng an toàn)`: `BienLai_ThanhToan_2026.pdf.exe` và `HoSo_ChuyenKhoan_2026.docm`.
- **Danh sách Dấu hiệu Lừa đảo (*Red Flags* — 5 dấu hiệu):**
  1. **Thất bại toàn bộ 3 lớp xác thực (`SPF=FAIL`, `DKIM=FAIL`, `DMARC=FAIL`):** IP gửi `203.0.113.211` không hợp lệ theo SPF của `unknown-sender-44.example`, chữ ký `DKIM-Signature` thất bại khi xác minh toàn vẹn (`signature verification failed`), và DMARC thất bại dẫn đến hành động cách ly `dis=QUARANTINE`.
  2. **Lệch `Return-Path` & không mã hóa đường truyền:** Hiển thị gửi từ đối tác `billing@partner-logistics.example`, nhưng `Return-Path` và `Message-ID` lại đến từ máy chủ lạ `unknown-sender-44.example` truyền qua `SMTP` thuần không bật TLS.
  3. **Ngụy trang phần mở rộng kép (*Double Extension*):** Nội dung email cố tình đánh lạc hướng khi chỉ nhắc tên tệp biên lai là `BienLai_ThanhToan_2026.pdf`, nhưng kiểm tra trường `filename` thực tế trong tệp đính kèm lại là **`BienLai_ThanhToan_2026.pdf.exe`** — lợi dụng cấu hình mặc định ẩn phần mở rộng đã biết của Windows để đánh lừa người dùng chạy tệp thực thi `.exe` (chứa *Trojan* / *Ransomware* / *Spyware* — *Bài 9 - Malicious Code.pptx*, Slide 25, 29).
  4. **Đính kèm tài liệu Office hỗ trợ Macro (`.docm`):** Tệp **`HoSo_ChuyenKhoan_2026.docm`** là định dạng Word cho phép nhúng mã VBA Macro tự động thực thi — phương thức lây lan kinh điển của *Macro Virus* (*Bài 9 - Malicious Code.pptx*, Slide 18).
  5. **Nội dung dụ người dùng tự tay tắt lớp bảo vệ:** Email hướng dẫn trực tiếp người nhận chọn **`"Enable Content / Enable Macros"`** để xem đầy đủ bảng kê — đây là dấu hiệu chắc chắn của kỹ thuật kích hoạt mã độc qua tài liệu Office (giai đoạn *Delivery → Exploitation* trong *Cyber Kill Chain*, *Bài 9*, Slide 6).

---

### Mẫu 06: `sample_06_legit_hr.eml` — Thông báo lịch khám sức khỏe Phòng Nhân sự
- **Đáp án:** **An toàn (*Legitimate*)**
- **Loại kịch bản:** Email nội bộ hợp lệ có đính kèm tệp `.pdf` sạch (dùng để kiểm tra độ chính xác, tránh tâm lý nghi ngờ mọi tệp đính kèm — *False Positive*).
- **Mức độ rủi ro:** Thấp (An toàn) — `EmailHeaderAnalyzer: 0 / 100 (safe)`.
- **Thông số Header trọng yếu:**
  - `From`: `"Phong Nhan Su - CorpVN" <hr@corp-vn.example>`
  - `Return-Path`: `<hr@corp-vn.example>`
  - `Truyền tải`: 2 hop nội bộ (`hr-portal.corp-vn.example` → `mail.corp-vn.example` → `mx.corp-vn.example`) qua `ESMTPS` / `ESMTPSA` mã hóa `TLS 1.3`.
  - `Authentication-Results`: `spf=pass`, `dkim=pass (d=corp-vn.example; s=mail2026)`, `dmarc=pass (p=REJECT sp=REJECT dis=NONE)`.
  - `Tệp đính kèm`: `Lich_Kham_Suc_Khoe_2026.pdf` (placeholder mô phỏng hợp lệ).
  - `URL`: `https://portal.corp-vn.example/hr/health-check`.
- **Danh sách Dấu hiệu An toàn (*Green Flags* — 4 dấu hiệu):**
  1. **Xác thực chuẩn và nhất quán với chính sách doanh nghiệp:** `SPF=PASS`, `DKIM=PASS`, `DMARC=PASS` (`p=REJECT`), toàn bộ miền `From`, `Return-Path` và `DKIM d=` trùng khớp là `corp-vn.example`.
  2. **Lộ trình gửi nội bộ minh bạch, có mã hóa TLS 1.3:** Đường đi 2 hop xuất phát từ cổng nhân sự nội bộ `hr-portal.corp-vn.example` qua máy chủ thư chính `mail.corp-vn.example` bằng `ESMTPS/TLS 1.3`.
  3. **Tệp đính kèm an toàn, đúng định dạng:** Tên tệp `Lich_Kham_Suc_Khoe_2026.pdf` có phần mở rộng đơn hợp lệ (`.pdf`), không dùng đuôi kép, không thuộc nhóm hỗ trợ Macro (`.docm/.xlsm`) và không yêu cầu nhập mật khẩu giải nén hay bật Macro.
  4. **Liên kết nội bộ hợp lệ & ngữ điệu tự nhiên:** Đường dẫn hiển thị trùng khớp 100% URL đích `https://portal.corp-vn.example/hr/health-check` (HTTPS), thông báo lịch định kỳ rõ ràng và không yêu cầu thông tin nhạy cảm.

---

## 3. Ghi chú Bàn giao Đồng bộ cho Thành viên 3 (`simulation/js/scenarios.js` & Chương 5)

Sau khi chuẩn hóa kỹ thuật RFC cho bộ 6 file `.eml`, Thành viên 2 tóm tắt 4 điểm điều chỉnh nhỏ cần Thành viên 3 đồng bộ vào `simulation/js/scenarios.js` (và cập nhật bảng tóm tắt Chương 5 nếu cần):

| Mẫu | Điểm đã chuẩn hóa ở file `.eml` | Nội dung cần TV3 đồng bộ trong `scenarios.js` |
| :-: | :--- | :--- |
| **Mẫu 02** | Sửa `p=QUARANTINE sp=QUARANTINE dis=QUARANTINE`; sửa chú thích `spf=fail` kiểm tra theo `promo-mailer-99.example`; sửa câu `"BỊ KHÓA VĨNH VIỄN SAU 02 GIỜ"`. | Cập nhật `bodyHtml` và `rawEml` của `sample_02`. |
| **Mẫu 03** | Chuyển sang *Display Name Spoofing* (`From: <ceo.corpvn@external-mail.example>`) và `header.from=external-mail.example` (`p=NONE`) để không mâu thuẫn với chính sách `p=REJECT` của `corp-vn.example` ở Mẫu 01 & 06. | Cập nhật `senderEmail`, `explanation`, `flagsDetail` và `rawEml` của `sample_03`. |
| **Mẫu 04** | Sửa chuỗi Punycode giả lập thành mã RFC 3492/5891 chính xác **`xn--micrsoft-qbh.example`** (giải mã Unicode ra `micrоsoft.example` với ký tự `о` Cyrillic `U+043E`). | Thay chuỗi `xn--micrsoft-7ya.example` → `xn--micrsoft-qbh.example` tại `sample_04` (và Chương 5 / kịch bản Demo). |
| **Mẫu 05** | Sửa `p=QUARANTINE sp=QUARANTINE dis=QUARANTINE` (khớp logic thư có `Delivered-To`); bổ sung header `DKIM-Signature` bị sai hash cho khớp `dkim=fail`; ẩn đuôi `.exe` trong phần lời nhắn (`BienLai_ThanhToan_2026.pdf`). | Cập nhật `bodyHtml` và `rawEml` của `sample_05`. |

*(Ghi chú mở rộng: Bộ mẫu hiện chuẩn hóa 6 kịch bản cốt lõi đồng bộ 1-1 với Web App và Chương 5. Nếu Trưởng nhóm yêu cầu mở rộng lên 7–8 kịch bản nâng cao như Clone Phishing kèm tệp nén `.zip` đặt mật khẩu hoặc HTML Smuggling `.html`, TV2 sẽ bổ sung tiếp `sample_07` / `sample_08` vào thư mục này.)*
