# Bộ Mẫu Email `.eml` An toàn & Hướng dẫn Đáp án (Scenarios Guide)

> **Phụ trách:** Thành viên 2 (Threat & Malware Analyst)  
> **Quy tắc an toàn:** Toàn bộ 6 mẫu chỉ dùng tên miền giả định `.example` (RFC 2606); tệp đính kèm là văn bản mô phỏng vô hại, tuyệt đối không chứa mã độc hay đường dẫn thật.

---

## 1. Bảng Tổng quan 6 Kịch bản Mô phỏng

| STT | Tên file `.eml` | Loại kịch bản | Kết luận | Xác thực mẫu (`SPF / DKIM / DMARC`) | Mức độ rủi ro |
| :-: | :--- | :--- | :---: | :---: | :---: |
| 1 | `sample_01_legit_it.eml` | Thông báo bảo trì từ Phòng IT nội bộ | **An toàn** | `PASS / PASS / PASS` | Thấp (An toàn) |
| 2 | `sample_02_phishing_bank.eml` | Phishing giả mạo Ngân hàng | **Lừa đảo** | `FAIL / NONE / FAIL` | Cao |
| 3 | `sample_03_spoofing_ceo_bec.eml` | Email Spoofing / BEC giả danh Giám đốc | **Lừa đảo** | `SOFTFAIL / NONE / FAIL` | Rất cao |
| 4 | `sample_04_lookalike_domain.eml` | Giả mạo tên miền (IDN Punycode & Subdomain) | **Lừa đảo** | `PASS* / NONE / NONE` | Cao |
| 5 | `sample_05_malicious_attachment.eml` | Phát tán tệp đính kèm độc hại | **Lừa đảo** | `FAIL / FAIL / FAIL` | Rất cao |
| 6 | `sample_06_legit_hr.eml` | Thông báo lịch khám sức khỏe từ Nhân sự | **An toàn** | `PASS / PASS / PASS` | Thấp (An toàn) |

*\*Lưu ý ở Mẫu 4: `SPF=PASS` vẫn xảy ra vì kẻ tấn công tự mua và cấu hình bản ghi SPF hợp lệ cho chính tên miền giả mạo (`xn--micrsoft-7ya.example`).*

---

## 2. Phân tích Chi tiết Từng Mẫu (Đáp án & Dấu hiệu Nhận diện)

### Mẫu 1: `sample_01_legit_it.eml` — Thông báo bảo trì Phòng IT
- **Kết luận:** **An toàn (Legitimate)**
- **Dấu hiệu xác nhận hợp lệ (Green Flags):**
  1. **Xác thực đầy đủ:** `SPF=PASS`, `DKIM=PASS` (`d=corp-vn.example; s=mail2026`), `DMARC=PASS`.
  2. **Khớp định danh (Alignment):** `From` (`corp-vn.example`) trùng khớp với `Return-Path` và miền ký DKIM.
  3. **Liên kết sạch:** URL hiển thị khớp hoàn toàn với đường dẫn đích `https://status.corp-vn.example/maintenance` (dùng HTTPS).
  4. **Ngữ điệu phù hợp:** Không thúc ép, không yêu cầu cung cấp mật khẩu hay mã OTP.

### Mẫu 2: `sample_02_phishing_bank.eml` — Phishing giả mạo Ngân hàng
- **Kết luận:** **Lừa đảo (Bulk/Spear Phishing)**
- **Danh sách Red Flags:**
  1. **Sai lệch xác thực:** `SPF=FAIL`, `DKIM=NONE`, `DMARC=FAIL`.
  2. **Lệch `Return-Path`:** Hiển thị gửi từ `no-reply@vcb-bank.example` nhưng `Return-Path` thuộc miền lạ `promo-mailer-99.example`.
  3. **Link ngụy trang (Mismatch Anchor Text vs `href`):** Chữ hiển thị là `https://vcb-bank.example/verify` nhưng đích thật là `http://vcb-security-check.login-verify.example/auth` (không có HTTPS).
  4. **Đòn tâm lý Social Engineering:** Tạo áp lực khẩn cấp (*"TẠM KHÓA VĨNH VIỄN SAU 02 GIỜ"*) và yêu cầu nhập thông tin thẻ + OTP.

### Mẫu 3: `sample_03_spoofing_ceo_bec.eml` — Email Spoofing / BEC giả danh Giám đốc
- **Kết luận:** **Lừa đảo (Email Spoofing & BEC)**
- **Danh sách Red Flags:**
  1. **Display Name Spoofing & Giả mạo `From`:** Hiện tên `"Giam doc Tran Minh Quan (CEO)" <ceo@corp-vn.example>` nhưng đi qua máy chủ lạ `relay-open88.example` (`SPF=SOFTFAIL`, `DMARC=FAIL`).
  2. **Đánh tráo `Reply-To`:** Trường `Reply-To` trỏ về hộp thư cá nhân miễn phí `tranminhquan.private2026@freemail.example`. Khi kế toán bấm Reply, thư sẽ đi ra ngoài công ty tới tay kẻ tấn công.
  3. **Kịch bản BEC điển hình:** Giả danh lãnh đạo đang họp không nghe máy, yêu cầu chuyển khoản gấp `245.000.000 VND` và cấm trao đổi với bộ phận khác (cô lập nạn nhân khỏi quy trình kiểm chứng).

### Mẫu 4: `sample_04_lookalike_domain.eml` — Giả mạo tên miền (IDN Punycode & Subdomain Trick)
- **Kết luận:** **Lừa đảo (Domain Spoofing / Lookalike)**
- **Danh sách Red Flags:**
  1. **Tên miền IDN Punycode (`xn--`):** Địa chỉ gửi là `security@xn--micrsoft-7ya.example` (mô phỏng tấn công Homograph dùng ký tự Unicode giả dạng thương hiệu lớn).
  2. **Subdomain Trick trong URL:** Link đích `https://login.microsoft.example.account-reset-portal.example/oauth` đưa tên thương hiệu lên làm subdomain; tên miền gốc thực sự ở cuối là `account-reset-portal.example`.
  3. **Cạm bẫy `SPF=PASS`:** Dù `SPF=PASS` (vì hacker tự cấu hình SPF cho miền giả), email vẫn thiếu `DKIM` và không thuộc tên miền chính thức của tổ chức.

### Mẫu 5: `sample_05_malicious_attachment.eml` — Tệp đính kèm độc hại
- **Kết luận:** **Lừa đảo (Malicious Attachment Delivery)**
- **Danh sách Red Flags:**
  1. **Thất bại toàn bộ xác thực:** `SPF=FAIL`, `DKIM=FAIL`, `DMARC=FAIL`; `Return-Path` là `unknown-sender-44.example` không liên quan `partner-logistics.example`.
  2. **Phần mở rộng kép (Double Extension):** Tệp `BienLai_ThanhToan_2026.pdf.exe` ngụy trang như file PDF nhưng thực chất là tệp thực thi `.exe`.
  3. **Tệp chứa Macro nguy hiểm:** Tệp `HoSo_ChuyenKhoan_2026.docm` có đuôi `.docm` (Word chứa VBA Macro).
  4. **Dụ người dùng hạ thấp phòng vệ:** Nội dung hướng dẫn người nhận bấm **"Enable Content / Enable Macros"** (dấu hiệu kinh điển của Macro Virus trong *Bài 8 - Malicious Code*).

### Mẫu 6: `sample_06_legit_hr.eml` — Thông báo lịch khám sức khỏe Phòng Nhân sự
- **Kết luận:** **An toàn (Legitimate)**
- **Dấu hiệu xác nhận hợp lệ (Green Flags):**
  1. **Xác thực chuẩn:** `SPF=PASS`, `DKIM=PASS`, `DMARC=PASS`, khớp miền `corp-vn.example`.
  2. **Tệp đính kèm an toàn:** Đuôi đơn hợp lệ `Lich_Kham_Suc_Khoe_2026.pdf`, không yêu cầu bật Macro hay nhập mật khẩu giải nén.
  3. **Liên kết nội bộ đúng chuẩn:** `https://portal.corp-vn.example/hr/health-check`.

---

## 3. Checklist Việc cần Làm tiếp (TV2)

- [ ] **[TODO (TV2)]:** Rà soát lại toàn bộ văn phong tiếng Việt (có thể thêm bản tiếng Việt có dấu UTF-8 hoặc giữ không dấu đồng nhất với Header mẫu) và kiểm chứng xem nội dung đã khớp với ví dụ phân tích trong Chương 2 chưa.
- [ ] **[TODO (TV2)]:** *(Khuyến khích mở rộng)* Tạo thêm 2 mẫu nâng cao (`sample_07_clone_phishing.eml` và `sample_08_html_smuggling.eml` đính kèm file `.html` giả lập) theo đúng quy tắc tên miền `.example`, sau đó báo cho TV3 cập nhật thêm vào `simulation/js/scenarios.js`.
- [ ] **[TODO (TV2)]:** Chụp ảnh cấu trúc 1–2 file `.eml` mẫu khi mở bằng trình soạn thảo/ứng dụng mô phỏng để đưa vào minh họa trong Chương 2 (`report/assets/`).
