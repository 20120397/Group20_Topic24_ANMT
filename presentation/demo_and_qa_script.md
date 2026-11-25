# Kịch bản Demo Trực tiếp & Ngân hàng Câu hỏi Q&A

---

## 1. Kịch bản Chạy Demo Trực tiếp (4–5 phút)

> **Chuẩn bị trước giờ báo cáo:** Mở sẵn tab trình duyệt trỏ tới `DeTai24_EmailSecurity\simulation\index.html` và mở sẵn một cửa sổ PowerShell tại `DeTai24_EmailSecurity\labs\dns_audit\`.

1. **Bước 1 — Thực nghiệm tra cứu DNS trên Terminal (1 phút — TV3):**
   - Chạy `.\check_email_auth.ps1 -Domains "gmail.com","vietcombank.com.vn"` (nếu phòng máy có mạng) hoặc `nslookup -type=txt _dmarc.gmail.com` để chỉ ra chuỗi `v=DMARC1; p=reject...`.
   - *(Dự phòng nếu phòng học mất mạng)*: Chạy `.\check_email_auth.ps1 -SelfTest` và chiếu ảnh kết quả đã chụp tại `audit_results.md`.
2. **Bước 2 — Tương tác Hộp thư Mô phỏng (2 phút — TV3 điều khiển, TV2 giải thích & mời lớp đoán):**
   - Mở **Tab 1 (`Hộp thư Mô phỏng`)**, chọn **Mẫu 3 (BEC Spoofing)** và mời giảng viên/sinh viên đoán nhanh *An toàn hay Lừa đảo?* → Bấm **"Soi Raw Header & Xác thực"** để chỉ `SPF=SOFTFAIL`, `DMARC=FAIL`, `Reply-To` lệch sang `freemail.example`.
   - Chuyển nhanh sang **Mẫu 4 (Lookalike / Punycode)** → chỉ điểm đặc biệt dù `SPF=PASS` nhưng địa chỉ gửi là `xn--micrsoft-7ya.example` và rê chuột lên link để thanh **URL Preview** hiện domain thật `account-reset-portal.example`.
   - Chuyển sang **Mẫu 6 (Nhân sự — An toàn)** để cho thấy sự đối chiếu cân bằng (không đánh đồng mọi file `.pdf` đều độc hại).
3. **Bước 3 — Phân tích Tự động trong Email Header Analyzer (1.5 phút — TV3):**
   - Chuyển sang **Tab 2 (`Phân tích Email Header`)**, bấm nút nạp nhanh **"Mẫu 5: Tệp độc hại"** hoặc chọn tải trực tiếp file `sample_05_malicious_attachment.eml` từ máy.
   - Chỉ kết quả công cụ tự chấm điểm rủi ro (`100/100 - NGUY HIỂM CAO`), cảnh báo tệp đuôi kép `.pdf.exe`, macro `.docm` và lời dụ *Enable Macros*.

---

## 2. Ngân hàng Câu hỏi Q&A Dự phòng (12 Câu hỏi & Gợi ý Trả lời)

- [ ] **Q1 (TV2):** *Phân biệt Envelope From (`MAIL FROM` / `Return-Path`) và Header From trong tấn công Email Spoofing?*  
  → **Gợi ý:** *Envelope From* dùng ở tầng giao thức SMTP để định tuyến và nhận thông báo lỗi trả về; *Header From* là dòng `From:` hiển thị trên giao diện người đọc. SMTP gốc không bắt buộc hai trường này phải giống nhau.
- [ ] **Q2 (TV2):** *Tại sao tệp nén đặt mật khẩu (`.zip/.rar`) đính kèm email lại dễ vượt qua bộ lọc Gateway?*  
  → **Gợi ý:** Bộ lọc Email Gateway không có mật khẩu để giải nén và kiểm tra mã độc bên trong nên không quét được chữ ký tĩnh; kẻ tấn công ghi mật khẩu ngay trong nội dung mail để lừa nạn nhân tự giải nén và chạy mã độc trên máy trạm.
- [ ] **Q3 (TV3):** *Tại sao một email có `SPF=PASS` vẫn có thể là email giả mạo hoặc lừa đảo?*  
  → **Gợi ý:** Hai trường hợp: (1) Kẻ tấn công đặt `MAIL FROM` bằng tên miền do chính hắn sở hữu nên vượt qua kiểm tra IP của SPF, trong khi giả mạo `Header From` thành nạn nhân (nếu không bật DMARC); (2) Kẻ tấn công đăng ký tên miền Lookalike/Punycode riêng và cấu hình SPF hợp lệ cho chính miền giả đó (như Mẫu 4).
- [ ] **Q4 (TV3):** *DMARC giải quyết lỗ hổng gì mà SPF và DKIM đứng riêng không giải quyết được?*  
  → **Gợi ý:** DMARC bổ sung cơ chế **Identifier Alignment** (buộc miền của SPF hoặc DKIM phải khớp với `Header From` mà người dùng nhìn thấy) và cung cấp chính sách xử lý thống nhất (`none`/`quarantine`/`reject`) cùng báo cáo `RUA`/`RUF`.
- [ ] **Q5 (TV1):** *Trong mô hình Defense in Depth, tại sao nâng cao nhận thức người dùng vẫn không thể thay thế hoàn toàn bằng giải pháp kỹ thuật?*  
  → **Gợi ý:** Vì các cuộc tấn công BEC hoặc dùng tên miền mới đăng ký có thể đạt chuẩn kỹ thuật (`SPF/DKIM/DMARC=PASS`) và không chứa file độc hay link xấu, nên mắt người dùng được đào tạo và quy trình xác minh đa kênh vẫn là chốt chặn cuối cùng.
- [ ] **Q6 (TV3):** *Tại sao SPF bị giới hạn tối đa 10 lần tra cứu DNS và bị gãy khi chuyển tiếp email (Forwarding)?*  
  → **Gợi ý:** Giới hạn 10 DNS lookup (RFC 7208) nhằm chống tấn công khuếch đại/từ chối dịch vụ vào hạ tầng DNS. Khi forwarding, IP gửi mới thuộc máy chủ chuyển tiếp không nằm trong SPF của người gửi ban đầu nên SPF fail (nhờ DKIM + ARC khắc phục).
- [ ] **Q7 (TV2):** *HTML Smuggling hoạt động như thế nào và khác gì tệp `.exe` đính kèm truyền thống?*  
  → **Gợi ý:** Kẻ tấn công đính kèm file `.html` vô hại bề ngoài nhưng chứa JavaScript dựng chuỗi base64 thành tệp nhị phân ngay trong trình duyệt của nạn nhân, qua mặt bộ lọc chỉ quét file `.exe` trên đường truyền.
- [ ] **Q8 (TV3):** *Sự khác nhau giữa chế độ Alignment `Relaxed (r)` và `Strict (s)` trong DMARC?*  
  → **Gợi ý:** `Relaxed` cho phép khớp chỉ cần cùng tên miền gốc (ví dụ `mail.corp-vn.example` khớp `corp-vn.example`); `Strict` yêu cầu khớp chính xác 100% chuỗi tên miền.
- [ ] **Q9 (TV1):** *Nên triển khai chính sách DMARC theo lộ trình nào để tránh chặn nhầm email hợp lệ của doanh nghiệp?*  
  → **Gợi ý:** Bắt đầu từ `p=none` kết hợp đọc báo cáo `RUA` để rà soát mọi dịch vụ gửi hợp pháp (CRM, marketing, thông báo tự động), sau đó nâng lên `p=quarantine` (tăng dần `pct=10..100`) và cuối cùng khóa ở `p=reject`.
- [ ] **Q10 (TV1):** *Vai trò của ISO/IEC 27002:2022 và 27005:2022 trong giải pháp của nhóm là gì?*  
  → **Gợi ý:** ISO/IEC 27002:2022 cung cấp khung kiểm soát cân bằng cả *Công nghệ*, *Con người* và *Tổ chức* (không thiên lệch kỹ thuật); ISO/IEC 27005:2022 giúp lượng hóa mức rủi ro email để ưu tiên đầu tư biện pháp phù hợp.
- [ ] **Q11 (TV3):** *Tại sao nhóm chọn xây dựng Web App mô phỏng chạy offline thay vì dựng một Mail Server thật để gửi thư giả mạo?*  
  → **Gợi ý:** Chạy offline bảo đảm 100% an toàn đạo đức an ninh mạng (không phát tán email giả ra ngoài, không chứa mã độc thật) và loại bỏ rủi ro mất mạng/lỗi dịch vụ khi trình diễn trước hội đồng.
- [ ] **Q12 (TV1/TV3):** *Nếu phải mở rộng đồ án thành sản phẩm triển khai trong doanh nghiệp thật, bước tiếp theo là gì?*  
  → **Gợi ý:** Tích hợp kết nối IMAP/Graph API qua Gateway có kiểm soát quyền, kết hợp mô hình ML/NLP phát hiện ngữ điệu BEC/tiếng Việt, kết nối hệ thống SOC/SOAR để tự động thu hồi thư lừa đảo.

- [ ] **[TODO (Cả nhóm)]:** Tự luyện trả lời không nhìn tài liệu tất cả 12 câu hỏi trên theo đúng phân công `TV1 / TV2 / TV3` trước buổi bảo vệ.
