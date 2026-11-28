# Kịch bản Demo Trực tiếp & Câu hỏi Phản biện Dự phòng

---

## 1. Kịch bản Chạy Demo Trực tiếp tại Slide 22 (4 - 5 phút)

> **Chuẩn bị trước buổi báo cáo:** Mở sẵn trình duyệt tại file `DeTai24_EmailSecurity\simulation\index.html` và mở sẵn cửa sổ PowerShell tại thư mục `DeTai24_EmailSecurity\labs\dns_audit\`.

1. **Bước 1 - Kiểm tra cấu hình DNS trên PowerShell (1 phút - Hữu Điền):**
   - Chạy lệnh `.\check_email_auth.ps1 -Domains "gmail.com","vietcombank.com.vn"` (nếu phòng học có mạng) hoặc `nslookup -type=txt _dmarc.gmail.com` để chỉ trực tiếp bản ghi `v=DMARC1; p=reject...`.
   - *(Trường hợp phòng học không có mạng)*: Chạy `.\check_email_auth.ps1 -SelfTest` và chiếu ảnh kết quả đã chụp sẵn trên Slide 15.
2. **Bước 2 - Thực hành trên Hộp thư Mô phỏng (2 phút - Hữu Điền thao tác, Gia Huy giải thích):**
   - Tại **Tab 1 (`Hộp thư Mô phỏng`)**, mở **Mẫu 3 (BEC giả danh Giám đốc)**, hỏi nhanh cả lớp thư này an toàn hay lừa đảo, sau đó chỉ rõ kỹ thuật *Display Name Spoofing* (`ceo.corpvn@external-mail.example` né `p=REJECT` của công ty) rồi bấm **"Soi Raw Header"** chỉ ra `SPF=SOFTFAIL`, `DMARC=FAIL` và trường `Reply-To` bị tráo sang `freemail.example`.
   - Chuyển sang **Mẫu 4 (Tên miền Punycode)**, chỉ ra chi tiết đáng chú ý: dù `SPF=PASS` nhưng địa chỉ gửi là `xn--micrsoft-qbh.example` (giải mã Unicode thành `micrоsoft.example` với ký tự `о` Cyrillic `U+043E`) và khi rê chuột vào link thì thanh xem trước dưới góc trái hiện tên miền thật là `account-reset-portal.example`.
   - Mở nhanh **Mẫu 6 (Phòng Nhân sự)** để đối chiếu một email nội bộ hợp lệ có đính kèm file `.pdf` sạch.
3. **Bước 3 - Phân tích tự động file `.eml` (1.5 phút - Hữu Điền):**
   - Chuyển sang **Tab 2 (`Phân tích Email Header`)**, chọn tải file `sample_05_malicious_attachment.eml` từ máy (hoặc bấm nút nạp nhanh Mẫu 5).
   - Trình bày kết quả công cụ tự động bóc tách Header, chấm điểm rủi ro `100/100` và liệt kê cảnh báo đuôi kép `.pdf.exe`, file `.docm` cùng câu dụ bật *Enable Macros*.

---

## 2. Danh sách 12 Câu hỏi Hỏi đáp (Q&A) & Gợi ý Trả lời

- [ ] **Câu 1 (Gia Huy):** *Phân biệt Envelope From (`MAIL FROM` / `Return-Path`) và Header From trong tấn công Email Spoofing?*  
  -> *Trả lời:* *Envelope From* được dùng ở bước hội thoại SMTP giữa các máy chủ mail để định tuyến và nhận thông báo lỗi trả về; còn *Header From* nằm trong phần dữ liệu thư để hiển thị tên/địa chỉ cho người đọc. Giao thức SMTP gốc không bắt buộc hai địa chỉ này phải trùng nhau.
- [ ] **Câu 2 (Gia Huy):** *Vì sao kẻ tấn công hay nén file đính kèm có đặt mật khẩu rồi ghi mật khẩu ngay trong nội dung email?*  
  -> *Trả lời:* Cổng bảo mật email (Gateway) không tự giải nén được tệp có mật khẩu nên không quét được mã độc bên trong; kẻ xấu ghi sẵn mật khẩu trong thư để dụ người nhận tự giải nén và chạy mã độc trên máy cá nhân.
- [ ] **Câu 3 (Hữu Điền):** *Tại sao có trường hợp `SPF=PASS` nhưng email vẫn là email giả mạo hoặc lừa đảo?*  
  -> *Trả lời:* Có hai lý do chính: (1) Nếu miền nạn nhân chưa bật DMARC, kẻ tấn công dùng miền riêng của hắn ở `MAIL FROM` nên vượt qua SPF, nhưng vẫn điền miền nạn nhân vào `Header From`; (2) Kẻ tấn công mua tên miền gần giống/Punycode riêng và tự cấu hình bản ghi SPF hợp lệ cho chính miền giả đó (như Mẫu 4).
- [ ] **Câu 4 (Hữu Điền):** *DMARC bổ sung cơ chế gì mà SPF và DKIM đứng riêng lẻ chưa giải quyết được?*  
  -> *Trả lời:* DMARC bổ sung bước kiểm tra **khớp định danh (Identifier Alignment)** bắt buộc miền đã xác thực bởi SPF hoặc DKIM phải trùng với miền hiển thị ở `Header From`, đồng thời cho phép chủ tên miền công bố chính sách xử lý (`none`/`quarantine`/`reject`) và nhận báo cáo thống kê (`RUA`/`RUF`).
- [ ] **Câu 5 (Quang Tùng):** *Khi đã có bộ lọc thư rác và SPF/DKIM/DMARC rồi, tại sao vẫn phải đào tạo nhận thức người dùng?*  
  -> *Trả lời:* Các kịch bản như BEC từ tài khoản đối tác bị chiếm quyền hoặc từ tên miền mới đăng ký có thể vượt qua đầy đủ kiểm tra SPF/DKIM/DMARC và không chứa mã độc hay đường dẫn xấu. Khi đó sự cảnh giác của nhân viên và quy trình gọi điện xác minh độc lập là chốt chặn cuối cùng.
- [ ] **Câu 6 (Hữu Điền):** *Tại sao SPF giới hạn tối đa 10 lần tra cứu DNS và hay gặp lỗi khi chuyển tiếp email (Forwarding)?*  
  -> *Trả lời:* Giới hạn 10 lần tra cứu theo RFC 7208 nhằm tránh lợi dụng SPF gây quá tải/tấn công DoS lên máy chủ DNS. Khi hộp thư tự động forward, IP kết nối tới máy nhận cuối là IP của máy chủ chuyển tiếp chứ không còn nằm trong danh sách SPF của miền gửi gốc (khắc phục nhờ chữ ký DKIM và chuẩn ARC).
- [ ] **Câu 7 (Gia Huy):** *Kỹ thuật HTML Smuggling hoạt động ra sao?*  
  -> *Trả lời:* Thay vì gửi trực tiếp file `.exe` qua mạng dễ bị chặn, kẻ tấn công đính kèm file `.html` chứa đoạn mã JavaScript ghép dữ liệu mã hóa thành tệp độc hại ngay bên trong trình duyệt trên máy người nhận.
- [ ] **Câu 8 (Hữu Điền):** *Chế độ khớp `Relaxed (r)` và `Strict (s)` trong DMARC khác nhau thế nào?*  
  -> *Trả lời:* `Relaxed` cho phép khớp cùng tên miền tổ chức gốc (ví dụ `mail.corp-vn.example` khớp với `corp-vn.example`), còn `Strict` đòi hỏi hai chuỗi tên miền phải giống hệt nhau hoàn toàn.
- [ ] **Câu 9 (Quang Tùng):** *Vì sao doanh nghiệp không bật ngay `DMARC p=reject` từ ngày đầu tiên?*  
  -> *Trả lời:* Nếu bật `p=reject` ngay khi chưa rà soát hết các dịch vụ gửi mail hợp lệ của công ty (như phần mềm kế toán, CRM, gửi thông báo tự động), chính các email thật của công ty sẽ bị từ chối. Do đó phải đi từ `p=none` để đọc báo cáo `RUA`, cấu hình đủ SPF/DKIM rồi mới nâng dần lên `quarantine` và `reject`.
- [ ] **Câu 10 (Quang Tùng):** *Việc đưa ISO/IEC 27002:2022 và ISO/IEC 27005:2022 vào Chương 4 mang lại ý nghĩa gì?*  
  -> *Trả lời:* ISO/IEC 27002 giúp tổ chức triển khai đồng đều cả kiểm soát công nghệ, con người và quy trình nội bộ thay vì chỉ mua phần mềm; còn ISO/IEC 27005 giúp đánh giá mức độ rủi ro để ưu tiên nguồn lực xử lý các kịch bản thiệt hại nặng nhất như BEC và Ransomware.
- [ ] **Câu 11 (Hữu Điền):** *Vì sao nhóm xây dựng ứng dụng Web chạy cục bộ thay vì dựng máy chủ gửi mail giả thật?*  
  -> *Trả lời:* Mô phỏng cục bộ với tên miền `.example` đảm bảo nguyên tắc an toàn và đạo đức môn học (không phát tán email giả mạo ra mạng thật, không lưu trữ mã độc thật), đồng thời hoạt động ổn định khi báo cáo trên lớp không phụ thuộc mạng Internet.
- [ ] **Câu 12 (Quang Tùng / Hữu Điền):** *Nếu phát triển tiếp đề tài này cho doanh nghiệp vừa và nhỏ thì nên làm thêm phần nào?*  
  -> *Trả lời:* Có thể viết thêm plugin tích hợp trực tiếp vào Outlook/Webmail để cảnh báo ngay khi mở thư, kết hợp mô hình NLP tiếng Việt nhận diện nội dung hối thúc chuyển tiền và kết nối hệ thống thu hồi thư tự động.
