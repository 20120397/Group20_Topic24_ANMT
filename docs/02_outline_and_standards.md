# Đề cương Báo cáo & Quy ước Trình bày

## 1. Đề cương 6 Chương

- **Chương 1 - Tổng quan về Bảo mật Thư điện tử (Bùi Quang Tùng - 20120397):** Đặt vấn đề & số liệu thực tế; kiến trúc MUA/MTA/MDA và giao thức SMTP/POP3/IMAP; hạn chế bảo mật của SMTP gốc; mục tiêu theo mô hình CIA Triad.
- **Chương 2 - Phân tích các Tấn công Giả mạo & Lừa đảo (Nguyễn Gia Huy - 23120273):** Phishing (Bulk, Spear, Whaling, BEC, Clone & kỹ nghệ xã hội); Email Spoofing (`Envelope From` vs `Header From`, Display Name, `Reply-To`, Open Relay); Giả mạo tên miền (Typosquatting, Combosquatting, IDN Punycode, Subdomain, DNS Cache Poisoning); Tệp đính kèm độc hại (Macro, đuôi kép `.pdf.exe`, file nén đặt mật khẩu, HTML Smuggling, phân tích tĩnh/động/Sandbox); Bảng dấu hiệu nhận biết.
- **Chương 3 - Cơ chế Xác thực Email SPF, DKIM, DMARC (Nguyễn Lê Hữu Điền - 23120233):** Bản ghi DNS (`MX`, `TXT`, `CNAME`, `PTR`); SPF (RFC 7208); DKIM (RFC 6376); DMARC (RFC 7489, khớp định danh Identifier Alignment, chính sách `none`/`quarantine`/`reject`, báo cáo `RUA`/`RUF`, mở rộng ARC/BIMI); So sánh 3 cơ chế & kết quả khảo sát DNS thực tế.
- **Chương 4 - Đề xuất Giải pháp Phòng thủ Nhiều lớp (Bùi Quang Tùng - 20120397):** Mô hình Defense in Depth 4 lớp; Bộ lọc thư rác & chống mã độc (Bayesian/ML, Sandbox, URL Rewriting); Xác thực & mã hóa (SPF/DKIM/DMARC, SMTPS/TLS, MTA-STS/DANE, PGP/S/MIME); Đào tạo nhận thức & quản trị theo `ISO/IEC 27002:2022` & `ISO/IEC 27005:2022`; Bảng kiểm tra an toàn Email.
- **Chương 5 - Xây dựng Tình huống Mô phỏng Nhận diện Email Lừa đảo (Nguyễn Lê Hữu Điền - 23120233):** Thiết kế ứng dụng chạy cục bộ (Hộp thư mô phỏng + Bộ phân tích Header); mô tả 6 kịch bản `.eml`; kết quả kiểm thử và khảo sát người dùng.
- **Chương 6 - Kết luận & Hướng phát triển (Bùi Quang Tùng - 20120397):** Tổng kết kết quả thực hiện, hạn chế của đề tài, hướng mở rộng (AI/ML, Zero Trust Email, BIMI, Mật mã hậu lượng tử, SOAR) & Tài liệu tham khảo.

## 2. Quy ước Trình bày Chung

| Hạng mục | Quy ước áp dụng trong nhóm |
| :--- | :--- |
| **Thuật ngữ** | Lần đầu xuất hiện ghi tiếng Việt kèm tiếng Anh trong ngoặc, ví dụ: *Giả mạo địa chỉ gửi (Email Spoofing)*. |
| **Hình & Bảng** | Đánh số theo chương (`Hình 1.1`, `Bảng 4.2`). Ảnh lưu trong `report/assets/` đặt tên tiếng Việt không dấu. |
| **Trích dẫn kỹ thuật** | `RFC 7208` (SPF), `RFC 6376` (DKIM), `RFC 7489` (DMARC), `ISO/IEC 27001:2022`, `ISO/IEC 27002:2022`, `ISO/IEC 27005:2022`. |
| **Tài liệu môn học** | Bám sát các bài giảng trong thư mục `Seminar` (Bài 2, Bài 7, Bài 8, L1, Tiêu chuẩn ISO 27000, Lab 5). |
| **Nguyên tắc an toàn** | Chỉ chạy mô phỏng cục bộ; dùng tên miền `.example` (RFC 2606); không tạo hoặc đính kèm mã độc thật. |
