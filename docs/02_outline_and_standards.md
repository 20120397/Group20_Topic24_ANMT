# Đề cương Báo cáo & Quy chuẩn Trình bày

## 1. Đề cương Tóm tắt 6 Chương

- **Chương 1 — Tổng quan về Bảo mật Thư điện tử (TV1):** Đặt vấn đề; kiến trúc MUA/MTA/MDA và SMTP/POP3/IMAP; lỗ hổng nguyên bản của SMTP; mục tiêu CIA Triad.
- **Chương 2 — Phân tích các Tấn công Giả mạo & Lừa đảo (TV2):** Phishing (Bulk/Spear/Whaling/BEC/Clone & Social Engineering); Email Spoofing (`Envelope From` vs `Header From`, Display Name, `Reply-To`, Open Relay); Giả mạo tên miền (Typosquatting, Combosquatting, Lookalike/Punycode, Subdomain, DNS Cache Poisoning); Tệp đính kèm độc hại (Macro Virus, Double Extension, Archive mật khẩu, HTML Smuggling, phân tích Static/Dynamic/Sandbox); Bảng Red Flags Matrix.
- **Chương 3 — Cơ chế Xác thực Email SPF, DKIM, DMARC (TV3):** DNS Records (`MX`, `TXT`, `CNAME`); SPF (RFC 7208); DKIM (RFC 6376); DMARC (RFC 7489 & Identifier Alignment, chính sách `none`/`quarantine`/`reject`, `RUA`/`RUF`, ARC/BIMI); So sánh 3 cơ chế & kết quả khảo sát DNS thực tế.
- **Chương 4 — Đề xuất Giải pháp Tổng thể Defense in Depth (TV1):** Bộ lọc thư rác & chống mã độc (Bayesian/ML, Sandbox, URL Rewriting); Xác thực & mã hóa (SPF/DKIM/DMARC, SMTPS/TLS, DANE, PGP/S/MIME); Nâng cao nhận thức người dùng & quản trị theo `ISO/IEC 27002:2022` & `ISO/IEC 27005:2022`; Checklist an toàn Email.
- **Chương 5 — Xây dựng Tình huống Mô phỏng Nhận diện Email Lừa đảo (TV3):** Thiết kế ứng dụng offline (Inbox Simulator + Header Analyzer); mô tả 6 kịch bản mẫu; kết quả thử nghiệm và đánh giá.
- **Chương 6 — Kết luận & Hướng phát triển (TV1):** Đánh giá mức độ hoàn thành mục tiêu, hạn chế, xu hướng AI/ML, Zero Trust Email Security, SOAR & Tài liệu tham khảo.

## 2. Quy chuẩn Trình bày & Đặt tên

| Quy chuẩn | Quy định áp dụng |
| :--- | :--- |
| **Thuật ngữ** | Lần đầu viết tiếng Việt kèm tiếng Anh trong ngoặc, ví dụ: *Giả mạo địa chỉ gửi (Email Spoofing)*. |
| **Hình & Bảng** | Đánh số theo chương: `Hình 2.1`, `Bảng 3.1`. Ảnh lưu tại `report/assets/` đặt tên không dấu: `ch3_nslookup_dmarc.png`. |
| **Chuẩn kỹ thuật trích dẫn** | `RFC 7208` (SPF), `RFC 6376` (DKIM), `RFC 7489` (DMARC), `ISO/IEC 27001:2022`, `ISO/IEC 27002:2022`, `ISO/IEC 27005:2022`. |
| **Tài liệu môn học** | Trích dẫn theo tên file gốc trong `d:\ANMT\Seminar\` (Bai 7, Bài 8, L1, Bài 2, Tieu chuan ISO 27000, Lab5). |
| **An toàn & Đạo đức** | Chỉ chạy mô phỏng offline; dùng tên miền `.example` (RFC 2606); tuyệt đối không tạo hay nhúng mã độc thật. |
