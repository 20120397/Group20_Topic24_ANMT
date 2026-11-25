# Dàn ý Chi tiết Slide Thuyết trình (15–20 phút)

> **Tổng hợp:** Thành viên 1 | **Phân bổ:** 18 Slides — 3 thành viên cùng trình bày

---

## Bảng Phân công Từng Slide

| Slide | Tiêu đề Slide | Nội dung trọng tâm & Hình minh họa | Người trình bày | Thời lượng |
| :-: | :--- | :--- | :---: | :-: |
| 1 | **Trang bìa** | Tên Đề tài 24, môn học, GVHD, tên & MSSV 3 thành viên | **TV1** | 0.5p |
| 2 | **Đặt vấn đề & Mục tiêu** | Thực trạng lừa đảo qua email + 4 mục tiêu đồ án | **TV1** | 1.0p |
| 3 | **Kiến trúc Email & Lỗ hổng SMTP** | Sơ đồ MUA–MTA–MDA (`Hình 1.1`) + 4 lỗ hổng nguyên bản của SMTP | **TV1** | 1.5p |
| 4 | **Tổng quan 4 Nguy cơ Tấn công** | Phishing, Spoofing, Giả mạo tên miền, Tệp đính kèm độc hại | **TV2** | 0.5p |
| 5 | **Tấn công Phishing & Social Engineering** | Bulk/Spear/Whaling/BEC/Clone + 4 đòn tâm lý (Khẩn cấp, Sợ hãi, Quyền lực, Tham) | **TV2** | 1.0p |
| 6 | **Email Spoofing & Giả mạo Tên miền** | `Envelope From` vs `Header From`, `Reply-To`, Typosquatting, Punycode `xn--`, Subdomain Trick | **TV2** | 1.5p |
| 7 | **Tệp đính kèm Độc hại & Red Flags** | Macro Virus (`.docm`), Double Extension (`.pdf.exe`), HTML Smuggling, Sandbox analysis | **TV2** | 1.0p |
| 8 | **Nền tảng DNS & Cơ chế SPF** | `MX/TXT`, cú pháp `v=spf1`, hạn chế `Header From` & giới hạn 10 lookup | **TV3** | 1.0p |
| 9 | **Cơ chế DKIM** | Ký số khóa bất đối xứng, `DKIM-Signature`, Selector & bảo vệ toàn vẹn | **TV3** | 1.0p |
| 10 | **Cơ chế DMARC & Bảng so sánh** | *Identifier Alignment*, chính sách `none/quarantine/reject`, `RUA/RUF`, ARC/BIMI | **TV3** | 1.0p |
| 11 | **Thực nghiệm Kiểm tra DNS Thực tế** | Kết quả chạy `check_email_auth.ps1` + ảnh chụp terminal (`ch3_dns_audit_terminal.png`) | **TV3** | 1.0p |
| 12 | **Kiến trúc Giải pháp Defense in Depth** | Sơ đồ 3 trụ cột / 4 lớp (`Hình 4.1`) | **TV1** | 1.0p |
| 13 | **Bộ lọc Kỹ thuật & Bảo mật Truyền tải** | Bayesian/ML, Sandboxing, URL Rewriting, TLS + MTA-STS/DANE, PGP/S/MIME | **TV1** | 1.0p |
| 14 | **Nâng cao Nhận thức & ISO 27002/27005** | Ánh xạ Technological/People/Organizational Controls + Diễn tập Phishing & Quy trình sự cố | **TV1** | 1.0p |
| 15 | **Kiến trúc Mô phỏng Nhận diện Email** | Giới thiệu 2 module Web App offline (`simulation/`) & 6 kịch bản mẫu | **TV3** | 0.5p |
| 16 | **DEMO TRỰC TIẾP** | Demo Inbox Simulator (2 mẫu) + Header Analyzer + lệnh DNS terminal | **TV3 + TV2** | 4.5p |
| 17 | **Kết quả Thử nghiệm & Đánh giá** | Thống kê tỷ lệ nhận diện qua mô phỏng & hạn chế của đồ án | **TV3 / TV1** | 1.0p |
| 18 | **Kết luận & Hướng phát triển** | Tổng kết 4 yêu cầu, AI/ML, Zero Trust, SOAR — Cảm ơn & Q&A | **TV1** | 1.0p |

---

## Checklist Chuẩn bị Slide

- [ ] **[TODO (TV1)]:** Tạo file PowerPoint/Canva/Google Slides theo đúng khung 18 slide trên, thiết kế đồng bộ font/màu và soạn Slide 1–3, 12–14, 18.
- [ ] **[TODO (TV2)]:** Soạn nội dung ngắn gọn (dùng bullet + ảnh/sơ đồ, tránh chữ dày đặc) cho Slide 4–7.
- [ ] **[TODO (TV3)]:** Soạn Slide 8–11, 15, 17 kèm ảnh chụp kết quả `check_email_auth.ps1` và giao diện `simulation/`.
- [ ] **[TODO (Cả nhóm)]:** Chạy bấm giờ thuyết trình thử (Dry-run) ít nhất 1 lần để bảo đảm tổng thời gian gọn trong 15–20 phút.
