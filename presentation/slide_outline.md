# Dàn ý Slide Thuyết trình (25 Slides - khoảng 20 phút)

> **File PowerPoint:** [DeTai24_EmailSecurity_Slides.pptx](DeTai24_EmailSecurity_Slides.pptx) (25 slides, tỷ lệ 16:9)  
> **Gợi ý lời nói của Bùi Quang Tùng:** [tv1_speaker_notes_and_guide.md](tv1_speaker_notes_and_guide.md)

---

## Phân công Trình bày 25 Slides

| Slide | Tiêu đề Slide | Nội dung chính | Người trình bày | Trạng thái |
| :-: | :--- | :--- | :---: | :---: |
| **1** | **Trang bìa** | Tên Đề tài 24, danh sách 3 sinh viên & MSSV, Giảng viên hướng dẫn | **Quang Tùng** | Điền tên GVHD |
| **2** | **Nội dung trình bày** | Giới thiệu 6 phần của bài báo cáo | **Quang Tùng** | **Đã hoàn thiện** |
| **3** | **1.1. Đặt vấn đề & Thực trạng** | Số liệu Verizon DBIR, APWG & 2 nguyên nhân gốc rễ | **Quang Tùng** | **Đã hoàn thiện** |
| **4** | **1.2. Kiến trúc hệ thống Email** | Sơ đồ `ch1_email_architecture.png` & luồng gửi/nhận qua DNS MX | **Quang Tùng** | **Đã hoàn thiện** |
| **5** | **1.3 & 1.4. Hạn chế SMTP & CIA Triad** | 4 điểm yếu của SMTP gốc & bảng mục tiêu CIA Triad | **Quang Tùng** | **Đã hoàn thiện** |
| **6** | **2.1. Phân loại tấn công Phishing** | Bulk, Spear Phishing, Whaling, BEC, Clone Phishing | **Gia Huy** | Khung sẵn |
| **7** | **2.1.2. Kỹ nghệ xã hội** | 4 cơ chế tác động tâm lý (Khẩn cấp, Sợ hãi, Quyền lực, Tò mò) | **Gia Huy** | Khung sẵn |
| **8** | **2.2. Kỹ thuật Email Spoofing** | Phân biệt `Envelope From`, `Header From`, đánh tráo `Reply-To` | **Gia Huy** | Khung sẵn |
| **9** | **2.3. Giả mạo tên miền & Rủi ro DNS** | Typosquatting, Combosquatting, Punycode `xn--`, Subdomain, DNS Poisoning | **Gia Huy** | Khung sẵn |
| **10** | **2.4 & 2.5. Tệp đính kèm độc hại** | Macro `.docm`, đuôi kép `.pdf.exe`, file nén mật khẩu, HTML Smuggling | **Gia Huy** | Khung sẵn |
| **11** | **3.1 & 3.2. Bản ghi DNS & SPF** | `MX/TXT/CNAME/PTR`, cú pháp `v=spf1` & 3 hạn chế lớn của SPF | **Hữu Điền** | Khung sẵn |
| **12** | **3.3. Cơ chế chữ ký số DKIM** | Quy trình ký khóa riêng, tra cứu Selector DNS & bảo vệ toàn vẹn | **Hữu Điền** | Khung sẵn |
| **13** | **3.4. Cơ chế DMARC** | Khớp định danh *Identifier Alignment* & chính sách `none/quarantine/reject` | **Hữu Điền** | Khung sẵn |
| **14** | **3.5. So sánh SPF, DKIM, DMARC** | Bảng đối chiếu 3 cơ chế & mở rộng ARC, BIMI | **Hữu Điền** | Khung sẵn |
| **15** | **3.5. Khảo sát cấu hình DNS thực tế** | Ảnh chạy `check_email_auth.ps1` & nhận xét trên 8 tên miền | **Hữu Điền** | Chờ ảnh thật |
| **16** | **4.1. Mô hình Defense in Depth** | Sơ đồ 4 lớp `ch4_defense_in_depth.png` | **Quang Tùng** | **Đã hoàn thiện** |
| **17** | **4.2. Lọc thư rác & Chống mã độc** | Bayesian/ML, Signature/Heuristic, Sandboxing VM, URL Rewriting, `[EXTERNAL]` | **Quang Tùng** | **Đã hoàn thiện** |
| **18** | **4.3. Xác thực & Mã hóa** | Lộ trình DMARC `p=reject`, SMTPS/TLS + MTA-STS/DANE, PGP & S/MIME | **Quang Tùng** | **Đã hoàn thiện** |
| **19** | **4.4. Nhận thức & ISO/IEC 27002:2022** | Bảng 3 nhóm kiểm soát Công nghệ, Con người, Tổ chức | **Quang Tùng** | **Đã hoàn thiện** |
| **20** | **4.4. Đánh giá rủi ro ISO/IEC 27005** | Bảng định lượng $L \times I$ cho 4 kịch bản rủi ro R1-R4 | **Quang Tùng** | **Đã hoàn thiện** |
| **21** | **5.1 & 5.2. Thiết kế ứng dụng mô phỏng** | Hộp thư mô phỏng (6 mẫu `.eml`) & Bộ phân tích Email Header | **Hữu Điền** | Khung sẵn |
| **22** | **Demo thực hành trực tiếp** | 3 bước: Kiểm tra DNS -> Hộp thư mô phỏng -> Phân tích file `.eml` | **Điền & Huy** | Khung sẵn |
| **23** | **5.4. Kết quả kiểm thử & Khảo sát** | Ảnh giao diện Web App & kết quả làm bài thử của người dùng | **Điền & Huy** | Chờ ảnh/số liệu |
| **24** | **6.1 & 6.2. Kết luận & Hạn chế** | Tổng kết 4 yêu cầu đã thực hiện & 3 hạn chế thực tế của đề tài | **Quang Tùng** | **Đã hoàn thiện** |
| **25** | **6.3. Hướng phát triển & Thảo luận** | 5 hướng mở rộng tiếp theo & mời đặt câu hỏi phản biện | **Quang Tùng** | **Đã hoàn thiện** |

---

## Tổng hợp Số lượng Slide theo Thành viên
- **Bùi Quang Tùng (`20120397`):** **12 slides** (Slides 1-5, 16-20, 24-25) - *Đã có đủ nội dung, bảng biểu và sơ đồ.*
- **Nguyễn Gia Huy (`23120273`):** **5 slides** (Slides 6-10) + phối hợp Demo ở Slide 22.
- **Nguyễn Lê Hữu Điền (`23120233`):** **8 slides** (Slides 11-15, 21-23).
