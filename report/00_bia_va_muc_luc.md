# ĐỒ ÁN CUỐI KÌ — HỌC PHẦN AN NINH MẠNG & HỆ THỐNG

> **ĐỀ TÀI 24:** BẢO MẬT THƯ ĐIỆN TỬ TRƯỚC CÁC CUỘC TẤN CÔNG GIẢ MẠO VÀ LỪA ĐẢO TRỰC TUYẾN  
> **Phụ trách tổng hợp:** Thành viên 1 (Trưởng nhóm)

---

## Thông tin Đồ án & Thành viên Thực hiện

- **Trường / Khoa:** `[Điền tên Trường / Khoa]`
- **Học phần:** An ninh Mạng & Hệ thống (`[Mã lớp học phần]`)
- **Giảng viên hướng dẫn:** `[Điền họ tên Giảng viên]`
- **Thời gian thực hiện:** Học kì `[...]` — Năm học `[2025–2026]`

| STT | Họ và tên thành viên | MSSV | Vai trò | Phần đóng góp chính | Tỷ lệ đóng góp |
| :-: | :--- | :--- | :--- | :--- | :-: |
| 1 | `[Họ tên TV1]` | `[MSSV]` | **Trưởng nhóm (Project Leader)** | Chương 1, Chương 4, Chương 6, Sơ đồ tổng thể, Ghép báo cáo & Slide | `[...%]` |
| 2 | `[Họ tên TV2]` | `[MSSV]` | **Threat & Malware Analyst** | Chương 2, Bộ 6 mẫu `.eml` an toàn & Đáp án Red Flags | `[...%]` |
| 3 | `[Họ tên TV3]` | `[MSSV]` | **Auth & Simulation Engineer** | Chương 3, DNS Audit (`check_email_auth.ps1`), Chương 5 & Web App mô phỏng | `[...%]` |

---

## Tóm tắt Đồ án

Thư điện tử (Email) giữ vai trò hạ tầng giao tiếp cốt lõi trong mọi tổ chức, nhưng kiến trúc giao thức SMTP truyền thống vốn thiếu cơ chế xác thực người gửi và bảo vệ tính toàn vẹn nguyên bản. Đồ án phân tích toàn diện bốn nhóm mối đe dọa phổ biến nhất qua email gồm **Phishing**, **Email Spoofing**, **giả mạo tên miền** và **tệp đính kèm độc hại**; làm rõ nguyên lý hoạt động và vai trò bổ trợ của bộ ba chuẩn xác thực **SPF (RFC 7208)**, **DKIM (RFC 6376)** và **DMARC (RFC 7489)** kết hợp khảo sát cấu hình DNS thực tế trên các tên miền phổ biến. Trên cơ sở nguyên lý **Defense in Depth** và khung kiểm soát **ISO/IEC 27002:2022 – ISO/IEC 27005:2022**, nhóm đề xuất giải pháp bảo vệ đa lớp kết hợp bộ lọc nội dung/mã độc, xác thực & mã hóa truyền tải/đầu-cuối và đào tạo nhận thức người dùng. Cuối cùng, nhóm xây dựng bộ mẫu `.eml` an toàn cùng ứng dụng Web mô phỏng chạy 100% offline phục vụ thực hành nhận diện email lừa đảo và phân tích Email Header.

---

## Mục lục Tổng thể

1. **Chương 1:** Tổng quan về Bảo mật Thư điện tử — [01_chuong1_tong_quan.md](01_chuong1_tong_quan.md)
   - 1.1. Đặt vấn đề & Bối cảnh tấn công qua Email
   - 1.2. Kiến trúc và Giao thức hoạt động của Hệ thống Email
   - 1.3. Lỗ hổng Bảo mật Nguyên bản của SMTP
   - 1.4. Mục tiêu Bảo mật Email theo Mô hình CIA Triad
2. **Chương 2:** Phân tích các Cuộc tấn công Giả mạo và Lừa đảo qua Email — [02_chuong2_phan_tich_tan_cong.md](02_chuong2_phan_tich_tan_cong.md)
   - 2.1. Tấn công Phishing & Đòn tâm lý Social Engineering
   - 2.2. Tấn công Email Spoofing
   - 2.3. Tấn công Giả mạo Tên miền & Liên hệ DNS Spoofing
   - 2.4. Tệp đính kèm Độc hại & Kỹ thuật Phân tích Mã độc
   - 2.5. Ma trận Dấu hiệu Nhận diện (Red Flags Matrix)
3. **Chương 3:** Cơ chế SPF, DKIM, DMARC trong Xác thực Email — [03_chuong3_spf_dkim_dmarc.md](03_chuong3_spf_dkim_dmarc.md)
   - 3.1. Nền tảng DNS Records Phục vụ Email
   - 3.2. Cơ chế SPF (RFC 7208)
   - 3.3. Cơ chế DKIM (RFC 6376)
   - 3.4. Cơ chế DMARC (RFC 7489) & Mở rộng ARC/BIMI
   - 3.5. So sánh Tổng hợp & Kết quả Khảo sát DNS Thực tế
4. **Chương 4:** Đề xuất Giải pháp Phòng thủ Đa lớp Defense in Depth — [04_chuong4_giai_phap_tong_the.md](04_chuong4_giai_phap_tong_the.md)
   - 4.1. Kiến trúc Phòng thủ Đa lớp cho Hệ thống Email
   - 4.2. Trụ cột 1: Bộ lọc Thư rác & Chống Mã độc
   - 4.3. Trụ cột 2: Xác thực Người gửi & Bảo mật Truyền tải/Nội dung
   - 4.4. Trụ cột 3: Nâng cao Nhận thức & Quản trị theo ISO/IEC 27002 & 27005
   - 4.5. Checklist Thực hành An toàn Email
5. **Chương 5:** Xây dựng Tình huống Mô phỏng Nhận diện Email Lừa đảo — [05_chuong5_mo_phong.md](05_chuong5_mo_phong.md)
   - 5.1. Mục tiêu & Phạm vi Môi trường Mô phỏng
   - 5.2. Kiến trúc Ứng dụng Mô phỏng Offline
   - 5.3. Bộ Kịch bản Tình huống Mẫu (`.eml`)
   - 5.4. Kết quả Thử nghiệm & Đánh giá
6. **Chương 6:** Kết luận, Hướng phát triển & Tài liệu Tham khảo — [06_chuong6_ket_luan.md](06_chuong6_ket_luan.md)

---

## Checklist Hoàn thiện Trang Bìa & Tổng hợp

- [ ] **[TODO (TV1)]:** Điền đầy đủ tên Trường, Khoa, Giảng viên hướng dẫn, Họ tên và MSSV của 3 thành viên.
- [ ] **[TODO (TV1)]:** Cập nhật Danh mục Hình (`Hình 1.1` ... `Hình 5.x`) và Danh mục Bảng (`Bảng 2.1` ... `Bảng 5.x`) sau khi ghép đủ 6 chương sang Word/PDF.
- [ ] **[TODO (Cả nhóm)]:** Rà soát thống nhất thuật ngữ và tỷ lệ đóng góp trước khi nộp bản cuối cùng.
