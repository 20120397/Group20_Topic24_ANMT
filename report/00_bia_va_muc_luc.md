# ĐỒ ÁN CUỐI KÌ - HỌC PHẦN AN NINH MẠNG & HỆ THỐNG

> **ĐỀ TÀI 24:** BẢO MẬT THƯ ĐIỆN TỬ TRƯỚC CÁC CUỘC TẤN CÔNG GIẢ MẠO VÀ LỪA ĐẢO TRỰC TUYẾN  
> **Tổng hợp báo cáo:** Bùi Quang Tùng (`20120397`)

---

## Thông tin Đồ án & Thành viên Thực hiện

- **Trường / Khoa:** `[Điền tên Trường / Khoa]`
- **Học phần:** An ninh Mạng & Hệ thống (`[Mã lớp học phần]`)
- **Giảng viên hướng dẫn:** `[Điền họ tên Giảng viên]`
- **Thời gian thực hiện:** Học kì `[...]` - Năm học `2025-2026`

| STT | Họ và tên sinh viên | MSSV | Vai trò | Phần công việc đảm nhận | Tỷ lệ đóng góp |
| :-: | :--- | :---: | :--- | :--- | :-: |
| 1 | **Bùi Quang Tùng** | `20120397` | **Nhóm trưởng** | Chương 1, Chương 4, Chương 6, Sơ đồ kiến trúc, Ghép báo cáo & Slide | `34%` |
| 2 | **Nguyễn Gia Huy** | `23120273` | Thành viên | Chương 2, Bộ 6 mẫu `.eml` & phân tích dấu hiệu nhận biết | `33%` |
| 3 | **Nguyễn Lê Hữu Điền** | `23120233` | Thành viên | Chương 3, Khảo sát DNS (`check_email_auth.ps1`), Chương 5 & Web App mô phỏng | `33%` |

---

## Tóm tắt Đồ án

Thư điện tử (Email) là phương tiện liên lạc chính trong các cơ quan và doanh nghiệp, nhưng giao thức gửi thư truyền thống SMTP lại thiếu cơ chế xác thực người gửi và bảo vệ tính toàn vẹn mặc định. Báo cáo tập trung tìm hiểu bốn nhóm nguy cơ phổ biến qua email gồm **Phishing**, **Email Spoofing**, **giả mạo tên miền** và **tệp đính kèm độc hại**; phân tích nguyên lý hoạt động và cách phối hợp của ba cơ chế xác thực **SPF (RFC 7208)**, **DKIM (RFC 6376)** và **DMARC (RFC 7489)** kèm khảo sát cấu hình DNS thực tế. Dựa trên mô hình phòng thủ nhiều lớp (*Defense in Depth*) và bộ tiêu chuẩn **ISO/IEC 27002:2022 - ISO/IEC 27005:2022**, nhóm đề xuất giải pháp kết hợp lọc nội dung/mã độc, xác thực & mã hóa kênh truyền và đào tạo nhận thức người dùng. Ở phần thực hành, nhóm xây dựng bộ 6 mẫu `.eml` và ứng dụng Web chạy cục bộ phục vụ mô phỏng nhận diện email lừa đảo và phân tích Email Header.

---

## Mục lục Tổng thể

1. **Chương 1:** Tổng quan về Bảo mật Thư điện tử - [01_chuong1_tong_quan.md](01_chuong1_tong_quan.md)
   - 1.1. Đặt vấn đề & Thực trạng tấn công qua Email
   - 1.2. Kiến trúc và Giao thức hoạt động của Hệ thống Email
   - 1.3. Hạn chế Bảo mật của Giao thức SMTP Gốc
   - 1.4. Mục tiêu Bảo mật Email theo Mô hình CIA Triad
2. **Chương 2:** Phân tích các Cuộc tấn công Giả mạo và Lừa đảo qua Email - [02_chuong2_phan_tich_tan_cong.md](02_chuong2_phan_tich_tan_cong.md)
   - 2.1. Tấn công Phishing & Kỹ nghệ Xã hội (Social Engineering)
   - 2.2. Tấn công Email Spoofing
   - 2.3. Tấn công Giả mạo Tên miền & Rủi ro DNS
   - 2.4. Tệp đính kèm Độc hại & Kỹ thuật Phân tích Mã độc
   - 2.5. Bảng Tổng hợp Dấu hiệu Nhận biết
3. **Chương 3:** Cơ chế SPF, DKIM, DMARC trong Xác thực Email - [03_chuong3_spf_dkim_dmarc.md](03_chuong3_spf_dkim_dmarc.md)
   - 3.1. Các Bản ghi DNS Phục vụ Email
   - 3.2. Cơ chế SPF (RFC 7208)
   - 3.3. Cơ chế DKIM (RFC 6376)
   - 3.4. Cơ chế DMARC (RFC 7489) & Mở rộng ARC/BIMI
   - 3.5. So sánh Tổng hợp & Kết quả Khảo sát DNS Thực tế
4. **Chương 4:** Đề xuất Giải pháp Phòng thủ Nhiều lớp - [04_chuong4_giai_phap_tong_the.md](04_chuong4_giai_phap_tong_the.md)
   - 4.1. Mô hình Phòng thủ Nhiều lớp (Defense in Depth)
   - 4.2. Giải pháp Lọc Thư rác & Phòng chống Mã độc
   - 4.3. Xác thực Người gửi & Mã hóa Kênh truyền / Nội dung
   - 4.4. Nâng cao Nhận thức & Quản trị theo ISO/IEC 27002 & 27005
   - 4.5. Bảng Kiểm tra Thực hành & Đối chiếu Giải pháp
5. **Chương 5:** Xây dựng Tình huống Mô phỏng Nhận diện Email Lừa đảo - [05_chuong5_mo_phong.md](05_chuong5_mo_phong.md)
   - 5.1. Mục tiêu & Phạm vi Mô phỏng
   - 5.2. Thiết kế Ứng dụng Mô phỏng
   - 5.3. Bộ 6 Kịch bản Mẫu (`.eml`)
   - 5.4. Kết quả Kiểm thử & Khảo sát Thử nghiệm
6. **Chương 6:** Kết luận, Hướng phát triển & Tài liệu Tham khảo - [06_chuong6_ket_luan.md](06_chuong6_ket_luan.md)

---

## Danh mục Hình ảnh

- **Hình 1.1:** Kiến trúc luồng gửi nhận thư điện tử & các điểm yếu bảo mật của SMTP ([assets/ch1_email_architecture.png](assets/ch1_email_architecture.png)) - *Chương 1*
- **Hình 2.1:** Cơ chế tách biệt Envelope From, Header From và Reply-To trong Email Spoofing - *Chương 2*
- **Hình 3.1:** Luồng kiểm tra SPF, DKIM và khớp định danh trong DMARC - *Chương 3*
- **Hình 3.2:** Kết quả khảo sát cấu hình DNS (MX/SPF/DMARC) trên PowerShell *(Hữu Điền bổ sung)* - *Chương 3*
- **Hình 4.1:** Kiến trúc phòng thủ nhiều lớp (Defense in Depth) cho hệ thống thư điện tử ([assets/ch4_defense_in_depth.png](assets/ch4_defense_in_depth.png)) - *Chương 4*
- **Hình 5.1:** Giao diện Hộp thư Mô phỏng nhận diện email lừa đảo *(Hữu Điền bổ sung)* - *Chương 5*
- **Hình 5.2:** Giao diện Bộ phân tích Email Header *(Hữu Điền bổ sung)* - *Chương 5*

---

## Danh mục Bảng biểu

- **Bảng 1.1:** Thành phần và giao thức chính trong hệ thống Email - *Chương 1*
- **Bảng 1.2:** Đối chiếu mục tiêu bảo mật Email theo mô hình CIA Triad - *Chương 1*
- **Bảng 2.1:** Các kỹ thuật giả mạo tên miền và ví dụ minh họa - *Chương 2*
- **Bảng 2.2:** Bảng tổng hợp dấu hiệu nhận biết (Red Flags) - *Chương 2*
- **Bảng 3.1:** So sánh vai trò của SPF, DKIM và DMARC - *Chương 3*
- **Bảng 3.2:** Kết quả khảo sát cấu hình DNS thực tế trên các tên miền - *Chương 3*
- **Bảng 4.1:** Ánh xạ 3 nhóm kiểm soát ISO/IEC 27002:2022 cho bảo mật Email - *Chương 4*
- **Bảng 4.2:** Đánh giá và xử lý rủi ro Email theo ISO/IEC 27005:2022 - *Chương 4*
- **Bảng 4.3:** Danh mục kiểm tra an toàn Email cho Quản trị viên IT & Người dùng - *Chương 4*
- **Bảng 4.4:** Đối chiếu giữa Tấn công (Chương 2), Xác thực (Chương 3) và Giải pháp (Chương 4) - *Chương 4*
- **Bảng 5.1:** Tóm tắt 6 kịch bản tình huống mẫu (`.eml`) - *Chương 5*
- **Bảng 5.2:** Kết quả khảo sát người dùng thử nghiệm ứng dụng mô phỏng - *Chương 5*
- **Bảng 6.1:** Tổng kết kết quả thực hiện so với yêu cầu Đề tài 24 - *Chương 6*

---

## Ghi chú Hoàn thiện trước khi Xuất Word/PDF

- [ ] **[Cần điền (Quang Tùng)]:** Bổ sung tên Trường/Khoa, Mã lớp và họ tên Giảng viên hướng dẫn ở đầu trang.
- [x] Điền đầy đủ họ tên và MSSV của 3 thành viên nhóm (`20120397`, `23120273`, `23120233`).
- [x] Lập sẵn Danh mục Hình ảnh và Danh mục Bảng biểu.
