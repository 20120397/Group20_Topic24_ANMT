# Đề tài 24: Bảo mật Thư điện tử trước các Cuộc tấn công Giả mạo và Lừa đảo Trực tuyến

> **Môn học:** An ninh Mạng & Hệ thống (Seminar)  
> **Hình thức:** Đồ án cuối kì - Nhóm 3 sinh viên

## 1. Nội dung Thực hiện
1. Phân tích các hình thức tấn công: **Phishing**, **Email Spoofing**, **giả mạo tên miền** và **tệp đính kèm độc hại**.
2. Tìm hiểu cơ chế **SPF, DKIM, DMARC** và vai trò của chúng trong xác thực email.
3. Đề xuất giải pháp kết hợp **bộ lọc thư rác**, **xác thực người gửi** và **nâng cao nhận thức người dùng** (theo hướng phòng thủ nhiều lớp và tiêu chuẩn *ISO/IEC 27002, 27005*).
4. Xây dựng **tình huống mô phỏng** nhận diện email lừa đảo và phân tích Email Header.

## 2. Danh sách Nhóm & Phân công

| Thành viên | MSSV | Vai trò | Phần báo cáo | Sản phẩm phụ trách |
| :--- | :---: | :--- | :--- | :--- |
| **Bùi Quang Tùng** *(TV1)* | `20120397` | Nhóm trưởng - Tổng quan & Giải pháp | Chương 1, 4, 6 & Tổng hợp | `docs/`, Sơ đồ kiến trúc, `presentation/` |
| **Nguyễn Gia Huy** *(TV2)* | `23120273` | Phân tích tấn công & Tạo mẫu email | Chương 2 | Bộ mẫu `.eml` (`labs/email_samples/`) |
| **Nguyễn Lê Hữu Điền** *(TV3)* | `23120233` | Cơ chế xác thực & Xây dựng mô phỏng | Chương 3, 5 | `labs/dns_audit/`, Web App (`simulation/`) |

## 3. Cấu trúc Thư mục

```text
DeTai24_EmailSecurity/
├── README.md
├── docs/              # Kế hoạch nhóm, đề cương & quy ước trình bày
├── report/            # Nội dung 6 chương báo cáo + thư mục ảnh assets/
├── labs/
│   ├── dns_audit/     # Script kiểm tra MX/SPF/DMARC & bảng kết quả khảo sát
│   └── email_samples/ # Bộ 6 mẫu .eml phục vụ phân tích & mô phỏng
├── simulation/        # Ứng dụng Web mô phỏng chạy cục bộ (HTML/CSS/JS)
└── presentation/      # Slide thuyết trình (.pptx), dàn ý & kịch bản hỏi đáp
```

## 4. Hướng dẫn Chạy Nhanh
- **Mở ứng dụng mô phỏng:** Mở trực tiếp file `simulation/index.html` trên trình duyệt Chrome hoặc Edge.
- **Chạy script kiểm tra DNS:** Mở PowerShell tại `labs/dns_audit/` và chạy:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\check_email_auth.ps1
  ```
  *(Nếu kiểm tra cú pháp/logic khi không có mạng, thêm tham số `-SelfTest`)*
