# Đề tài 24: Bảo mật Thư điện tử trước các Cuộc tấn công Giả mạo và Lừa đảo Trực tuyến

> **Môn học:** An ninh Mạng & Hệ thống (Seminar)  
> **Hình thức:** Đồ án cuối kì — Nhóm 3 thành viên  


## 1. Mục tiêu Đề tài
1. Phân tích **Phishing**, **Email Spoofing**, **giả mạo tên miền** và **tệp đính kèm độc hại**.
2. Tìm hiểu cơ chế **SPF, DKIM, DMARC** và vai trò của chúng trong xác thực email.
3. Đề xuất giải pháp kết hợp **bộ lọc thư rác**, **xác thực người gửi** và **nâng cao nhận thức người dùng** (gắn với *Defense in Depth* & *ISO/IEC 27002, 27005*).
4. Xây dựng **tình huống mô phỏng** nhận diện email lừa đảo.

## 2. Phân công Thành viên

| Thành viên | Vai trò | Phạm vi báo cáo | Sản phẩm kỹ thuật |
| :--- | :--- | :--- | :--- |
| **Thành viên 1** | Trưởng nhóm & Kiến trúc giải pháp | Chương 1, 4, 6 & Tổng hợp | `docs/`, Sơ đồ giải pháp, `presentation/` |
| **Thành viên 2** | Threat & Malware Analyst | Chương 2 | Bộ mẫu `.eml` an toàn (`labs/email_samples/`) |
| **Thành viên 3** | Auth & Simulation Engineer | Chương 3, 5 | `labs/dns_audit/`, Web App (`simulation/`) |

## 3. Cây thư mục Dự án

```text
DeTai24_EmailSecurity/
├── README.md
├── docs/            # Kế hoạch 4 mốc, đề cương & quy chuẩn
├── report/          # Khung 6 chương báo cáo + assets/
├── labs/
│   ├── dns_audit/   # Script kiểm tra MX/SPF/DMARC & bảng kết quả
│   └── email_samples/ # Bộ mẫu .eml an toàn & tài liệu Red Flags
├── simulation/      # Khung Web App mô phỏng offline (HTML/CSS/JS)
└── presentation/    # Dàn ý slide & kịch bản demo + Q&A
```

## 4. Bắt đầu nhanh cho Thành viên
- **TV1:** Điền tên/MSSV vào `docs/01_project_plan_and_roles.md`, chốt đề cương ở `docs/02_outline_and_standards.md` và viết Chương 1, 4, 6.
- **TV2:** Viết Chương 2 và tạo các file `.eml` mẫu trong `labs/email_samples/` theo kế hoạch tại `scenarios_guide.md`.
- **TV3:** Hoàn thiện `labs/dns_audit/check_email_auth.ps1`, chạy khảo sát DNS, xây dựng Web App tại `simulation/` và viết Chương 3, 5.
