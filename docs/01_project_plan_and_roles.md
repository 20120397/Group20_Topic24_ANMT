# Kế hoạch Thực hiện & Phân công Nhóm (Đề tài 24)

## 1. Thông tin Thành viên

| STT | Họ và tên | MSSV | Vai trò | Liên hệ |
| :-: | :--- | :--- | :--- | :--- |
| 1 | `[Điền tên TV1]` | `[MSSV]` | Trưởng nhóm / Kiến trúc giải pháp | `[Email/Zalo]` |
| 2 | `[Điền tên TV2]` | `[MSSV]` | Threat & Malware Analyst | `[Email/Zalo]` |
| 3 | `[Điền tên TV3]` | `[MSSV]` | Auth & Simulation Engineer | `[Email/Zalo]` |

## 2. Lộ trình 4 Mốc (Milestones)

| Mốc | Giai đoạn | Đầu việc chính | Tiêu chí đạt (Gate Check) | Trạng thái |
| :-: | :--- | :--- | :--- | :---: |
| **1** | Khởi tạo & Khung sườn | Chốt đề cương, cây thư mục, danh sách 6 mẫu email và tên miền audit DNS | Cả nhóm thống nhất phạm vi & thuật ngữ | `[x] Khung` |
| **2** | Nghiên cứu & Tạo mẫu | TV1 viết C1, C4; TV2 viết C2 + tạo bộ `.eml`; TV3 viết C3 + chạy audit DNS + dựng UI mô phỏng | TV2 bàn giao đủ bộ `.eml` cho TV3 | `[ ]` |
| **3** | Tích hợp & Kiểm thử | TV3 tích hợp dữ liệu mẫu vào `simulation/`, viết C5; cả nhóm chạy thử ghi nhận số liệu | Web App chạy offline ổn định, đủ 6 chương | `[ ]` |
| **4** | Hoàn thiện & Tổng duyệt | TV1 ghép báo cáo hoàn chỉnh; cả nhóm làm Slide, chạy thử Demo & Q&A | Sẵn sàng nộp báo cáo và thuyết trình | `[ ]` |

## 3. Ma trận Bàn giao (Handoff Matrix)

| Từ | Đến | Sản phẩm bàn giao | Vị trí |
| :---: | :---: | :--- | :--- |
| TV1 | TV2, TV3 | Đề cương chi tiết & quy chuẩn trình bày | `docs/02_outline_and_standards.md` |
| TV2 | TV3 | Bộ 6–8 file `.eml` an toàn + danh sách Red Flags | `labs/email_samples/` |
| TV2 | TV1 | Bản thảo hoàn chỉnh Chương 2 | `report/02_chuong2_phan_tich_tan_cong.md` |
| TV3 | TV1 | Bản thảo Chương 3, 5 + ảnh chụp DNS Audit & Demo | `report/03_*.md`, `05_*.md`, `report/assets/` |
| TV1 | Cả nhóm | Bản ghép báo cáo hoàn chỉnh & bộ Slide + Q&A | `report/`, `presentation/` |

## 4. Checklist Nghiệm thu Tổng thể
- [ ] Đủ 6 chương báo cáo đúng định dạng và trích dẫn chuẩn.
- [ ] Có kết quả chạy thực nghiệm DNS (`MX`, `SPF`, `DMARC`) kèm ảnh chụp minh chứng.
- [ ] Có tối thiểu 6 mẫu `.eml` an toàn và Web App mô phỏng chạy mượt offline.
- [ ] Hoàn thiện Slide và kịch bản Demo + Q&A (15–20 phút).
