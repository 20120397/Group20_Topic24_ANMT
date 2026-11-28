# Chương 5: Xây dựng Tình huống Mô phỏng Nhận diện Email Lừa đảo

> **Sinh viên thực hiện:** Nguyễn Lê Hữu Điền (`23120233`)  
> **Phối hợp mẫu dữ liệu:** Nguyễn Gia Huy (`23120273` - bộ mẫu `.eml` & dấu hiệu nhận biết)

---

## 5.1. Mục tiêu và Phạm vi Môi trường Mô phỏng

Nhằm cụ thể hóa lý thuyết ở Chương 2–4 thành công cụ trực quan phục vụ đào tạo nhận thức người dùng và minh họa kiểm tra kỹ thuật Header, nhóm xây dựng bộ mô phỏng đáp ứng 3 tiêu chí:
1. **An toàn tuyệt đối:** Chạy 100% cục bộ (*offline*) trên trình duyệt bằng HTML5/CSS3/JavaScript thuần, không phụ thuộc thư viện CDN bên ngoài và không gửi dữ liệu qua mạng.
2. **Dữ liệu vô hại:** Sử dụng tên miền dành riêng cho tài liệu `.example` (RFC 2606); mọi liên kết trong email được chặn điều hướng thật và thay bằng thanh xem trước URL; tệp đính kèm chỉ hiển thị siêu dữ liệu mô tả.
3. **Tính tương tác cao:** Người dùng trực tiếp kiểm tra Header, soi link, phát hiện Red Flags và thử phân tích file `.eml` bất kỳ.

---

## 5.2. Kiến trúc Ứng dụng Mô phỏng (`simulation/`)

Ứng dụng được tổ chức thành 3 tab chức năng chính trong [simulation/index.html](../simulation/index.html):
- **Module 1 — Hộp thư Mô phỏng (*Phishing Inbox Simulator*):**
  - Hiển thị danh sách kịch bản kèm trạng thái làm bài, bộ đếm tiến độ và tỷ lệ chính xác theo thời gian thực.
  - Trang bị nút **"Soi Raw Header & Xác thực"** hiển thị huy hiệu `SPF / DKIM / DMARC` cùng toàn bộ Header thô.
  - Mô phỏng thanh **URL Preview Bar** ở góc dưới trái khi người dùng rê chuột lên liên kết, đồng thời chặn mọi hành vi mở URL ngoài.
  - Cho phép người dùng chọn kết luận (*An toàn* / *Lừa đảo*) kết hợp tick chọn các Red Flags nhận diện được, sau đó phản hồi đáp án chi tiết và tổng hợp kết quả qua Modal báo cáo.
- **Module 2 — Bộ Phân tích Email Header (*Email Header & Spoofing Analyzer*):**
  - Cài đặt tại `simulation/js/header_analyzer.js`, hỗ trợ bóc tách Header chuẩn RFC 5322 (kể cả dòng gập *folded headers*) từ dữ liệu dán trực tiếp, nút nạp nhanh 6 mẫu hoặc tải tệp `.eml` bằng `FileReader`.
  - Áp dụng 6 nhóm quy tắc tự động: kiểm tra `SPF/DKIM/DMARC`, đối chiếu *Domain Alignment* (`From` vs `Return-Path` & `DKIM d=`), phát hiện đánh tráo `Reply-To`, phát hiện *Display Name Spoofing*, phát hiện *Punycode* (`xn--`), *Subdomain Trick*, liên kết ngụy trang và tệp đính kèm nguy hiểm (*Double Extension*, `.docm`, dụ *Enable Macros*) để tính điểm rủi ro (`0–100`).
- **Module 3 — Cẩm nang Red Flags:** Tóm tắt quy trình 5 bước kiểm tra email đáng ngờ cho người học ôn tập nhanh.

---

## 5.3. Bộ Kịch bản Tình huống Mẫu

Chi tiết kịch bản và đáp án đầy đủ lưu tại [labs/email_samples/scenarios_guide.md](../labs/email_samples/scenarios_guide.md). Bảng tóm tắt 6 tình huống tích hợp sẵn trong `simulation/js/scenarios.js`:

| STT | File mẫu `.eml` | Tình huống mô phỏng | Kết luận | Kỹ năng kiểm tra trọng tâm |
| :-: | :--- | :--- | :---: | :--- |
| 1 | `sample_01_legit_it.eml` | Phòng IT thông báo bảo trì cuối tuần | An toàn | Xác thực `PASS` cả 3, `From` khớp `Return-Path`, link HTTPS chuẩn |
| 2 | `sample_02_phishing_bank.eml` | Phishing ngân hàng dọa khóa thẻ sau 2 giờ | Lừa đảo | Tâm lý khẩn cấp, `SPF/DMARC=FAIL`, link hiển thị khác URL đích thật |
| 3 | `sample_03_spoofing_ceo_bec.eml` | Giả danh Tổng Giám đốc yêu cầu chuyển tiền (BEC) | Lừa đảo | Display Name Spoofing, `Reply-To` trỏ mail cá nhân, `DMARC=FAIL` |
| 4 | `sample_04_lookalike_domain.eml` | Cảnh báo đăng nhập từ tên miền `xn--micrsoft-7ya.example` | Lừa đảo | `SPF=PASS` nhưng dùng Punycode `xn--` & Subdomain Trick |
| 5 | `sample_05_malicious_attachment.eml` | Hóa đơn đính kèm `.pdf.exe` và `.docm` | Lừa đảo | Double Extension, Macro `.docm`, nội dung dụ bấm *Enable Macros* |
| 6 | `sample_06_legit_hr.eml` | Phòng Nhân sự gửi lịch khám sức khỏe (`.pdf`) | An toàn | Tránh đánh đồng mọi file `.pdf` đều độc; kiểm tra đối chiếu sạch |

---

## 5.4. Kết quả Chạy Thử nghiệm & Đánh giá

### 5.4.1. Kết quả Kiểm thử Tự động Bộ Phân tích Header (`EmailHeaderAnalyzer`)
- `[TODO (TV3): Ghi tóm tắt kết quả chạy kiểm thử đối chiếu 6 file .eml qua EmailHeaderAnalyzer.analyzeEmail() (xác nhận mẫu 1 & 6 xếp loại 'safe'; mẫu 2, 3, 4, 5 xếp loại 'danger' kèm điểm rủi ro và danh sách cảnh báo chính xác).]`

### 5.4.2. Kết quả Thực nghiệm Khảo sát Người dùng Thử nghiệm (Dry-run)
> `[TODO (Cả nhóm): Mời 5–10 bạn sinh viên hoặc các thành viên tự chạy thử Tab 1 và ghi lại số liệu thực tế vào bảng dưới đây trước khi thuyết trình.]`

| Người thử nghiệm | Số mẫu đúng (lần đầu / 6) | Mẫu hay nhầm nhất | Nhận xét sau khi xem giải thích Red Flags |
| :--- | :---: | :--- | :--- |
| `[Người thử 1]` | `[.../6]` | `[Ví dụ: Mẫu 4 SPF=PASS]` | `[TODO]` |
| `[Người thử 2]` | `[.../6]` | `[...]` | `[TODO]` |
| `[Người thử 3]` | `[.../6]` | `[...]` | `[TODO]` |

---

## Checklist Hoàn thiện Chương 5 (TV3)

- [ ] **[TODO (TV3)]:** Mở `simulation/index.html` trên trình duyệt Chrome/Edge, chụp tối thiểu 2 ảnh màn hình rõ nét (`report/assets/ch5_inbox_simulator.png` và `report/assets/ch5_header_analyzer.png`) và chèn vào Mục 5.2 / 5.4.
- [ ] **[TODO (Cả nhóm)]:** Thực hiện chạy thử nghiệm nội bộ với ít nhất 3–5 người tham gia, điền số liệu thật vào Bảng 5.4.2 và rút ra nhận xét về hiệu quả của việc hướng dẫn kiểm tra Header + Hover link.
