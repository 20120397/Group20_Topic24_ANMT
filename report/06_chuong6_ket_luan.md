# Chương 6: Kết luận, Hướng phát triển & Tài liệu Tham khảo

> **Sinh viên thực hiện:** Bùi Quang Tùng (`20120397`)  
> **Tài liệu môn học tham khảo:** `Bai 7 - Web - DHCP - DNS - Email Security.pptx` (S57)

---

## 6.1. Kết luận

Qua quá trình tìm hiểu lý thuyết và xây dựng thực nghiệm, nhóm đã hoàn thành bốn nội dung yêu cầu của **Đề tài 24** như tổng hợp tại *Bảng 6.1*:

| Nội dung yêu cầu của đề tài | Kết quả thực hiện của nhóm | Chương / Thư mục tương ứng |
| :--- | :--- | :--- |
| 1. Phân tích Phishing, Email Spoofing, giả mạo tên miền và tệp đính kèm độc hại | Trình bày cơ chế kỹ thuật, cách tác động tâm lý người dùng, tổng hợp bảng dấu hiệu nhận biết và thiết kế bộ 6 file `.eml` mẫu. | Chương 1, Chương 2 & `labs/email_samples/` |
| 2. Tìm hiểu cơ chế SPF, DKIM, DMARC và vai trò xác thực | Phân tích quy trình kiểm tra qua DNS, chữ ký số, khớp định danh Identifier Alignment và viết script PowerShell khảo sát các tên miền thực tế. | Chương 3 & `labs/dns_audit/` |
| 3. Đề xuất giải pháp kết hợp lọc thư rác, xác thực và nâng cao nhận thức | Xây dựng mô hình phòng thủ nhiều lớp (4 lớp), gắn với khung kiểm soát `ISO/IEC 27002:2022` và đánh giá rủi ro `ISO/IEC 27005:2022`. | Chương 4 & `report/assets/` |
| 4. Xây dựng tình huống mô phỏng nhận diện email lừa đảo | Cài đặt ứng dụng Web chạy cục bộ gồm *Hộp thư mô phỏng* (6 kịch bản) và *Bộ phân tích Email Header* tự động chấm điểm rủi ro. | Chương 5, `simulation/` & `presentation/` |

*Bảng 6.1: Tổng kết kết quả thực hiện so với yêu cầu Đề tài 24.*

Kết quả nghiên cứu cho thấy các chuẩn xác thực như SPF, DKIM, DMARC giúp ngăn chặn hiệu quả việc mạo danh trực tiếp tên miền của tổ chức, nhưng không thể thay thế bộ lọc mã độc hay sự cảnh giác của con người trước các tên miền giả mạo mới đăng ký và kịch bản BEC. Sự kết hợp đồng bộ giữa công nghệ và quy trình đào tạo người dùng là điều kiện bắt buộc để bảo vệ hệ thống thư điện tử.

---

## 6.2. Hạn chế của Đề tài

1. **Môi trường mô phỏng hoạt động cục bộ:** Ứng dụng Web tập trung mô phỏng giao diện đọc thư và phân tích cấu trúc Header/MIME từ tệp `.eml`, chưa dựng cụm máy chủ gửi/nhận thư thực tế (như Postfix, Exchange) để thử nghiệm chặn thư trực tiếp trên luồng SMTP.
2. **Phân tích dựa trên tập luật cố định:** Module `EmailHeaderAnalyzer` đánh giá nguy cơ dựa trên các quy tắc kiểm tra Header và biểu thức chính quy, chưa tích hợp mô hình học máy để nhận diện văn phong lừa đảo tiếng Việt tự động.
3. **Quy mô khảo sát thử nghiệm còn nhỏ:** Việc đánh giá khả năng nhận diện email lừa đảo mới dừng ở phạm vi thử nghiệm nhỏ trong nhóm và lớp học, chưa có điều kiện theo dõi qua nhiều đợt diễn tập định kỳ như môi trường doanh nghiệp.

---

## 6.3. Hướng Phát triển

Dựa trên các xu hướng bảo mật email được giới thiệu trong *Bai 7* (Slide 57), đề tài có thể tiếp tục phát triển theo các hướng sau:
1. **Ứng dụng AI/ML và xử lý ngôn ngữ tự nhiên (NLP):** Huấn luyện mô hình phát hiện sớm các email lừa đảo BEC bằng tiếng Việt thông qua phân tích ngữ điệu hối thúc bất thường và thói quen giao tiếp nội bộ.
2. **Mô hình Zero Trust cho Email:** Áp dụng nguyên tắc xác minh liên tục đối với mọi liên kết và tệp đính kèm ngay cả khi thư được gửi từ đối tác quen thuộc hoặc tài khoản nội bộ (phòng trường hợp tài khoản đối tác bị chiếm quyền).
3. **Tự động hóa phân tích báo cáo DMARC & triển khai BIMI:** Xây dựng công cụ đọc báo cáo XML (`RUA`) trực quan giúp quản trị viên sớm chuyển chính sách lên `p=reject` và hiển thị biểu trưng thương hiệu xác thực qua chuẩn **BIMI**.
4. **Chuẩn bị cho mật mã hậu lượng tử (Post-Quantum Cryptography):** Thử nghiệm các thuật toán chữ ký số kháng lượng tử mới cho DKIM, PGP và S/MIME.
5. **Kết nối tự động hóa phản ứng sự cố (SOAR):** Liên kết nút báo cáo lừa đảo của người dùng với hệ thống SIEM/SOAR để tự động cách ly và thu hồi các email tương tự trong toàn bộ hộp thư của tổ chức.

---

## 6.4. Tài liệu Tham khảo

1. S. Kitterman, *RFC 7208: Sender Policy Framework (SPF) for Authorizing Use of Domains in Email*, IETF, 2014.
2. D. Crocker, T. Hansen, M. Kucherawy, *RFC 6376: DomainKeys Identified Mail (DKIM) Signatures*, IETF, 2011.
3. M. Kucherawy, E. Zwicky, *RFC 7489: Domain-based Message Authentication, Reporting, and Conformance (DMARC)*, IETF, 2015.
4. P. Resnick, *RFC 5322: Internet Message Format* & D. Eastlake, A. Panitz, *RFC 2606: Reserved Top Level DNS Names*.
5. Tiêu chuẩn quốc tế *ISO/IEC 27001:2022, ISO/IEC 27002:2022, ISO/IEC 27005:2022* (tham khảo từ bài giảng `Tieu chuan ISO 27000.pptx`).
6. Verizon, *2024 & 2025 Data Breach Investigations Report (DBIR)*.
7. Anti-Phishing Working Group (APWG), *Phishing Activity Trends Reports (2024 - 2025)*.
8. Tập bài giảng học phần An ninh mạng (`L1-Introduction to Cybersecurity.pptx`, `Bài 2 - Networking Essentials - Review.pptx`, `Bai 7 - Web - DHCP - DNS - Email Security.pptx`, `Bài 8 - Malicious Code.pptx`, `Lab5. Web -DHCP-DNS-Email Security.docx`).
