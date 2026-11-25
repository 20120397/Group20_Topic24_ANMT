# Chương 6: Kết luận, Hướng phát triển & Tài liệu Tham khảo

> **Phụ trách:** Thành viên 1 (Trưởng nhóm)  
> **Tài liệu tham chiếu:** `Bai 7 - Web - DHCP - DNS - Email Security.pptx` (S57), toàn bộ nội dung Chương 1–5

---

## 6.1. Kết luận & Đối chiếu Mục tiêu Đề tài

Đồ án đã giải quyết trọn vẹn bốn yêu cầu trọng tâm của **Đề tài 24**:

| Yêu cầu của Đề tài 24 | Kết quả nhóm đã hoàn thành | Vị trí minh chứng |
| :--- | :--- | :--- |
| 1. Phân tích Phishing, Email Spoofing, giả mạo tên miền và tệp đính kèm độc hại | Phân tích hệ thống cơ chế kỹ thuật, tâm lý Social Engineering và xây dựng ma trận Red Flags kèm 6 mẫu `.eml` minh họa. | Chương 2 & `labs/email_samples/` |
| 2. Tìm hiểu cơ chế SPF, DKIM, DMARC và vai trò xác thực | Trình bày chuẩn xác luồng DNS/mật mã, Identifier Alignment và viết script kiểm tra cấu hình thực tế trên nhiều tên miền. | Chương 3 & `labs/dns_audit/` |
| 3. Đề xuất giải pháp kết hợp lọc thư rác, xác thực và nâng cao nhận thức | Đề xuất mô hình *Defense in Depth* 3 trụ cột tích hợp quy trình kiểm soát và quản lý rủi ro `ISO/IEC 27002 & 27005:2022`. | Chương 4 |
| 4. Xây dựng tình huống mô phỏng nhận diện email lừa đảo | Xây dựng ứng dụng Web chạy 100% offline gồm *Inbox Phishing Simulator* và *Email Header Analyzer*. | Chương 5 & `simulation/` |

---

## 6.2. Hạn chế của Đề tài

1. **Phạm vi mô phỏng cục bộ:** Ứng dụng mô phỏng chưa kết nối trực tiếp tới một Mail Server thật (Postfix/Exchange) mà mô phỏng dữ liệu Header và nội dung `.eml` ở phía client để bảo đảm an toàn tuyệt đối khi trình diễn.
2. **Tập quy tắc phân tích tĩnh:** Bộ `EmailHeaderAnalyzer` hoạt động dựa trên luật heuristic và khớp mẫu Header, chưa tích hợp mô hình học máy/NLP huấn luyện trên tập dữ liệu email lớn ngoài thực tế.
3. **Chưa đánh giá dài hạn:** Thử nghiệm nhận diện người dùng chỉ thực hiện ở quy mô nhỏ trong phạm vi nhóm/lớp học, chưa theo dõi chu kỳ diễn tập lặp lại nhiều tháng như trong doanh nghiệp.

---

## 6.3. Hướng Phát triển

Dựa trên xu hướng an toàn thư điện tử trong *Bai 7* (Slide 57), đề tài có thể mở rộng theo năm hướng sau:
1. **AI/ML & LLM phân tích ngữ cảnh thời gian thực:** Phát hiện các cuộc tấn công BEC tinh vi không chứa link hay mã độc dựa trên phân tích văn phong, đồ thị giao tiếp nội bộ và bất thường hành vi.
2. **Zero Trust Email Security:** Không mặc định tin tưởng email chỉ vì vượt qua SPF hay xuất phát từ địa chỉ đối tác quen thuộc; xác minh liên tục theo ngữ cảnh truy cập và độ nhạy cảm dữ liệu.
3. **Tự động hóa cưỡng chế DMARC & Triển khai BIMI:** Hỗ trợ phân tích báo cáo XML RUA tự động để chuyển nhanh từ `p=none` lên `p=reject`, kết hợp chuẩn **BIMI** hiển thị logo xác thực nâng cao niềm tin người dùng.
4. **Mật mã hậu lượng tử (Post-Quantum Cryptography):** Nghiên cứu nâng cấp thuật toán ký/mã hóa trong PGP, S/MIME và DKIM trước nguy cơ máy tính lượng tử.
5. **Tích hợp SOAR (*Security Orchestration, Automation & Response*):** Tự động cách ly và thu hồi hàng loạt email lừa đảo trên toàn bộ hộp thư nhân viên ngay khi có báo cáo từ người dùng hoặc cảnh báo từ SIEM.

---

## 6.4. Tài liệu Tham khảo

1. S. Kitterman, *RFC 7208: Sender Policy Framework (SPF) for Authorizing Use of Domains in Email*, IETF, 2014.
2. D. Crocker, T. Hansen, M. Kucherawy, *RFC 6376: DomainKeys Identified Mail (DKIM) Signatures*, IETF, 2011.
3. M. Kucherawy, E. Zwicky, *RFC 7489: Domain-based Message Authentication, Reporting, and Conformance (DMARC)*, IETF, 2015.
4. P. Resnick, *RFC 5322: Internet Message Format* & J. Bhutta et al., *RFC 2606: Reserved Top Level DNS Names*.
5. ISO/IEC 27001:2022, ISO/IEC 27002:2022, ISO/IEC 27005:2022 *(tài liệu `Tieu chuan ISO 27000.pptx`)*.
6. Tài liệu bài giảng học phần tại `d:\ANMT\Seminar\`: `L1-Introduction to Cybersecurity.pptx`, `Bài 2 - Networking Essentials - Review.pptx`, `Bai 7 - Web - DHCP - DNS - Email Security.pptx`, `Bài 8 - Malicious Code.pptx`, `Lab5. Web -DHCP-DNS-Email Security.docx`.

---

## Checklist Hoàn thiện Chương 6 (TV1)

- [ ] **[TODO (TV1)]:** Cập nhật lại Bảng 6.1 sau khi TV3 điền xong kết quả chạy thực nghiệm DNS Audit và thử nghiệm Web App ở Chương 3 và Chương 5.
- [ ] **[TODO (TV1)]:** Bổ sung thêm các bài báo/báo cáo thống kê (như Verizon DBIR, APWG Phishing Activity Trends Report) vào Mục 6.4 nếu có trích dẫn trong Chương 1 hoặc Chương 2.
