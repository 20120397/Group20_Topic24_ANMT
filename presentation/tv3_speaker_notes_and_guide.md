# Gợi ý Lời Thuyết trình cho Nguyễn Lê Hữu Điền (8 Slides) & Hướng dẫn Demo Phần TV3

> **Sinh viên thực hiện:** Nguyễn Lê Hữu Điền (`23120233` — *Auth & Simulation Engineer*)  
> **File slide chính:** [DeTai24_EmailSecurity_Slides.pptx](DeTai24_EmailSecurity_Slides.pptx) (25 slides — phần TV3 gồm **Slides 11–15** và **Slides 21–23**)  
> **Đồng bộ tài liệu:** [slide_outline.md](slide_outline.md), [demo_and_qa_script.md](demo_and_qa_script.md), [tv1_speaker_notes_and_guide.md](tv1_speaker_notes_and_guide.md)

---

## 1. Gợi ý Lời nói cho Nguyễn Lê Hữu Điền (`23120233`)

### Chương 3 — Cơ chế SPF, DKIM, DMARC & Khảo sát DNS Thực tế (Slides 11 – 15 · khoảng 5 – 5.5 phút)

- **Slide 11 (`3.1 & 3.2. Bản ghi DNS & SPF`):**  
  *"Cảm ơn Gia Huy. Từ các kỹ thuật giả mạo mà bạn vừa phân tích, câu hỏi đặt ra là làm sao máy chủ nhận biết được email có thực sự đến từ miền hợp pháp hay không? Vì giao thức SMTP gốc không có xác thực, các chuẩn hiện đại tận dụng hệ thống DNS làm kho công bố chính sách qua các bản ghi `MX`, `A/AAAA`, `TXT`, `CNAME` và bảo vệ tầng DNS bằng `DNSSEC`. Cơ chế đầu tiên là **SPF (`RFC 7208`)**, lưu trong bản ghi `TXT` bắt đầu bằng `v=spf1` để liệt kê các IP hoặc dịch vụ (`include:`) được phép gửi thư cho miền `MAIL FROM`. Tuy nhiên SPF có 3 hạn chế lớn: chỉ kiểm tra `Envelope From` chứ không bảo vệ địa chỉ `Header From` người dùng thấy; dễ bị gãy khi email bị tự động chuyển tiếp (Forwarding); và bị giới hạn tối đa **10 lần tra cứu DNS đệ quy** để chống lạm dụng gây quá tải DNS."*

- **Slide 12 (`3.3. Cơ chế chữ ký số DKIM`):**  
  *"Để khắc phục lỗ hổng toàn vẹn và chuyển tiếp của SPF, chuẩn **DKIM (`RFC 6376`)** dùng mật mã khóa bất đối xứng (thường là RSA 2048-bit). Máy gửi dùng khóa bí mật ký lên phần băm nội dung `bh=` và các tiêu đề trọng yếu trong danh sách `h=`, rồi đính kèm trường `DKIM-Signature`. Khi nhận thư, máy nhận đọc tên miền `d=` và bộ chọn khóa `s=` (*Selector*), tra DNS tại `<s>._domainkey.<d>` lấy khóa công khai để xác minh. Nhờ gắn trực tiếp vào thư, DKIM sống sót qua quá trình Forwarding và phát hiện ngay mọi chỉnh sửa nội dung. Dù vậy, DKIM đứng riêng vẫn chưa bắt buộc tên miền ký `d=` phải trùng với địa chỉ hiển thị `Header From`."*

- **Slide 13 (`3.4. Cơ chế DMARC`):**  
  *"Mảnh ghép hợp nhất cả hai cơ chế trên là **DMARC (`RFC 7489`)**, công bố tại bản ghi `_dmarc.<domain>`. DMARC bổ sung cơ chế cốt lõi là **Identifier Alignment (Khớp định danh)**: email chỉ đạt `DMARC=PASS` khi SPF hoặc DKIM vượt qua kiểm tra **đồng thời** tên miền đã xác thực đó khớp với miền hiển thị ở `Header From` (theo chế độ nới lỏng `Relaxed` cùng miền gốc, hoặc nghiêm ngặt `Strict` trùng khớp tuyệt đối). Bên cạnh đó, DMARC cho phép tổ chức quy định chính sách xử lý từ giám sát (`p=none`), cách ly (`p=quarantine`) đến chặn cứng (`p=reject`), kèm gửi báo cáo XML tổng hợp (`RUA`) và chi tiết lỗi (`RUF`)."*

- **Slide 14 (`3.5. So sánh SPF, DKIM, DMARC & ARC, BIMI`):**  
  *"Bảng so sánh trên cho thấy 3 chuẩn bổ trợ nhau chứ không thay thế nhau: SPF khóa theo IP nguồn, DKIM bảo vệ toàn vẹn và chống gãy khi chuyển tiếp, còn DMARC khóa chặt `Header From` cùng chính sách chặn và báo cáo. Ngoài ra, hệ sinh thái hiện đại còn có thêm hai chuẩn mở rộng: **ARC (`RFC 8617`)** bảo toàn chuỗi tin cậy khi thư đi qua Mailing List có sửa nhẹ nội dung, và **BIMI** cho phép hiển thị logo thương hiệu chính thức ngay cạnh tên người gửi khi tổ chức đã khóa chặt DMARC ở mức `quarantine` hoặc `reject`."*

- **Slide 15 (`3.5. Khảo sát cấu hình DNS thực tế trên 10 tên miền`):**  
  *"Để kiểm chứng ngoài thực tế, nhóm đã viết script PowerShell `check_email_auth.ps1` hỗ trợ đếm đệ quy chuỗi `include:`/`redirect=` theo đúng giới hạn 10 lookup của RFC 7208 và tra cứu khóa công khai DKIM selector. Trên màn hình là kết quả chạy trực tiếp trên **10 tên miền thực tế ngày 25/11/2026**:*  
  *- Nhóm **Mạnh** gồm `microsoft.com`, `cloudflare.com`, `vietcombank.com.vn` và `uit.edu.vn` đều đã khóa chặt `DMARC p=reject`; riêng `vietcombank.com.vn` ủy quyền khóa DKIM qua `CNAME` sang Microsoft 365 để xoay vòng khóa tự động.*  
  *- Nhóm **Trung bình** cho thấy những bài học kỹ thuật rất thực tế: `github.com` hiện chạm đúng ngưỡng **10/10 DNS lookups**; `gmail.com` dùng `redirect=_spf.google.com` và giữ `p=none` để tránh gián đoạn chuyển tiếp của người dùng cá nhân; trong khi `vnexpress.net`, `hust.edu.vn` mới dừng ở `p=none`, và `hcmus.edu.vn` thậm chí **chưa có bản ghi `_dmarc`**.*  
  *- Cuối cùng `neverssl.com` chưa cấu hình cả SPF lẫn DMARC nên không có khả năng tự vệ khi bị mạo danh. Do đó, chỉ riêng lớp xác thực DNS vẫn chưa đủ — tiếp theo mời Quang Tùng trình bày mô hình phòng thủ nhiều lớp ở Chương 4."*

---

### Chương 5 & Demo Trực tiếp (Slides 21 – 23 · khoảng 4.5 – 5.5 phút, phối hợp Gia Huy)

- **Slide 21 (`5.1 & 5.2. Thiết kế ứng dụng mô phỏng MailGuard Lab`):**  
  *"Cảm ơn Quang Tùng. Để biến lý thuyết Chương 2–4 thành công cụ thực hành trực quan, nhóm đã xây dựng ứng dụng web **MailGuard Lab** chạy **100% cục bộ offline** bằng HTML5/CSS3/Vanilla JS thuần, không gọi CDN ngoài, chỉ dùng tên miền `.example` chuẩn RFC 2606 và tuyệt đối không chứa mã độc thật. Như trên sơ đồ kiến trúc 3 tầng: Tầng 1 đồng bộ 1-1 toàn bộ 6 tệp `.eml` chuẩn RFC của Gia Huy vào `scenarios.js`; Tầng 2 là lõi `header_analyzer.js` bóc tách Header RFC 5322 và chấm điểm rủi ro `0–100` qua **7 nhóm luật kỹ thuật**; Tầng 3 là bàn làm việc 3 phân hệ gồm **Hộp thư Mô phỏng 3 cột**, **Bộ Phân tích Email Header 2 cột** và **Cẩm nang Blue-Team** kèm xuất kết quả khảo sát."*

- **Slide 22 (`Demo thực hành trực tiếp` — Điền thao tác chính, Huy giải thích kịch bản & tâm lý):**  
  *"Sau đây mình và Gia Huy xin trình diễn trực tiếp 3 bước thực hành:*  
  *- **Bước 1 (PowerShell DNS Audit — ~1 phút):** Chạy `.\check_email_auth.ps1 -Domains "gmail.com","vietcombank.com.vn"` (hoặc `.\check_email_auth.ps1 -SelfTest` với 9/9 unit tests nếu phòng học không có mạng) để đối chiếu bản ghi SPF đệ quy và `v=DMARC1; p=reject`.*  
  *- **Bước 2 (Tab 1 — Hộp thư Mô phỏng — ~2 phút):** Mở **Mẫu 3 (BEC giả danh CEO)** — vì `corp-vn.example` đã khóa `p=REJECT`, kẻ xấu đổi sang *Display Name Spoofing* bằng địa chỉ ngoài `ceo.corpvn@external-mail.example`, đi qua `relay-open88.example` và đánh tráo `Reply-To` về `freemail.example`. Tiếp theo mở **Mẫu 4 (Punycode)** — chỉ ra cạm bẫy `SPF=PASS` nhưng tên miền gửi là **`xn--micrsoft-qbh.example`** (giải mã thành `micrоsoft.example` với chữ `о` bảng Cyrillic `U+043E`), đồng thời rê chuột lên link để thanh Preview Bar lộ miền thật `account-reset-portal.example`. Cuối cùng mở nhanh **Mẫu 6 (Phòng Nhân sự)** để đối chiếu một email hợp lệ kèm `.pdf` sạch tránh báo động giả.*  
  *- **Bước 3 (Tab 2 — Phân tích tự động file `.eml` — ~1.5 phút):** Tải trực tiếp file `sample_05_malicious_attachment.eml` (hoặc nạp nhanh Mẫu 5). Công cụ lập tức bóc tách Header, chấm điểm **`100/100 (Nguy hiểm cao)`**, hiển thị ma trận `SPF/DKIM/DMARC = FAIL` và liệt kê chính xác tệp đuôi kép `BienLai_ThanhToan_2026.pdf.exe`, tài liệu Macro `HoSo_ChuyenKhoan_2026.docm` cùng cụm từ dụ bấm `Enable Content / Enable Macros`."*

- **Slide 23 (`5.4. Kết quả kiểm thử tự động & Khảo sát người dùng`):**  
  *"Trên màn hình là ảnh chụp thực tế giao diện Tab 1 và Tab 2 cùng kết quả kiểm thử tự động bằng `node simulation/tests/test_analyzer.js`: toàn bộ **17/17 bài kiểm thử đạt 100% PASS** — hai mẫu hợp lệ (Mẫu 1 và Mẫu 6) đều trả về **`0/100 (safe)`** không báo động giả, cả bốn mẫu tấn công (Mẫu 2–5) đều đạt **`100/100 (danger)`** bao gồm cả bẫy `SPF=PASS` ở Mẫu 4. Đối với đánh giá người dùng, Modal Tổng kết đã tích hợp sẵn thống kê theo 6 nhóm kỹ năng và nút sao chép dòng kết quả Markdown để ghi nhận số liệu thực nghiệm trung thực vào Bảng 5.4. Tiếp theo xin mời Quang Tùng tổng kết Chương 6 và hướng phát triển."*

---

## 2. Checklist Cập nhật File `DeTai24_EmailSecurity_Slides.pptx` cho Hữu Điền

Đối chiếu với ghi chú của Trưởng nhóm trong [tv1_speaker_notes_and_guide.md](tv1_speaker_notes_and_guide.md), trước khi chốt file `.pptx` nộp bài, Hữu Điền kiểm tra và hoàn tất 4 điểm sau:

- [ ] **Slides 11–14 (Chương 3):** Rà soát ngắn gọn bullet theo ý lời nói ở Mục 1; có thể chèn [ch3_spf_dkim_dmarc_flow.png](../report/assets/ch3_spf_dkim_dmarc_flow.png) vào Slide 13 (DMARC Alignment) để trực quan hóa luồng đánh giá.
- [ ] **Slide 15 (Khảo sát DNS):** Sửa tiêu đề/chú thích `"8 tên miền"` thành **`"10 tên miền thực tế (25/11/2026)"`** và thay khung chờ bằng ảnh thật [ch3_dns_audit_terminal.png](../report/assets/ch3_dns_audit_terminal.png).
- [ ] **Slide 21 (Kiến trúc Mô phỏng):** Chèn sơ đồ kiến trúc 3 tầng [ch5_simulator_architecture.png](../report/assets/ch5_simulator_architecture.png).
- [ ] **Slide 23 (Kết quả Kiểm thử & Khảo sát):** Thay khung chờ bằng 2 ảnh giao diện thật [ch5_inbox_simulator.png](../report/assets/ch5_inbox_simulator.png) & [ch5_header_analyzer.png](../report/assets/ch5_header_analyzer.png), ghi rõ kết quả kiểm thử tự động **`17/17 PASS`** (`0/100 safe` trên Mẫu 1 & 6; `100/100 danger` trên Mẫu 2–5), và bổ sung bảng tóm tắt số liệu Dry-run sau khi nhóm thu thập thực tế.
- [ ] **Hoàn thiện cuối:** **Xóa toàn bộ thanh ghi chú màu vàng ở đáy các slide 11–15 và 21–23** trước khi xuất bản cuối cùng.

---

## 3. Trọng tâm Phản biện (Q&A) Phần Hữu Điền (TV3)

Ngoài các câu trả lời chuẩn tại [demo_and_qa_script.md](demo_and_qa_script.md) (**Câu 3, 4, 6, 8, 11, 12**), cần ghi nhớ thêm 2 tình huống hỏi sâu dễ gặp khi bảo vệ:

1. **Nếu giảng viên hỏi về chữ ký `DKIM-Signature` (`bh=`, `b=`) trong bộ 6 mẫu `.eml`:**  
   → Trả lời thẳng thắn và nhất quán cả nhóm: *"Các giá trị `bh=` và `b=` trong 6 tệp `.eml` là chuỗi mô phỏng tĩnh chuẩn hóa cấu trúc theo RFC 6376 phục vụ môi trường huấn luyện offline không phụ thuộc DNS thật; bộ phân tích tĩnh `header_analyzer.js` đánh giá trên trường `Authentication-Results`, tên miền ký `d=` và đối chiếu căn chỉnh định danh thay vì xác minh mật mã RSA trực tiếp qua mạng."*
2. **Nếu giảng viên hỏi vì sao Mẫu 4 (`xn--micrsoft-qbh.example`) đạt `SPF Alignment` mà công cụ vẫn chấm `100/100 (danger)`:**  
   → Trả lời: *"Về mặt kỹ thuật RFC 7489, kẻ tấn công tự sở hữu tên miền giả `xn--micrsoft-qbh.example` nên có thể tự cấu hình SPF hợp lệ cho chính miền đó (`SPF=PASS` và khớp `Header From` giả). Tuy nhiên, `header_analyzer.js` áp dụng 7 nhóm luật độc lập nên vẫn cộng điểm rủi ro từ Punycode `xn--` (`+35`), liên kết ngụy trang (`+30`), subdomain 5 cấp (`+20`), thiếu `DKIM/DMARC` (`+25`) và giả mạo tên thương hiệu (`+15`) — chứng minh thực nghiệm vì sao xác thực DNS phải đi kèm bộ lọc URL/nội dung và nhận thức người dùng."*
