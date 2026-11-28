# Gợi ý Lời Thuyết trình cho Bùi Quang Tùng (12 Slides) & Hướng dẫn Nhóm

> **File slide chính:** [DeTai24_EmailSecurity_Slides.pptx](DeTai24_EmailSecurity_Slides.pptx) (25 slides)

---

## 1. Gợi ý Lời nói cho Bùi Quang Tùng (`20120397`)

### Mở đầu & Chương 1 (Slides 1 - 5 · khoảng 3.5 - 4 phút)

- **Slide 1 (Trang bìa):**  
  *"Chào thầy/cô và các bạn. Hôm nay nhóm mình gồm Bùi Quang Tùng, Nguyễn Gia Huy và Nguyễn Lê Hữu Điền xin trình bày đồ án cuối kì Đề tài 24: Bảo mật thư điện tử trước các cuộc tấn công giả mạo và lừa đảo trực tuyến."*
- **Slide 2 (Nội dung trình bày):**  
  *"Bài báo cáo của nhóm gồm 6 phần: Phần 1 là kiến trúc email và hạn chế của giao thức SMTP; Phần 2 do bạn Gia Huy trình bày về 4 nhóm tấn công; Phần 3 do bạn Hữu Điền trình bày về cơ chế SPF, DKIM, DMARC kèm khảo sát thực tế; Phần 4 là giải pháp phòng thủ nhiều lớp gắn với chuẩn ISO; Phần 5 là Demo ứng dụng mô phỏng nhận diện email lừa đảo; và cuối cùng là Kết luận, hướng phát triển."*
- **Slide 3 (Đặt vấn đề & Thực trạng):**  
  *"Về lý do chọn đề tài, email là kênh làm việc chính nhưng cũng là con đường dễ bị khai thác nhất. Theo báo cáo Verizon DBIR 2025, 60% vụ xâm phạm dữ liệu có liên quan đến yếu tố con người; báo cáo năm 2024 cũng cho thấy trung bình người dùng chỉ mất 21 giây từ lúc mở thư đến khi bấm vào link lừa đảo. Mỗi năm APWG ghi nhận khoảng 3,8 triệu vụ phishing. Nguyên nhân bắt nguồn từ cả thiết kế cũ của giao thức SMTP lẫn tâm lý vội vàng của người đọc."*
- **Slide 4 (Kiến trúc hệ thống Email):**  
  *"Trên Hình 1.1 là luồng đi của một bức thư điện tử. Người gửi soạn thư trên MUA rồi đẩy lên máy chủ MSA/MTA qua cổng 587 hoặc 465. Máy chủ gửi sẽ hỏi DNS bản ghi MX để biết máy chủ nhận thư đích nằm ở đâu, rồi chuyển thư sang qua cổng 25. Cuối cùng MDA cất thư vào hộp thư để người nhận đọc qua IMAPS hoặc POP3S."*
- **Slide 5 (Hạn chế SMTP gốc & CIA Triad):**  
  *"Vấn đề nằm ở chỗ giao thức SMTP gốc có 4 hạn chế lớn: thứ nhất là không kiểm tra người gửi nên ai cũng tự điền địa chỉ From tùy ý được; thứ hai là truyền văn bản rõ nếu không bật TLS; thứ ba là không có chữ ký kiểm tra toàn vẹn; và thứ tư là nguy cơ cấu hình hở Open Relay. Bảng bên phải đối chiếu các cơ chế cần bổ sung để đảm bảo tính bí mật, toàn vẹn, sẵn sàng và xác thực. Tiếp theo, mình xin nhường lời cho Gia Huy phân tích các hình thức tấn công cụ thể."*

---

### Chương 4 - Giải pháp Đề xuất (Slides 16 - 20 · khoảng 4.5 - 5 phút)

- **Slide 16 (Mô hình Defense in Depth):**  
  *"Tiếp nối phần trình bày của Hữu Điền, chúng ta thấy SPF, DKIM, DMARC giúp chặn giả mạo tên miền của tổ chức, nhưng nếu kẻ xấu tự mua một tên miền gần giống mới tinh hoặc gửi thư BEC chỉ có vài dòng chữ thúc chuyển tiền thì một công cụ đơn lẻ sẽ không chặn hết được. Vì vậy nhóm đề xuất mô hình phòng thủ 4 lớp như trên sơ đồ, kết hợp từ tầng kết nối, cổng lọc nội dung, bảo vệ tài khoản cho đến nhận thức con người."*
- **Slide 17 (Lọc thư rác & Chống mã độc tại Gateway):**  
  *"Ở cổng kiểm soát email (SEG), nhóm kết hợp 4 kỹ thuật: dùng bộ lọc Bayesian cùng học máy để bắt ngữ cảnh thư rác; quét chữ ký kết hợp chặn cứng các đuôi file thực thi; mở thử các file đáng ngờ trong máy ảo Sandboxing để xem hành vi trước khi giao vào hộp thư; đồng thời viết lại URL để kiểm tra ngay thời điểm bấm chuột và gắn nhãn [EXTERNAL] cho mọi thư từ ngoài công ty."*
- **Slide 18 (Xác thực & Mã hóa):**  
  *"Về mặt xác thực và mật mã, tổ chức cần triển khai đồng bộ SPF, DKIM khóa 2048-bit và nâng dần chính sách DMARC từ none lên quarantine rồi khóa ở reject. Trên đường truyền giữa các máy chủ mail thì bật STARTTLS kết hợp MTA-STS hoặc DANE để chống nghe lén và hạ cấp. Riêng các email tài chính, hợp đồng nhạy cảm thì dùng thêm mã hóa đầu-cuối PGP hoặc S/MIME."*
- **Slide 19 (Nhận thức người dùng & ISO/IEC 27002:2022):**  
  *"Để giải pháp duy trì lâu dài, nhóm đối chiếu vào 3 nhóm kiểm soát của tiêu chuẩn ISO/IEC 27002:2022 đã học trên lớp: về Công nghệ là bắt buộc MFA/FIDO2; về Con người là tập huấn theo vị trí làm việc và tổ chức diễn tập gửi mail Phishing giả lập hằng quý; về Tổ chức là quy định bắt buộc gọi điện xác nhận qua kênh độc lập trước mọi lệnh chuyển tiền và tích hợp nút Report Phishing."*
- **Slide 20 (Đánh giá rủi ro theo ISO/IEC 27005:2022):**  
  *"Bảng này minh họa việc áp dụng quy trình đánh giá rủi ro ISO/IEC 27005:2022 theo công thức Khả năng xảy ra nhân Hậu quả. Ba kịch bản nguy hiểm nhất gồm lừa đảo BEC phòng Kế toán, tệp đính kèm chứa Ransomware và Phishing qua tên miền gần giống đều có điểm ban đầu ở mức Rất cao (20 điểm). Sau khi áp dụng các lớp kiểm soát tương ứng, rủi ro còn lại giảm xuống mức Thấp và Trung bình chấp nhận được. Tiếp theo mời Hữu Điền và Gia Huy trình bày phần ứng dụng mô phỏng."*

---

### Chương 6 - Kết luận & Hướng phát triển (Slides 24 - 25 · khoảng 1.5 - 2 phút)

- **Slide 24 (Kết luận & Hạn chế):**  
  *"Để khép lại bài báo cáo, nhóm đã hoàn thành 4 nội dung yêu cầu của đề tài từ phân tích lý thuyết, khảo sát DNS, thiết kế giải pháp theo chuẩn ISO đến xây dựng công cụ mô phỏng. Về mặt hạn chế, trong phạm vi đồ án môn học, ứng dụng hiện mô phỏng ở phía trình duyệt với tập luật cố định chứ chưa dựng cụm Mail Server thực tế hay huấn luyện mô hình học máy trên tập dữ liệu lớn."*
- **Slide 25 (Hướng phát triển & Thảo luận):**  
  *"Từ những hạn chế đó, đề tài có thể phát triển tiếp theo 5 hướng: ứng dụng NLP tiếng Việt để phát hiện sớm kịch bản BEC, áp dụng Zero Trust cho email, tự động hóa phân tích báo cáo DMARC kèm chuẩn BIMI, thử nghiệm chữ ký số hậu lượng tử và kết nối hệ thống SOAR để tự động thu hồi thư độc hại. Cảm ơn thầy/cô và các bạn đã lắng nghe, nhóm rất mong nhận được câu hỏi và góp ý ạ."*

---

## 2. Lưu ý Nhanh cho Gia Huy & Hữu Điền khi Chỉnh File `.pptx`

- **Nguyễn Gia Huy (`23120273` - Slides 6 đến 10):** Bổ sung ví dụ ngắn, chèn hình minh họa vào Slide 10 và **xóa thanh ghi chú màu vàng ở đáy mỗi slide** sau khi chỉnh xong.
- **Nguyễn Lê Hữu Điền (`23120233` - Slides 11 đến 15 & 21 đến 23):** Thay khung chờ ở Slide 15 bằng ảnh chụp chạy `check_email_auth.ps1`, thay khung chờ ở Slide 23 bằng ảnh chụp màn hình Web App + số liệu khảo sát, và **xóa thanh ghi chú màu vàng ở đáy slide** trước khi nộp.
