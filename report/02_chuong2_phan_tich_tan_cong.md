# Chương 2: Phân tích các Cuộc tấn công Giả mạo và Lừa đảo qua Email

> **Sinh viên thực hiện:** Nguyễn Gia Huy (`23120273`) — Thành viên 2 (*Threat & Malware Analyst*)  
> **Tài liệu tham chiếu:** `Bai 7 - Web - DHCP - DNS - Email Security.pptx` (S43–S49, S50–S52, S55), `Bài 9 - Malicious Code.pptx` (S3–S13, S15–S19, S23, S25, S27, S29–S38), `L1-Introduction to Cybersecurity.pptx` (S8–S10, S15, S29, S33) và các chuẩn kỹ thuật `RFC 1135`, `RFC 2606`, `RFC 3492`, `RFC 5321`, `RFC 5322`, `RFC 5737`, `RFC 5891`, `RFC 6376`, `RFC 7208`, `RFC 7489`, `RFC 8601`.

---

Thư điện tử là kênh trao đổi thông tin trọng yếu của mọi tổ chức, đồng thời cũng là bề mặt tấn công bị khai thác phổ biến nhất (*Bai 7 - Web - DHCP - DNS - Email Security.pptx*, Slide 50–51; *L1-Introduction to Cybersecurity.pptx*, Slide 33). Để thiết kế các lớp phòng thủ hiệu quả ở các chương sau, chương này đi sâu phân tích cơ chế kỹ thuật, thủ thuật tâm lý và dấu hiệu nhận diện của bốn nhóm tấn công cốt lõi qua email — bao gồm lừa đảo trực tuyến, giả mạo địa chỉ người gửi, giả mạo tên miền và phát tán tệp đính kèm độc hại — gắn trực tiếp với bộ 6 mẫu email chuẩn mô phỏng an toàn tại [labs/email_samples/](../labs/email_samples/scenarios_guide.md).

---

## 2.1. Tấn công Lừa đảo trực tuyến (Phishing)

**Lừa đảo trực tuyến (*Phishing*)** là hình thức tấn công dựa trên **Kỹ nghệ xã hội (*Social Engineering*)** thông qua thư điện tử nhằm đánh lừa nạn nhân tiết lộ thông tin nhạy cảm (tên đăng nhập, mật khẩu, mã OTP, dữ liệu thẻ ngân hàng), chuyển tiền trái phép hoặc kích hoạt mã độc (*Bai 7*, Slide 51; *L1-Introduction to Cybersecurity.pptx*, Slide 33). Xét theo mô hình mục tiêu an toàn thông tin (*L1*, Slide 8–10), Phishing xâm phạm trực tiếp **Tính xác thực (*Authenticity*)** để phá vỡ **Tính bí mật (*Confidentiality*)** và kéo theo thiệt hại tài chính hoặc xâm nhập sâu hơn vào hệ thống nội bộ.

### 2.1.1. Phân loại các Biến thể Phishing Phổ biến

Tùy theo phạm vi mục tiêu, mức độ thu thập thông tin trước tấn công và hình thức ngụy trang, tấn công Phishing qua email được phân chia thành năm biến thể truyền thống cùng một xu hướng né lọc mới nổi:

1. **Lừa đảo đại trà (*Bulk Phishing*):** Kẻ tấn công gửi hàng loạt thư theo kịch bản chung (cảnh báo khóa tài khoản ngân hàng, thông báo giao hàng thất bại, hóa đơn quá hạn) tới hàng nghìn địa chỉ thu thập sẵn. Mức độ cá nhân hóa thấp nhưng tận dụng xác suất lớn để tìm nạn nhân mất cảnh giác. Kịch bản này được minh họa rõ qua mẫu [sample_02_phishing_bank.eml](../labs/email_samples/sample_02_phishing_bank.eml).
2. **Lừa đảo có chủ đích (*Spear Phishing*):** Nhắm vào một cá nhân, phòng ban hoặc tổ chức cụ thể sau quá trình trinh sát thông tin về chức vụ, dự án đang triển khai và mối quan hệ công việc. Nội dung thư sát thực tế nên tỷ lệ đánh lừa cao hơn đáng kể so với *Bulk Phishing*.
3. **Lừa đảo săn cá lớn (*Whaling*):** Một phân nhánh đặc biệt của *Spear Phishing* nhắm thẳng vào lãnh đạo cấp cao (CEO, CFO, Giám đốc nhân sự) — những người nắm quyền phê duyệt tài chính hoặc tiếp cận tài sản trí tuệ, dữ liệu nhân sự tối mật.
4. **Xâm phạm email doanh nghiệp (*Business Email Compromise — BEC*):** Kẻ tấn công mạo danh lãnh đạo, đối tác hoặc nhà cung cấp quen thuộc (hoặc chiếm dụng hộp thư hợp pháp) để yêu cầu bộ phận kế toán thực hiện chuyển khoản gấp hoặc thay đổi số tài khoản thụ hưởng hợp đồng. Điểm nguy hiểm của BEC là thư thường **không chứa liên kết độc hại hay tệp đính kèm**, khiến các bộ lọc chống mã độc truyền thống khó phát hiện — như kịch bản giả danh Tổng Giám đốc tại [sample_03_spoofing_ceo_bec.eml](../labs/email_samples/sample_03_spoofing_ceo_bec.eml).
5. **Lừa đảo nhân bản (*Clone Phishing*):** Kẻ tấn công sao chép nguyên văn giao diện, ngữ điệu và cấu trúc của một email hợp lệ từng được gửi trước đó (ví dụ thông báo từ phòng IT hoặc nhân sự), sau đó thay thế liên kết hoặc tệp đính kèm sạch bằng phiên bản độc hại rồi gửi lại dưới danh nghĩa *"cập nhật / gửi lại bản sửa lỗi"*.
6. **Lừa đảo qua mã QR (*QR Code Phishing — Quishing*):** Là biến thể hiện đại ngày càng phổ biến nhằm vượt qua các bộ lọc phân tích URL dạng văn bản trên cổng bảo mật email (*Email Gateway*). Thay vì chèn trực tiếp thẻ `<a href="...">`, kẻ tấn công nhúng liên kết lừa đảo vào hình ảnh mã QR trong thân email hoặc tệp PDF đính kèm (ví dụ yêu cầu *"quét mã để thiết lập lại xác thực đa yếu tố MFA"*). Cách làm này vừa che giấu đường dẫn đích khỏi trình quét tĩnh, vừa đẩy nạn nhân sang dùng điện thoại cá nhân — thiết bị thường không nằm dưới lớp bảo vệ tường lửa hay phần mềm giám sát của doanh nghiệp.

### 2.1.2. Vòng đời của Một Chiến dịch Phishing

Tương tự các bước khởi đầu trong chuỗi tấn công mạng *Cyber Kill Chain* (*Bài 9 - Malicious Code.pptx*, Slide 6), một chiến dịch Phishing bài bản thường vận hành theo bốn giai đoạn liên hoàn:

1. **Trinh sát (*Reconnaissance*):** Kẻ tấn công thu thập thông tin công khai (OSINT) từ website doanh nghiệp, mạng xã hội nghề nghiệp hoặc các bộ dữ liệu rò rỉ để xác định định dạng địa chỉ email nội bộ (ví dụ `ketoan@corp-vn.example`), cơ cấu lãnh đạo và tên đối tác quen thuộc.
2. **Dựng nội dung và hạ tầng giả (*Weaponization & Infrastructure Setup*):** Đăng ký tên miền giả mạo gần giống thương hiệu, dựng trang đăng nhập giả mạo (*credential harvesting page*) hoặc soạn kịch bản thư phù hợp tâm lý mục tiêu, đồng thời thiết lập máy chủ gửi thư (hoặc lợi dụng máy chủ trung gian bị xâm nhập).
3. **Phát tán (*Delivery*):** Gửi thư lừa đảo qua giao thức SMTP kèm các kỹ thuật né bộ lọc thư rác (ngụy trang liên kết, giả mạo tên hiển thị, đính kèm mã QR hoặc tệp độc hại).
4. **Khai thác và trục lợi (*Exploitation & Monetization*):** Nạn nhân bị thuyết phục nhập mật khẩu, cung cấp mã OTP, chuyển khoản tài chính hoặc mở tệp độc hại. Dữ liệu đánh cắp được kẻ tấn công sử dụng để chiếm đoạt tài sản, bán trên chợ đen hoặc mở rộng bàn đạp tấn công sâu hơn vào mạng nội bộ.

### 2.1.3. Các Đòn tâm lý Kỹ nghệ xã hội (Social Engineering)

Theo *L1-Introduction to Cybersecurity.pptx* (Slide 29, Câu hỏi Q5), kỹ nghệ xã hội khai thác trực tiếp lỗ hổng tâm lý của con người để thu thập thông tin hệ thống và mật khẩu, khiến việc nâng cao nhận thức và đào tạo người dùng (*User Training*) trở thành tuyến phòng thủ không thể thay thế. Các chiến dịch Phishing thường kết hợp bốn đòn tâm lý cốt lõi sau:

1. **Tạo áp lực khẩn cấp (*Urgency*):** Ép nạn nhân hành động trong khung thời gian rất ngắn để triệt tiêu quá trình suy xét và kiểm chứng. Ví dụ, tại `sample_02_phishing_bank.eml`, tiêu đề gắn nhãn `[KHAN CAP]` đi kèm cảnh báo tài khoản sẽ **"BỊ KHÓA VĨNH VIỄN SAU 02 GIỜ"**; còn tại `sample_03_spoofing_ceo_bec.eml`, kẻ tấn công thúc giục chuyển khoản gấp *"trước 11:00 trưa nay"*.
2. **Đe dọa và gây sợ hãi (*Fear*):** Khai thác nỗi lo mất quyền truy cập, khóa tài khoản ngân hàng hoặc gánh chịu hậu quả công việc. Cả `sample_02_phishing_bank.eml` (đe dọa khóa tài khoản VCB Digibank do *"đăng nhập bất thường từ thiết bị lạ"*) và `sample_04_lookalike_domain.eml` (cảnh báo *"mất quyền truy cập hộp thư công ty"*) đều đánh mạnh vào tâm lý này.
3. **Lạm dụng quyền lực và cô lập kiểm chứng (*Authority & Isolation*):** Mạo danh cấp trên hoặc bộ phận có thẩm quyền để tận dụng tâm lý phục tùng của nhân viên. Điển hình tại `sample_03_spoofing_ceo_bec.eml`, kẻ tấn công giả danh Tổng Giám đốc Trần Minh Quân, ra lệnh chuyển `245.000.000 VND`, đồng thời khéo léo chặn đứng kênh xác minh chéo bằng hai lý do: *"đang họp gấp với đối tác nước ngoài nên không tiện nghe điện thoại"* và yêu cầu *"tuyệt đối không trao đổi với các phòng ban khác"*.
4. **Kích thích lòng tham hoặc sự tò mò (*Greed / Curiosity*):** Dụ nạn nhân tương tác bằng các chủ đề nhạy cảm như thưởng lương, hoàn thuế, hoặc chứng từ tài chính bất ngờ (ví dụ gửi biên lai thanh toán và hợp đồng bổ sung tại `sample_05_malicious_attachment.eml`).

---

## 2.2. Tấn công Giả mạo Địa chỉ Người gửi (Email Spoofing)

**Giả mạo địa chỉ người gửi (*Email Spoofing*)** là kỹ thuật làm sai lệch thông tin nguồn gửi của email nhằm khiến người nhận tin rằng thư xuất phát từ một cá nhân hoặc tổ chức đáng tin cậy (*Bai 7*, Slide 51).

### 2.2.1. Lỗ hổng Nguyên bản của SMTP và Cơ chế Tách biệt Hai Tầng Địa chỉ

Theo *Bai 7 - Web - DHCP - DNS - Email Security.pptx* (Slide 52), **Giao thức truyền thư đơn giản (*Simple Mail Transfer Protocol — SMTP*)** được thiết kế ban đầu trong môi trường mạng học thuật tin cậy, do đó tồn tại ba khiếm khuyết bảo mật cố hữu: không có mã hóa kênh truyền (truyền bản rõ trước khi áp dụng TLS), **không có cơ chế xác thực người gửi tích hợp** dẫn đến rất dễ giả mạo trường `From`, và thiếu cơ chế kiểm tra tính toàn vẹn nội dung.

Cụ thể hơn, kiến trúc gửi thư điện tử theo tiêu chuẩn kỹ thuật tách biệt rõ ràng hai tầng địa chỉ hoàn toàn độc lập:

- **Địa chỉ người gửi tầng phong bì (*Envelope From* — `MAIL FROM` / `Return-Path`, theo `RFC 5321`):** Là địa chỉ được khai báo trong phiên hội thoại giao vận giữa máy chủ gửi và máy chủ nhận (lệnh `MAIL FROM:<...>`). Địa chỉ này dùng để định tuyến thư và chỉ định nơi tiếp nhận thông báo lỗi trả về (*bounce*), sau đó được tác nhân chuyển phát thư (*MDA*) ghi vào tiêu đề `Return-Path:` ở đầu thư. Thông thường, người dùng cuối không nhìn thấy trường này trên giao diện hộp thư mặc định.
- **Địa chỉ người gửi tầng tiêu đề (*Header From* — `From:`, theo `RFC 5322`):** Nằm bên trong khối dữ liệu `DATA` của thông điệp, bao gồm hai thành phần là *Tên hiển thị (Display Name)* và *Địa chỉ email thực (`<addr-spec>`)*, cùng trường tùy chọn `Reply-To:` để chỉ định địa chỉ nhận thư phản hồi. Đây là phần xuất hiện trực tiếp trong hộp thư đến của nạn nhân.

Do SMTP nguyên bản không yêu cầu `Envelope From` phải khớp với `Header From`, cũng không kiểm chứng máy chủ phát tán có được chủ sở hữu tên miền ủy quyền hay không, kẻ tấn công có thể tùy ý tạo ra các tiêu đề giả mạo để đánh lừa người đọc.

```mermaid
sequenceDiagram
    participant Attacker as "May chu Ke tan cong<br/>(relay-open88.example)"
    participant VictimMTA as "MTA Nan nhan<br/>(mx.corp-vn.example)"
    participant User as "Hop thu Ke toan<br/>(ketoan@corp-vn.example)"

    Attacker->>VictimMTA: "SMTP MAIL FROM: <mailer@relay-open88.example>"
    Attacker->>VictimMTA: "DATA -> From: 'Giam doc Tran Minh Quan (CEO)' <ceo.corpvn@external-mail.example>"
    Attacker->>VictimMTA: "DATA -> Reply-To: 'Tran Minh Quan' <tranminhquan.private2026@freemail.example>"
    Note over VictimMTA: "Kiem tra xac thuc:<br/>spf=softfail (relay-open88.example)<br/>dkim=none | dmarc=fail (p=NONE; dis=NONE)"
    VictimMTA->>User: "Chuyen phat vao hop thu (vi external-mail.example co p=NONE)<br/>Hien thi noi bat: Giam doc Tran Minh Quan (CEO)"
    User-->>Attacker: "Neu nan nhan bam Reply -> thu di toi tranminhquan.private2026@freemail.example"
```
*Hình 2.1: Cơ chế tách biệt `Envelope From`, `Header From` (Display Name Spoofing) và `Reply-To` trong kịch bản BEC tại `sample_03_spoofing_ceo_bec.eml`.*

### 2.2.2. Các Kỹ thuật Giả mạo Địa chỉ Phổ biến

Trong thực tế, kẻ tấn công vận dụng linh hoạt bốn kỹ thuật chính tùy thuộc vào mức độ cấu hình bảo mật của tên miền mục tiêu:

1. **Giả mạo trực tiếp `Header From` (*Direct Domain Spoofing*):** Kẻ tấn công điền trực tiếp địa chỉ tổ chức uy tín vào trường `From:` trong khi `Envelope From` (`Return-Path`) thuộc máy chủ khác. Kỹ thuật này có thể đưa thư lọt vào hộp thư hoặc thư mục Spam khi tên miền bị giả mạo chưa áp dụng chính sách DMARC từ chối cứng (`p=REJECT`).
   - *Dẫn chứng từ `sample_02_phishing_bank.eml`:* Thư khai báo `From: "VCB Digibank Security" <no-reply@vcb-bank.example>` nhưng `Return-Path` lại là `<bounce@promo-mailer-99.example>` gửi từ IP `203.0.113.88` qua kênh `SMTP` không mã hóa TLS. Do IP không hợp lệ cho `promo-mailer-99.example` (`spf=fail`), thiếu chữ ký (`dkim=none`) và không khớp định danh với `vcb-bank.example`, hệ thống trả về `dmarc=fail (p=QUARANTINE sp=QUARANTINE dis=QUARANTINE)` — thư vẫn có tiêu đề `Delivered-To:` và bị đưa vào khu vực cách ly/Spam mô phỏng thay vì bị chặn bỏ hoàn toàn ở tầng giao vận.
2. **Giả mạo tên hiển thị (*Display Name Spoofing*):** Khi tên miền mục tiêu đã triển khai chặt chẽ chính sách **`DMARC p=REJECT`** (như `corp-vn.example` tại `sample_01_legit_it.eml` và `sample_06_legit_hr.eml`), mọi nỗ lực giả mạo trực tiếp `From: <ceo@corp-vn.example>` từ bên ngoài sẽ bị máy chủ nhận từ chối ngay lập tức. Để lách rào cản này, kẻ tấn công sử dụng một tên miền bên ngoài có chính sách yếu (`p=NONE`) làm địa chỉ thật trong cặp ngoặc `<...>`, nhưng đặt phần *Display Name* trùng khớp hoàn toàn với họ tên và chức danh lãnh đạo. Trên nhiều trình đọc mail và thiết bị di động, phần tên hiển thị được in đậm nổi bật còn địa chỉ thật bị rút gọn hoặc ẩn đi.
   - *Dẫn chứng từ `sample_03_spoofing_ceo_bec.eml`:* Như minh họa tại **Hình 2.1**, kẻ tấn công đặt `From: "Giam doc Tran Minh Quan (CEO)" <ceo.corpvn@external-mail.example>`. Vì `external-mail.example` cấu hình `p=NONE sp=NONE dis=NONE`, dù email thất bại kiểm tra căn chỉnh định danh giữa `relay-open88.example` và `external-mail.example` (`dmarc=fail`), thư vẫn vượt qua cổng nhận để rơi vào hộp thư của kế toán (`ketoan@corp-vn.example`).
3. **Đánh tráo trường `Reply-To` (*Reply-To Spoofing*):** Theo chuẩn `RFC 5322`, khi trường `Reply-To:` tồn tại, ứng dụng email sẽ ưu tiên gửi thư trả lời tới địa chỉ này thay vì địa chỉ trong `From:`. Tại `sample_03_spoofing_ceo_bec.eml`, kẻ tấn công cài cắm `Reply-To: "Tran Minh Quan" <tranminhquan.private2026@freemail.example>`, âm thầm điều hướng toàn bộ phản hồi trao đổi số tài khoản của phòng kế toán về hộp thư miễn phí do chúng kiểm soát.
4. **Lợi dụng máy chủ chuyển tiếp mở (*Open Relay*):** Các máy chủ SMTP cấu hình sai cho phép bên thứ ba bất kỳ gửi chuyển tiếp thư đi mà không cần xác thực (mô phỏng qua `relay-open88.example [203.0.113.154]` tại `sample_03_spoofing_ceo_bec.eml`), giúp kẻ tấn công che giấu IP gốc và phát tán thư giả mạo hàng loạt.

---

## 2.3. Tấn công Giả mạo Tên miền (Domain Spoofing / Lookalike Domains)

Khi cơ chế xác thực email ngăn chặn hiệu quả việc giả mạo trực tiếp tên miền hợp pháp, kẻ tấn công chuyển sang đăng ký các **Tên miền giống mắt (*Lookalike Domains*)** — những tên miền hoàn toàn hợp lệ về mặt đăng ký DNS nhưng có hình dạng gần giống hệt thương hiệu gốc nhằm đánh lừa thị giác người đọc.

### 2.3.1. Phân loại các Kỹ thuật Giả mạo Tên miền

Bốn kỹ thuật giả mạo tên miền phổ biến nhất trong các chiến dịch lừa đảo qua email được tổng hợp và đối chiếu tại **Bảng 2.1**.

| Kỹ thuật giả mạo | Cơ chế thực hiện | Đặc điểm nhận diện | Ví dụ minh họa an toàn (`.example`) |
| :--- | :--- | :--- | :--- |
| **Lợi dụng lỗi gõ phím (*Typosquatting*)** | Đăng ký tên miền sai chính tả nhẹ hoặc thay ký tự dễ nhìn nhầm (`l` ↔ `1`, `o` ↔ `0`, `m` ↔ `rn`, đảo/thiếu chữ cái). | So kỹ từng ký tự thấy sai khác chính tả so với tên miền chuẩn. | `micorsoft.example`, `vcb-bamk.example`, `gmai1.example` |
| **Ghép từ khóa tin cậy (*Combosquatting*)** | Giữ nguyên tên thương hiệu nhưng ghép thêm các từ khóa tạo cảm giác uy tín như `security`, `support`, `verify`, `login`. | Tên miền gốc chứa dấu gạch nối dài kèm từ khóa hành động bất thường. | `vcb-security-check.login-verify.example` *(Mẫu 02)*, `corp-vn-support.example` |
| **Tấn công đồng tự (*Homograph Attack / IDN Punycode*)** | Thay thế ký tự Latin bằng ký tự giống hệt thuộc bảng mã Unicode khác (Cyrillic, Hy Lạp); tầng DNS mã hóa sang dạng ASCII bắt đầu bằng `xn--` (`RFC 3492`, `RFC 5891`). | Xuất hiện tiền tố **`xn--`** trong Raw Header hoặc thanh địa chỉ khi trình duyệt tắt hiển thị Unicode. | **`xn--micrsoft-qbh.example`** → hiển thị `micrоsoft.example` *(chữ `о` Cyrillic `U+043E`, Mẫu 04)* |
| **Đánh lừa bằng tên miền phụ (*Subdomain Trick*)** | Đưa tên thương hiệu hợp lệ lên làm các cấp tên miền phụ (*subdomain*) đứng đầu một tên miền do kẻ tấn công sở hữu. | Chuỗi tên miền dài từ 4–5 cấp trở lên; tên miền đăng ký thực sự nằm ở **2 nhãn cuối cùng**. | `login.microsoft.example.account-reset-portal.example` *(miền thật: `account-reset-portal.example`, Mẫu 04)* |

*Bảng 2.1: So sánh bốn kỹ thuật giả mạo tên miền (Lookalike / Domain Spoofing) phổ biến qua Email.*

### 2.3.2. Cơ chế IDN Punycode và "Cạm bẫy `SPF=PASS`" trong Mẫu 04

Để hỗ trợ tên miền đa ngôn ngữ không thuộc bảng chữ cái Latin, hệ thống **Tên miền quốc tế hóa (*Internationalized Domain Name — IDN*)** theo chuẩn `RFC 5891` và thuật toán **Punycode (`RFC 3492`)** quy đổi các nhãn chứa ký tự Unicode sang chuỗi **Mã hóa tương thích ASCII (*ASCII Compatible Encoding — ACE*)** có tiền tố nhận diện bắt buộc là `xn--` trước khi truy vấn ở tầng DNS.

Kịch bản tại [sample_04_lookalike_domain.eml](../labs/email_samples/sample_04_lookalike_domain.eml) phơi bày sự tinh vi khi kết hợp đồng thời ba thủ thuật:

1. **Giả dạng đồng tự chuẩn RFC:** Địa chỉ người gửi là `security@xn--micrsoft-qbh.example`. Khi giải mã Punycode sang dạng Unicode, tên miền này trở thành **`micrоsoft.example`**, trong đó ký tự thứ năm là chữ **`о` thuộc bảng mã Cyrillic (`U+043E`)** — về mặt thị giác gần như không thể phân biệt với chữ **`o` Latin (`U+006F`)**.
2. **Đánh lừa bằng *Subdomain Trick* và liên kết ngụy trang:** Văn bản liên kết hiển thị là `https://login.microsoft.example/verify`, nhưng thuộc tính `href` thực sự trỏ tới `https://login.microsoft.example.account-reset-portal.example/oauth`. Chuỗi tên miền 5 cấp này đánh lừa mắt người đọc tập trung vào cụm `login.microsoft.example` phía trước, che khuất tên miền gốc thực sự do kẻ tấn công kiểm soát ở phía cuối là `account-reset-portal.example`.
3. **Cạm bẫy kỹ thuật `SPF=PASS`:** Vì kẻ tấn công **tự đăng ký và toàn quyền quản trị DNS** của tên miền giả `xn--micrsoft-qbh.example`, chúng dễ dàng công bố bản ghi `TXT` SPF ủy quyền cho máy chủ gửi `198.51.100.77` và bật cả kết nối `ESMTPS (TLS 1.2)`. Kết quả là email vượt qua kiểm tra SPF hoàn toàn hợp lệ (`spf=pass`, `Return-Path` khớp `Header From`), dù thiếu `DKIM` (`dkim=none`) và không có `DMARC` (`dmarc=none`). Đây là minh chứng thực tế quan trọng: **`SPF=PASS` đơn lẻ chỉ khẳng định IP gửi được chủ tên miền đó cho phép, tuyệt đối không chứng minh tên miền đó thuộc về tổ chức hợp pháp.**

### 2.3.3. Liên hệ Tấn công Đầu độc Bộ nhớ đệm DNS (DNS Cache Poisoning)

Bên cạnh việc đăng ký tên miền giống mắt, theo *Bai 7 - Web - DHCP - DNS - Email Security.pptx* (Slide 43–45), hạ tầng phân giải tên miền truyền thống còn tồn tại lỗ hổng nghiêm trọng vì **không có cơ chế xác thực tích hợp** và hoạt động trên giao thức `UDP/53` với trường định danh truy vấn (*Transaction ID*) có độ ngẫu nhiên yếu. Điều này khiến hệ thống dễ bị khai thác bởi **Đầu độc bộ nhớ đệm DNS (*DNS Cache Poisoning / DNS Spoofing*)** — điển hình là tấn công *Kaminsky (2008)*, **Tấn công xen giữa (*Man-in-the-Middle — MITM*)** hoặc đầu độc trình phân giải (*Resolver Poisoning*).

Khi bộ nhớ đệm của máy chủ DNS bị tiêm bản ghi giả mạo (*Bai 7*, Slide 44), ngay cả khi người dùng kiểm tra cẩn thận và truy cập **đúng tên miền hợp lệ**, máy chủ DNS vẫn phân giải sang địa chỉ IP của trang lừa đảo nhằm đánh cắp thông tin đăng nhập hoặc chuyển hướng lưu lượng thư điện tử qua máy chủ độc hại. Để ngăn chặn nguy cơ này ở tầng hạ tầng tên miền, cần triển khai **Phần mở rộng bảo mật DNS (*Domain Name System Security Extensions — DNSSEC*, *Bai 7*, Slide 46–49)** — bổ sung chữ ký số mật mã khóa công khai (thông qua các bản ghi `RRSIG`, `DNSKEY`, `DS`) tạo chuỗi xác thực từ vùng gốc (*Root Zone*) nhằm bảo đảm tính xác thực nguồn gốc và tính toàn vẹn của mọi phản hồi DNS.

---

## 2.4. Tệp đính kèm Độc hại (Malicious Attachments)

Theo *Bài 9 - Malicious Code.pptx* (Slide 31 — *Where does Malicious Code Hide?*), **Email đứng ở vị trí số 1** trong các kênh ẩn náu và phát tán **Mã độc (*Malware*)**, xếp trên cả nội dung web và tải tệp trực tiếp. Mã độc là tập lệnh chạy trên máy tính nạn nhân nhằm thực hiện hành vi theo ý muốn kẻ tấn công (*Bài 9*, Slide 3), thường nhắm tới ba nhóm mục tiêu cốt lõi: đánh cắp dữ liệu (*Data*: bí mật doanh nghiệp IP, thông tin định danh cá nhân PII), trục lợi tài chính (*Money*: thông tin tài chính, tiền mã hóa) hoặc phá hoại hệ thống (*Damage*) (*Bài 9*, Slide 5). Trong chuỗi tấn công *Cyber Kill Chain* (*Bài 9*, Slide 6), email đính kèm đóng vai trò mắt xích trung tâm tại bước **Phát tán (*Delivery*)** để dẫn sang **Khai thác (*Exploitation*)** và **Cài đặt (*Installation*)** trên máy trạm.

### 2.4.1. Các Kỹ thuật Ngụy trang và Giao nhận Tệp đính kèm Độc hại

Để vượt qua cả lớp rà soát kỹ thuật tại Email Gateway lẫn sự cảnh giác của người nhận, kẻ tấn công thường triển khai bốn thủ thuật giao nhận sau:

1. **Virus macro (*Macro Virus* — `.docm`, `.xlsm`, `.pptm`):** Theo định nghĩa từ `RFC 1135` (*Bài 9*, Slide 15–16), virus là đoạn mã không thể tự chạy độc lập mà phải gắn vào vật chủ để kích hoạt qua bốn pha (*Dormant → Propagation → Triggering → Execution*). *Macro Virus* (*Bài 9*, Slide 18) là loại virus nhúng trực tiếp mã kịch bản VBA độc hại vào tài liệu Microsoft Office. Kẻ tấn công thường tạo vỏ bọc là hóa đơn, hợp đồng hoặc bảng lương và hướng dẫn nạn nhân nhấn nút **"Enable Content / Enable Macros"** để kích hoạt mã tải payload từ máy chủ điều khiển.
2. **Phần mở rộng kép (*Double Extension* — `.pdf.exe`, `.docx.scr`):** Kẻ tấn công đặt tên tệp gồm một phần mở rộng tài liệu vô hại đứng trước phần mở rộng thực thi thật (ví dụ `BienLai_ThanhToan_2026.pdf.exe`). Trên hệ điều hành Windows để chế độ mặc định ẩn các phần mở rộng tệp đã biết, giao diện chỉ hiển thị `BienLai_ThanhToan_2026.pdf`, khiến người dùng nhấp đúp và vô tình thực thi trực tiếp mã độc.
3. **Tệp nén đặt mật khẩu (*Password-Protected Archive* — `.zip`, `.rar`, `.7z`, `.iso`):** Kẻ tấn công nén tệp độc hại bằng mật khẩu và ghi trực tiếp mật khẩu giải nén trong nội dung email. Thủ thuật này vô hiệu hóa bộ lọc quét chữ ký tĩnh tại Email Gateway vì máy quét không thể tự động giải mã nội dung bên trong kho lưu trữ để kiểm tra, buộc gánh nặng phát hiện dồn hoàn toàn lên máy trạm khi nạn nhân tự giải nén.
4. **Buôn lậu mã độc qua HTML (*HTML Smuggling* — `.html`, `.htm`):** Thay vì gửi trực tiếp tệp thực thi `.exe` vốn dễ bị tường lửa chặn, kẻ tấn công đính kèm một tệp `.html` tưởng chừng vô hại chứa mã JavaScript và chuỗi dữ liệu mã hóa Base64. Khi nạn nhân mở tệp bằng trình duyệt, JavaScript sẽ tự động giải mã và lắp ghép thành tệp nhị phân độc hại ngay cục bộ trên máy nạn nhân (*HTML5 Blob/Download*), qua mặt hoàn toàn các bộ lọc kiểm tra tệp trên đường truyền mạng.

**Phân tích dẫn chứng thực tế từ [sample_05_malicious_attachment.eml](../labs/email_samples/sample_05_malicious_attachment.eml):**
- **Tầng xác thực và định tuyến:** Thư mạo danh đối tác vận tải `billing@partner-logistics.example`, nhưng `Return-Path` lại thuộc miền lạ `unknown-sender-44.example` truyền qua `SMTP` thuần không TLS. Kết quả xác thực thất bại toàn diện: `spf=fail` (IP `203.0.113.211` không hợp lệ), `dkim=fail` (có header `DKIM-Signature` nhưng sai mã băm thân thư `signature verification failed`) và `dmarc=fail (p=QUARANTINE sp=QUARANTINE dis=QUARANTINE)`.
- **Thủ thuật ngụy trang tinh vi trong nội dung và MIME:** Phần thân email **cố tình giấu đuôi `.exe`**, chỉ nhắc người nhận mở *"tệp biên lai `BienLai_ThanhToan_2026.pdf` hoặc `HoSo_ChuyenKhoan_2026.docm`"*, trong khi phần tiêu đề MIME `Content-Disposition` thực tế lại đính kèm tệp phần mở rộng kép **`BienLai_ThanhToan_2026.pdf.exe`** (placeholder mô phỏng an toàn) song song với tệp hỗ trợ macro **`HoSo_ChuyenKhoan_2026.docm`**, kèm chỉ dẫn trực tiếp yêu cầu bấm **`"Enable Content / Enable Macros"`**.
- **Đối chiếu chống báo động giả (*False Positive*):** Khi so sánh với mẫu sạch [sample_06_legit_hr.eml](../labs/email_samples/sample_06_legit_hr.eml) — cũng có tệp đính kèm `Lich_Kham_Suc_Khoe_2026.pdf` nhưng là đuôi đơn hợp lệ, đạt `SPF/DKIM/DMARC=PASS` (`p=REJECT`), truyền nội bộ qua `TLS 1.3` và không đòi bật Macro — người học sẽ rèn được kỹ năng phân biệt chính xác thay vì nghi ngờ cực đoan mọi tệp đính kèm.

### 2.4.2. Các Nhóm Tải trọng Độc hại (Payload) và Hậu quả

Sau khi tệp đính kèm độc hại được nạn nhân kích hoạt, **Tải trọng độc hại (*Payload*)** cài đặt xuống máy trạm thường thuộc các nhóm chính được phân loại theo cơ chế phát tán và ẩn giấu trong *Bài 9 - Malicious Code.pptx* (Slide 4, 8–13, 23, 25, 27, 29–30):

- **Ngựa thành Troy (*Trojan Horse* — *Bài 9*, Slide 4, 8, 25):** Phần mềm độc hại ngụy trang dưới hình thức thực hiện tác vụ hữu ích bề ngoài (*Visible action: Something useful*, ví dụ hiển thị một hóa đơn giả), nhưng âm thầm thực hiện hành vi nguy hại (*Invisible action: Something malicious*) như mở cửa hậu điều khiển từ xa (*RAT/Backdoor*) hoặc tải thêm các giai đoạn mã độc khác.
- **Phần mềm gián điệp (*Spyware*) và Trình ghi thao tác phím (*Keylogger* — *Bài 9*, Slide 8, 9, 29):** Hoạt động lặng lẽ dưới nền để ghi lại toàn bộ thao tác bàn phím, mật khẩu, nội dung email/chat, ảnh chụp màn hình và thông tin thẻ tín dụng, sau đó định kỳ gửi dữ liệu thu thập được về máy chủ của kẻ tấn công nhằm đánh cắp danh tính hoặc buôn bán trên chợ đen.
- **Mã độc tống tiền (*Ransomware* — *Bài 9*, Slide 10–13):** Mã hóa toàn bộ tài liệu, cơ sở dữ liệu và tệp hệ thống trên máy tính (cùng các ổ đĩa chia sẻ trong mạng LAN) hoặc khóa quyền truy cập hệ điều hành — như các họ điển hình *WannaCry*, *CryptoLocker*, *CryptoWall* — kèm thông báo đếm ngược đòi tiền chuộc bằng tiền mã hóa (Bitcoin), phá hủy trực tiếp **Tính sẵn sàng (*Availability*)** của tổ chức.
- **Máy tính ma trong mạng lưới botnet (*Botnet Zombie* — *Bài 9*, Slide 30):** Biến máy tính nạn nhân thành một nút *zombie* chịu lệnh điều khiển từ xa (*Command & Control — C2*) của kẻ tấn công, phục vụ các chiến dịch tấn công từ chối dịch vụ phân tán (*DDoS*), đào tiền mã hóa trái phép hoặc tiếp tục phát tán email rác/lừa đảo sang các nạn nhân kế tiếp.
- *(Ghi chú bổ sung về khả năng lan truyền và ẩn mình)*: Nhiều chiến dịch hiện đại còn kết hợp cơ chế tự lây lan qua mạng nội bộ của **Sâu máy tính (*Computer Worm* — *Bài 9*, Slide 4, 23)**, kỹ thuật che giấu sự tồn tại ở mức hệ điều hành của **Rootkit** (Slide 4, 27) và khả năng tự biến đổi cấu trúc mã sau mỗi lần lây nhiễm của **Virus đa hình (*Polymorphic Virus* — Slide 19)** để né tránh bộ quét truyền thống.

### 2.4.3. Nguyên lý Phát hiện và Phân tích Tệp đính kèm Độc hại

Theo *Bài 9 - Malicious Code.pptx* (Slide 32–38) và *Bai 7* (Slide 55), hệ thống bảo mật email hiện đại phân biệt rõ mục tiêu **Phát hiện (*Detection*)** hành vi khả nghi với **Phòng ngừa (*Prevention*)** ngăn chặn trước khi mã độc kịp lây nhiễm. Để xử lý hiệu quả cả mã độc đã biết lẫn các biến thể chưa từng xuất hiện (*zero-day*), các giải pháp chống mã độc kết hợp hai phương pháp nền tảng là **Phân tích tĩnh (*Static Analysis*)** và **Phân tích động / Hộp cát (*Dynamic Analysis / Sandboxing*)**, được đối chiếu chi tiết tại **Bảng 2.2**.

| Tiêu chí so sánh | Phân tích tĩnh (*Static Analysis*) | Phân tích động / Hộp cát (*Dynamic Analysis / Sandboxing*) |
| :--- | :--- | :--- |
| **Nguyên lý hoạt động** (*Bài 9*, S33–34, S38) | Kiểm tra mã nguồn, cấu trúc nhị phân hoặc đặc trưng tệp **không cần thực thi** tệp đó. | **Thực thi trực tiếp** tệp đính kèm bên trong máy ảo cô lập (*VM / Sandbox*) để quan sát hành vi thực tế (*Bài 9*, S33, S38; *Bai 7*, S55). |
| **Chỉ số và kỹ thuật kiểm tra** | So khớp mã băm (*hash*) và **Chữ ký (*Signatures*)** với CSDL mã độc (*Bài 9*, S34); kiểm tra chuỗi ký tự khả nghi, phần mở rộng kép, cấu trúc PE Header, luồng mã VBA Macro. | Giám sát tiến trình con (*process spawning*), thao tác tạo/xóa/mã hóa tệp, chỉnh sửa Registry, truy cập bộ nhớ và kết nối mạng tới máy chủ C2 (*Bài 9*, S33). |
| **Ưu điểm nổi bật** | Tốc độ quét cực nhanh, tiêu tốn ít tài nguyên, chặn tức thời các mẫu mã độc đã biết với tỷ lệ báo động giả rất thấp. | Phát hiện hiệu quả mã độc mới (*zero-day*), virus đa hình (*Polymorphic*) và các tệp né chữ ký nhờ quan sát trực tiếp hành vi gây hại (*Heuristics / Behavioral*). |
| **Hạn chế chính** | Dễ bị qua mặt bởi tệp nén đặt mật khẩu, mã bị làm rối (*obfuscation*), *HTML Smuggling* hoặc mã độc biến thể mới chưa có chữ ký. | Tốn tài nguyên tính toán, gây độ trễ nhất định khi chuyển phát email; mã độc tinh vi có thể nhận biết môi trường máy ảo (*anti-VM*) hoặc trì hoãn kích hoạt (*Logic/Time Bomb*, *Bài 9*, S26) để ẩn mình. |
| **Vai trò trong Email Security** | Tuyến lọc đầu tiên (*First-pass scanning*) tại Email Gateway để loại bỏ nhanh lượng lớn thư rác và mã độc phổ biến. | Tuyến phân tích chuyên sâu (*Deep inspection*) cho các tệp khả nghi chưa có chữ ký (`.docm`, `.html`, tệp thực thi mới) trước khi chuyển tới hộp thư người dùng. |

*Bảng 2.2: So sánh phương pháp Phân tích tĩnh (Static Analysis) và Phân tích động / Hộp cát (Dynamic Analysis / Sandboxing) đối với tệp đính kèm email.*

---

## 2.5. Ma trận Dấu hiệu Nhận diện (Red Flags Matrix)

Tổng hợp từ phân tích chuyên sâu bốn nhóm tấn công ở các mục 2.1–2.4, **Bảng 2.3** xây dựng **Ma trận dấu hiệu nhận diện (*Red Flags Matrix*)** đối chiếu các chỉ báo bất thường qua từng lớp kiểm tra (Header/Xác thực, Tên miền/URL, Nội dung/Tệp đính kèm) và ánh xạ trực tiếp tới bộ mẫu mô phỏng an toàn tại `labs/email_samples/`.

| Loại tấn công | Dấu hiệu ở Header / Xác thực | Dấu hiệu ở Tên miền / URL | Dấu hiệu ở Nội dung / Tệp đính kèm | Mẫu minh họa |
| :--- | :--- | :--- | :--- | :---: |
| **Lừa đảo trực tuyến (*Phishing*)** | `SPF=FAIL`, `DKIM=NONE`, `DMARC=FAIL` (`dis=QUARANTINE`); lệch `Return-Path` so với `From`; truyền `SMTP` không TLS. | Văn bản hiển thị (*anchor text*) khác URL đích thật (`href`); tên miền đích kiểu *Combosquatting* và dùng `http://` không mã hóa. | Gắn nhãn `[KHAN CAP]`, đe dọa *"BỊ KHÓA VĨNH VIỄN SAU 02 GIỜ"*, yêu cầu nhập thông tin thẻ và mã OTP. | **Mẫu 02** (`sample_02_phishing_bank.eml`) |
| **Giả mạo địa chỉ người gửi (*Email Spoofing / BEC*)** | `SPF=SOFTFAIL`, `DKIM=NONE`, `DMARC=FAIL` (`p=NONE`); lệch `Return-Path` (`Open Relay`); **đánh tráo `Reply-To`** sang email miễn phí (`freemail.example`). | Địa chỉ gửi thật trong `<...>` thuộc miền ngoài (`external-mail.example`), không phải miền nội bộ công ty; máy chủ chuyển tiếp lạ không TLS. | *Display Name Spoofing* mạo danh lãnh đạo; yêu cầu chuyển khoản gấp số tiền lớn; viện cớ không nghe điện thoại và cấm trao đổi với phòng ban khác. | **Mẫu 03** (`sample_03_spoofing_ceo_bec.eml`) |
| **Giả mạo tên miền (*Lookalike / Domain Spoofing*)** | Có thể **`SPF=PASS`** (cạm bẫy vì hacker tự cấu hình SPF cho miền giả), nhưng `DKIM=NONE`, `DMARC=NONE`; *Display Name* mạo danh thương hiệu lớn. | Tên miền người gửi chứa tiền tố **Punycode `xn--`** (`xn--micrsoft-qbh.example` → `micrоsoft.example`); URL dùng *Subdomain Trick* dài 5 cấp (`account-reset-portal.example`). | Cảnh báo đăng nhập bất thường từ IP nước ngoài, đe dọa mất quyền truy cập hộp thư công ty nhằm dụ nhập mật khẩu. | **Mẫu 04** (`sample_04_lookalike_domain.eml`) |
| **Tệp đính kèm độc hại (*Malicious Attachments*)** | Thất bại toàn bộ **`SPF=FAIL`, `DKIM=FAIL`** (chữ ký giả/sai hash), **`DMARC=FAIL`** (`dis=QUARANTINE`); lệch `Return-Path`; truyền `SMTP` không TLS. | Có thể kèm liên kết tải tệp ngoài hoặc tệp `.html` đính kèm chứa mã *HTML Smuggling*. | Thân thư giấu đuôi `.exe` nhưng `filename` là phần mở rộng kép **`.pdf.exe`**; đính kèm tệp chứa Macro **`.docm`** hoặc tệp nén đặt mật khẩu; dụ bấm **"Enable Content / Enable Macros"**. | **Mẫu 05** (`sample_05_malicious_attachment.eml`) |

*Bảng 2.3: Ma trận tổng hợp dấu hiệu nhận diện (Red Flags Matrix) cho bốn hình thức tấn công qua Email và ánh xạ sang bộ mẫu mô phỏng.*

*(Lưu ý đối chiếu: Hai mẫu hợp lệ **Mẫu 01** `sample_01_legit_it.eml` và **Mẫu 06** `sample_06_legit_hr.eml` đóng vai trò đối chứng an toàn trong bộ mô phỏng với đầy đủ `SPF=PASS`, `DKIM=PASS`, `DMARC=PASS` ở chính sách `p=REJECT`, truyền tải `ESMTPS/TLS 1.3`, liên kết HTTPS nội bộ khớp hoàn toàn và tệp `.pdf` đuôi đơn sạch.)*

---

**Tổng kết chuyển tiếp sang Chương 3:** Qua phân tích bốn hình thức tấn công trên có thể thấy một điểm hội tụ rõ rệt: dù kẻ tấn công vận dụng đòn tâm lý *Social Engineering* hay ngụy trang tên miền, tệp đính kèm tinh vi đến đâu, phần lớn các kịch bản đều trực tiếp khai thác **sự thiếu vắng cơ chế xác thực nguồn gửi và bảo vệ tính toàn vẹn của giao thức SMTP nguyên bản** (*Bai 7*, Slide 52). Để ngăn chặn việc mạo danh tên miền ngay từ cổng tiếp nhận thư và tạo cơ sở kỹ thuật cho máy chủ nhận phân loại chính xác thư hợp lệ với thư giả mạo, **Chương 3** sẽ trình bày chuyên sâu cơ chế hoạt động, cấu trúc bản ghi DNS và vai trò bổ trợ lẫn nhau của bộ ba tiêu chuẩn xác thực **SPF (`RFC 7208`)**, **DKIM (`RFC 6376`)** và **DMARC (`RFC 7489`)**, kèm kết quả khảo sát thực tế trên các tên miền phổ biến.
