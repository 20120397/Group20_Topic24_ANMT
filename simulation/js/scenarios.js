/**
 * Bộ 6 kịch bản mô phỏng đồng bộ 1-1 với labs/email_samples/*.eml
 * Thiết kế kịch bản & mẫu .eml: Thành viên 2 — Nguyễn Gia Huy (23120273)
 * Tích hợp Web App & kiểm thử: Thành viên 3 — Nguyễn Lê Hữu Điền (23120233)
 */
const EMAIL_SCENARIOS = [
  {
    id: "sample_01",
    filename: "sample_01_legit_it.eml",
    shortLabel: "Mẫu 1: IT Bảo trì",
    senderName: "Phong Ky Thuat IT - CorpVN",
    senderEmail: "it-support@corp-vn.example",
    to: "staff@corp-vn.example",
    date: "Wed, 25 Nov 2026 08:15:00 +0700",
    subject: "[Thong bao] Bao tri he thong mang noi bo cuoi tuan (28/11)",
    returnPath: "it-support@corp-vn.example",
    replyTo: "",
    auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
    verdict: "safe",
    attackType: "Email hợp lệ (Legitimate)",
    expectedFlags: [],
    attachments: [],
    bodyHtml: `
      <p>Kính gửi Anh/Chị,</p>
      <p>Phòng Kỹ thuật IT xin thông báo kế hoạch bảo trì định kỳ hệ thống máy chủ và VPN nội bộ từ <strong>22:00 Thứ Bảy (28/11/2026)</strong> đến <strong>02:00 Chủ Nhật (29/11/2026)</strong>.</p>
      <p>Trong thời gian trên, truy cập hệ thống ngoài giờ làm việc có thể gián đoạn tạm thời. Nhân viên không cần cung cấp mật khẩu hay mã xác thực cho bất kỳ cá nhân nào.</p>
      <p>Chi tiết trạng thái dịch vụ được cập nhật tại cổng nội bộ: <a href="#" data-url="https://status.corp-vn.example/maintenance">https://status.corp-vn.example/maintenance</a></p>
      <p>Trân trọng,<br>Phòng Kỹ thuật IT — CorpVN</p>
    `,
    explanation: "Đây là email nội bộ hợp lệ: đạt đầy đủ SPF=PASS, DKIM=PASS, DMARC=PASS (p=REJECT); tên miền From, Return-Path và DKIM d= đều đồng nhất (corp-vn.example); truyền qua 2 hop nội bộ mã hóa TLS 1.3; liên kết HTTPS khớp hoàn toàn và không đòi thông tin nhạy cảm.",
    flagsDetail: [
      "Vượt qua đầy đủ bộ ba xác thực: SPF=PASS, DKIM=PASS (d=corp-vn.example; s=mail2026) và DMARC=PASS (p=REJECT sp=REJECT).",
      "Khớp định danh (Identifier Alignment) hoàn toàn giữa Header From, Return-Path và DKIM d=; đường truyền 2 hop nội bộ ESMTPS/ESMTPSA mã hóa TLS 1.3.",
      "URL hiển thị khớp 100% URL đích (https://status.corp-vn.example/maintenance) và ngữ điệu chuyên nghiệp, không tạo áp lực hay đòi mật khẩu."
    ],
    rawEml: `Return-Path: <it-support@corp-vn.example>
Delivered-To: staff@corp-vn.example
Received: from mail.corp-vn.example (mail.corp-vn.example [198.51.100.10])
\tby mx.corp-vn.example with ESMTPS id 20261125-001A
\t(version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384)
\tfor <staff@corp-vn.example>; Wed, 25 Nov 2026 08:15:02 +0700
Received: from mail-sub.corp-vn.example (mail-sub.corp-vn.example [198.51.100.12])
\tby mail.corp-vn.example with ESMTPSA id 20261125-001S
\t(version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384);
\tWed, 25 Nov 2026 08:15:00 +0700
Received-SPF: pass (mx.corp-vn.example: domain of it-support@corp-vn.example designates 198.51.100.10 as permitted sender)
\tclient-ip=198.51.100.10; envelope-from=it-support@corp-vn.example; helo=mail.corp-vn.example;
Authentication-Results: mx.corp-vn.example;
\tspf=pass (mx.corp-vn.example: domain of it-support@corp-vn.example designates 198.51.100.10 as permitted sender) smtp.mailfrom=it-support@corp-vn.example;
\tdkim=pass header.d=corp-vn.example header.s=mail2026 header.b=MIIBIjAN;
\tdmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=corp-vn.example
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=corp-vn.example;
\ts=mail2026; t=1795569300;
\th=from:to:subject:date:message-id:mime-version:content-type;
\tbh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
\tb=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7x9kLm2Sample01==
From: "Phong Ky Thuat IT - CorpVN" <it-support@corp-vn.example>
To: "Toan the Nhan vien" <staff@corp-vn.example>
Subject: [Thong bao] Bao tri he thong mang noi bo cuoi tuan (28/11)
Date: Wed, 25 Nov 2026 08:15:00 +0700
Message-ID: <20261125081500.001@corp-vn.example>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: 8bit

<!DOCTYPE html>
<html lang="vi">
<body>
  <p>Kính gửi Anh/Chị,</p>
  <p>Phòng Kỹ thuật IT xin thông báo kế hoạch bảo trì định kỳ hệ thống máy chủ và VPN nội bộ từ <strong>22:00 Thứ Bảy (28/11/2026)</strong> đến <strong>02:00 Chủ Nhật (29/11/2026)</strong>.</p>
  <p>Trong thời gian trên, truy cập hệ thống ngoài giờ làm việc có thể gián đoạn tạm thời. Nhân viên không cần cung cấp mật khẩu hay mã xác thực cho bất kỳ cá nhân nào.</p>
  <p>Chi tiết trạng thái dịch vụ được cập nhật tại cổng nội bộ: <a href="https://status.corp-vn.example/maintenance">https://status.corp-vn.example/maintenance</a></p>
  <p>Trân trọng,<br>Phòng Kỹ thuật IT — CorpVN</p>
</body>
</html>`
  },
  {
    id: "sample_02",
    filename: "sample_02_phishing_bank.eml",
    shortLabel: "Mẫu 2: Phishing Bank",
    senderName: "VCB Digibank Security",
    senderEmail: "no-reply@vcb-bank.example",
    to: "khachhang@corp-vn.example",
    date: "Wed, 25 Nov 2026 08:42:10 +0700",
    subject: "[KHAN CAP] Tai khoan cua ban se bi KHOA sau 02 gio!",
    returnPath: "bounce@promo-mailer-99.example",
    replyTo: "",
    auth: { spf: "fail", dkim: "none", dmarc: "fail" },
    verdict: "phishing",
    attackType: "Phishing (Giả mạo Ngân hàng)",
    expectedFlags: ["auth_fail", "mismatch", "link", "social"],
    attachments: [],
    bodyHtml: `
      <p>Kính gửi Quý khách hàng,</p>
      <p>Hệ thống phát hiện hoạt động đăng nhập bất thường từ thiết bị lạ. Tài khoản VCB Digibank của Quý khách sẽ <strong>BỊ KHÓA VĨNH VIỄN SAU 02 GIỜ</strong> nếu không xác minh ngay lập tức.</p>
      <p>Vui lòng truy cập liên kết dưới đây để xác nhận thông tin thẻ và mã OTP:</p>
      <p><a href="#" data-url="http://vcb-security-check.login-verify.example/auth">https://vcb-bank.example/verify</a></p>
      <p>Bộ phận Bảo mật Ngân hàng</p>
    `,
    explanation: "Đây là email Phishing giả mạo ngân hàng: tạo tâm lý hoảng loạn khẩn cấp, ngụy trang liên kết dẫn tới tên miền lạ không mã hóa HTTP, lệch hoàn toàn Return-Path và thất bại xác thực SPF/DMARC (p=QUARANTINE).",
    flagsDetail: [
      "Thất bại xác thực: SPF=FAIL (IP 203.0.113.88 không hợp lệ cho promo-mailer-99.example), DKIM=NONE và DMARC=FAIL (p=QUARANTINE dis=QUARANTINE).",
      "Lệch Envelope From và Header From: From hiển thị @vcb-bank.example nhưng Return-Path & Message-ID thuộc @promo-mailer-99.example, truyền qua SMTP thuần không TLS.",
      "Liên kết ngụy trang (Anchor vs href mismatch): chữ hiển thị là https://vcb-bank.example/verify nhưng URL đích thật là http://vcb-security-check.login-verify.example/auth (HTTP không mã hóa, miền gốc lạ login-verify.example).",
      "Đòn tâm lý Social Engineering: tiêu đề [KHAN CAP], đe dọa \"BỊ KHÓA VĨNH VIỄN SAU 02 GIỜ\" và yêu cầu nhập thông tin thẻ + mã OTP."
    ],
    rawEml: `Return-Path: <bounce@promo-mailer-99.example>
Delivered-To: khachhang@corp-vn.example
Received: from host88.promo-mailer-99.example ([203.0.113.88])
\tby mx.corp-vn.example with SMTP id 20261125-002B
\tfor <khachhang@corp-vn.example>; Wed, 25 Nov 2026 08:42:10 +0700
Received-SPF: fail (mx.corp-vn.example: domain of bounce@promo-mailer-99.example does not designate 203.0.113.88 as permitted sender)
\tclient-ip=203.0.113.88; envelope-from=bounce@promo-mailer-99.example; helo=host88.promo-mailer-99.example;
Authentication-Results: mx.corp-vn.example;
\tspf=fail (mx.corp-vn.example: domain of bounce@promo-mailer-99.example does not designate 203.0.113.88 as permitted sender) smtp.mailfrom=bounce@promo-mailer-99.example;
\tdkim=none (message not signed);
\tdmarc=fail (p=QUARANTINE sp=QUARANTINE dis=QUARANTINE; spf/dkim alignment failed) header.from=vcb-bank.example
From: "VCB Digibank Security" <no-reply@vcb-bank.example>
To: <khachhang@corp-vn.example>
Subject: [KHAN CAP] Tai khoan cua ban se bi KHOA sau 02 gio!
Date: Wed, 25 Nov 2026 08:42:10 +0700
Message-ID: <20261125084210.002@promo-mailer-99.example>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: 8bit

<!DOCTYPE html>
<html lang="vi">
<body>
  <p>Kính gửi Quý khách hàng,</p>
  <p>Hệ thống phát hiện hoạt động đăng nhập bất thường từ thiết bị lạ. Tài khoản VCB Digibank của Quý khách sẽ <strong>BỊ KHÓA VĨNH VIỄN SAU 02 GIỜ</strong> nếu không xác minh ngay lập tức.</p>
  <p>Vui lòng truy cập liên kết dưới đây để xác nhận thông tin thẻ và mã OTP:</p>
  <p><a href="http://vcb-security-check.login-verify.example/auth">https://vcb-bank.example/verify</a></p>
  <p>Bộ phận Bảo mật Ngân hàng</p>
</body>
</html>`
  },
  {
    id: "sample_03",
    filename: "sample_03_spoofing_ceo_bec.eml",
    shortLabel: "Mẫu 3: BEC Spoofing",
    senderName: "Giam doc Tran Minh Quan (CEO)",
    senderEmail: "ceo.corpvn@external-mail.example",
    to: "ketoan@corp-vn.example",
    date: "Wed, 25 Nov 2026 09:05:00 +0700",
    subject: "Khan: Xu ly thanh toan hop dong mat trong sang nay",
    returnPath: "mailer@relay-open88.example",
    replyTo: "tranminhquan.private2026@freemail.example",
    auth: { spf: "softfail", dkim: "none", dmarc: "fail" },
    verdict: "phishing",
    attackType: "Email Spoofing / BEC (Display Name + Reply-To)",
    expectedFlags: ["auth_fail", "mismatch", "social"],
    attachments: [],
    bodyHtml: `
      <p>Chào em,</p>
      <p>Anh đang họp gấp với đối tác nước ngoài nên không tiện nghe điện thoại. Em xử lý chuyển khoản gấp số tiền <strong>245.000.000 VND</strong> cho đối tác tư vấn theo số tài khoản mới anh vừa duyệt trong sáng nay (trước 11:00 trưa nay).</p>
      <p>Đây là thương vụ mua bán bảo mật, em <strong>tuyệt đối không trao đổi với các phòng ban khác</strong> và chỉ bấm Reply trực tiếp vào email này để anh gửi thông tin số tài khoản nhận.</p>
      <p>Trần Minh Quân<br>Tổng Giám Đốc</p>
    `,
    explanation: "Đây là tấn công BEC kết hợp Display Name Spoofing và Reply-To Spoofing: vì tên miền công ty corp-vn.example đã khóa DMARC p=REJECT, kẻ tấn công dùng địa chỉ ngoài ceo.corpvn@external-mail.example (p=NONE) gắn tên hiển thị CEO, gửi qua Open Relay và trỏ Reply-To về hộp thư cá nhân freemail.example để chiếm quyền trao đổi với kế toán.",
    flagsDetail: [
      "Giả mạo tên hiển thị (Display Name Spoofing): tên hiển thị ghi \"Giam doc Tran Minh Quan (CEO)\" nhưng địa chỉ gửi thật là ceo.corpvn@external-mail.example (không phải miền nội bộ @corp-vn.example).",
      "Lệch Return-Path & xác thực thất bại: đi qua máy chủ relay-open88.example bằng SMTP không TLS, dẫn tới SPF=SOFTFAIL, DKIM=NONE và DMARC=FAIL (p=NONE; lệch relay-open88.example vs external-mail.example).",
      "Đánh tráo Reply-To: trỏ về hộp thư miễn phí tranminhquan.private2026@freemail.example nhằm hứng toàn bộ phản hồi của phòng Kế toán.",
      "Đòn tâm lý BEC (Quyền lực + Khẩn cấp + Cô lập): thúc chuyển gấp 245.000.000 VND trước 11:00, viện cớ họp không nghe điện thoại và cấm trao đổi với phòng ban khác để chặn xác minh đa kênh."
    ],
    rawEml: `Return-Path: <mailer@relay-open88.example>
Delivered-To: ketoan@corp-vn.example
Received: from relay-open88.example ([203.0.113.154])
\tby mx.corp-vn.example with SMTP id 20261125-003C
\tfor <ketoan@corp-vn.example>; Wed, 25 Nov 2026 09:05:00 +0700
Received-SPF: softfail (mx.corp-vn.example: transitioning domain of mailer@relay-open88.example does not designate 203.0.113.154 as permitted sender)
\tclient-ip=203.0.113.154; envelope-from=mailer@relay-open88.example; helo=relay-open88.example;
Authentication-Results: mx.corp-vn.example;
\tspf=softfail (mx.corp-vn.example: transitioning domain of mailer@relay-open88.example does not designate 203.0.113.154 as permitted sender) smtp.mailfrom=mailer@relay-open88.example;
\tdkim=none (message not signed);
\tdmarc=fail (p=NONE sp=NONE dis=NONE; spf alignment failed: smtp.mailfrom=relay-open88.example != header.from=external-mail.example) header.from=external-mail.example
From: "Giam doc Tran Minh Quan (CEO)" <ceo.corpvn@external-mail.example>
Reply-To: "Tran Minh Quan" <tranminhquan.private2026@freemail.example>
To: "Phong Ke Toan" <ketoan@corp-vn.example>
Subject: Khan: Xu ly thanh toan hop dong mat trong sang nay
Date: Wed, 25 Nov 2026 09:05:00 +0700
Message-ID: <20261125090500.003@relay-open88.example>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit

Chào em,

Anh đang họp gấp với đối tác nước ngoài nên không tiện nghe điện thoại. Em xử lý chuyển khoản gấp số tiền 245.000.000 VND cho đối tác tư vấn theo số tài khoản mới anh vừa duyệt trong sáng nay (trước 11:00 trưa nay).

Đây là thương vụ mua bán bảo mật, em tuyệt đối không trao đổi với các phòng ban khác và chỉ bấm Reply trực tiếp vào email này để anh gửi thông tin số tài khoản nhận.

Trần Minh Quân
Tổng Giám Đốc`
  },
  {
    id: "sample_04",
    filename: "sample_04_lookalike_domain.eml",
    shortLabel: "Mẫu 4: Punycode / Domain",
    senderName: "Microsoft 365 Account Team",
    senderEmail: "security@xn--micrsoft-qbh.example",
    to: "user@corp-vn.example",
    date: "Wed, 25 Nov 2026 09:20:00 +0700",
    subject: "Canh bao dang nhap bat thuong - Yeu cau xac minh mat khau",
    returnPath: "bounce@xn--micrsoft-qbh.example",
    replyTo: "",
    auth: { spf: "pass", dkim: "none", dmarc: "none" },
    verdict: "phishing",
    attackType: "Giả mạo tên miền (IDN Punycode & Subdomain Trick)",
    expectedFlags: ["domain", "link", "auth_fail"],
    attachments: [],
    bodyHtml: `
      <p>Xin chào,</p>
      <p>Hệ thống Microsoft 365 ghi nhận một phiên đăng nhập mới từ địa chỉ IP nước ngoài. Nếu đây không phải là bạn, hãy đổi mật khẩu ngay tại cổng xác minh:</p>
      <p><a href="#" data-url="https://login.microsoft.example.account-reset-portal.example/oauth">https://login.microsoft.example/verify</a></p>
      <p>Lưu ý: Bỏ qua email này có thể dẫn đến mất quyền truy cập hộp thư công ty.</p>
      <p>Microsoft Security Team</p>
    `,
    explanation: "Tình huống bẫy kỹ thuật tinh vi: dù SPF=PASS và có TLS 1.2 (vì kẻ tấn công tự cấu hình SPF trên miền giả), địa chỉ gửi dùng chuỗi Punycode RFC 3492 xn--micrsoft-qbh.example (hiển thị Unicode là micrоsoft.example với chữ 'о' bảng Cyrillic U+043E) kết hợp Subdomain Trick trỏ tới miền thật account-reset-portal.example.",
    flagsDetail: [
      "Tên miền IDN Punycode (Homograph Attack): xn--micrsoft-qbh.example giải mã thành micrоsoft.example, thay chữ 'o' Latin (U+006F) bằng chữ 'о' Cyrillic (U+043E).",
      "Subdomain Trick & liên kết ngụy trang: chữ hiển thị là https://login.microsoft.example/verify nhưng URL đích thật là https://login.microsoft.example.account-reset-portal.example/oauth (miền gốc thực sự là account-reset-portal.example).",
      "Cạm bẫy SPF=PASS nhưng thiếu bảo chứng danh tính thực: kẻ tấn công tự cấu hình SPF cho miền giả nên SPF=PASS, nhưng DKIM=NONE và DMARC=NONE — chứng minh SPF=PASS đơn lẻ không đảm bảo email an toàn."
    ],
    rawEml: `Return-Path: <bounce@xn--micrsoft-qbh.example>
Delivered-To: user@corp-vn.example
Received: from mail.xn--micrsoft-qbh.example ([198.51.100.77])
\tby mx.corp-vn.example with ESMTPS id 20261125-004D
\t(version=TLS1_2 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
\tfor <user@corp-vn.example>; Wed, 25 Nov 2026 09:20:00 +0700
Received-SPF: pass (mx.corp-vn.example: domain of bounce@xn--micrsoft-qbh.example designates 198.51.100.77 as permitted sender)
\tclient-ip=198.51.100.77; envelope-from=bounce@xn--micrsoft-qbh.example; helo=mail.xn--micrsoft-qbh.example;
Authentication-Results: mx.corp-vn.example;
\tspf=pass (mx.corp-vn.example: domain of bounce@xn--micrsoft-qbh.example designates 198.51.100.77 as permitted sender) smtp.mailfrom=bounce@xn--micrsoft-qbh.example;
\tdkim=none (message not signed);
\tdmarc=none (no DMARC policy published for xn--micrsoft-qbh.example) header.from=xn--micrsoft-qbh.example
From: "Microsoft 365 Account Team" <security@xn--micrsoft-qbh.example>
To: <user@corp-vn.example>
Subject: Canh bao dang nhap bat thuong - Yeu cau xac minh mat khau
Date: Wed, 25 Nov 2026 09:20:00 +0700
Message-ID: <20261125092000.004@xn--micrsoft-qbh.example>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: 8bit

<!DOCTYPE html>
<html lang="vi">
<body>
  <p>Xin chào,</p>
  <p>Hệ thống Microsoft 365 ghi nhận một phiên đăng nhập mới từ địa chỉ IP nước ngoài. Nếu đây không phải là bạn, hãy đổi mật khẩu ngay tại cổng xác minh:</p>
  <p><a href="https://login.microsoft.example.account-reset-portal.example/oauth">https://login.microsoft.example/verify</a></p>
  <p>Lưu ý: Bỏ qua email này có thể dẫn đến mất quyền truy cập hộp thư công ty.</p>
  <p>Microsoft Security Team</p>
</body>
</html>`
  },
  {
    id: "sample_05",
    filename: "sample_05_malicious_attachment.eml",
    shortLabel: "Mẫu 5: Tệp độc hại",
    senderName: "Bo phan Thanh toan - Doi tac Van tai",
    senderEmail: "billing@partner-logistics.example",
    to: "ketoan@corp-vn.example",
    date: "Wed, 25 Nov 2026 09:35:00 +0700",
    subject: "Gui lai Bien lai thanh toan va Hop dong bo sung T11/2026",
    returnPath: "bounce@unknown-sender-44.example",
    replyTo: "",
    auth: { spf: "fail", dkim: "fail", dmarc: "fail" },
    verdict: "phishing",
    attackType: "Phát tán Tệp đính kèm Độc hại (Double Extension & Macro)",
    expectedFlags: ["auth_fail", "mismatch", "attachment"],
    attachments: [
      { name: "BienLai_ThanhToan_2026.pdf.exe", size: "1.4 MB (Mô phỏng an toàn)", risk: "Nguy hiểm: Đuôi kép .pdf.exe" },
      { name: "HoSo_ChuyenKhoan_2026.docm", size: "420 KB (Mô phỏng an toàn)", risk: "Nguy hiểm: Word chứa Macro .docm" }
    ],
    bodyHtml: `
      <p>Kính gửi Phòng Kế toán,</p>
      <p>Chúng tôi xin gửi kèm biên lai thanh toán đợt 2 và file hợp đồng bổ sung tháng 11/2026.</p>
      <p>Vui lòng mở tệp biên lai <code>BienLai_ThanhToan_2026.pdf</code> hoặc <code>HoSo_ChuyenKhoan_2026.docm</code> đính kèm và chọn <strong>"Enable Content / Enable Macros"</strong> khi được hỏi để xem đầy đủ bảng kê chi tiết.</p>
      <p>Trân trọng,<br>Bộ phận Thanh toán</p>
    `,
    explanation: "Email phát tán mã độc qua tệp đính kèm: thất bại toàn bộ SPF/DKIM/DMARC (chữ ký DKIM-Signature giả mạo/sai mã băm, dis=QUARANTINE), lệch Return-Path (unknown-sender-44.example), phần lời nhắn cố ý ẩn đuôi .exe nhưng tên tệp đính kèm thực là BienLai_ThanhToan_2026.pdf.exe kết hợp file Word .docm dụ bật Enable Macros.",
    flagsDetail: [
      "Thất bại toàn bộ 3 lớp xác thực: SPF=FAIL, DKIM=FAIL (chữ ký giả mạo/sai body hash), DMARC=FAIL (p=QUARANTINE dis=QUARANTINE).",
      "Lệch Return-Path (unknown-sender-44.example vs partner-logistics.example) và truyền tải qua SMTP thuần không TLS.",
      "Kỹ thuật Double Extension: nội dung thư đánh lạc hướng khi chỉ nhắc BienLai_ThanhToan_2026.pdf, nhưng tên tệp thực tế là BienLai_ThanhToan_2026.pdf.exe (tệp thực thi).",
      "Tệp Word chứa Macro (HoSo_ChuyenKhoan_2026.docm) kèm hướng dẫn trực tiếp người dùng bấm \"Enable Content / Enable Macros\" để kích hoạt mã độc."
    ],
    rawEml: `Return-Path: <bounce@unknown-sender-44.example>
Delivered-To: ketoan@corp-vn.example
Received: from unknown-sender-44.example ([203.0.113.211])
\tby mx.corp-vn.example with SMTP id 20261125-005E
\tfor <ketoan@corp-vn.example>; Wed, 25 Nov 2026 09:35:00 +0700
Received-SPF: fail (mx.corp-vn.example: domain of bounce@unknown-sender-44.example does not designate 203.0.113.211 as permitted sender)
\tclient-ip=203.0.113.211; envelope-from=bounce@unknown-sender-44.example; helo=unknown-sender-44.example;
Authentication-Results: mx.corp-vn.example;
\tspf=fail (mx.corp-vn.example: domain of bounce@unknown-sender-44.example does not designate 203.0.113.211 as permitted sender) smtp.mailfrom=bounce@unknown-sender-44.example;
\tdkim=fail reason="signature verification failed" header.d=partner-logistics.example header.s=mail2025;
\tdmarc=fail (p=QUARANTINE sp=QUARANTINE dis=QUARANTINE) header.from=partner-logistics.example
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=partner-logistics.example;
\ts=mail2025; t=1795574100;
\th=from:to:subject:date:message-id;
\tbh=INVALID_BODY_HASH_SIMULATED_FOR_TRAINING_SAMPLE_05=;
\tb=SIMUL05E_FORGED_OR_TAMPERED_DKIM_SIGNATURE_SAMPLE_05
From: "Bo phan Thanh toan - Doi tac Van tai" <billing@partner-logistics.example>
To: <ketoan@corp-vn.example>
Subject: Gui lai Bien lai thanh toan va Hop dong bo sung T11/2026
Date: Wed, 25 Nov 2026 09:35:00 +0700
Message-ID: <20261125093500.005@unknown-sender-44.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_Sample05_Boundary"

------=_Part_Sample05_Boundary
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit

Kính gửi Phòng Kế toán,

Chúng tôi xin gửi kèm biên lai thanh toán đợt 2 và file hợp đồng bổ sung tháng 11/2026.
Vui lòng mở tệp biên lai BienLai_ThanhToan_2026.pdf hoặc HoSo_ChuyenKhoan_2026.docm đính kèm và chọn "Enable Content / Enable Macros" khi được hỏi để xem đầy đủ bảng kê chi tiết.

Trân trọng,
Bộ phận Thanh toán
------=_Part_Sample05_Boundary
Content-Type: text/plain; charset="UTF-8"; name="BienLai_ThanhToan_2026.pdf.exe"
Content-Transfer-Encoding: 8bit
Content-Disposition: attachment; filename="BienLai_ThanhToan_2026.pdf.exe"

[Tệp văn bản mô phỏng phục vụ đồ án - Không chứa mã thực thi]
Đây là tệp văn bản mô phỏng an toàn cho đề tài bảo mật email (Đề tài 24).
Tuyệt đối không chứa mã thực thi (.exe) hay payload độc hại thật.
Mục đích: minh họa kỹ thuật giả mạo phần mở rộng kép (Double Extension).
------=_Part_Sample05_Boundary
Content-Type: text/plain; charset="UTF-8"; name="HoSo_ChuyenKhoan_2026.docm"
Content-Transfer-Encoding: 8bit
Content-Disposition: attachment; filename="HoSo_ChuyenKhoan_2026.docm"

[Tệp văn bản mô phỏng phục vụ đồ án - Không chứa VBA macro]
Đây là tệp văn bản mô phỏng an toàn cho đề tài bảo mật email (Đề tài 24).
Tuyệt đối không chứa mã VBA Macro hay mã độc thật.
Mục đích: minh họa kỹ thuật phát tán Macro Virus qua tài liệu Office (.docm).
------=_Part_Sample05_Boundary--`
  },
  {
    id: "sample_06",
    filename: "sample_06_legit_hr.eml",
    shortLabel: "Mẫu 6: Nhân sự (Sạch)",
    senderName: "Phong Nhan Su - CorpVN",
    senderEmail: "hr@corp-vn.example",
    to: "staff@corp-vn.example",
    date: "Wed, 25 Nov 2026 09:50:00 +0700",
    subject: "Lich kham suc khoe dinh ky nam 2026 cho nhan vien",
    returnPath: "hr@corp-vn.example",
    replyTo: "",
    auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
    verdict: "safe",
    attackType: "Email hợp lệ (Legitimate)",
    expectedFlags: [],
    attachments: [
      { name: "Lich_Kham_Suc_Khoe_2026.pdf", size: "310 KB (Mô phỏng an toàn)", risk: "Hợp lệ (.pdf)" }
    ],
    bodyHtml: `
      <p>Chào Anh/Chị,</p>
      <p>Phòng Nhân sự gửi kèm kế hoạch khám sức khỏe định kỳ năm 2026 (thời gian từ 05/12 đến 12/12/2026).</p>
      <p>Anh/Chị vui lòng xem chi tiết khung giờ theo phòng ban trong file PDF đính kèm và đăng ký ca khám trên cổng nội bộ: <a href="#" data-url="https://portal.corp-vn.example/hr/health-check">https://portal.corp-vn.example/hr/health-check</a></p>
      <p>Trân trọng,<br>Phòng Nhân sự — CorpVN</p>
    `,
    explanation: "Đây là email nội bộ hợp lệ (giúp kiểm tra False Positive): đạt đầy đủ SPF/DKIM/DMARC (p=REJECT), đi qua 2 hop nội bộ TLS 1.3 (hr-portal → mail → mx), tệp đính kèm PDF đơn thuần (Lich_Kham_Suc_Khoe_2026.pdf) không yêu cầu bật Macro và liên kết dẫn đúng tới cổng nội bộ portal.corp-vn.example.",
    flagsDetail: [
      "SPF=PASS, DKIM=PASS (d=corp-vn.example; s=mail2026) và DMARC=PASS (p=REJECT sp=REJECT) với tên miền đồng nhất corp-vn.example.",
      "Đường truyền 2 hop nội bộ minh bạch (hr-portal.corp-vn.example → mail.corp-vn.example → mx.corp-vn.example) sử dụng ESMTPS/ESMTPSA mã hóa TLS 1.3.",
      "Tệp đính kèm là PDF đơn chuẩn (Lich_Kham_Suc_Khoe_2026.pdf), không dùng đuôi kép, không chứa Macro và URL đích khớp 100% (https://portal.corp-vn.example/hr/health-check)."
    ],
    rawEml: `Return-Path: <hr@corp-vn.example>
Delivered-To: staff@corp-vn.example
Received: from mail.corp-vn.example (mail.corp-vn.example [198.51.100.10])
\tby mx.corp-vn.example with ESMTPS id 20261125-006F
\t(version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384)
\tfor <staff@corp-vn.example>; Wed, 25 Nov 2026 09:50:02 +0700
Received: from hr-portal.corp-vn.example (hr-portal.corp-vn.example [198.51.100.15])
\tby mail.corp-vn.example with ESMTPSA id 20261125-006S
\t(version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384);
\tWed, 25 Nov 2026 09:50:00 +0700
Received-SPF: pass (mx.corp-vn.example: domain of hr@corp-vn.example designates 198.51.100.10 as permitted sender)
\tclient-ip=198.51.100.10; envelope-from=hr@corp-vn.example; helo=mail.corp-vn.example;
Authentication-Results: mx.corp-vn.example;
\tspf=pass (mx.corp-vn.example: domain of hr@corp-vn.example designates 198.51.100.10 as permitted sender) smtp.mailfrom=hr@corp-vn.example;
\tdkim=pass header.d=corp-vn.example header.s=mail2026 header.b=MIIBIjAN;
\tdmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=corp-vn.example
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=corp-vn.example;
\ts=mail2026; t=1795575000;
\th=from:to:subject:date:message-id:mime-version:content-type;
\tbh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
\tb=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9p4tQw8Sample06==
From: "Phong Nhan Su - CorpVN" <hr@corp-vn.example>
To: "Toan the Nhan vien" <staff@corp-vn.example>
Subject: Lich kham suc khoe dinh ky nam 2026 cho nhan vien
Date: Wed, 25 Nov 2026 09:50:00 +0700
Message-ID: <20261125095000.006@corp-vn.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_Sample06_Boundary"

------=_Part_Sample06_Boundary
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: 8bit

<!DOCTYPE html>
<html lang="vi">
<body>
  <p>Chào Anh/Chị,</p>
  <p>Phòng Nhân sự gửi kèm kế hoạch khám sức khỏe định kỳ năm 2026 (thời gian từ 05/12 đến 12/12/2026).</p>
  <p>Anh/Chị vui lòng xem chi tiết khung giờ theo phòng ban trong file PDF đính kèm và đăng ký ca khám trên cổng nội bộ: <a href="https://portal.corp-vn.example/hr/health-check">https://portal.corp-vn.example/hr/health-check</a></p>
  <p>Trân trọng,<br>Phòng Nhân sự — CorpVN</p>
</body>
</html>
------=_Part_Sample06_Boundary
Content-Type: text/plain; charset="UTF-8"; name="Lich_Kham_Suc_Khoe_2026.pdf"
Content-Transfer-Encoding: 8bit
Content-Disposition: attachment; filename="Lich_Kham_Suc_Khoe_2026.pdf"

[Tệp văn bản mô phỏng phục vụ đồ án môn học - Nội dung PDF lịch khám sức khỏe]
Nội dung mô phỏng lịch khám sức khỏe định kỳ năm 2026 của CorpVN.
Tệp văn bản vô hại phục vụ mô phỏng an toàn (Đề tài 24).
------=_Part_Sample06_Boundary--`
  }
];

if (typeof window !== "undefined") {
  window.EMAIL_SCENARIOS = EMAIL_SCENARIOS;
}
if (typeof module !== "undefined" && module.exports) {
  module.exports = { EMAIL_SCENARIOS };
}
