/**
 * Bộ 6 kịch bản mô phỏng đồng bộ 1-1 với labs/email_samples/*.eml (TV2 thiết kế, TV3 tích hợp).
 * TODO (TV3 + TV2): Có thể bổ sung thêm kịch bản thứ 7, 8 (Clone Phishing / HTML Smuggling) vào cuối mảng EMAIL_SCENARIOS.
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
    explanation: "Đây là email hợp lệ: SPF=PASS, DKIM=PASS, DMARC=PASS; tên miền From khớp Return-Path (corp-vn.example); liên kết dùng HTTPS trỏ đúng cổng nội bộ và không yêu cầu thông tin nhạy cảm.",
    flagsDetail: [
      "SPF, DKIM và DMARC đều đạt PASS.",
      "From khớp hoàn toàn Return-Path và tên miền ký DKIM (d=corp-vn.example).",
      "URL hiển thị khớp chính xác URL đích (status.corp-vn.example)."
    ],
    rawEml: `Return-Path: <it-support@corp-vn.example>
Received: from mail.corp-vn.example (mail.corp-vn.example [198.51.100.10])
\tby mx.corp-vn.example with ESMTPS (TLSv1.3)
\tfor <staff@corp-vn.example>; Wed, 25 Nov 2026 08:15:00 +0700
Authentication-Results: mx.corp-vn.example;
\tspf=pass (sender IP is 198.51.100.10) smtp.mailfrom=corp-vn.example;
\tdkim=pass header.d=corp-vn.example header.s=mail2026;
\tdmarc=pass action=none header.from=corp-vn.example
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=corp-vn.example;
\ts=mail2026; h=from:to:subject:date:message-id;
\tbh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
\tb=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7x9kLm2Sample01==
From: "Phong Ky Thuat IT - CorpVN" <it-support@corp-vn.example>
To: "Toan the Nhan vien" <staff@corp-vn.example>
Subject: [Thong bao] Bao tri he thong mang noi bo cuoi tuan (28/11)
Date: Wed, 25 Nov 2026 08:15:00 +0700
Content-Type: text/html; charset=UTF-8

<p>Chi tiet tai: <a href="https://status.corp-vn.example/maintenance">https://status.corp-vn.example/maintenance</a></p>`
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
      <p>Hệ thống phát hiện hoạt động đăng nhập bất thường từ thiết bị lạ. Tài khoản VCB Digibank của Quý khách sẽ bị <strong>TẠM KHÓA VĨNH VIỄN SAU 02 GIỜ</strong> nếu không xác minh ngay lập tức.</p>
      <p>Vui lòng truy cập liên kết dưới đây để xác nhận thông tin thẻ và mã OTP:</p>
      <p><a href="#" data-url="http://vcb-security-check.login-verify.example/auth">https://vcb-bank.example/verify</a></p>
      <p>Bộ phận Bảo mật Ngân hàng</p>
    `,
    explanation: "Đây là email Phishing giả mạo ngân hàng: tạo tâm lý hoảng loạn khẩn cấp, đánh lừa bằng liên kết hiển thị khác URL đích thật và thất bại xác thực SPF/DMARC.",
    flagsDetail: [
      "SPF=FAIL, DKIM=NONE, DMARC=FAIL.",
      "From hiển thị @vcb-bank.example nhưng Return-Path lại là @promo-mailer-99.example.",
      "Chữ liên kết là https://vcb-bank.example/verify nhưng URL đích thật là http://vcb-security-check.login-verify.example/auth (HTTP không mã hóa).",
      "Đe dọa khóa tài khoản sau 2 giờ và đòi nhập thông tin thẻ + OTP."
    ],
    rawEml: `Return-Path: <bounce@promo-mailer-99.example>
Received: from host88.promo-mailer-99.example ([203.0.113.88])
\tby mx.corp-vn.example with SMTP
\tfor <khachhang@corp-vn.example>; Wed, 25 Nov 2026 08:42:10 +0700
Authentication-Results: mx.corp-vn.example;
\tspf=fail (203.0.113.88 is not authorized to send for vcb-bank.example) smtp.mailfrom=promo-mailer-99.example;
\tdkim=none;
\tdmarc=fail action=quarantine header.from=vcb-bank.example
From: "VCB Digibank Security" <no-reply@vcb-bank.example>
To: <khachhang@corp-vn.example>
Subject: [KHAN CAP] Tai khoan cua ban se bi KHOA sau 02 gio!
Date: Wed, 25 Nov 2026 08:42:10 +0700
Content-Type: text/html; charset=UTF-8

<p>Xac minh ngay: <a href="http://vcb-security-check.login-verify.example/auth">https://vcb-bank.example/verify</a></p>`
  },
  {
    id: "sample_03",
    filename: "sample_03_spoofing_ceo_bec.eml",
    shortLabel: "Mẫu 3: BEC Spoofing",
    senderName: "Giam doc Tran Minh Quan (CEO)",
    senderEmail: "ceo@corp-vn.example",
    to: "ketoan@corp-vn.example",
    date: "Wed, 25 Nov 2026 09:05:00 +0700",
    subject: "Khan: Xu ly thanh toan hop dong mat trong sang nay",
    returnPath: "mailer@relay-open88.example",
    replyTo: "tranminhquan.private2026@freemail.example",
    auth: { spf: "softfail", dkim: "none", dmarc: "fail" },
    verdict: "phishing",
    attackType: "Email Spoofing / BEC (Giả danh Lãnh đạo)",
    expectedFlags: ["auth_fail", "mismatch", "social"],
    attachments: [],
    bodyHtml: `
      <p>Chào em,</p>
      <p>Anh đang họp gấp với đối tác nước ngoài nên không tiện nghe điện thoại. Em xử lý chuyển khoản gấp số tiền <strong>245.000.000 VND</strong> cho đối tác tư vấn theo số tài khoản mới anh vừa duyệt trong sáng nay (trước 11:00 trua nay).</p>
      <p>Đây là thương vụ mua bán bảo mật, em <strong>tuyệt đối không trao đổi với các phòng ban khác</strong> và chỉ bấm Reply trực tiếp vào email này để anh gửi thông tin số tài khoản nhận.</p>
      <p>Trần Minh Quân<br>Tổng Giám Đốc</p>
    `,
    explanation: "Đây là tấn công BEC kết hợp Email Spoofing: kẻ tấn công giả địa chỉ ceo@corp-vn.example qua máy chủ lạ và cài đặt Reply-To trỏ về email cá nhân freemail.example để nhận phản hồi của kế toán.",
    flagsDetail: [
      "SPF=SOFTFAIL, DKIM=NONE, DMARC=FAIL; đi qua relay-open88.example.",
      "Reply-To bị chuyển sang tranminhquan.private2026@freemail.example khác hoàn toàn miền công ty.",
      "Yêu cầu chuyển tiền gấp, lấy cớ đang họp không nghe điện thoại và cấm xác minh với phòng ban khác."
    ],
    rawEml: `Return-Path: <mailer@relay-open88.example>
Received: from relay-open88.example ([203.0.113.154])
\tby mx.corp-vn.example with SMTP
\tfor <ketoan@corp-vn.example>; Wed, 25 Nov 2026 09:05:00 +0700
Authentication-Results: mx.corp-vn.example;
\tspf=softfail (domain relay-open88.example does not match header.from) smtp.mailfrom=relay-open88.example;
\tdkim=none;
\tdmarc=fail action=none header.from=corp-vn.example
From: "Giam doc Tran Minh Quan (CEO)" <ceo@corp-vn.example>
Reply-To: "Tran Minh Quan" <tranminhquan.private2026@freemail.example>
To: "Phong Ke Toan" <ketoan@corp-vn.example>
Subject: Khan: Xu ly thanh toan hop dong mat trong sang nay
Date: Wed, 25 Nov 2026 09:05:00 +0700
Content-Type: text/plain; charset=UTF-8

Chuyen khoan gap 245.000.000 VND va chi Reply truc tiep vao email nay.`
  },
  {
    id: "sample_04",
    filename: "sample_04_lookalike_domain.eml",
    shortLabel: "Mẫu 4: Punycode / Domain",
    senderName: "Microsoft 365 Account Team",
    senderEmail: "security@xn--micrsoft-7ya.example",
    to: "user@corp-vn.example",
    date: "Wed, 25 Nov 2026 09:20:00 +0700",
    subject: "Canh bao dang nhap bat thuong - Yeu cau xac minh mat khau",
    returnPath: "bounce@xn--micrsoft-7ya.example",
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
    explanation: "Tình huống tinh vi: Dù SPF=PASS (vì hacker tự cấu hình SPF trên tên miền giả), địa chỉ gửi dùng Punycode xn--micrsoft-7ya.example và liên kết dùng thủ thuật Subdomain dài dẫn tới account-reset-portal.example.",
    flagsDetail: [
      "Tên miền người gửi chứa tiền tố Punycode xn-- (dấu hiệu giả mạo ký tự IDN Homograph).",
      "URL đích dùng subdomain trick: login.microsoft.example.account-reset-portal.example (tên miền thật là account-reset-portal.example).",
      "SPF=PASS nhưng DKIM=NONE, DMARC=NONE — minh chứng SPF=PASS không đảm bảo an toàn nếu tên miền bị giả mạo."
    ],
    rawEml: `Return-Path: <bounce@xn--micrsoft-7ya.example>
Received: from mail.xn--micrsoft-7ya.example ([198.51.100.77])
\tby mx.corp-vn.example with ESMTPS (TLSv1.2)
\tfor <user@corp-vn.example>; Wed, 25 Nov 2026 09:20:00 +0700
Authentication-Results: mx.corp-vn.example;
\tspf=pass (198.51.100.77 is permitted by xn--micrsoft-7ya.example) smtp.mailfrom=xn--micrsoft-7ya.example;
\tdkim=none;
\tdmarc=none header.from=xn--micrsoft-7ya.example
From: "Microsoft 365 Account Team" <security@xn--micrsoft-7ya.example>
To: <user@corp-vn.example>
Subject: Canh bao dang nhap bat thuong - Yeu cau xac minh mat khau
Date: Wed, 25 Nov 2026 09:20:00 +0700
Content-Type: text/html; charset=UTF-8

<p><a href="https://login.microsoft.example.account-reset-portal.example/oauth">https://login.microsoft.example/verify</a></p>`
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
    attackType: "Phát tán Tệp đính kèm Độc hại",
    expectedFlags: ["auth_fail", "mismatch", "attachment"],
    attachments: [
      { name: "BienLai_ThanhToan_2026.pdf.exe", size: "1.4 MB (Mô phỏng an toàn)", risk: "Nguy hiểm: Đuôi kép .pdf.exe" },
      { name: "HoSo_ChuyenKhoan_2026.docm", size: "420 KB (Mô phỏng an toàn)", risk: "Nguy hiểm: Word chứa Macro .docm" }
    ],
    bodyHtml: `
      <p>Kính gửi Phòng Kế toán,</p>
      <p>Chúng tôi xin gửi kèm biên lai thanh toán đợt 2 và file hợp đồng bổ sung tháng 11/2026.</p>
      <p>Vui lòng mở tệp đính kèm <code>BienLai_ThanhToan_2026.pdf.exe</code> hoặc <code>HoSo_ChuyenKhoan_2026.docm</code> và chọn <strong>"Enable Content / Enable Macros"</strong> khi được hỏi để xem đầy đủ bảng kê chi tiết.</p>
      <p>Trân trọng,<br>Bộ phận Thanh toán</p>
    `,
    explanation: "Email phát tán mã độc qua tệp đính kèm: thất bại toàn bộ SPF/DKIM/DMARC, đính kèm tệp phần mở rộng kép .pdf.exe và file Word chứa Macro .docm kèm lời dụ bật Enable Macros.",
    flagsDetail: [
      "SPF=FAIL, DKIM=FAIL, DMARC=FAIL; lệch Return-Path (unknown-sender-44.example).",
      "Tệp BienLai_ThanhToan_2026.pdf.exe sử dụng kỹ thuật Double Extension để ngụy trang tệp thực thi thành PDF.",
      "Tệp HoSo_ChuyenKhoan_2026.docm có thể chứa VBA Macro độc hại và nội dung cố tình dụ người dùng bấm Enable Macros."
    ],
    rawEml: `Return-Path: <bounce@unknown-sender-44.example>
Received: from unknown-sender-44.example ([203.0.113.211])
\tby mx.corp-vn.example with SMTP
\tfor <ketoan@corp-vn.example>; Wed, 25 Nov 2026 09:35:00 +0700
Authentication-Results: mx.corp-vn.example;
\tspf=fail smtp.mailfrom=unknown-sender-44.example;
\tdkim=fail reason="signature verification failed";
\tdmarc=fail action=reject header.from=partner-logistics.example
From: "Bo phan Thanh toan - Doi tac Van tai" <billing@partner-logistics.example>
To: <ketoan@corp-vn.example>
Subject: Gui lai Bien lai thanh toan va Hop dong bo sung T11/2026
Date: Wed, 25 Nov 2026 09:35:00 +0700
Content-Type: multipart/mixed; boundary="----=_Part_Sample05_Boundary"

------=_Part_Sample05_Boundary
Content-Type: text/plain; charset=UTF-8

Vui long mo tep dinh kem va chon "Enable Content / Enable Macros".
------=_Part_Sample05_Boundary
Content-Type: text/plain; name="BienLai_ThanhToan_2026.pdf.exe"
Content-Disposition: attachment; filename="BienLai_ThanhToan_2026.pdf.exe"

[Tep van ban mo phong phuc vu do an]
------=_Part_Sample05_Boundary
Content-Type: text/plain; name="HoSo_ChuyenKhoan_2026.docm"
Content-Disposition: attachment; filename="HoSo_ChuyenKhoan_2026.docm"

[Tep van ban mo phong phuc vu do an]
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
    explanation: "Đây là email nội bộ hợp lệ: đạt đầy đủ SPF/DKIM/DMARC, tệp đính kèm PDF bình thường (không có đuôi kép hay Macro) và liên kết dẫn đúng tới cổng nội bộ portal.corp-vn.example.",
    flagsDetail: [
      "SPF=PASS, DKIM=PASS, DMARC=PASS với tên miền nhất quán corp-vn.example.",
      "Tệp đính kèm là PDF đơn thuần (Lich_Kham_Suc_Khoe_2026.pdf), không yêu cầu bật Macro.",
      "URL hiển thị và URL đích đều thuộc https://portal.corp-vn.example/."
    ],
    rawEml: `Return-Path: <hr@corp-vn.example>
Received: from mail.corp-vn.example (mail.corp-vn.example [198.51.100.10])
\tby mx.corp-vn.example with ESMTPS (TLSv1.3)
\tfor <staff@corp-vn.example>; Wed, 25 Nov 2026 09:50:00 +0700
Authentication-Results: mx.corp-vn.example;
\tspf=pass smtp.mailfrom=corp-vn.example;
\tdkim=pass header.d=corp-vn.example header.s=mail2026;
\tdmarc=pass action=none header.from=corp-vn.example
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=corp-vn.example;
\ts=mail2026; h=from:to:subject:date:message-id;
\tbh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
\tb=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9p4tQw8Sample06==
From: "Phong Nhan Su - CorpVN" <hr@corp-vn.example>
To: "Toan the Nhan vien" <staff@corp-vn.example>
Subject: Lich kham suc khoe dinh ky nam 2026 cho nhan vien
Date: Wed, 25 Nov 2026 09:50:00 +0700
Content-Type: multipart/mixed; boundary="----=_Part_Sample06_Boundary"

------=_Part_Sample06_Boundary
Content-Type: text/html; charset=UTF-8

<p>Dang ky tai: <a href="https://portal.corp-vn.example/hr/health-check">https://portal.corp-vn.example/hr/health-check</a></p>
------=_Part_Sample06_Boundary
Content-Type: text/plain; name="Lich_Kham_Suc_Khoe_2026.pdf"
Content-Disposition: attachment; filename="Lich_Kham_Suc_Khoe_2026.pdf"

[Tep van ban mo phong phuc vu do an]
------=_Part_Sample06_Boundary--`
  }
];

if (typeof window !== "undefined") {
  window.EMAIL_SCENARIOS = EMAIL_SCENARIOS;
}
if (typeof module !== "undefined" && module.exports) {
  module.exports = { EMAIL_SCENARIOS };
}
