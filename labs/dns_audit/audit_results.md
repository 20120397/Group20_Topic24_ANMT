# Kết quả Khảo sát Cấu hình Xác thực Email (DNS Audit)

> **Sinh viên thực hiện:** Nguyễn Lê Hữu Điền (`23120233`)  
> **Công cụ sử dụng:** Script PowerShell [check_email_auth.ps1](check_email_auth.ps1), `Resolve-DnsName`, `nslookup`

---

## 1. Hướng dẫn Chạy Thực nghiệm

### Cách 1: Chạy kiểm thử logic offline (không cần Internet)
```powershell
powershell -ExecutionPolicy Bypass -File .\check_email_auth.ps1 -SelfTest
```

### Cách 2: Chạy khảo sát trực tiếp trên máy có Internet
```powershell
powershell -ExecutionPolicy Bypass -File .\check_email_auth.ps1
```
Hoặc xuất kết quả ra file Markdown để đối chiếu và chèn vào Chương 3:
```powershell
powershell -ExecutionPolicy Bypass -File .\check_email_auth.ps1 -ExportMarkdown .\live_audit_output.md
```

### Cách 3: Truy vấn thủ công bằng `nslookup` (đối chiếu với Bài 7)
```powershell
nslookup -type=mx gmail.com
nslookup -type=txt gmail.com
nslookup -type=txt _dmarc.gmail.com
```

---

## 2. Tiêu chí Đánh giá Mức độ Bảo vệ

| Mức đánh giá | Điều kiện kỹ thuật (`SPF` + `DMARC`) | Ý nghĩa chống giả mạo |
| :--- | :--- | :--- |
| **Mạnh** | Có SPF với `-all` hoặc `~all` (≤ 10 DNS lookups) **và** DMARC `p=reject` | Máy nhận từ chối thẳng email giả mạo `Header From` khi sai xác thực. |
| **Trung bình** | Có DMARC `p=quarantine`, hoặc chỉ có SPF `-all`/`~all` nhưng DMARC `p=none` / thiếu DMARC | Mới dừng ở mức đánh dấu Spam hoặc chỉ theo dõi báo cáo (`none`), chưa chặn triệt để. |
| **Yếu / Chưa cấu hình** | Thiếu cả SPF & DMARC, hoặc dùng `+all`/`?all`, hoặc chỉ `p=none` thiếu SPF chặt | Nguy cơ cao bị lợi dụng giả mạo tên miền (Email Spoofing). |

---

## 3. Bảng Kết quả Khảo sát Thực tế (Điền dữ liệu chạy thực tế)

> **Lưu ý trung thực học thuật:** Bảng dưới đây để trống kết quả live để TV3 chạy trực tiếp trên máy có Internet rồi ghi nhận đúng bản ghi thực tế quan sát được (kèm ngày giờ khảo sát).

| STT | Tên miền | Bản ghi MX chính | SPF (`v=spf1`) & Cơ chế cuối | DMARC (`_dmarc`) | Đánh giá | Ghi chú |
| :-: | :--- | :--- | :--- | :--- | :---: | :--- |
| 1 | `gmail.com` | `[TODO TV3]` | `[TODO TV3]` | `[TODO TV3]` | `[ ]` | |
| 2 | `microsoft.com` | `[TODO TV3]` | `[TODO TV3]` | `[TODO TV3]` | `[ ]` | |
| 3 | `github.com` | `[TODO TV3]` | `[TODO TV3]` | `[TODO TV3]` | `[ ]` | |
| 4 | `vietcombank.com.vn` | `[TODO TV3]` | `[TODO TV3]` | `[TODO TV3]` | `[ ]` | |
| 5 | `vnexpress.net` | `[TODO TV3]` | `[TODO TV3]` | `[TODO TV3]` | `[ ]` | |
| 6 | `hust.edu.vn` | `[TODO TV3]` | `[TODO TV3]` | `[TODO TV3]` | `[ ]` | |
| 7 | `uit.edu.vn` | `[TODO TV3]` | `[TODO TV3]` | `[TODO TV3]` | `[ ]` | |
| 8 | `cloudflare.com` | `[TODO TV3]` | `[TODO TV3]` | `[TODO TV3]` | `[ ]` | |

---

## 4. Checklist Hoàn thiện & Nhận xét (TV3)

- [ ] **[TODO (TV3)]:** Chạy `.\check_email_auth.ps1 -ExportMarkdown .\live_audit_output.md` trên máy có kết nối Internet và điền đầy đủ bảng Mục 3 ở trên (ghi rõ ngày/giờ khảo sát).
- [ ] **[TODO (TV3)]:** Chụp ảnh màn hình cửa sổ PowerShell hiển thị kết quả chạy thực tế và lưu tại `report/assets/ch3_dns_audit_terminal.png`.
- [ ] **[TODO (TV3)]:** Chạy thêm lệnh `nslookup -type=txt google._domainkey.gmail.com` (hoặc selector DKIM của 1 tên miền thực tế tìm thấy trong header email thật của bạn) để minh họa khóa công khai DKIM trên DNS.
- [ ] **[TODO (TV3)]:** Viết 3–4 gạch đầu dòng nhận xét sự khác biệt giữa nhóm công nghệ/ngân hàng (thường bật `p=reject`) và nhóm giáo dục/tin tức (có thể đang ở `p=none` hoặc `~all`), sau đó đưa bảng kết quả sang Mục 3.5 của Chương 3.
