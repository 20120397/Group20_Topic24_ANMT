/**
 * Bộ phân tích Raw Email Header & Phát hiện dấu hiệu Phishing / Email Spoofing.
 * Phụ trách: Thành viên 3 (Auth & Simulation Engineer).
 */

function extractEmailInfo(value) {
  if (!value) {
    return { raw: "", displayName: "", address: "", domain: "" };
  }
  const clean = value.trim();
  const angleMatch = clean.match(/^(?:"?([^"]*?)"?\s*)?<([^>\s]+@[^>\s]+)>/);
  let displayName = "";
  let address = "";

  if (angleMatch) {
    displayName = (angleMatch[1] || "").trim();
    address = angleMatch[2].trim().toLowerCase();
  } else {
    const plainMatch = clean.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    if (plainMatch) {
      address = plainMatch[1].toLowerCase();
    }
  }

  const domain = address.includes("@") ? address.split("@")[1] : "";
  return { raw: clean, displayName, address, domain };
}

function getRegistrableDomain(domain) {
  if (!domain) return "";
  const parts = domain.toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  if (parts.length >= 3 && ["vn", "uk", "jp", "au"].includes(parts[parts.length - 1]) && ["com", "edu", "gov", "net", "org"].includes(parts[parts.length - 2])) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

function domainsRelated(d1, d2) {
  if (!d1 || !d2) return false;
  return getRegistrableDomain(d1) === getRegistrableDomain(d2);
}

function extractHostFromUrl(urlStr) {
  const m = String(urlStr || "").match(/^https?:\/\/([^/:?#\s]+)/i);
  return m ? m[1].toLowerCase() : "";
}

function parseRawEmail(rawText) {
  const text = typeof rawText === "string" ? rawText : "";
  const splitIdx = text.search(/\r?\n\r?\n/);
  const rawHeaderBlock = splitIdx >= 0 ? text.slice(0, splitIdx) : text;
  const bodyBlock = splitIdx >= 0 ? text.slice(splitIdx).trim() : "";

  const unfolded = rawHeaderBlock.replace(/\r?\n[ \t]+/g, " ");
  const lines = unfolded.split(/\r?\n/);

  const headers = {};
  const receivedHeaders = [];

  for (const line of lines) {
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const val = line.slice(idx + 1).trim();
    if (key === "received") {
      receivedHeaders.push(val);
    }
    if (!headers[key]) {
      headers[key] = val;
    }
  }

  const from = extractEmailInfo(headers["from"]);
  const returnPath = extractEmailInfo(headers["return-path"]);
  const replyTo = extractEmailInfo(headers["reply-to"]);

  const authRaw = headers["authentication-results"] || "";
  const spfMatch = authRaw.match(/\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b/i);
  const dkimMatch = authRaw.match(/\bdkim=(pass|fail|none|neutral|temperror|permerror)\b/i);
  const dmarcMatch = authRaw.match(/\bdmarc=(pass|fail|none|bestguesspass|temperror|permerror)\b/i);

  const dkimSig = headers["dkim-signature"] || "";
  const dkimDomainMatch = dkimSig.match(/\bd=([^;\s]+)/i) || authRaw.match(/header\.d=([^;\s]+)/i);
  const dkimSelectorMatch = dkimSig.match(/\bs=([^;\s]+)/i) || authRaw.match(/header\.s=([^;\s]+)/i);

  const attachments = [];
  const seenFiles = new Set();
  const fileRegex = /(?:filename|name)\s*=\s*"?([^"\r\n;]+)"?/gi;
  let fm;
  while ((fm = fileRegex.exec(text)) !== null) {
    const fname = fm[1].trim();
    if (fname && !fname.toLowerCase().startsWith("utf-8") && !seenFiles.has(fname)) {
      seenFiles.add(fname);
      attachments.push(fname);
    }
  }

  const anchors = [];
  const anchorRegex = /<a\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let am;
  while ((am = anchorRegex.exec(bodyBlock)) !== null) {
    anchors.push({
      href: am[1].trim(),
      anchorText: am[2].replace(/<[^>]+>/g, "").trim()
    });
  }

  const allUrls = [];
  const urlRegex = /https?:\/\/[^\s"'<>()]+/gi;
  let um;
  while ((um = urlRegex.exec(bodyBlock)) !== null) {
    if (!allUrls.includes(um[0])) {
      allUrls.push(um[0]);
    }
  }

  return {
    rawLength: text.length,
    from,
    returnPath,
    replyTo,
    subject: headers["subject"] || "",
    date: headers["date"] || "",
    receivedCount: receivedHeaders.length,
    auth: {
      spf: spfMatch ? spfMatch[1].toLowerCase() : "unknown",
      dkim: dkimMatch ? dkimMatch[1].toLowerCase() : "unknown",
      dmarc: dmarcMatch ? dmarcMatch[1].toLowerCase() : "unknown"
    },
    dkimDomain: dkimDomainMatch ? dkimDomainMatch[1].toLowerCase() : "",
    dkimSelector: dkimSelectorMatch ? dkimSelectorMatch[1].toLowerCase() : "",
    attachments,
    anchors,
    allUrls,
    bodyBlock
  };
}

function analyzeEmail(rawText) {
  const parsed = parseRawEmail(rawText);
  const findings = [];
  let score = 0;

  if (!rawText || !rawText.trim()) {
    return {
      metadata: parsed,
      findings: [{ level: "WARNING", title: "Chưa có dữ liệu đầu vào", detail: "Hãy dán Raw Email Header hoặc chọn một mẫu có sẵn." }],
      riskScore: 0,
      riskLevel: "warning",
      alignment: { spfAligned: false, dkimAligned: false }
    };
  }

  // 1. SPF / DKIM / DMARC
  if (parsed.auth.spf === "fail") {
    score += 25;
    findings.push({ level: "CRITICAL", title: "SPF thất bại (spf=fail)", detail: "IP máy chủ gửi không nằm trong danh sách được ủy quyền của tên miền." });
  } else if (parsed.auth.spf === "softfail") {
    score += 15;
    findings.push({ level: "WARNING", title: "SPF cảnh báo (spf=softfail)", detail: "Máy chủ gửi không được ủy quyền rõ ràng (~all)." });
  } else if (parsed.auth.spf === "none") {
    score += 10;
    findings.push({ level: "WARNING", title: "Thiếu bản ghi SPF (spf=none)", detail: "Không có chính sách SPF để kiểm chứng IP gửi." });
  } else if (parsed.auth.spf === "pass") {
    findings.push({ level: "OK", title: "SPF đạt (spf=pass)", detail: "IP máy chủ gửi hợp lệ theo cấu hình SPF của miền gửi thư." });
  }

  if (parsed.auth.dkim === "fail") {
    score += 25;
    findings.push({ level: "CRITICAL", title: "DKIM thất bại (dkim=fail)", detail: "Chữ ký số không hợp lệ hoặc nội dung đã bị thay đổi trên đường truyền." });
  } else if (parsed.auth.dkim === "none") {
    score += 10;
    findings.push({ level: "WARNING", title: "Không có chữ ký DKIM (dkim=none)", detail: "Email không được ký số xác thực nguồn gốc và toàn vẹn." });
  } else if (parsed.auth.dkim === "pass") {
    findings.push({ level: "OK", title: "DKIM đạt (dkim=pass)", detail: "Chữ ký số DKIM hợp lệ (" + (parsed.dkimDomain || "verified") + ")." });
  }

  if (parsed.auth.dmarc === "fail") {
    score += 25;
    findings.push({ level: "CRITICAL", title: "DMARC thất bại (dmarc=fail)", detail: "Email không vượt qua kiểm tra căn chỉnh định danh với Header From." });
  } else if (parsed.auth.dmarc === "none") {
    score += 15;
    findings.push({ level: "WARNING", title: "Chưa áp dụng DMARC (dmarc=none)", detail: "Tên miền thiếu chính sách bảo vệ DMARC chống giả mạo Header From." });
  } else if (parsed.auth.dmarc === "pass") {
    findings.push({ level: "OK", title: "DMARC đạt (dmarc=pass)", detail: "Đã xác thực và khớp định danh với Header From." });
  }

  // 2. Domain Alignment (From vs Return-Path / DKIM d=)
  const spfAligned = Boolean(parsed.from.domain && parsed.returnPath.domain && domainsRelated(parsed.from.domain, parsed.returnPath.domain));
  const dkimAligned = Boolean(parsed.from.domain && parsed.dkimDomain && domainsRelated(parsed.from.domain, parsed.dkimDomain));

  if (parsed.from.domain && parsed.returnPath.domain && !spfAligned) {
    score += 20;
    findings.push({
      level: "CRITICAL",
      title: "Lệch tên miền From và Return-Path",
      detail: `Header From (${parsed.from.domain}) không khớp Return-Path (${parsed.returnPath.domain}) — dấu hiệu Email Spoofing.`
    });
  } else if (spfAligned) {
    findings.push({ level: "OK", title: "Khớp tên miền From và Return-Path", detail: `Cùng thuộc tên miền ${getRegistrableDomain(parsed.from.domain)}.` });
  }

  if (parsed.from.domain && parsed.dkimDomain && !dkimAligned) {
    score += 15;
    findings.push({
      level: "WARNING",
      title: "Tên miền ký DKIM không khớp From",
      detail: `DKIM ký bởi ${parsed.dkimDomain}, khác với Header From (${parsed.from.domain}).`
    });
  }

  // 3. Reply-To Mismatch
  if (parsed.from.domain && parsed.replyTo.domain && !domainsRelated(parsed.from.domain, parsed.replyTo.domain)) {
    score += 30;
    findings.push({
      level: "CRITICAL",
      title: "Phát hiện đánh tráo Reply-To (BEC / Spoofing)",
      detail: `Thư hiển thị từ ${parsed.from.address} nhưng phản hồi sẽ bị chuyển sang ${parsed.replyTo.address}.`
    });
  }

  // 4. Display Name Spoofing
  if (parsed.from.displayName) {
    const embeddedEmail = parsed.from.displayName.match(/[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    if (embeddedEmail && !domainsRelated(embeddedEmail[1], parsed.from.domain)) {
      score += 25;
      findings.push({
        level: "CRITICAL",
        title: "Giả mạo Display Name chứa địa chỉ email khác",
        detail: `Display Name chứa miền ${embeddedEmail[1]} nhưng địa chỉ gửi thật là ${parsed.from.address}.`
      });
    } else if (/(ceo|giam doc|director|bank|security|microsoft)/i.test(parsed.from.displayName) && (parsed.auth.dmarc !== "pass" || (parsed.replyTo.domain && !domainsRelated(parsed.from.domain, parsed.replyTo.domain)))) {
      score += 15;
      findings.push({
        level: "WARNING",
        title: "Nguy cơ giả mạo tên hiển thị (Display Name Spoofing)",
        detail: `Tên hiển thị "${parsed.from.displayName}" mang danh nghĩa nhạy cảm trong khi xác thực DMARC/Reply-To không an toàn.`
      });
    }
  }

  // 5. Domain Lookalike / Punycode / Subdomain Trick / Anchor Link Mismatch
  const domainsToCheck = new Set([parsed.from.domain, parsed.returnPath.domain].filter(Boolean));
  for (const u of parsed.allUrls) {
    const h = extractHostFromUrl(u);
    if (h) domainsToCheck.add(h);
  }

  for (const dom of domainsToCheck) {
    if (dom.includes("xn--")) {
      score += 35;
      findings.push({
        level: "CRITICAL",
        title: `Phát hiện tên miền Punycode (${dom})`,
        detail: "Tiền tố xn-- cho thấy tên miền IDN có thể đang dùng ký tự Unicode giả dạng (Homograph Attack)."
      });
    }
    const labels = dom.split(".").filter(Boolean);
    if (labels.length >= 4) {
      score += 20;
      findings.push({
        level: "WARNING",
        title: `Cấu trúc subdomain dài bất thường (${dom})`,
        detail: `Tên miền có ${labels.length} cấp — cần kiểm tra kỹ thủ thuật Subdomain Trick; tên miền gốc thực sự là ${getRegistrableDomain(dom)}.`
      });
    }
  }

  for (const anchor of parsed.anchors) {
    const textHost = extractHostFromUrl(anchor.anchorText);
    const hrefHost = extractHostFromUrl(anchor.href);
    if (textHost && hrefHost && textHost !== hrefHost) {
      score += 30;
      findings.push({
        level: "CRITICAL",
        title: "Liên kết ngụy trang (Anchor Text khác URL đích)",
        detail: `Chữ hiển thị trỏ về ${textHost} nhưng đường dẫn thực tế dẫn tới ${anchor.href}.`
      });
    }
  }

  // 6. Malicious Attachments & Macro Bait
  for (const fname of parsed.attachments) {
    if (/\.[a-z0-9]{2,5}\.(exe|scr|bat|cmd|vbs|js|jse|ps1|pif|com|hta)$/i.test(fname)) {
      score += 40;
      findings.push({
        level: "CRITICAL",
        title: `Tệp phần mở rộng kép nguy hiểm (${fname})`,
        detail: "Kỹ thuật Double Extension đánh lừa người dùng tưởng là tài liệu nhưng thực chất là tệp thực thi."
      });
    } else if (/\.(exe|scr|bat|cmd|vbs|js|jse|ps1|pif|com|hta|iso|img|html|htm)$/i.test(fname)) {
      score += 35;
      findings.push({
        level: "CRITICAL",
        title: `Tệp đính kèm có khả năng thực thi / HTML Smuggling (${fname})`,
        detail: "Phần mở rộng này thường được dùng để phát tán mã độc qua email."
      });
    } else if (/\.(docm|xlsm|pptm|dotm|xltm)$/i.test(fname)) {
      score += 30;
      findings.push({
        level: "CRITICAL",
        title: `Tệp Office chứa Macro (${fname})`,
        detail: "Định dạng hỗ trợ chạy VBA Macro tự động nếu người dùng nhấn Enable Content."
      });
    } else if (/\.(zip|rar|7z)$/i.test(fname) && /(password|mat khau|pass:)/i.test(parsed.bodyBlock)) {
      score += 20;
      findings.push({
        level: "WARNING",
        title: `Tệp nén có dấu hiệu đặt mật khẩu (${fname})`,
        detail: "Kẻ tấn công thường đặt mật khẩu file nén để né bộ lọc quét virus tại Email Gateway."
      });
    } else {
      findings.push({
        level: "INFO",
        title: `Tệp đính kèm (${fname})`,
        detail: "Đuôi tệp phổ thông; vẫn cần kiểm tra nguồn gửi và quét AV trước khi mở."
      });
    }
  }

  if (/(enable\s+content|enable\s+macros?)/i.test(parsed.bodyBlock)) {
    score += 25;
    findings.push({
      level: "CRITICAL",
      title: "Nội dung dụ người dùng bật Macro",
      detail: "Cụm từ 'Enable Content / Enable Macros' là dấu hiệu điển hình của tấn công Macro Virus."
    });
  }

  const riskScore = Math.min(100, score);
  let riskLevel = "safe";
  if (riskScore >= 55) {
    riskLevel = "danger";
  } else if (riskScore >= 25) {
    riskLevel = "warning";
  }

  return {
    metadata: parsed,
    findings,
    riskScore,
    riskLevel,
    alignment: { spfAligned, dkimAligned }
  };
}

const EmailHeaderAnalyzer = {
  parseRawEmail,
  analyzeEmail,
  extractEmailInfo,
  getRegistrableDomain,
  domainsRelated
};

if (typeof window !== "undefined") {
  window.EmailHeaderAnalyzer = EmailHeaderAnalyzer;
}
if (typeof module !== "undefined" && module.exports) {
  module.exports = EmailHeaderAnalyzer;
}
