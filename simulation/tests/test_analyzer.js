/**
 * Bộ kiểm thử tự động cho EmailHeaderAnalyzer & đối chiếu đồng bộ 1-1 với labs/email_samples/*.eml.
 * Chạy bằng Node.js (không cần thư viện ngoài):
 *   node simulation/tests/test_analyzer.js
 *
 * Sinh viên thực hiện: Nguyễn Lê Hữu Điền (23120233 — Auth & Simulation Engineer)
 */

const fs = require("fs");
const path = require("path");
const assert = require("assert");

const repoRoot = path.resolve(__dirname, "..", "..");
const samplesDir = path.join(repoRoot, "labs", "email_samples");
const analyzer = require(path.join(repoRoot, "simulation", "js", "header_analyzer.js"));
const { EMAIL_SCENARIOS } = require(path.join(repoRoot, "simulation", "js", "scenarios.js"));

function normalizeEol(str) {
  return String(str || "").replace(/\r\n/g, "\n").trim();
}

function hasFinding(res, level, substring) {
  return res.findings.some(
    (f) => (!level || f.level === level) && f.title.toLowerCase().includes(substring.toLowerCase())
  );
}

let passedTests = 0;
function runTest(name, fn) {
  try {
    fn();
    passedTests += 1;
    console.log(`  [PASS] ${name}`);
  } catch (err) {
    console.error(`  [FAIL] ${name}`);
    console.error("        ", err && err.message ? err.message : err);
    process.exitCode = 1;
  }
}

console.log("=== 1. KIỂM THỬ ĐỒNG BỘ 1-1 GIỮA labs/email_samples/*.eml VÀ scenarios.js ===");

const emlFiles = fs
  .readdirSync(samplesDir)
  .filter((f) => f.toLowerCase().endsWith(".eml"))
  .sort();

runTest(`Phát hiện đủ tệp .eml trong labs/email_samples (${emlFiles.length} tệp)`, () => {
  assert.ok(emlFiles.length >= 6, `Kỳ vọng >= 6 tệp .eml, tìm thấy ${emlFiles.length}`);
  assert.strictEqual(
    EMAIL_SCENARIOS.length,
    emlFiles.length,
    `Số kịch bản trong scenarios.js (${EMAIL_SCENARIOS.length}) khác số file .eml (${emlFiles.length})`
  );
});

const scenarioByFile = new Map(EMAIL_SCENARIOS.map((sc) => [sc.filename, sc]));

for (const fname of emlFiles) {
  const filePath = path.join(samplesDir, fname);
  const diskContent = fs.readFileSync(filePath, "utf8");
  const sc = scenarioByFile.get(fname);

  runTest(`Đồng bộ byte-for-byte & metadata: ${fname}`, () => {
    assert.ok(sc, `Thiếu kịch bản trong scenarios.js cho file ${fname}`);
    assert.strictEqual(
      normalizeEol(sc.rawEml),
      normalizeEol(diskContent),
      `rawEml trong scenarios.js khác với nội dung file ${fname}`
    );

    const parsed = analyzer.parseRawEmail(diskContent);
    assert.strictEqual(parsed.from.address, sc.senderEmail.toLowerCase(), `senderEmail lệch ở ${fname}`);
    assert.strictEqual(parsed.returnPath.address, sc.returnPath.toLowerCase(), `returnPath lệch ở ${fname}`);
    assert.strictEqual(parsed.replyTo.address || "", (sc.replyTo || "").toLowerCase(), `replyTo lệch ở ${fname}`);
    assert.strictEqual(parsed.auth.spf, sc.auth.spf, `auth.spf lệch ở ${fname}`);
    assert.strictEqual(parsed.auth.dkim, sc.auth.dkim, `auth.dkim lệch ở ${fname}`);
    assert.strictEqual(parsed.auth.dmarc, sc.auth.dmarc, `auth.dmarc lệch ở ${fname}`);

    // Kiểm tra quy tắc đạo đức RFC 2606: mọi tên miền trong mẫu chỉ dùng hậu tố .example
    const domains = [parsed.from.domain, parsed.returnPath.domain, parsed.replyTo.domain].filter(Boolean);
    for (const dom of domains) {
      assert.ok(dom.endsWith(".example"), `Tên miền ${dom} trong ${fname} không thuộc chuẩn an toàn .example (RFC 2606)`);
    }
    for (const url of parsed.allUrls) {
      const m = url.match(/^https?:\/\/([^/:?#\s]+)/i);
      assert.ok(m && m[1].toLowerCase().endsWith(".example"), `URL ${url} trong ${fname} không thuộc chuẩn .example`);
    }
  });
}

console.log("\n=== 2. KIỂM THỬ PHÂN TÍCH RỦI RO TRÊN TỪNG FILE .eml ===");

const expectedSpecs = {
  "sample_01_legit_it.eml": {
    riskLevel: "safe",
    exactScore: 0,
    spfAligned: true,
    dkimAligned: true,
    dmarcAligned: true,
    transportEncrypted: true,
    receivedCount: 2,
    senderIp: "198.51.100.12",
    mustFind: [
      ["OK", "SPF đạt"],
      ["OK", "DKIM đạt"],
      ["OK", "DMARC đạt"],
      ["OK", "mã hóa TLS"]
    ]
  },
  "sample_02_phishing_bank.eml": {
    riskLevel: "danger",
    minScore: 55,
    spfAligned: false,
    dkimAligned: false,
    dmarcAligned: false,
    transportEncrypted: false,
    receivedCount: 1,
    senderIp: "203.0.113.88",
    mustFind: [
      ["CRITICAL", "SPF thất bại"],
      ["CRITICAL", "DMARC thất bại"],
      ["CRITICAL", "Lệch tên miền From và Return-Path"],
      ["CRITICAL", "Liên kết ngụy trang"],
      ["WARNING", "không mã hóa TLS"]
    ]
  },
  "sample_03_spoofing_ceo_bec.eml": {
    riskLevel: "danger",
    minScore: 55,
    spfAligned: false,
    dkimAligned: false,
    dmarcAligned: false,
    transportEncrypted: false,
    receivedCount: 1,
    senderIp: "203.0.113.154",
    mustFind: [
      ["WARNING", "SPF cảnh báo"],
      ["CRITICAL", "DMARC thất bại"],
      ["CRITICAL", "Lệch tên miền From và Return-Path"],
      ["CRITICAL", "đánh tráo Reply-To"],
      ["WARNING", "giả mạo tên hiển thị"]
    ]
  },
  "sample_04_lookalike_domain.eml": {
    riskLevel: "danger",
    minScore: 55,
    spfAligned: true,
    dkimAligned: false,
    dmarcAligned: true, // SPF aligns with the attacker's own Punycode domain (educational trap!)
    transportEncrypted: true,
    receivedCount: 1,
    senderIp: "198.51.100.77",
    mustFind: [
      ["OK", "SPF đạt"],
      ["CRITICAL", "Punycode (xn--micrsoft-qbh.example)"],
      ["WARNING", "subdomain dài bất thường"],
      ["CRITICAL", "Liên kết ngụy trang"]
    ]
  },
  "sample_05_malicious_attachment.eml": {
    riskLevel: "danger",
    minScore: 55,
    spfAligned: false,
    dkimAligned: false,
    dmarcAligned: false,
    transportEncrypted: false,
    receivedCount: 1,
    senderIp: "203.0.113.211",
    mustFind: [
      ["CRITICAL", "SPF thất bại"],
      ["CRITICAL", "DKIM thất bại"],
      ["CRITICAL", "DMARC thất bại"],
      ["CRITICAL", "phần mở rộng kép nguy hiểm (BienLai_ThanhToan_2026.pdf.exe)"],
      ["CRITICAL", "Office chứa Macro (HoSo_ChuyenKhoan_2026.docm)"],
      ["CRITICAL", "dụ người dùng bật Macro"]
    ]
  },
  "sample_06_legit_hr.eml": {
    riskLevel: "safe",
    exactScore: 0,
    spfAligned: true,
    dkimAligned: true,
    dmarcAligned: true,
    transportEncrypted: true,
    receivedCount: 2,
    senderIp: "198.51.100.15",
    mustFind: [
      ["OK", "SPF Alignment đạt chuẩn"],
      ["OK", "DKIM Alignment đạt chuẩn"],
      ["INFO", "Lich_Kham_Suc_Khoe_2026.pdf"]
    ]
  }
};

const summaryRows = [];

for (const fname of emlFiles) {
  const raw = fs.readFileSync(path.join(samplesDir, fname), "utf8");
  const res = analyzer.analyzeEmail(raw);
  const spec = expectedSpecs[fname];

  const critCount = res.findings.filter((f) => f.level === "CRITICAL").length;
  const warnCount = res.findings.filter((f) => f.level === "WARNING").length;
  const okCount = res.findings.filter((f) => f.level === "OK").length;

  summaryRows.push({
    fname,
    score: res.riskScore,
    level: res.riskLevel,
    auth: `${res.metadata.auth.spf.toUpperCase()} / ${res.metadata.auth.dkim.toUpperCase()} / ${res.metadata.auth.dmarc.toUpperCase()}`,
    align: `SPF:${res.alignment.spfAligned ? "OK" : "FAIL"}, DKIM:${res.alignment.dkimAligned ? "OK" : "FAIL"}`,
    tls: res.metadata.transportEncrypted === true ? "TLS" : "Plain SMTP",
    hops: `${res.metadata.receivedCount} (${res.metadata.senderIp})`,
    counts: `${critCount} CRIT / ${warnCount} WARN / ${okCount} OK`,
    keyFindings: res.findings
      .filter((f) => f.level === "CRITICAL" || f.level === "WARNING")
      .map((f) => f.title)
  });

  runTest(`Phân tích ${fname} -> ${res.riskLevel} (${res.riskScore}/100)`, () => {
    assert.ok(spec, `Chưa có đặc tả kiểm thử cho ${fname}`);
    assert.strictEqual(res.riskLevel, spec.riskLevel, `riskLevel sai cho ${fname}`);
    if (typeof spec.exactScore === "number") {
      assert.strictEqual(res.riskScore, spec.exactScore, `riskScore sai cho ${fname}`);
    }
    if (typeof spec.minScore === "number") {
      assert.ok(res.riskScore >= spec.minScore, `riskScore ${res.riskScore} < ${spec.minScore} cho ${fname}`);
    }
    assert.strictEqual(res.alignment.spfAligned, spec.spfAligned, `spfAligned sai cho ${fname}`);
    assert.strictEqual(res.alignment.dkimAligned, spec.dkimAligned, `dkimAligned sai cho ${fname}`);
    assert.strictEqual(res.alignment.dmarcAligned, spec.dmarcAligned, `dmarcAligned sai cho ${fname}`);
    assert.strictEqual(res.metadata.transportEncrypted, spec.transportEncrypted, `transportEncrypted sai cho ${fname}`);
    assert.strictEqual(res.metadata.receivedCount, spec.receivedCount, `receivedCount sai cho ${fname}`);
    assert.strictEqual(res.metadata.senderIp, spec.senderIp, `senderIp sai cho ${fname}`);

    for (const [lvl, text] of spec.mustFind) {
      assert.ok(
        hasFinding(res, lvl, text),
        `Thiếu cảnh báo [${lvl}] chứa "${text}" trong ${fname}. Các cảnh báo hiện có: ${res.findings
          .map((f) => `[${f.level}] ${f.title}`)
          .join("; ")}`
      );
    }
  });
}

console.log("\n=== 3. KIỂM THỬ BIÊN (EDGE-CASE UNIT TESTS) ===");

runTest("Đầu vào rỗng trả về warning (0/100)", () => {
  const res = analyzer.analyzeEmail("   ");
  assert.strictEqual(res.riskLevel, "warning");
  assert.strictEqual(res.riskScore, 0);
});

runTest("Email chuyển tiếp (SPF=fail nhưng DKIM=pass & aligned) vẫn đạt DMARC Alignment", () => {
  const forwarded = [
    "Return-Path: <bounce@forwarder.example>",
    "Received: from relay.forwarder.example ([198.51.100.99]) by mx.corp-vn.example with ESMTPSA (version=TLS1_3)",
    "Authentication-Results: mx.corp-vn.example; spf=fail smtp.mailfrom=forwarder.example; dkim=pass header.d=corp-vn.example header.s=mail2026; dmarc=pass header.from=corp-vn.example",
    "From: \"IT\" <it@corp-vn.example>",
    "Subject: Forwarded notice",
    "",
    "Noi dung chuyen tiep hop le."
  ].join("\n");
  const res = analyzer.analyzeEmail(forwarded);
  assert.strictEqual(res.alignment.spfAligned, false);
  assert.strictEqual(res.alignment.dkimAligned, true);
  assert.strictEqual(res.alignment.dmarcAligned, true);
  assert.strictEqual(res.metadata.transportEncrypted, true, "ESMTPSA + TLS1_3 phải được nhận diện có TLS");
});

runTest("Phát hiện tên miền chứa ký tự Unicode Homograph trực tiếp (Cyrillic 'о' U+043E)", () => {
  const unicodeRaw = [
    "Return-Path: <sec@micr\u043Esoft.example>",
    "Authentication-Results: mx.corp-vn.example; spf=pass smtp.mailfrom=micr\u043Esoft.example; dkim=none; dmarc=none",
    "From: \"Security\" <sec@micr\u043Esoft.example>",
    "Subject: Alert",
    "",
    "Test homograph"
  ].join("\n");
  const res = analyzer.analyzeEmail(unicodeRaw);
  assert.ok(hasFinding(res, "CRITICAL", "Unicode ngoài bảng mã ASCII"));
  assert.strictEqual(res.riskLevel, "danger");
});

runTest("Phát hiện tệp nén đặt mật khẩu (.zip + 'mat khau')", () => {
  const zipRaw = [
    "Return-Path: <sender@other.example>",
    "Authentication-Results: mx.corp-vn.example; spf=fail; dkim=none; dmarc=fail",
    "From: \"Invoice\" <billing@partner.example>",
    "Content-Disposition: attachment; filename=\"HoaDon_2026.zip\"",
    "",
    "Vui long giai nen voi mat khau: 123456"
  ].join("\n");
  const res = analyzer.analyzeEmail(zipRaw);
  assert.ok(hasFinding(res, "WARNING", "Tệp nén có dấu hiệu đặt mật khẩu"));
});

console.log("\n=== BẢNG TÓM TẮT KẾT QUẢ KIỂM THỬ (MARKDOWN CHO MỤC 5.4.1) ===");
console.log("| File `.eml` | Xác thực (`SPF/DKIM/DMARC`) | Alignment | Truyền tải & IP nguồn | Điểm rủi ro | Phân loại | Số phát hiện |");
console.log("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |");
for (const r of summaryRows) {
  console.log(`| \`${r.fname}\` | \`${r.auth}\` | ${r.align} | ${r.tls} · ${r.hops} | **${r.score}/100** | \`${r.level}\` | ${r.counts} |`);
}

console.log(`\nTỔNG KẾT: ${passedTests} bài kiểm thử ĐẠT${process.exitCode ? " (CÓ LỖI!)" : " (100% PASS)"}.`);
