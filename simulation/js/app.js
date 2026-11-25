/**
 * Logic giao diện Web App Mô phỏng Nhận diện Email Lừa đảo (Offline).
 * Phụ trách: Thành viên 3 — Nguyễn Lê Hữu Điền (23120233, Auth & Simulation Engineer).
 */

(function () {
  if (typeof document === "undefined") return;

  const SKILL_FLAG_META = [
    { key: "auth_fail", short: "Xác thực SPF/DKIM/DMARC", label: "SPF / DKIM / DMARC thất bại hoặc thiếu" },
    { key: "mismatch", short: "Lệch Return-Path / Reply-To", label: "Lệch Return-Path hoặc Reply-To" },
    { key: "domain", short: "Giả mạo tên miền / Punycode", label: "Tên miền giả mạo / Punycode / Subdomain" },
    { key: "link", short: "Liên kết ngụy trang", label: "Liên kết hiển thị khác URL đích thật" },
    { key: "attachment", short: "Tệp đính kèm độc hại / Macro", label: "Tệp đính kèm nguy hiểm / Đuôi kép / Macro" },
    { key: "social", short: "Tâm lý Social Eng. / BEC", label: "Áp lực khẩn cấp / Giả danh lãnh đạo (BEC)" }
  ];

  const SKILL_LABEL_MAP = Object.fromEntries(SKILL_FLAG_META.map((item) => [item.key, item.label]));
  const SKILL_SHORT_MAP = Object.fromEntries(SKILL_FLAG_META.map((item) => [item.key, item.short]));

  const state = {
    currentScenarioId: null,
    headerVisible: false,
    answers: {} // scenarioId -> { userVerdict, selectedFlags, isCorrect, caughtFlags, missedFlags, extraFlags }
  };

  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function badgeClassForAuth(val) {
    if (val === "pass") return "badge-pass";
    if (val === "softfail") return "badge-softfail";
    if (val === "fail") return "badge-fail";
    return "badge-none";
  }

  function badgeClassForAttachmentRisk(att) {
    const text = `${att && att.name ? att.name : ""} ${att && att.risk ? att.risk : ""}`.toLowerCase();
    if (text.includes("nguy hiểm") || /\.(exe|scr|docm|xlsm|pptm|vbs|js|html|htm|iso)/.test(text)) {
      return "badge-danger";
    }
    if (text.includes("hợp lệ")) {
      return "badge-safe";
    }
    return "badge-warning";
  }

  function getScenarios() {
    return Array.isArray(window.EMAIL_SCENARIOS) ? window.EMAIL_SCENARIOS : [];
  }

  function activateTab(target) {
    const tabBtns = document.querySelectorAll(".tab-btn");
    const panels = document.querySelectorAll(".tab-panel");
    tabBtns.forEach((b) => {
      b.classList.toggle("active", b.getAttribute("data-tab") === target);
    });
    panels.forEach((p) => {
      p.classList.toggle("active", p.id === "panel-" + target);
    });
  }

  function setupTabs() {
    document.querySelectorAll(".tab-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        activateTab(btn.getAttribute("data-tab"));
      });
    });
  }

  function updateToolbarStats() {
    const scenarios = getScenarios();
    const total = scenarios.length;
    const answered = Object.keys(state.answers).length;
    const correct = Object.values(state.answers).filter((a) => a.isCorrect).length;
    const accuracy = answered > 0 ? Math.round((correct / answered) * 100) : 0;

    document.getElementById("stat-progress").textContent = `${answered} / ${total}`;
    document.getElementById("stat-score").textContent = `${correct} / ${total}`;
    document.getElementById("stat-accuracy").textContent = `${accuracy}%`;

    const listTitle = document.getElementById("inbox-list-title");
    if (listTitle) {
      listTitle.textContent = `Hộp thư đến (${total} kịch bản)`;
    }
  }

  function renderScenarioList() {
    const listEl = document.getElementById("scenario-list");
    const scenarios = getScenarios();
    listEl.innerHTML = "";

    scenarios.forEach((sc) => {
      const ans = state.answers[sc.id];
      let statusBadge = '<span class="badge badge-none">Chưa làm</span>';
      if (ans) {
        statusBadge = ans.isCorrect
          ? '<span class="badge badge-pass">Đúng</span>'
          : '<span class="badge badge-fail">Sai</span>';
      }

      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "scenario-item" + (sc.id === state.currentScenarioId ? " active" : "");
      btn.innerHTML = `
        <div class="scenario-item-top">
          <span class="scenario-sender">${escapeHtml(sc.shortLabel)}</span>
          ${statusBadge}
        </div>
        <span class="scenario-subj">${escapeHtml(sc.subject)}</span>
      `;
      btn.addEventListener("click", () => selectScenario(sc.id));
      listEl.appendChild(btn);
    });
  }

  function attachLinkPreviewHandlers(container) {
    const previewBar = document.getElementById("url-preview-bar");
    const links = container.querySelectorAll("a[data-url]");
    links.forEach((link) => {
      const targetUrl = link.getAttribute("data-url");
      link.addEventListener("mouseenter", () => {
        previewBar.textContent = "URL đích thực tế: " + targetUrl;
        previewBar.classList.remove("hidden");
      });
      link.addEventListener("mouseleave", () => {
        previewBar.classList.add("hidden");
      });
      link.addEventListener("click", (e) => {
        e.preventDefault();
        alert("Mô phỏng an toàn: Đã chặn mở liên kết ngoài.\nURL đích của liên kết này là:\n" + targetUrl);
      });
    });
  }

  function renderFlagBadges(flags, badgeClass, emptyText) {
    if (!flags || flags.length === 0) {
      return `<span class="muted">${escapeHtml(emptyText)}</span>`;
    }
    return flags
      .map((f) => `<span class="badge badge-inline ${badgeClass}">${escapeHtml(SKILL_LABEL_MAP[f] || f)}</span>`)
      .join("");
  }

  function renderFeedback(sc, ans) {
    const panel = document.getElementById("feedback-panel");
    if (!ans) {
      panel.classList.add("hidden");
      panel.innerHTML = "";
      return;
    }

    panel.classList.remove("hidden", "correct", "wrong");
    panel.classList.add(ans.isCorrect ? "correct" : "wrong");

    const actualLabel = sc.verdict === "safe" ? "Email An toàn (Hợp lệ)" : "Email Lừa đảo / Giả mạo";
    const resultTitle = ans.isCorrect ? "Chính xác!" : "Chưa chính xác!";
    const expectedFlags = Array.isArray(sc.expectedFlags) ? sc.expectedFlags : [];

    let flagReviewHtml = "";
    if (expectedFlags.length > 0) {
      flagReviewHtml = `
        <div class="flag-review-box">
          <div class="flag-review-row">
            <span class="flag-review-label">Red Flags đã phát hiện (${ans.caughtFlags.length}/${expectedFlags.length}):</span>
            ${renderFlagBadges(ans.caughtFlags, "badge-safe", "Chưa chọn đúng dấu hiệu nào")}
          </div>
          <div class="flag-review-row">
            <span class="flag-review-label">Red Flags bị bỏ sót (${ans.missedFlags.length}):</span>
            ${
              ans.missedFlags.length === 0
                ? '<span class="badge badge-inline badge-safe">Không bỏ sót dấu hiệu nào!</span>'
                : renderFlagBadges(ans.missedFlags, "badge-fail", "")
            }
          </div>
          ${
            ans.extraFlags.length > 0
              ? `<div class="flag-review-row">
                   <span class="flag-review-label">Dấu hiệu chọn dư / nhầm (${ans.extraFlags.length}):</span>
                   ${renderFlagBadges(ans.extraFlags, "badge-warning", "")}
                 </div>`
              : ""
          }
        </div>
      `;
    } else {
      flagReviewHtml = `
        <div class="flag-review-box">
          <div class="flag-review-row">
            <span class="flag-review-label">Đánh giá Red Flags (Email sạch):</span>
            ${
              ans.extraFlags.length === 0
                ? '<span class="badge badge-inline badge-safe">Chuẩn xác — Không gắn nhầm cảnh báo giả</span>'
                : renderFlagBadges(ans.extraFlags, "badge-warning", "")
            }
          </div>
        </div>
      `;
    }

    const itemsHtml = sc.flagsDetail.map((d) => `<li>${escapeHtml(d)}</li>`).join("");
    panel.innerHTML = `
      <strong>${resultTitle}</strong> — Đáp án đúng: <strong>${actualLabel}</strong> (${escapeHtml(sc.attackType)})
      <p>${escapeHtml(sc.explanation)}</p>
      ${flagReviewHtml}
      <ul>${itemsHtml}</ul>
    `;
  }

  function selectScenario(id) {
    const sc = getScenarios().find((item) => item.id === id);
    if (!sc) return;

    state.currentScenarioId = id;
    state.headerVisible = false;
    renderScenarioList();

    document.getElementById("view-subject").textContent = sc.subject;
    document.getElementById("view-from").textContent = `${sc.senderName} <${sc.senderEmail}>`;
    document.getElementById("view-to").textContent = sc.to;
    document.getElementById("view-date").textContent = sc.date;
    document.getElementById("view-return-path").textContent = sc.returnPath;

    const replyRow = document.getElementById("view-reply-to-row");
    if (sc.replyTo) {
      replyRow.classList.remove("hidden");
      document.getElementById("view-reply-to").textContent = sc.replyTo;
    } else {
      replyRow.classList.add("hidden");
    }

    const headerBox = document.getElementById("raw-header-box");
    headerBox.classList.add("hidden");
    document.getElementById("btn-toggle-header").textContent = "Soi Raw Header & Xác thực";

    const badgesEl = document.getElementById("view-auth-badges");
    badgesEl.innerHTML = `
      <span class="badge ${badgeClassForAuth(sc.auth.spf)}">SPF: ${sc.auth.spf}</span>
      <span class="badge ${badgeClassForAuth(sc.auth.dkim)}">DKIM: ${sc.auth.dkim}</span>
      <span class="badge ${badgeClassForAuth(sc.auth.dmarc)}">DMARC: ${sc.auth.dmarc}</span>
    `;
    document.getElementById("view-raw-headers").textContent = sc.rawEml;

    const bodyEl = document.getElementById("view-body");
    bodyEl.innerHTML = sc.bodyHtml;
    attachLinkPreviewHandlers(bodyEl);

    const attWrap = document.getElementById("view-attachments-wrap");
    const attList = document.getElementById("view-attachments");
    attList.innerHTML = "";
    if (sc.attachments && sc.attachments.length > 0) {
      attWrap.classList.remove("hidden");
      sc.attachments.forEach((a) => {
        const chip = document.createElement("button");
        chip.type = "button";
        chip.className = "attachment-chip";
        const riskClass = badgeClassForAttachmentRisk(a);
        const riskText = a.risk || "Cần kiểm tra trước khi mở";
        chip.innerHTML = `
          <div><strong>${escapeHtml(a.name)}</strong> <span class="badge badge-inline ${riskClass}">${escapeHtml(riskText)}</span></div>
          <span class="attachment-meta">${escapeHtml(a.size)} — Bấm để xem cảnh báo an toàn</span>
        `;
        chip.addEventListener("click", () => {
          alert(
            `Mô phỏng an toàn: Không tải hoặc mở tệp đính kèm thật.\n\nTên tệp: ${a.name}\nKích thước: ${a.size}\nĐánh giá rủi ro: ${riskText}`
          );
        });
        attList.appendChild(chip);
      });
    } else {
      attWrap.classList.add("hidden");
    }

    const existing = state.answers[sc.id];
    document.querySelectorAll('input[name="user-verdict"]').forEach((r) => {
      r.checked = Boolean(existing && existing.userVerdict === r.value);
    });
    document.querySelectorAll('#user-flags-grid input[type="checkbox"]').forEach((c) => {
      c.checked = Boolean(existing && existing.selectedFlags.includes(c.value));
    });

    renderFeedback(sc, existing);
  }

  function handleSubmitVerdict() {
    const sc = getScenarios().find((item) => item.id === state.currentScenarioId);
    if (!sc) return;

    const checkedRadio = document.querySelector('input[name="user-verdict"]:checked');
    if (!checkedRadio) {
      alert("Vui lòng chọn 'Email An toàn' hoặc 'Email Lừa đảo / Giả mạo' trước khi gửi.");
      return;
    }

    const selectedFlags = Array.from(document.querySelectorAll('#user-flags-grid input[type="checkbox"]:checked')).map(
      (c) => c.value
    );
    const expectedFlags = Array.isArray(sc.expectedFlags) ? sc.expectedFlags : [];
    const caughtFlags = expectedFlags.filter((f) => selectedFlags.includes(f));
    const missedFlags = expectedFlags.filter((f) => !selectedFlags.includes(f));
    const extraFlags = selectedFlags.filter((f) => !expectedFlags.includes(f));
    const isCorrect = checkedRadio.value === sc.verdict;

    state.answers[sc.id] = {
      userVerdict: checkedRadio.value,
      selectedFlags,
      isCorrect,
      caughtFlags,
      missedFlags,
      extraFlags
    };

    updateToolbarStats();
    renderScenarioList();
    renderFeedback(sc, state.answers[sc.id]);
  }

  function computeSkillStats(scenarios) {
    const stats = {};
    SKILL_FLAG_META.forEach((m) => {
      stats[m.key] = { key: m.key, label: m.label, short: m.short, expected: 0, caught: 0, missed: 0 };
    });

    scenarios.forEach((sc) => {
      const ans = state.answers[sc.id];
      if (!ans) return;
      const expectedFlags = Array.isArray(sc.expectedFlags) ? sc.expectedFlags : [];
      expectedFlags.forEach((flagKey) => {
        if (!stats[flagKey]) return;
        stats[flagKey].expected += 1;
        if (ans.caughtFlags.includes(flagKey)) {
          stats[flagKey].caught += 1;
        } else {
          stats[flagKey].missed += 1;
        }
      });
    });

    return SKILL_FLAG_META.map((m) => stats[m.key]);
  }

  function buildMarkdownSurveyRow(testerName) {
    const scenarios = getScenarios();
    const total = scenarios.length;
    const correctCount = Object.values(state.answers).filter((a) => a.isCorrect).length;
    const safeName = (testerName || "").trim().replace(/\|/g, "/") || "[Tên người thử nghiệm]";

    const wrongScenarios = scenarios
      .filter((sc) => state.answers[sc.id] && !state.answers[sc.id].isCorrect)
      .map((sc) => sc.shortLabel.replace(/\|/g, "/"));
    const wrongCol = wrongScenarios.length > 0 ? wrongScenarios.join(", ") : "Không có";

    const skillStats = computeSkillStats(scenarios);
    const missedSkills = skillStats
      .filter((s) => s.missed > 0)
      .sort((a, b) => b.missed - a.missed)
      .map((s) => `${s.short} (sót ${s.missed}/${s.expected})`);

    let noteCol = "Chưa hoàn thành lượt thử nghiệm.";
    if (Object.keys(state.answers).length > 0) {
      if (missedSkills.length > 0) {
        noteCol = `Cần chú ý thêm: ${missedSkills.slice(0, 3).join("; ")}.`;
      } else if (wrongScenarios.length > 0) {
        noteCol = "Phân biệt tốt Red Flags sau khi xem giải thích chi tiết.";
      } else {
        noteCol = "Nhận diện chính xác và chỉ rõ đầy đủ các Red Flags.";
      }
    }

    return `| ${safeName} | ${correctCount}/${total} | ${wrongCol} | ${noteCol} |`;
  }

  function refreshMarkdownPreview() {
    const nameInput = document.getElementById("tester-name-input");
    const previewEl = document.getElementById("md-export-preview");
    if (previewEl) {
      previewEl.value = buildMarkdownSurveyRow(nameInput ? nameInput.value : "");
    }
  }

  function openSummaryModal() {
    const scenarios = getScenarios();
    const answeredCount = Object.keys(state.answers).length;
    const correctCount = Object.values(state.answers).filter((a) => a.isCorrect).length;
    const pct = scenarios.length > 0 ? Math.round((correctCount / scenarios.length) * 100) : 0;

    const rows = scenarios
      .map((sc) => {
        const ans = state.answers[sc.id];
        const status = !ans ? "Chưa làm" : ans.isCorrect ? "Đúng" : "Sai";
        const expectedLen = Array.isArray(sc.expectedFlags) ? sc.expectedFlags.length : 0;
        const flagNote = !ans
          ? "—"
          : expectedLen > 0
            ? `Đúng ${ans.caughtFlags.length}/${expectedLen} (sót ${ans.missedFlags.length})`
            : ans.extraFlags.length === 0
              ? "Sạch (0 nhầm)"
              : `Nhầm ${ans.extraFlags.length} cờ`;

        return `<tr>
          <td>${escapeHtml(sc.shortLabel)}</td>
          <td>${escapeHtml(sc.attackType)}</td>
          <td><strong>${status}</strong></td>
          <td>${escapeHtml(flagNote)}</td>
        </tr>`;
      })
      .join("");

    const skillStats = computeSkillStats(scenarios);
    const skillRows = skillStats
      .map((s) => {
        const rate = s.expected > 0 ? Math.round((s.caught / s.expected) * 100) : null;
        const rateText = rate === null ? "Chưa gặp" : `${s.caught}/${s.expected} (${rate}%)`;
        const barWidth = rate === null ? 0 : rate;
        return `<tr>
          <td>${escapeHtml(s.label)}</td>
          <td>${escapeHtml(rateText)}</td>
          <td>
            <div class="skill-bar-wrap">
              <div class="skill-bar-track"><div class="skill-bar-fill" style="width:${barWidth}%"></div></div>
              <span>${rate === null ? "—" : rate + "%"}</span>
            </div>
          </td>
        </tr>`;
      })
      .join("");

    document.getElementById("summary-modal-body").innerHTML = `
      <p>Đã hoàn thành: <strong>${answeredCount}/${scenarios.length}</strong> kịch bản | Chính xác: <strong>${correctCount}/${scenarios.length} (${pct}%)</strong></p>
      <table class="meta-table">
        <thead><tr><th>Kịch bản</th><th>Phân loại</th><th>Phán đoán</th><th>Nhận diện Red Flags</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <h3 class="modal-section-title">Thống kê Tỷ lệ Nhận diện theo 6 Nhóm Kỹ năng</h3>
      <table class="meta-table">
        <thead><tr><th>Nhóm kỹ năng (Red Flag)</th><th>Số lần phát hiện</th><th>Tỷ lệ chính xác</th></tr></thead>
        <tbody>${skillRows}</tbody>
      </table>
    `;

    const statusEl = document.getElementById("copy-status-msg");
    if (statusEl) statusEl.textContent = "";
    refreshMarkdownPreview();
    document.getElementById("summary-modal").classList.remove("hidden");
  }

  function renderAnalyzerResult(res) {
    const outEl = document.getElementById("analyzer-output");
    outEl.classList.remove("hidden");

    const riskLabels = {
      safe: "Mức rủi ro THẤP (An toàn)",
      warning: "CẢNH BÁO (Cần kiểm tra thêm)",
      danger: "NGUY HIỂM CAO (Dấu hiệu Lừa đảo / Spoofing)"
    };

    const findingsHtml = res.findings
      .map(
        (f) => `<div class="finding-item ${escapeHtml(f.level)}">
          <strong>[${escapeHtml(f.level)}] ${escapeHtml(f.title)}:</strong> ${escapeHtml(f.detail)}
        </div>`
      )
      .join("");

    const attText =
      res.metadata.attachments.length > 0
        ? res.metadata.attachments.map(escapeHtml).join(", ")
        : "Không phát hiện tệp đính kèm";

    const tlsText =
      res.metadata.transportEncrypted === true
        ? "Có mã hóa TLS (ESMTPS)"
        : res.metadata.transportEncrypted === false
          ? "Không mã hóa (SMTP văn bản rõ)"
          : "Không có thông tin Received";

    const spfAlignBadge = res.alignment.spfAligned
      ? '<span class="badge badge-safe">SPF Alignment: Đạt</span>'
      : '<span class="badge badge-warning">SPF Alignment: Không đạt</span>';
    const dkimAlignBadge = res.alignment.dkimAligned
      ? '<span class="badge badge-safe">DKIM Alignment: Đạt</span>'
      : '<span class="badge badge-warning">DKIM Alignment: Không đạt</span>';
    const dmarcAlignBadge = res.alignment.dmarcAligned
      ? '<span class="badge badge-safe">DMARC Alignment: Đạt (PASS)</span>'
      : '<span class="badge badge-fail">DMARC Alignment: Trượt (FAIL)</span>';

    outEl.innerHTML = `
      <div class="risk-banner ${escapeHtml(res.riskLevel)}">
        <div><strong>${riskLabels[res.riskLevel] || "Không xác định"}</strong></div>
        <div>Điểm rủi ro ước lượng: <strong>${res.riskScore} / 100</strong></div>
      </div>

      <div class="auth-badges">
        <span class="badge ${badgeClassForAuth(res.metadata.auth.spf)}">SPF: ${escapeHtml(res.metadata.auth.spf)}</span>
        <span class="badge ${badgeClassForAuth(res.metadata.auth.dkim)}">DKIM: ${escapeHtml(res.metadata.auth.dkim)}</span>
        <span class="badge ${badgeClassForAuth(res.metadata.auth.dmarc)}">DMARC: ${escapeHtml(res.metadata.auth.dmarc)}</span>
        ${spfAlignBadge}
        ${dkimAlignBadge}
        ${dmarcAlignBadge}
      </div>

      <table class="meta-table">
        <tr><th>From</th><td>${escapeHtml(res.metadata.from.raw || "(Không có)")}</td></tr>
        <tr><th>Return-Path</th><td>${escapeHtml(res.metadata.returnPath.raw || "(Không có)")}</td></tr>
        <tr><th>Reply-To</th><td>${escapeHtml(res.metadata.replyTo.raw || "(Không có)")}</td></tr>
        <tr><th>Subject</th><td>${escapeHtml(res.metadata.subject || "(Không có)")}</td></tr>
        <tr><th>DKIM Domain / Selector</th><td>${escapeHtml(res.metadata.dkimDomain || "—")} / ${escapeHtml(res.metadata.dkimSelector || "—")}</td></tr>
        <tr><th>Số hop Received / IP nguồn</th><td>${res.metadata.receivedCount} hop${res.metadata.senderIp ? " (IP: " + escapeHtml(res.metadata.senderIp) + ")" : ""}</td></tr>
        <tr><th>Mã hóa đường truyền (TLS)</th><td>${escapeHtml(tlsText)}</td></tr>
        <tr><th>Tệp đính kèm phát hiện</th><td>${attText}</td></tr>
      </table>

      <h3>Chi tiết Phát hiện Kỹ thuật</h3>
      <div class="findings-list">${findingsHtml}</div>
    `;
  }

  function setupAnalyzerTab() {
    const quickWrap = document.getElementById("quick-sample-buttons");
    const inputEl = document.getElementById("raw-header-input");

    getScenarios().forEach((sc) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "quick-btn";
      btn.textContent = sc.shortLabel;
      btn.addEventListener("click", () => {
        inputEl.value = sc.rawEml;
        if (window.EmailHeaderAnalyzer) {
          renderAnalyzerResult(window.EmailHeaderAnalyzer.analyzeEmail(inputEl.value));
        }
      });
      quickWrap.appendChild(btn);
    });

    document.getElementById("eml-file-input").addEventListener("change", (e) => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        inputEl.value = String(reader.result || "");
        if (window.EmailHeaderAnalyzer) {
          renderAnalyzerResult(window.EmailHeaderAnalyzer.analyzeEmail(inputEl.value));
        }
      };
      reader.readAsText(file, "UTF-8");
    });

    document.getElementById("btn-analyze").addEventListener("click", () => {
      if (window.EmailHeaderAnalyzer) {
        renderAnalyzerResult(window.EmailHeaderAnalyzer.analyzeEmail(inputEl.value));
      }
    });

    document.getElementById("btn-clear-analyzer").addEventListener("click", () => {
      inputEl.value = "";
      document.getElementById("analyzer-output").classList.add("hidden");
    });
  }

  function setupSummaryExportControls() {
    const nameInput = document.getElementById("tester-name-input");
    const copyBtn = document.getElementById("btn-copy-md-row");
    const previewEl = document.getElementById("md-export-preview");
    const statusEl = document.getElementById("copy-status-msg");

    if (nameInput) {
      nameInput.addEventListener("input", () => {
        refreshMarkdownPreview();
        if (statusEl) statusEl.textContent = "";
      });
    }

    if (copyBtn && previewEl) {
      copyBtn.addEventListener("click", async () => {
        const text = previewEl.value;
        let copied = false;
        if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
          try {
            await navigator.clipboard.writeText(text);
            copied = true;
          } catch (_err) {
            copied = false;
          }
        }
        if (!copied) {
          previewEl.focus();
          previewEl.select();
          try {
            copied = document.execCommand("copy");
          } catch (_err) {
            copied = false;
          }
        }
        if (statusEl) {
          statusEl.textContent = copied
            ? "Đã sao chép dòng Markdown!"
            : "Hãy chọn và nhấn Ctrl+C ở ô bên dưới.";
        }
      });
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    setupTabs();
    setupAnalyzerTab();
    setupSummaryExportControls();
    updateToolbarStats();

    document.getElementById("btn-toggle-header").addEventListener("click", () => {
      state.headerVisible = !state.headerVisible;
      document.getElementById("raw-header-box").classList.toggle("hidden", !state.headerVisible);
      document.getElementById("btn-toggle-header").textContent = state.headerVisible
        ? "Ẩn Raw Header"
        : "Soi Raw Header & Xác thực";
    });

    const sendBtn = document.getElementById("btn-send-to-analyzer");
    if (sendBtn) {
      sendBtn.addEventListener("click", () => {
        const sc = getScenarios().find((item) => item.id === state.currentScenarioId);
        if (!sc) return;
        const inputEl = document.getElementById("raw-header-input");
        inputEl.value = sc.rawEml;
        activateTab("analyzer");
        if (window.EmailHeaderAnalyzer) {
          renderAnalyzerResult(window.EmailHeaderAnalyzer.analyzeEmail(sc.rawEml));
          const outEl = document.getElementById("analyzer-output");
          if (outEl && typeof outEl.scrollIntoView === "function") {
            outEl.scrollIntoView({ behavior: "smooth", block: "start" });
          }
        }
      });
    }

    document.getElementById("btn-submit-verdict").addEventListener("click", handleSubmitVerdict);

    document.getElementById("btn-reset").addEventListener("click", () => {
      state.answers = {};
      updateToolbarStats();
      const scenarios = getScenarios();
      if (scenarios.length > 0) selectScenario(scenarios[0].id);
    });

    document.getElementById("btn-summary").addEventListener("click", openSummaryModal);
    document.getElementById("btn-close-modal").addEventListener("click", () => {
      document.getElementById("summary-modal").classList.add("hidden");
    });

    const scenarios = getScenarios();
    if (scenarios.length > 0) {
      selectScenario(scenarios[0].id);
    }
  });
})();
