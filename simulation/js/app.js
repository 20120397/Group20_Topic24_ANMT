/**
 * Logic giao diện Web App Mô phỏng Nhận diện Email Lừa đảo (Offline).
 * Phụ trách: Thành viên 3 (Auth & Simulation Engineer).
 */

(function () {
  if (typeof document === "undefined") return;

  const state = {
    currentScenarioId: null,
    headerVisible: false,
    answers: {} // scenarioId -> { userVerdict, selectedFlags, isCorrect }
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

  function getScenarios() {
    return Array.isArray(window.EMAIL_SCENARIOS) ? window.EMAIL_SCENARIOS : [];
  }

  function setupTabs() {
    const tabBtns = document.querySelectorAll(".tab-btn");
    const panels = document.querySelectorAll(".tab-panel");
    tabBtns.forEach((btn) => {
      btn.addEventListener("click", () => {
        const target = btn.getAttribute("data-tab");
        tabBtns.forEach((b) => b.classList.remove("active"));
        panels.forEach((p) => p.classList.remove("active"));
        btn.classList.add("active");
        const panel = document.getElementById("panel-" + target);
        if (panel) panel.classList.add("active");
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

    const itemsHtml = sc.flagsDetail.map((d) => `<li>${escapeHtml(d)}</li>`).join("");
    panel.innerHTML = `
      <strong>${resultTitle}</strong> — Đáp án đúng: <strong>${actualLabel}</strong> (${escapeHtml(sc.attackType)})
      <p>${escapeHtml(sc.explanation)}</p>
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
    if (sc.attachments && sc.attachments.length > 0) {
      attWrap.classList.remove("hidden");
      attList.innerHTML = sc.attachments
        .map((a) => `<div class="attachment-chip"><strong>${escapeHtml(a.name)}</strong> — ${escapeHtml(a.size)}</div>`)
        .join("");
    } else {
      attWrap.classList.add("hidden");
      attList.innerHTML = "";
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

    const selectedFlags = Array.from(document.querySelectorAll('#user-flags-grid input[type="checkbox"]:checked')).map((c) => c.value);
    const isCorrect = checkedRadio.value === sc.verdict;

    state.answers[sc.id] = {
      userVerdict: checkedRadio.value,
      selectedFlags,
      isCorrect
    };

    updateToolbarStats();
    renderScenarioList();
    renderFeedback(sc, state.answers[sc.id]);
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
        return `<tr>
          <td>${escapeHtml(sc.shortLabel)}</td>
          <td>${escapeHtml(sc.attackType)}</td>
          <td><strong>${status}</strong></td>
        </tr>`;
      })
      .join("");

    document.getElementById("summary-modal-body").innerHTML = `
      <p>Đã hoàn thành: <strong>${answeredCount}/${scenarios.length}</strong> kịch bản | Chính xác: <strong>${correctCount}/${scenarios.length} (${pct}%)</strong></p>
      <table class="meta-table">
        <thead><tr><th>Kịch bản</th><th>Phân loại</th><th>Kết quả</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    `;
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

    const attText = res.metadata.attachments.length > 0 ? res.metadata.attachments.map(escapeHtml).join(", ") : "Không phát hiện tệp đính kèm";

    outEl.innerHTML = `
      <div class="risk-banner ${escapeHtml(res.riskLevel)}">
        <div><strong>${riskLabels[res.riskLevel] || "Không xác định"}</strong></div>
        <div>Điểm rủi ro ước lượng: <strong>${res.riskScore} / 100</strong></div>
      </div>

      <div class="auth-badges">
        <span class="badge ${badgeClassForAuth(res.metadata.auth.spf)}">SPF: ${escapeHtml(res.metadata.auth.spf)}</span>
        <span class="badge ${badgeClassForAuth(res.metadata.auth.dkim)}">DKIM: ${escapeHtml(res.metadata.auth.dkim)}</span>
        <span class="badge ${badgeClassForAuth(res.metadata.auth.dmarc)}">DMARC: ${escapeHtml(res.metadata.auth.dmarc)}</span>
        <span class="badge ${res.alignment.spfAligned ? "badge-safe" : "badge-warning"}">SPF Alignment: ${res.alignment.spfAligned ? "Khớp" : "Không khớp / Thiếu"}</span>
      </div>

      <table class="meta-table">
        <tr><th>From</th><td>${escapeHtml(res.metadata.from.raw || "(Không có)")}</td></tr>
        <tr><th>Return-Path</th><td>${escapeHtml(res.metadata.returnPath.raw || "(Không có)")}</td></tr>
        <tr><th>Reply-To</th><td>${escapeHtml(res.metadata.replyTo.raw || "(Không có)")}</td></tr>
        <tr><th>Subject</th><td>${escapeHtml(res.metadata.subject || "(Không có)")}</td></tr>
        <tr><th>DKIM Domain / Selector</th><td>${escapeHtml(res.metadata.dkimDomain || "—")} / ${escapeHtml(res.metadata.dkimSelector || "—")}</td></tr>
        <tr><th>Số hop Received</th><td>${res.metadata.receivedCount}</td></tr>
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

  document.addEventListener("DOMContentLoaded", () => {
    setupTabs();
    setupAnalyzerTab();
    updateToolbarStats();

    document.getElementById("btn-toggle-header").addEventListener("click", () => {
      state.headerVisible = !state.headerVisible;
      document.getElementById("raw-header-box").classList.toggle("hidden", !state.headerVisible);
      document.getElementById("btn-toggle-header").textContent = state.headerVisible
        ? "Ẩn Raw Header"
        : "Soi Raw Header & Xác thực";
    });

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
