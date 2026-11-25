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

  const state = {
    currentScenarioId: null,
    headerVisible: false,
    toastTimer: null,
    answers: {} // scenarioId -> { userVerdict, selectedFlags, isCorrect, caughtFlags, missedFlags, extraFlags }
  };

  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function getInitials(name) {
    const words = String(name || "")
      .replace(/[^a-zA-Z0-9\u00C0-\u024F\s]/g, " ")
      .trim()
      .split(/\s+/)
      .filter(Boolean);
    if (words.length === 0) return "EM";
    if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
    return (words[0][0] + words[words.length - 1][0]).toUpperCase();
  }

  function getAvatarToneIndex(id) {
    let hash = 0;
    const str = String(id || "");
    for (let i = 0; i < str.length; i++) {
      hash = (hash * 31 + str.charCodeAt(i)) % 6;
    }
    return Math.abs(hash) % 6;
  }

  function formatHighlightedHeaders(rawEml) {
    const text = String(rawEml || "");
    const splitIdx = text.search(/\r?\n\r?\n/);
    const headerPart = splitIdx >= 0 ? text.slice(0, splitIdx) : text;
    const bodyPart = splitIdx >= 0 ? text.slice(splitIdx) : "";

    const highlightedHeader = escapeHtml(headerPart)
      .split(/\r?\n/)
      .map((line) => line.replace(/^([A-Za-z0-9-]+):/, '<span class="hdr-key">$1:</span>'))
      .join("\n");

    return highlightedHeader + escapeHtml(bodyPart);
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

  function showSandboxToast(title, detail, tone = "info") {
    const toast = document.getElementById("sandbox-toast");
    const titleEl = document.getElementById("toast-title");
    const detailEl = document.getElementById("toast-detail");
    if (!toast || !titleEl || !detailEl) return;

    titleEl.textContent = title;
    detailEl.textContent = detail;
    toast.classList.remove("hidden", "toast-danger", "toast-safe");
    if (tone === "danger") toast.classList.add("toast-danger");
    if (tone === "safe") toast.classList.add("toast-safe");

    if (state.toastTimer) clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => {
      toast.classList.add("hidden");
    }, 5500);
  }

  function setInlineDecisionError(msg) {
    const errEl = document.getElementById("decision-error");
    if (!errEl) return;
    if (!msg) {
      errEl.textContent = "";
      errEl.classList.add("hidden");
    } else {
      errEl.textContent = msg;
      errEl.classList.remove("hidden");
    }
  }

  function updateHeaderToggleLabel(isOpen) {
    const labelEl = document.getElementById("toggle-header-label");
    if (labelEl) {
      labelEl.textContent = isOpen ? "Ẩn Raw Header" : "Soi Raw Header";
    } else {
      const btn = document.getElementById("btn-toggle-header");
      if (btn) btn.textContent = isOpen ? "Ẩn Raw Header" : "Soi Raw Header";
    }
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
        const target = btn.getAttribute("data-tab");
        activateTab(target);
        try {
          if (typeof window !== "undefined" && window.history && typeof window.history.replaceState === "function") {
            window.history.replaceState(null, "", "#" + target);
          }
        } catch (_err) {
          // Ignore under restricted file:// origins
        }
      });
    });
  }

  function updateToolbarStats() {
    const scenarios = getScenarios();
    const total = scenarios.length;
    const answered = Object.keys(state.answers).length;
    const correct = Object.values(state.answers).filter((a) => a.isCorrect).length;
    const accuracy = answered > 0 ? Math.round((correct / answered) * 100) : 0;
    const progressPct = total > 0 ? Math.round((answered / total) * 100) : 0;

    document.getElementById("stat-progress").textContent = `${answered} / ${total}`;
    document.getElementById("stat-score").textContent = `${correct} / ${total}`;
    document.getElementById("stat-accuracy").textContent = `${accuracy}%`;

    const fillEl = document.getElementById("topbar-progress-fill");
    if (fillEl) {
      fillEl.style.width = `${progressPct}%`;
    }

    const listTitle = document.getElementById("inbox-list-title");
    if (listTitle) {
      listTitle.textContent = `Hộp thư đến (${total} kịch bản)`;
    }

    const unreadPill = document.getElementById("rail-unread-count");
    if (unreadPill) {
      const remaining = Math.max(0, total - answered);
      unreadPill.textContent = remaining === 0 ? "Hoàn tất" : `${remaining} chờ xét`;
    }
  }

  function renderScenarioList() {
    const listEl = document.getElementById("scenario-list");
    const scenarios = getScenarios();
    listEl.innerHTML = "";

    scenarios.forEach((sc) => {
      const ans = state.answers[sc.id];
      const statusHtml = ans
        ? ans.isCorrect
          ? '<span class="badge badge-pass">Đúng</span>'
          : '<span class="badge badge-fail">Sai</span>'
        : '<span class="unread-dot" title="Chưa đánh giá"></span>';

      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "scenario-item" + (sc.id === state.currentScenarioId ? " active" : "");
      btn.innerHTML = `
        <span class="avatar avatar-tone-${getAvatarToneIndex(sc.id)}" aria-hidden="true">${escapeHtml(getInitials(sc.senderName))}</span>
        <span class="scenario-body">
          <span class="scenario-item-top">
            <span class="scenario-sender">${escapeHtml(sc.senderName || sc.shortLabel)}</span>
            ${statusHtml}
          </span>
          <span class="scenario-tag-mini">${escapeHtml(sc.shortLabel)}</span>
          <span class="scenario-subj">${escapeHtml(sc.subject)}</span>
        </span>
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
      const showBar = () => {
        if (!previewBar) return;
        previewBar.textContent = "URL đích thực tế: " + targetUrl;
        previewBar.classList.remove("hidden");
      };
      const hideBar = () => {
        if (!previewBar) return;
        previewBar.classList.add("hidden");
      };
      link.addEventListener("mouseenter", showBar);
      link.addEventListener("focus", showBar);
      link.addEventListener("mouseleave", hideBar);
      link.addEventListener("blur", hideBar);
      link.addEventListener("click", (e) => {
        e.preventDefault();
        showSandboxToast("Đã chặn mở liên kết ngoài (Offline Safe Lab)", "URL đích thực tế: " + targetUrl, "info");
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

  function findNextScenarioId(currentId) {
    const scenarios = getScenarios();
    if (scenarios.length <= 1) return null;
    const idx = scenarios.findIndex((s) => s.id === currentId);
    const nextUnanswered = scenarios.find((s) => s.id !== currentId && !state.answers[s.id]);
    if (nextUnanswered) return nextUnanswered.id;
    return scenarios[(idx + 1) % scenarios.length].id;
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

    const nextId = findNextScenarioId(sc.id);
    const itemsHtml = sc.flagsDetail.map((d) => `<li>${escapeHtml(d)}</li>`).join("");
    panel.innerHTML = `
      <div class="feedback-head">
        <div><strong>${resultTitle}</strong> — Đáp án đúng: <strong>${actualLabel}</strong></div>
        <span class="badge badge-neutral">${escapeHtml(sc.attackType)}</span>
      </div>
      <p>${escapeHtml(sc.explanation)}</p>
      ${flagReviewHtml}
      <ul>${itemsHtml}</ul>
      ${
        nextId
          ? `<div class="feedback-footer">
               <button type="button" class="btn btn-secondary btn-xs btn-next-scenario" data-next-id="${escapeHtml(nextId)}">Email tiếp theo &rarr;</button>
             </div>`
          : ""
      }
    `;

    const nextBtn = typeof panel.querySelector === "function" ? panel.querySelector(".btn-next-scenario") : null;
    if (nextBtn) {
      nextBtn.addEventListener("click", () => selectScenario(nextId));
    }
  }

  function selectScenario(id) {
    const scenarios = getScenarios();
    const idx = scenarios.findIndex((item) => item.id === id);
    const sc = idx >= 0 ? scenarios[idx] : null;
    if (!sc) return;

    state.currentScenarioId = id;
    state.headerVisible = false;
    setInlineDecisionError("");
    renderScenarioList();

    const posEl = document.getElementById("mail-position-label");
    if (posEl) posEl.textContent = `Thư ${idx + 1} / ${scenarios.length}`;

    const prevBtn = document.getElementById("btn-prev-mail");
    if (prevBtn) prevBtn.disabled = idx <= 0;

    const nextBtn = document.getElementById("btn-next-mail");
    if (nextBtn) nextBtn.disabled = idx >= scenarios.length - 1;

    const tagEl = document.getElementById("inspector-scenario-tag");
    if (tagEl) tagEl.textContent = sc.shortLabel;

    document.getElementById("view-subject").textContent = sc.subject;
    document.getElementById("view-from").textContent = `${sc.senderName} <${sc.senderEmail}>`;
    document.getElementById("view-to").textContent = sc.to;
    document.getElementById("view-date").textContent = sc.date;
    document.getElementById("view-return-path").textContent = sc.returnPath;

    const avatarEl = document.getElementById("view-avatar");
    if (avatarEl) {
      avatarEl.textContent = getInitials(sc.senderName);
      avatarEl.className = `avatar avatar-lg avatar-tone-${getAvatarToneIndex(sc.id)}`;
    }

    const replyRow = document.getElementById("view-reply-to-row");
    if (sc.replyTo) {
      replyRow.classList.remove("hidden");
      document.getElementById("view-reply-to").textContent = sc.replyTo;
    } else {
      replyRow.classList.add("hidden");
    }

    const headerBox = document.getElementById("raw-header-box");
    headerBox.classList.add("hidden");
    updateHeaderToggleLabel(false);

    const badgesEl = document.getElementById("view-auth-badges");
    badgesEl.innerHTML = `
      <span class="badge ${badgeClassForAuth(sc.auth.spf)}">SPF: ${sc.auth.spf}</span>
      <span class="badge ${badgeClassForAuth(sc.auth.dkim)}">DKIM: ${sc.auth.dkim}</span>
      <span class="badge ${badgeClassForAuth(sc.auth.dmarc)}">DMARC: ${sc.auth.dmarc}</span>
    `;
    document.getElementById("view-raw-headers").innerHTML = formatHighlightedHeaders(sc.rawEml);

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
          <svg class="attachment-chip-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l8.57-8.57A4 4 0 1 1 18 8.84l-8.59 8.57a2 2 0 0 1-2.83-2.83l8.49-8.48"/>
          </svg>
          <span class="attachment-chip-info">
            <span class="attachment-chip-top"><strong>${escapeHtml(a.name)}</strong> <span class="badge badge-inline ${riskClass}">${escapeHtml(riskText)}</span></span>
            <span class="attachment-meta">${escapeHtml(a.size)} · Bấm để xem cảnh báo mô phỏng</span>
          </span>
        `;
        chip.addEventListener("click", () => {
          showSandboxToast(
            "Tệp đính kèm mô phỏng (Không tải/thực thi thật)",
            `${a.name} (${a.size}) — ${riskText}`,
            riskClass === "badge-danger" ? "danger" : "safe"
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
      setInlineDecisionError("Vui lòng chọn kết luận 'Email An toàn' hoặc 'Lừa đảo / Giả mạo' trước khi gửi.");
      return;
    }
    setInlineDecisionError("");

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

    const skillStats = computeSkillStats(scenarios);
    const totalExpectedFlags = skillStats.reduce((sum, s) => sum + s.expected, 0);
    const totalCaughtFlags = skillStats.reduce((sum, s) => sum + s.caught, 0);
    const flagCoverage = totalExpectedFlags > 0 ? Math.round((totalCaughtFlags / totalExpectedFlags) * 100) + "%" : "—";

    const rows = scenarios
      .map((sc) => {
        const ans = state.answers[sc.id];
        const statusBadge = !ans
          ? '<span class="badge badge-none">Chưa làm</span>'
          : ans.isCorrect
            ? '<span class="badge badge-pass">Đúng</span>'
            : '<span class="badge badge-fail">Sai</span>';
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
          <td>${statusBadge}</td>
          <td>${escapeHtml(flagNote)}</td>
        </tr>`;
      })
      .join("");

    const skillRows = skillStats
      .map((s) => {
        const rate = s.expected > 0 ? Math.round((s.caught / s.expected) * 100) : null;
        const rateText = rate === null ? "Chưa gặp" : `${s.caught}/${s.expected}`;
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
      <div class="kpi-grid">
        <div class="kpi-tile">
          <div class="kpi-label">Tiến độ thực hành</div>
          <div class="kpi-val">${answeredCount} / ${scenarios.length}</div>
        </div>
        <div class="kpi-tile">
          <div class="kpi-label">Phán đoán chính xác</div>
          <div class="kpi-val">${correctCount} / ${scenarios.length} (${pct}%)</div>
        </div>
        <div class="kpi-tile">
          <div class="kpi-label">Độ phủ Red Flags</div>
          <div class="kpi-val">${flagCoverage}</div>
        </div>
      </div>

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

  function cellToneForAuth(val) {
    if (val === "pass") return "cell-safe";
    if (val === "softfail" || val === "none") return "cell-warning";
    if (val === "fail") return "cell-danger";
    return "";
  }

  function statusSvgForTone(tone) {
    if (tone === "cell-safe") {
      return '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>';
    }
    if (tone === "cell-danger") {
      return '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
    }
    return '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
  }

  function renderRiskRingSvg(score, riskLevel) {
    const safeScore = Math.max(0, Math.min(100, Number(score) || 0));
    const radius = 32;
    const circumference = 2 * Math.PI * radius;
    const dashOffset = circumference * (1 - safeScore / 100);
    return `
      <div class="risk-ring-wrap" aria-label="Điểm rủi ro ${safeScore} trên 100">
        <svg class="risk-ring-svg" width="78" height="78" viewBox="0 0 78 78" aria-hidden="true">
          <circle class="risk-ring-bg" cx="39" cy="39" r="${radius}"></circle>
          <circle class="risk-ring-fg ${escapeHtml(riskLevel)}" cx="39" cy="39" r="${radius}"
            stroke-dasharray="${circumference.toFixed(2)}"
            stroke-dashoffset="${dashOffset.toFixed(2)}"></circle>
        </svg>
        <div class="risk-ring-center">
          <span class="risk-ring-num">${safeScore}</span>
          <span class="risk-ring-max">/ 100</span>
        </div>
      </div>
    `;
  }

  function renderAnalyzerResult(res) {
    const emptyEl = document.getElementById("analyzer-empty");
    if (emptyEl) emptyEl.classList.add("hidden");

    const outEl = document.getElementById("analyzer-output");
    outEl.classList.remove("hidden");

    const riskLabels = {
      safe: "Mức rủi ro THẤP (Email An toàn)",
      warning: "CẢNH BÁO (Cần kiểm tra thêm)",
      danger: "NGUY HIỂM CAO (Dấu hiệu Lừa đảo / Spoofing)"
    };

    const riskHints = {
      safe: "Các lớp xác thực DNS khớp định danh và không phát hiện dấu hiệu giả mạo.",
      warning: "Một số chỉ báo chưa chuẩn hoặc thiếu xác thực; cần xác minh thủ công.",
      danger: "Phát hiện dấu hiệu kỹ thuật nghiêm trọng (Spoofing, URL ngụy trang hoặc Tệp độc hại)."
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

    const matrixCells = [
      { label: "SPF", val: res.metadata.auth.spf.toUpperCase(), tone: cellToneForAuth(res.metadata.auth.spf) },
      { label: "DKIM", val: res.metadata.auth.dkim.toUpperCase(), tone: cellToneForAuth(res.metadata.auth.dkim) },
      { label: "DMARC", val: res.metadata.auth.dmarc.toUpperCase(), tone: cellToneForAuth(res.metadata.auth.dmarc) },
      {
        label: "SPF Alignment",
        val: res.alignment.spfAligned ? "Đạt" : "Không đạt",
        tone: res.alignment.spfAligned ? "cell-safe" : "cell-warning"
      },
      {
        label: "DKIM Alignment",
        val: res.alignment.dkimAligned ? "Đạt" : "Không đạt",
        tone: res.alignment.dkimAligned ? "cell-safe" : "cell-warning"
      },
      {
        label: "DMARC Alignment",
        val: res.alignment.dmarcAligned ? "Đạt (PASS)" : "Trượt (FAIL)",
        tone: res.alignment.dmarcAligned ? "cell-safe" : "cell-danger"
      }
    ];

    const matrixHtml = matrixCells
      .map(
        (c) => `
        <div class="auth-cell ${c.tone}">
          <div class="auth-cell-head">
            <span class="auth-cell-label">${escapeHtml(c.label)}</span>
            <span class="auth-cell-icon">${statusSvgForTone(c.tone)}</span>
          </div>
          <span class="auth-cell-val">${escapeHtml(c.val)}</span>
        </div>
      `
      )
      .join("");

    const metaPairs = [
      { k: "From", v: res.metadata.from.raw || "(Không có)", mono: true },
      { k: "Return-Path", v: res.metadata.returnPath.raw || "(Không có)", mono: true },
      { k: "Reply-To", v: res.metadata.replyTo.raw || "(Không có)", mono: true },
      { k: "Subject", v: res.metadata.subject || "(Không có)", mono: false },
      {
        k: "DKIM Domain / Selector",
        v: `${res.metadata.dkimDomain || "—"} / ${res.metadata.dkimSelector || "—"}`,
        mono: true
      },
      {
        k: "Received / IP nguồn",
        v: `${res.metadata.receivedCount} hop${res.metadata.senderIp ? " (" + res.metadata.senderIp + ")" : ""}`,
        mono: true
      },
      { k: "Mã hóa đường truyền (TLS)", v: tlsText, mono: false },
      { k: "Tệp đính kèm", v: attText, mono: true }
    ];

    const metaGridHtml = metaPairs
      .map(
        (m) => `
        <div class="meta-kv-item">
          <div class="meta-kv-k">${escapeHtml(m.k)}</div>
          <div class="meta-kv-v${m.mono ? " mono" : ""}">${escapeHtml(m.v)}</div>
        </div>
      `
      )
      .join("");

    outEl.innerHTML = `
      <div class="risk-score-header ${escapeHtml(res.riskLevel)}">
        <div>
          <div class="risk-kicker">KẾT QUẢ KIỂM TRA HEADER TĨNH</div>
          <div class="risk-headline">${riskLabels[res.riskLevel] || "Không xác định"}</div>
          <div class="risk-subline">${riskHints[res.riskLevel] || ""}</div>
        </div>
        ${renderRiskRingSvg(res.riskScore, res.riskLevel)}
      </div>

      <div class="auth-matrix">${matrixHtml}</div>

      <div class="meta-kv-grid">${metaGridHtml}</div>

      <h3 class="findings-heading">Chi tiết Phát hiện Kỹ thuật (${res.findings.length})</h3>
      <div class="findings-list">${findingsHtml}</div>
    `;
  }

  function setActiveQuickButton(scenarioId) {
    const quickWrap = document.getElementById("quick-sample-buttons");
    if (!quickWrap) return;
    Array.from(quickWrap.children).forEach((btn) => {
      if (btn && btn.classList) {
        btn.classList.toggle("active", btn.getAttribute("data-sample-id") === scenarioId);
      }
    });
  }

  function setupAnalyzerTab() {
    const quickWrap = document.getElementById("quick-sample-buttons");
    const inputEl = document.getElementById("raw-header-input");

    getScenarios().forEach((sc) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "quick-btn";
      btn.setAttribute("data-sample-id", sc.id);
      btn.textContent = sc.shortLabel;
      btn.addEventListener("click", () => {
        setActiveQuickButton(sc.id);
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
      setActiveQuickButton("");
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
      setActiveQuickButton("");
      inputEl.value = "";
      document.getElementById("analyzer-output").classList.add("hidden");
      const emptyEl = document.getElementById("analyzer-empty");
      if (emptyEl) emptyEl.classList.remove("hidden");
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

  function applyInitialRoute() {
    const hash = typeof window !== "undefined" && window.location && window.location.hash ? window.location.hash : "";
    if (!hash) return false;

    const clean = hash.replace(/^#/, "");
    const [tabPart, queryPart] = clean.split("?");
    let sampleParam = "";
    if (queryPart) {
      const m = queryPart.match(/(?:^|&)sample=([^&]+)/);
      if (m) sampleParam = decodeURIComponent(m[1]);
    }

    if (tabPart === "analyzer") {
      activateTab("analyzer");
      if (sampleParam) {
        const sc = getScenarios().find((s) => s.id === sampleParam);
        if (sc) {
          setActiveQuickButton(sc.id);
          const inputEl = document.getElementById("raw-header-input");
          inputEl.value = sc.rawEml;
          if (window.EmailHeaderAnalyzer) {
            renderAnalyzerResult(window.EmailHeaderAnalyzer.analyzeEmail(sc.rawEml));
          }
        }
      }
      return true;
    }
    if (tabPart === "guide") {
      activateTab("guide");
      return true;
    }
    if (tabPart === "inbox" && sampleParam) {
      activateTab("inbox");
      selectScenario(sampleParam);
      return true;
    }
    return false;
  }

  document.addEventListener("DOMContentLoaded", () => {
    setupTabs();
    setupAnalyzerTab();
    setupSummaryExportControls();
    updateToolbarStats();

    document.getElementById("btn-toggle-header").addEventListener("click", () => {
      state.headerVisible = !state.headerVisible;
      document.getElementById("raw-header-box").classList.toggle("hidden", !state.headerVisible);
      updateHeaderToggleLabel(state.headerVisible);
    });

    const prevMailBtn = document.getElementById("btn-prev-mail");
    if (prevMailBtn) {
      prevMailBtn.addEventListener("click", () => {
        const scenarios = getScenarios();
        const idx = scenarios.findIndex((s) => s.id === state.currentScenarioId);
        if (idx > 0) selectScenario(scenarios[idx - 1].id);
      });
    }

    const nextMailBtn = document.getElementById("btn-next-mail");
    if (nextMailBtn) {
      nextMailBtn.addEventListener("click", () => {
        const scenarios = getScenarios();
        const idx = scenarios.findIndex((s) => s.id === state.currentScenarioId);
        if (idx >= 0 && idx < scenarios.length - 1) selectScenario(scenarios[idx + 1].id);
      });
    }

    const sendBtn = document.getElementById("btn-send-to-analyzer");
    if (sendBtn) {
      sendBtn.addEventListener("click", () => {
        const sc = getScenarios().find((item) => item.id === state.currentScenarioId);
        if (!sc) return;
        const inputEl = document.getElementById("raw-header-input");
        inputEl.value = sc.rawEml;
        setActiveQuickButton(sc.id);
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

    document.querySelectorAll('input[name="user-verdict"]').forEach((r) => {
      r.addEventListener("change", () => setInlineDecisionError(""));
    });

    document.getElementById("btn-submit-verdict").addEventListener("click", handleSubmitVerdict);

    document.getElementById("btn-reset").addEventListener("click", () => {
      state.answers = {};
      setInlineDecisionError("");
      updateToolbarStats();
      const scenarios = getScenarios();
      if (scenarios.length > 0) selectScenario(scenarios[0].id);
    });

    document.getElementById("btn-summary").addEventListener("click", openSummaryModal);
    document.getElementById("btn-close-modal").addEventListener("click", () => {
      document.getElementById("summary-modal").classList.add("hidden");
    });

    const modalEl = document.getElementById("summary-modal");
    if (modalEl) {
      modalEl.addEventListener("click", (e) => {
        if (e.target === modalEl) {
          modalEl.classList.add("hidden");
        }
      });
    }

    const closeToastBtn = document.getElementById("btn-close-toast");
    if (closeToastBtn) {
      closeToastBtn.addEventListener("click", () => {
        document.getElementById("sandbox-toast").classList.add("hidden");
      });
    }

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && modalEl && !modalEl.classList.contains("hidden")) {
        modalEl.classList.add("hidden");
      }
    });

    const scenarios = getScenarios();
    if (scenarios.length > 0) {
      selectScenario(scenarios[0].id);
    }
    applyInitialRoute();
  });
})();
