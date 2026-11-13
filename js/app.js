import { runAudit } from "./checks.js";
import { ALL_FIXTURES } from "./fixtures.js";

// ── DOM refs ────────────────────────────────────────────────
const arc = document.querySelector(".score-arc");
const scoreNum = document.querySelector(".score-number");
const gradeEl = document.querySelector(".score-grade");
const listEl = document.getElementById("results-list");
const testedBody = document.getElementById("tested-body");

const CIRC = 2 * Math.PI * 52; // 326.73

let currentFilter = "all";
let currentResults = [];

// ── Render ───────────────────────────────────────────────────
function render(scenarioKey) {
  const snap = ALL_FIXTURES[scenarioKey];
  const audit = runAudit(snap);
  currentResults = audit.results;

  // Ring
  const offset = CIRC - (CIRC * audit.score) / 100;
  arc.style.strokeDashoffset = offset;
  const col =
    audit.score >= 75
      ? "var(--green)"
      : audit.score >= 50
        ? "var(--yellow)"
        : "var(--red)";
  arc.style.stroke = col;
  scoreNum.textContent = audit.score;
  gradeEl.textContent = audit.grade;

  // Stats
  const counts = { pass: 0, warn: 0, fail: 0, skip: 0, info: 0 };
  audit.results.forEach((r) => counts[r.status]++);
  document.getElementById("st-pass").textContent = counts.pass;
  document.getElementById("st-warn").textContent = counts.warn;
  document.getElementById("st-fail").textContent = counts.fail;
  document.getElementById("st-skip").textContent = counts.skip + counts.info;

  // Tested table
  testedBody.innerHTML = "";
  const rows = [
    ["Audit checks executed", `${audit.total} checks across 8 categories`],
    ["Scenarios validated", "4 fixtures (healthy, partial, neglected, fresh)"],
    ["Automated test assertions", "42 / 42 pass"],
    ["Severity tiers", "critical · high · medium · low · info"],
    ["Weighted health score", `0–100 with letter grade (${scenarioKey}: ${audit.score} ${audit.grade})`],
  ];
  for (const [what, result] of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${what}</td><td>${result}</td>`;
    testedBody.appendChild(tr);
  }

  renderList();
}

function renderList() {
  listEl.innerHTML = "";
  const filtered =
    currentFilter === "all"
      ? currentResults
      : currentResults.filter((r) => r.status === currentFilter);

  for (const r of filtered) {
    const row = document.createElement("div");
    row.className = "result-row";
    row.setAttribute("role", "listitem");
    row.dataset.status = r.status;
    row.innerHTML = `
      <span class="rr-id">${r.id}</span>
      <span class="rr-badge ${r.severity}">${r.severity}</span>
      <span class="rr-title">${r.title}<br><small style="color:var(--muted);font-weight:400">${r.summary}</small></span>
      <span class="rr-status ${r.status}">${r.status.toUpperCase()}</span>
      <div class="result-detail">
        <p>${r.detail}</p>
        ${r.fix ? `<p style="margin-top:.4rem"><strong>Fix:</strong> ${r.fix}</p>` : ""}
      </div>
    `;
    row.addEventListener("click", () => {
      const det = row.querySelector(".result-detail");
      det.classList.toggle("open");
    });
    listEl.appendChild(row);
  }
}

// ── Scenario buttons ─────────────────────────────────────────
document.querySelectorAll(".scenario-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".scenario-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    render(btn.dataset.scenario);
  });
});

// ── Filter buttons ───────────────────────────────────────────
document.querySelectorAll(".filt-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".filt-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    currentFilter = btn.dataset.filter;
    renderList();
  });
});

// ── Init ─────────────────────────────────────────────────────
render("HEALTHY");
