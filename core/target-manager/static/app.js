/* global fetch */

const statusEl = document.getElementById("status");
const tabs = Array.from(document.querySelectorAll(".tab"));
const sdLink = document.getElementById("sd-link");
const hintEl = document.getElementById("hint");
const form = document.getElementById("add-form");
const nameInput = document.getElementById("name");
const targetInput = document.getElementById("target");
const scrapeProfileSelect = document.getElementById("scrape-profile");
const icmpConfigEl = document.getElementById("icmp-config");
const icmpCountInput = document.getElementById("icmp-count");
const icmpIntervalInput = document.getElementById("icmp-interval-ms");
const icmpTimeoutInput = document.getElementById("icmp-timeout-ms");
const icmpPacketSizeInput = document.getElementById("icmp-packet-size");
const icmpDfInput = document.getElementById("icmp-df");
const submitBtn = document.getElementById("submit");
const cancelEditBtn = document.getElementById("cancel-edit");
const refreshBtn = document.getElementById("refresh");
const tbody = document.getElementById("targets-body");

let currentType = "http";
let editId = null;

const ICMP_DEFAULTS = {
  count: 4,
  interval_ms: 1000,
  timeout_ms: 1000,
  packet_size: 56,
  df: false,
};

const SCRAPE_PROFILES = ["1s", "5s", "15s", "60s"];
const DEFAULT_SCRAPE_PROFILE = "15s";

function setStatus(message, kind = "info") {
  statusEl.textContent = message || "";
  statusEl.classList.toggle("error", kind === "error");
}

function hintFor(type) {
  switch (type) {
    case "http":
      return "HTTP: example.com, https://example.com/path (scheme defaults to https).";
    case "tcp":
      return "TCP: host:port (port defaults to 443). IPv6: [2001:db8::1]:443";
    case "dns":
      return "DNS: resolver:53 (port defaults to 53). Example: 1.1.1.1:53";
    case "icmp":
      return "ICMP: hostname or IP (no port). Configure count/interval/timeout/size/DF for loss+jitter.";
    default:
      return "";
  }
}

function updateIcmpDfAvailability() {
  if (currentType !== "icmp") return;
  const t = (targetInput.value || "").trim();
  const looksLikeIpv6 = t.includes(":") || (t.startsWith("[") && t.includes("]"));
  icmpDfInput.disabled = looksLikeIpv6;
  if (looksLikeIpv6) icmpDfInput.checked = false;
}

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }

  const res = await fetch(path, opts);
  const isJson = (res.headers.get("content-type") || "").includes("application/json");
  const payload = isJson ? await res.json() : await res.text();
  if (!res.ok) {
    const msg = payload && payload.error ? payload.error : `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return payload;
}

function renderRows(items) {
  tbody.innerHTML = "";
  if (!items.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 6;
    td.textContent = "No targets yet.";
    td.className = "muted";
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  function effectiveScrapeProfile(item) {
    const raw = item.scrape_profile == null ? "" : String(item.scrape_profile);
    const p = raw.trim();
    if (SCRAPE_PROFILES.includes(p)) return p;
    return DEFAULT_SCRAPE_PROFILE;
  }

  function effectiveIcmp(item) {
    return {
      count: item.icmp_count == null ? ICMP_DEFAULTS.count : Number(item.icmp_count),
      interval_ms: item.icmp_interval_ms == null ? ICMP_DEFAULTS.interval_ms : Number(item.icmp_interval_ms),
      timeout_ms: item.icmp_timeout_ms == null ? ICMP_DEFAULTS.timeout_ms : Number(item.icmp_timeout_ms),
      packet_size: item.icmp_packet_size == null ? ICMP_DEFAULTS.packet_size : Number(item.icmp_packet_size),
      df: item.icmp_df == null ? ICMP_DEFAULTS.df : Boolean(item.icmp_df),
    };
  }

  for (const item of items) {
    const tr = document.createElement("tr");

    const tdEnabled = document.createElement("td");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = Boolean(item.enabled);
    checkbox.addEventListener("change", async () => {
      try {
        setStatus("Saving…");
        await api("PATCH", `/api/targets/${item.id}`, { enabled: checkbox.checked });
        await refresh();
        setStatus("Saved");
      } catch (err) {
        checkbox.checked = !checkbox.checked;
        setStatus(err.message, "error");
      }
    });
    tdEnabled.appendChild(checkbox);

    const tdName = document.createElement("td");
    tdName.textContent = item.name || "";

    const tdTarget = document.createElement("td");
    tdTarget.textContent = item.target;

    const tdScrape = document.createElement("td");
    tdScrape.textContent = effectiveScrapeProfile(item);

    const tdIcmp = document.createElement("td");
    if (item.type === "icmp") {
      const cfg = effectiveIcmp(item);
      tdIcmp.textContent = `count=${cfg.count} interval=${cfg.interval_ms}ms timeout=${cfg.timeout_ms}ms size=${cfg.packet_size} df=${
        cfg.df ? "on" : "off"
      }`;
    } else {
      tdIcmp.textContent = "";
    }

    const tdActions = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";

    const edit = document.createElement("button");
    edit.textContent = "Edit";
    edit.className = "secondary";
    edit.addEventListener("click", () => {
      editId = item.id;
      submitBtn.textContent = "Save";
      cancelEditBtn.hidden = false;
      nameInput.value = item.name || "";
      targetInput.value = item.target;
      scrapeProfileSelect.value = effectiveScrapeProfile(item);

      if (item.type === "icmp") {
        const cfg = effectiveIcmp(item);
        icmpCountInput.value = String(cfg.count);
        icmpIntervalInput.value = String(cfg.interval_ms);
        icmpTimeoutInput.value = String(cfg.timeout_ms);
        icmpPacketSizeInput.value = String(cfg.packet_size);
        icmpDfInput.checked = Boolean(cfg.df);
      }

      updateIcmpDfAvailability();
      setStatus(`Editing target #${item.id}`);
    });
    actions.appendChild(edit);

    const del = document.createElement("button");
    del.textContent = "Delete";
    del.className = "danger";
    del.addEventListener("click", async () => {
      if (!confirm(`Delete target "${item.target}"?`)) return;
      try {
        setStatus("Deleting…");
        await api("DELETE", `/api/targets/${item.id}`);
        await refresh();
        setStatus("Deleted");
      } catch (err) {
        setStatus(err.message, "error");
      }
    });

    actions.appendChild(del);
    tdActions.appendChild(actions);

    tr.appendChild(tdEnabled);
    tr.appendChild(tdName);
    tr.appendChild(tdTarget);
    tr.appendChild(tdScrape);
    tr.appendChild(tdIcmp);
    tr.appendChild(tdActions);
    tbody.appendChild(tr);
  }
}

async function refresh() {
  const items = await api("GET", `/api/targets?type=${encodeURIComponent(currentType)}`);
  renderRows(items);
}

function setType(type) {
  currentType = type;
  for (const t of tabs) t.classList.toggle("active", t.dataset.type === type);
  sdLink.href = `/sd/${type}`;
  hintEl.textContent = hintFor(type);
  icmpConfigEl.hidden = type !== "icmp";
  setStatus("");
  editId = null;
  submitBtn.textContent = "Add";
  cancelEditBtn.hidden = true;
  nameInput.value = "";
  targetInput.value = "";
  scrapeProfileSelect.value = DEFAULT_SCRAPE_PROFILE;
  icmpCountInput.value = String(ICMP_DEFAULTS.count);
  icmpIntervalInput.value = String(ICMP_DEFAULTS.interval_ms);
  icmpTimeoutInput.value = String(ICMP_DEFAULTS.timeout_ms);
  icmpPacketSizeInput.value = String(ICMP_DEFAULTS.packet_size);
  icmpDfInput.checked = Boolean(ICMP_DEFAULTS.df);
  updateIcmpDfAvailability();
  refresh().catch((err) => setStatus(err.message, "error"));
}

tabs.forEach((btn) => btn.addEventListener("click", () => setType(btn.dataset.type)));

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const body = {
      name: nameInput.value,
      target: targetInput.value,
      scrape_profile: scrapeProfileSelect.value,
    };

    if (currentType === "icmp") {
      body.icmp_count = Number(icmpCountInput.value);
      body.icmp_interval_ms = Number(icmpIntervalInput.value);
      body.icmp_timeout_ms = Number(icmpTimeoutInput.value);
      body.icmp_packet_size = Number(icmpPacketSizeInput.value);
      body.icmp_df = Boolean(icmpDfInput.checked);
    }

    if (editId == null) {
      setStatus("Adding…");
      await api("POST", "/api/targets", { type: currentType, ...body });
    } else {
      setStatus("Saving…");
      await api("PATCH", `/api/targets/${editId}`, body);
    }

    nameInput.value = "";
    targetInput.value = "";
    editId = null;
    submitBtn.textContent = "Add";
    cancelEditBtn.hidden = true;
    updateIcmpDfAvailability();
    await refresh();
    setStatus("Saved");
  } catch (err) {
    setStatus(err.message, "error");
  }
});

refreshBtn.addEventListener("click", () => refresh().catch((err) => setStatus(err.message, "error")));

cancelEditBtn.addEventListener("click", () => {
  editId = null;
  submitBtn.textContent = "Add";
  cancelEditBtn.hidden = true;
  nameInput.value = "";
  targetInput.value = "";
  scrapeProfileSelect.value = DEFAULT_SCRAPE_PROFILE;
  icmpCountInput.value = String(ICMP_DEFAULTS.count);
  icmpIntervalInput.value = String(ICMP_DEFAULTS.interval_ms);
  icmpTimeoutInput.value = String(ICMP_DEFAULTS.timeout_ms);
  icmpPacketSizeInput.value = String(ICMP_DEFAULTS.packet_size);
  icmpDfInput.checked = Boolean(ICMP_DEFAULTS.df);
  updateIcmpDfAvailability();
  setStatus("");
});

targetInput.addEventListener("input", updateIcmpDfAvailability);

setType("http");
