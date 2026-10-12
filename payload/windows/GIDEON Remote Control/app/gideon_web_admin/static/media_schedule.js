(() => {
  const root = document.querySelector("[data-media-calendar]");
  if (!root) return;

  const grid = root.querySelector("[data-calendar-grid]");
  const weekdays = root.querySelector("[data-calendar-weekdays]");
  const agenda = root.querySelector("[data-calendar-agenda-view]");
  const occupied = root.querySelector("[data-calendar-occupied]");
  const status = root.querySelector("[data-calendar-status]");
  const title = root.querySelector("[data-calendar-title]");
  const conflictBadge = root.querySelector("[data-calendar-conflicts]");
  const state = { view: "month", cursor: new Date(), entries: [], occurrences: [], loading: false };
  const dayNames = ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"];
  const monthNames = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"];
  const stateLabels = { ACTIVE: "Activa", SCHEDULED: "Programada", PAUSED: "Pausada", PENDING_APPROVAL: "Pendiente", DRAFT: "Borrador", EXPIRED: "Vencida", ARCHIVED: "Archivada" };

  const pad = (value) => String(value).padStart(2, "0");
  const key = (date) => `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
  const parseDate = (value) => {
    const parts = String(value || "").split("-").map(Number);
    return parts.length === 3 && parts.every(Number.isFinite) ? new Date(parts[0], parts[1] - 1, parts[2]) : null;
  };
  const addDays = (date, amount) => { const next = new Date(date); next.setDate(next.getDate() + amount); return next; };
  const mondayIndex = (date) => (date.getDay() + 6) % 7;
  const startOfWeek = (date) => addDays(new Date(date.getFullYear(), date.getMonth(), date.getDate()), -mondayIndex(date));
  const rangeFor = () => {
    if (state.view === "week") {
      const start = startOfWeek(state.cursor);
      return { start, end: addDays(start, 6) };
    }
    const first = new Date(state.cursor.getFullYear(), state.cursor.getMonth(), 1);
    const start = addDays(first, -mondayIndex(first));
    return { start, end: addDays(start, 41) };
  };
  const rangeTitle = (range) => {
    if (state.view === "week") {
      return `${range.start.getDate()}–${range.end.getDate()} ${monthNames[range.end.getMonth()]} ${range.end.getFullYear()}`;
    }
    return `${monthNames[state.cursor.getMonth()][0].toUpperCase()}${monthNames[state.cursor.getMonth()].slice(1)} ${state.cursor.getFullYear()}`;
  };
  const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
  const minutes = (value, endOfDay = false) => {
    const match = String(value || "").match(/^(\d{2}):(\d{2})$/);
    if (!match) return endOfDay ? 1440 : 0;
    return Number(match[1]) * 60 + Number(match[2]);
  };
  const timeLabel = (item) => `${item.start_time || "00:00"}–${item.end_time || "24:00"}`;
  const dateLabel = (value, options = {}) => {
    const date = parseDate(value);
    return date ? date.toLocaleDateString("es-PE", { day: "2-digit", month: "short", ...options }) : value;
  };

  const filters = () => {
    const result = {};
    root.querySelectorAll("[data-calendar-filter]").forEach((element) => { result[element.dataset.calendarFilter] = String(element.value || "").trim(); });
    return result;
  };
  const setStatus = (message, kind = "") => {
    if (!status) return;
    status.textContent = message;
    status.classList.toggle("is-error", kind === "error");
    status.classList.toggle("is-loading", kind === "loading");
  };
  const inRange = (date, start, end) => date >= start && date <= end;

  const expandEntries = (entries, range) => {
    const result = [];
    entries.forEach((entry) => {
      const sourceStart = parseDate(entry.start_date);
      const sourceEnd = parseDate(entry.end_date);
      if (!sourceStart || !sourceEnd) return;
      const first = sourceStart > range.start ? sourceStart : range.start;
      const last = sourceEnd < range.end ? sourceEnd : range.end;
      const blocked = new Set((entry.blackout_dates || []).map(String));
      for (let current = new Date(first); current <= last; current = addDays(current, 1)) {
        const weekday = mondayIndex(current);
        if (!(entry.weekdays || [0, 1, 2, 3, 4, 5, 6]).map(Number).includes(weekday) || blocked.has(key(current))) continue;
        result.push({ entry, date: new Date(current), dateKey: key(current), conflict: false });
      }
    });
    const groups = new Map();
    result.forEach((item) => {
      const groupKey = `${item.entry.screen_id}|${item.dateKey}`;
      if (!groups.has(groupKey)) groups.set(groupKey, []);
      groups.get(groupKey).push(item);
    });
    let conflicts = 0;
    groups.forEach((items) => {
      items.sort((left, right) => minutes(left.entry.start_time) - minutes(right.entry.start_time));
      items.forEach((left, index) => items.slice(index + 1).forEach((right) => {
        const leftStart = minutes(left.entry.start_time);
        const rightStart = minutes(right.entry.start_time);
        let leftEnd = minutes(left.entry.end_time, true);
        let rightEnd = minutes(right.entry.end_time, true);
        if (leftEnd <= leftStart) leftEnd += 1440;
        if (rightEnd <= rightStart) rightEnd += 1440;
        const overlaps = Math.max(leftStart, rightStart) < Math.min(leftEnd, rightEnd);
        const differentPriority = Number(left.entry.priority || 0) !== Number(right.entry.priority || 0) && left.entry.priority && right.entry.priority;
        if (overlaps && !differentPriority) { left.conflict = true; right.conflict = true; }
      }));
    });
    conflicts = result.filter((item) => item.conflict).length;
    return { occurrences: result, conflicts };
  };

  const eventHtml = (item, compact = false) => {
    const entry = item.entry;
    const stateClass = String(entry.state || "").toLowerCase();
    const label = `${entry.title} · ${entry.screen_name} · ${timeLabel(entry)}`;
    return `<a class="media-calendar-event media-calendar-event-${escapeHtml(stateClass)}${item.conflict ? " is-conflict" : ""}" href="/media/campaigns/${encodeURIComponent(entry.campaign_id)}" title="${escapeHtml(label)}"><span>${escapeHtml(compact ? entry.title : `${entry.title} · ${timeLabel(entry)}`)}</span>${item.conflict ? "<b aria-label=\"Conflicto\">!</b>" : ""}</a>`;
  };
  const emptyMessage = (message) => `<div class="media-calendar-empty-state"><strong>${escapeHtml(message)}</strong><span>Pruebe otro periodo o ajuste los filtros.</span></div>`;

  const renderMonthOrWeek = (range) => {
    if (!grid || !weekdays) return;
    weekdays.innerHTML = dayNames.map((name) => `<span>${name}</span>`).join("");
    const total = state.view === "week" ? 7 : 42;
    const cells = [];
    for (let index = 0; index < total; index += 1) {
      const date = addDays(range.start, index);
      const dayOccurrences = state.occurrences.filter((item) => item.dateKey === key(date));
      const outside = state.view === "month" && date.getMonth() !== state.cursor.getMonth();
      const today = key(date) === key(new Date());
      const visible = dayOccurrences.slice(0, state.view === "week" ? 20 : 4);
      cells.push(`<div class="media-calendar-cell${outside ? " is-outside" : ""}${today ? " is-today" : ""}"><div class="media-calendar-cell-head"><strong>${date.getDate()}</strong><span>${dayOccurrences.length ? `${dayOccurrences.length} ocupada(s)` : ""}</span></div><div class="media-calendar-events">${visible.map((item) => eventHtml(item, state.view !== "week")).join("")}${dayOccurrences.length > visible.length ? `<span class="media-calendar-more">+${dayOccurrences.length - visible.length} más</span>` : ""}</div></div>`);
    }
    grid.innerHTML = cells.join("");
    grid.classList.toggle("is-week", state.view === "week");
    weekdays.classList.toggle("is-week", state.view === "week");
  };

  const renderAgenda = (range) => {
    if (!agenda) return;
    const byDate = new Map();
    state.occurrences.forEach((item) => { if (!byDate.has(item.dateKey)) byDate.set(item.dateKey, []); byDate.get(item.dateKey).push(item); });
    const groups = [...byDate.entries()].sort(([left], [right]) => left.localeCompare(right));
    agenda.innerHTML = groups.length ? groups.map(([dateKey, items]) => `<section class="media-calendar-agenda-day"><h3>${escapeHtml(dateLabel(dateKey, { weekday: "long" }))} <small>${escapeHtml(dateLabel(dateKey))}</small></h3><div>${items.sort((a, b) => minutes(a.entry.start_time) - minutes(b.entry.start_time)).map((item) => `<div class="media-calendar-agenda-entry${item.conflict ? " is-conflict" : ""}"><span class="media-calendar-agenda-time">${escapeHtml(timeLabel(item.entry))}</span><span><a href="/media/campaigns/${encodeURIComponent(item.entry.campaign_id)}">${escapeHtml(item.entry.title)}</a><small>${escapeHtml(item.entry.site_code)} · ${escapeHtml(item.entry.screen_name)}${item.entry.asset_name ? ` · ${escapeHtml(item.entry.asset_name)}` : ""}</small></span>${item.conflict ? "<b>Conflicto</b>" : ""}</div>`).join("")}</div></section>`).join("") : emptyMessage("No hay campañas en este periodo");
    void range;
  };

  const renderOccupied = () => {
    if (!occupied) return;
    const rows = [...state.occurrences].sort((a, b) => `${a.dateKey}${a.entry.start_time}`.localeCompare(`${b.dateKey}${b.entry.start_time}`)).slice(0, 16);
    occupied.innerHTML = rows.length ? rows.map((item) => `<a class="media-calendar-occupied-row${item.conflict ? " is-conflict" : ""}" href="/media/campaigns/${encodeURIComponent(item.entry.campaign_id)}"><span>${escapeHtml(dateLabel(item.dateKey))}<small>${escapeHtml(timeLabel(item.entry))}</small></span><span><strong>${escapeHtml(item.entry.screen_name)}</strong><small>${escapeHtml(item.entry.title)} · ${escapeHtml(item.entry.site_code)}</small></span></a>`).join("") : emptyMessage("No hay horarios ocupados");
  };

  const render = () => {
    const range = rangeFor();
    if (title) title.textContent = rangeTitle(range);
    const agendaMode = state.view === "agenda";
    if (grid) grid.hidden = agendaMode;
    if (weekdays) weekdays.hidden = agendaMode;
    if (agenda) agenda.hidden = !agendaMode;
    if (!agendaMode) renderMonthOrWeek(range); else renderAgenda(range);
    renderOccupied();
    const conflicts = state.occurrences.filter((item) => item.conflict).length;
    if (conflictBadge) { conflictBadge.textContent = `${conflicts} conflicto${conflicts === 1 ? "" : "s"}`; conflictBadge.classList.toggle("is-conflict", conflicts > 0); }
    setStatus(`${state.entries.length} campaña(s), ${new Set(state.occurrences.map((item) => item.entry.screen_id)).size} pantalla(s) y ${state.occurrences.length} ventana(s) en el periodo.`);
  };

  const load = async () => {
    if (state.loading) return;
    state.loading = true;
    const range = rangeFor();
    const query = new URLSearchParams({ from: key(range.start), to: key(range.end) });
    Object.entries(filters()).forEach(([name, value]) => { if (value) query.set(name, value); });
    setStatus("Actualizando calendario…", "loading");
    try {
      const response = await fetch(`${root.dataset.calendarUrl}?${query.toString()}`, { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.detail || "No se pudo consultar la programación.");
      state.entries = Array.isArray(payload.Entries) ? payload.Entries : [];
      const expanded = expandEntries(state.entries, range);
      state.occurrences = expanded.occurrences;
      render();
    } catch (error) {
      state.entries = [];
      state.occurrences = [];
      if (grid) grid.innerHTML = emptyMessage(error.message || "No se pudo cargar el calendario.");
      if (occupied) occupied.innerHTML = emptyMessage("Calendario temporalmente no disponible");
      setStatus(error.message || "No se pudo cargar el calendario.", "error");
    } finally { state.loading = false; }
  };

  root.querySelector("[data-calendar-prev]")?.addEventListener("click", () => { if (state.view === "week") state.cursor = addDays(state.cursor, -7); else state.cursor = new Date(state.cursor.getFullYear(), state.cursor.getMonth() - 1, 1); void load(); });
  root.querySelector("[data-calendar-next]")?.addEventListener("click", () => { if (state.view === "week") state.cursor = addDays(state.cursor, 7); else state.cursor = new Date(state.cursor.getFullYear(), state.cursor.getMonth() + 1, 1); void load(); });
  root.querySelector("[data-calendar-today]")?.addEventListener("click", () => { state.cursor = new Date(); void load(); });
  root.querySelectorAll("[data-calendar-view]").forEach((button) => button.addEventListener("click", () => { state.view = button.dataset.calendarView || "month"; root.querySelectorAll("[data-calendar-view]").forEach((item) => item.classList.toggle("is-selected", item === button)); void load(); }));
  root.querySelector("[data-calendar-apply]")?.addEventListener("click", () => void load());
  root.querySelectorAll("[data-calendar-filter]").forEach((element) => element.addEventListener("change", () => void load()));
  root.querySelector("[data-calendar-filter='q']")?.addEventListener("keydown", (event) => { if (event.key === "Enter") { event.preventDefault(); void load(); } });
  void load();
})();
