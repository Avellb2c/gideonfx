(() => {
  "use strict";

  const ready = (fn) => document.readyState === "loading"
    ? document.addEventListener("DOMContentLoaded", fn, { once: true })
    : fn();
  const assetLabels = {
    QUARANTINED: "En revisión",
    ANALYZING: "Analizando",
    READY: "Listo para usar",
    REJECTED: "No compatible",
    ERROR: "Requiere atención",
    ARCHIVED: "Archivado",
  };
  const distributionLabels = {
    PENDING: "Pendiente",
    SYNCING: "Sincronizando",
    READY: "Listo",
    OFFLINE: "Sin conexión",
    ERROR: "Requiere atención",
  };
  const text = (value, fallback = "") => String(value ?? fallback).trim() || fallback;
  const stateText = (state, labels = assetLabels) => labels[text(state).toUpperCase()] || text(state, "Pendiente").replaceAll("_", " ");
  const make = (tag, className = "", value = "") => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (value) element.textContent = value;
    return element;
  };

  const formatDuration = (seconds) => {
    const total = Number(seconds);
    if (!Number.isFinite(total) || total <= 0) return "";
    const rounded = Math.round(total);
    const minutes = Math.floor(rounded / 60);
    const rest = rounded % 60;
    return minutes ? `${minutes} min ${String(rest).padStart(2, "0")} s` : `${rest} s`;
  };

  // Dates in a campaign are calendar dates, not instants.  Build them at
  // midday so a browser's timezone/DST change never moves a selected day.
  const parseCalendarDate = (value) => {
    const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text(value));
    if (!match) return null;
    const date = new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]), 12);
    return date.getFullYear() === Number(match[1]) && date.getMonth() === Number(match[2]) - 1
      && date.getDate() === Number(match[3]) ? date : null;
  };
  const calendarDateValue = (date) => [date.getFullYear(), String(date.getMonth() + 1).padStart(2, "0"), String(date.getDate()).padStart(2, "0")].join("-");
  const calendarDateAt = (date, offset) => new Date(date.getFullYear(), date.getMonth(), date.getDate() + offset, 12);
  const calendarDateLabel = (value) => {
    const date = parseCalendarDate(value);
    if (!date) return "fecha por definir";
    return new Intl.DateTimeFormat("es-PE", { day: "numeric", month: "short", year: "numeric" }).format(date);
  };
  // Campaign dates belong to Peru, not to the browser or VM clock.  Build a
  // calendar date from the IANA zone so a session opened near midnight in a
  // different region still offers the correct "Hoy" and month.
  const peruToday = () => {
    const parts = new Intl.DateTimeFormat("en-CA", {
      timeZone: "America/Lima", year: "numeric", month: "2-digit", day: "2-digit",
    }).formatToParts(new Date());
    const value = `${parts.find((part) => part.type === "year")?.value || ""}-${parts.find((part) => part.type === "month")?.value || ""}-${parts.find((part) => part.type === "day")?.value || ""}`;
    return parseCalendarDate(value) || new Date();
  };
  const calendarDateLongLabel = (value) => {
    const date = parseCalendarDate(value);
    if (!date) return "Sin fecha";
    return new Intl.DateTimeFormat("es-PE", {
      weekday: "long", day: "numeric", month: "long", year: "numeric",
    }).format(date);
  };
  const calendarMonthLabel = (date) => {
    const value = new Intl.DateTimeFormat("es-PE", { month: "long", year: "numeric" }).format(date);
    return value.charAt(0).toLocaleUpperCase("es-PE") + value.slice(1);
  };

  // Browser-native date inputs deliberately follow the browser locale, which
  // can make an es-PE Marketing screen show mm/dd/yyyy.  These controls keep
  // the canonical, no-JavaScript ISO input intact while offering a keyboard
  // accessible local calendar with an explicit Spanish-Peru presentation.
  const initLocalizedDatePickers = () => {
    const roots = Array.from(document.querySelectorAll("[data-localized-date-picker]"));
    if (!roots.length) return;
    const states = [];
    let openState = null;

    const statesForForm = (form) => states.filter((state) => state.form === form);
    const refreshForm = (form) => statesForForm(form).forEach((state) => state.render());
    const close = (state = openState, restoreFocus = false) => {
      if (!state) return;
      state.popup.hidden = true;
      state.trigger.setAttribute("aria-expanded", "false");
      if (openState === state) openState = null;
      if (restoreFocus) state.trigger.focus();
    };
    // The upload card intentionally clips its contents to preserve its rounded
    // surface. A calendar rendered inside it would therefore be cut off (and
    // would inherit the full width of a large form field). The dialog is
    // portalled to body and positioned relative to its trigger instead.
    const placePopup = (state) => {
      if (!state || state.popup.hidden) return;
      const margin = 12;
      const viewportWidth = Math.max(0, document.documentElement.clientWidth || window.innerWidth || 0);
      const viewportHeight = Math.max(0, document.documentElement.clientHeight || window.innerHeight || 0);
      const triggerRect = state.trigger.getBoundingClientRect();
      const popup = state.popup;
      const availableWidth = Math.max(1, viewportWidth - (margin * 2));
      // A date picker should remain a compact calendar even when the form
      // column spans half of a wide desktop screen. On narrow screens it can
      // still use the available viewport width.
      const preferredWidth = Math.max(272, Math.min(triggerRect.width || 0, 352));
      const width = Math.min(preferredWidth, availableWidth);
      popup.style.setProperty("--gideon-local-date-picker-width", `${Math.floor(width)}px`);
      popup.style.removeProperty("--gideon-local-date-picker-max-height");
      popup.style.left = "0px";
      popup.style.top = "0px";
      popup.style.visibility = "hidden";
      popup.style.pointerEvents = "none";

      const naturalHeight = popup.getBoundingClientRect().height || 0;
      const roomBelow = Math.max(0, viewportHeight - triggerRect.bottom - margin);
      const roomAbove = Math.max(0, triggerRect.top - margin);
      const openAbove = roomBelow < Math.min(naturalHeight, 320) && roomAbove > roomBelow;
      const availableHeight = openAbove ? roomAbove : roomBelow;
      popup.style.setProperty(
        "--gideon-local-date-picker-max-height",
        `${Math.floor(Math.max(1, Math.min(availableHeight, 420)))}px`,
      );

      const popupHeight = popup.getBoundingClientRect().height || Math.min(naturalHeight, availableHeight);
      const left = Math.min(
        Math.max(margin, triggerRect.left),
        Math.max(margin, viewportWidth - margin - width),
      );
      const top = openAbove
        ? Math.max(margin, triggerRect.top - 8 - popupHeight)
        : Math.min(
          Math.max(margin, triggerRect.bottom + 8),
          Math.max(margin, viewportHeight - margin - popupHeight),
        );
      popup.style.left = `${Math.round(left)}px`;
      popup.style.top = `${Math.round(top)}px`;
      popup.dataset.placement = openAbove ? "above" : "below";
      popup.style.visibility = "";
      popup.style.pointerEvents = "";
    };
    const syncAssetDateWindow = (form) => {
      if (!(form instanceof HTMLFormElement)) return;
      const validFrom = form.querySelector("input[name=valid_from]");
      const validUntil = form.querySelector("input[name=valid_until]");
      if (!(validFrom instanceof HTMLInputElement) || !(validUntil instanceof HTMLInputElement)) return;
      validUntil.min = validFrom.value || "";
      const invalid = Boolean(validFrom.value && validUntil.value && validUntil.value < validFrom.value);
      validUntil.setCustomValidity(invalid ? "La vigencia hasta debe ser igual o posterior a la vigencia desde." : "");
      validUntil.setAttribute("aria-invalid", String(invalid));
    };
    const selectedMonth = (value) => {
      const selected = parseCalendarDate(value);
      return new Date((selected || new Date()).getFullYear(), (selected || new Date()).getMonth(), 1, 12);
    };

    roots.forEach((root, index) => {
      if (!(root instanceof HTMLElement)) return;
      const input = root.querySelector("input[data-localized-date-value]");
      if (!(input instanceof HTMLInputElement) || input.dataset.localizedDateReady === "true") return;
      const form = input.form;
      if (!(form instanceof HTMLFormElement)) return;
      input.dataset.localizedDateReady = "true";
      input.classList.add("media-local-date-native");
      input.tabIndex = -1;
      input.setAttribute("aria-hidden", "true");

      const originalId = input.id || `mediaLocalDate${index + 1}`;
      if (!input.id) input.id = originalId;
      const label = Array.from(form.querySelectorAll("label")).find((candidate) => candidate.htmlFor === originalId);
      const labelText = text(label?.textContent, "fecha");
      const trigger = make("button", "media-local-date-trigger", "Elegir fecha");
      trigger.type = "button";
      trigger.id = `${originalId}LocalizedPicker`;
      trigger.setAttribute("aria-haspopup", "dialog");
      trigger.setAttribute("aria-expanded", "false");
      if (label) label.htmlFor = trigger.id;

      const popup = make("section", "media-local-date-popover");
      popup.hidden = true;
      popup.id = `${originalId}LocalizedPickerDialog`;
      popup.setAttribute("role", "dialog");
      popup.setAttribute("aria-label", `Calendario para ${labelText}`);
      trigger.setAttribute("aria-controls", popup.id);
      const header = make("div", "media-local-date-popover-head");
      const previous = make("button", "btn btn-small", "‹");
      previous.type = "button";
      previous.setAttribute("aria-label", "Mes anterior");
      const month = make("strong", "media-local-date-month");
      const next = make("button", "btn btn-small", "›");
      next.type = "button";
      next.setAttribute("aria-label", "Mes siguiente");
      header.append(previous, month, next);
      const weekdays = make("div", "media-local-date-weekdays");
      weekdays.setAttribute("aria-hidden", "true");
      ["L", "M", "X", "J", "V", "S", "D"].forEach((day) => weekdays.append(make("span", "", day)));
      const grid = make("div", "media-local-date-grid");
      grid.setAttribute("role", "grid");
      grid.setAttribute("aria-label", `Días de ${labelText}`);
      const footer = make("div", "media-local-date-popover-actions");
      const today = make("button", "btn btn-small", "Hoy");
      today.type = "button";
      const clear = make("button", "btn btn-small", "Sin fecha");
      clear.type = "button";
      footer.append(today, clear);
      popup.append(header, weekdays, grid, footer);
      root.append(trigger);
      // Keep the visible dialog out of cards that use overflow:hidden, while
      // retaining the native input inside its form as the no-JavaScript
      // submission contract.
      document.body.append(popup);

      let cursor = selectedMonth(input.value);
      const dateIsAllowed = (value) => (!input.min || value >= input.min) && (!input.max || value <= input.max);
      const setValue = (value) => {
        if (value && !parseCalendarDate(value)) return;
        input.value = value;
        syncAssetDateWindow(form);
        refreshForm(form);
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.dispatchEvent(new Event("change", { bubbles: true }));
      };
      const render = () => {
        const selected = input.value;
        const selectedDate = parseCalendarDate(selected);
        trigger.textContent = selectedDate ? calendarDateLongLabel(selected) : "Elegir fecha";
        trigger.classList.toggle("has-value", Boolean(selectedDate));
        trigger.setAttribute("aria-label", selectedDate
          ? `Cambiar ${labelText}: ${calendarDateLongLabel(selected)}`
          : `Elegir ${labelText}`);
        month.textContent = calendarMonthLabel(cursor);
        grid.replaceChildren();
        const firstWeekday = (cursor.getDay() + 6) % 7;
        for (let blank = 0; blank < firstWeekday; blank += 1) grid.append(make("span", "media-local-date-empty"));
        const days = new Date(cursor.getFullYear(), cursor.getMonth() + 1, 0).getDate();
        const now = calendarDateValue(new Date());
        for (let day = 1; day <= days; day += 1) {
          const date = new Date(cursor.getFullYear(), cursor.getMonth(), day, 12);
          const value = calendarDateValue(date);
          const dayButton = make("button", "media-local-date-day", String(day));
          const allowed = dateIsAllowed(value);
          dayButton.type = "button";
          dayButton.disabled = !allowed;
          dayButton.classList.toggle("is-selected", value === selected);
          dayButton.classList.toggle("is-today", value === now);
          dayButton.dataset.localizedDate = value;
          dayButton.setAttribute("aria-pressed", String(value === selected));
          dayButton.setAttribute("aria-label", `${calendarDateLongLabel(value)}${allowed ? "" : ", no disponible"}`);
          grid.append(dayButton);
        }
      };
      const state = { root, form, input, trigger, popup, render };
      states.push(state);
      trigger.addEventListener("click", () => {
        if (openState === state) {
          close(state);
          return;
        }
        close();
        cursor = selectedMonth(input.value);
        render();
        popup.hidden = false;
        trigger.setAttribute("aria-expanded", "true");
        openState = state;
        placePopup(state);
        window.requestAnimationFrame(() => {
          placePopup(state);
          grid.querySelector(".is-selected:not(:disabled), button:not(:disabled)")?.focus();
        });
      });
      previous.addEventListener("click", () => {
        cursor = new Date(cursor.getFullYear(), cursor.getMonth() - 1, 1, 12);
        render();
      });
      next.addEventListener("click", () => {
        cursor = new Date(cursor.getFullYear(), cursor.getMonth() + 1, 1, 12);
        render();
      });
      grid.addEventListener("click", (event) => {
        const day = event.target instanceof Element ? event.target.closest("[data-localized-date]") : null;
        if (!(day instanceof HTMLButtonElement) || day.disabled) return;
        setValue(text(day.dataset.localizedDate));
        close(state, true);
      });
      today.addEventListener("click", () => {
        const value = calendarDateValue(new Date());
        if (!dateIsAllowed(value)) return;
        setValue(value);
        close(state, true);
      });
      clear.addEventListener("click", () => {
        setValue("");
        close(state, true);
      });
      input.addEventListener("change", () => {
        syncAssetDateWindow(form);
        render();
      });
      render();
    });
    Array.from(new Set(states.map((state) => state.form))).forEach((form) => {
      syncAssetDateWindow(form);
      form.addEventListener("reset", () => window.requestAnimationFrame(() => {
        syncAssetDateWindow(form);
        refreshForm(form);
      }));
    });
    document.addEventListener("pointerdown", (event) => {
      if (
        openState
        && event.target instanceof Node
        && !openState.root.contains(event.target)
        && !openState.popup.contains(event.target)
      ) close();
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && openState) {
        event.preventDefault();
        close(openState, true);
      }
    });
    let queuedPlacement = false;
    const repositionOpenPopup = () => {
      if (!openState || queuedPlacement) return;
      queuedPlacement = true;
      window.requestAnimationFrame(() => {
        queuedPlacement = false;
        placePopup(openState);
      });
    };
    window.addEventListener("resize", repositionOpenPopup, { passive: true });
    document.addEventListener("scroll", repositionOpenPopup, true);
  };

  const showFeedback = (target, message, tone = "progress") => {
    if (!target) return;
    target.hidden = false;
    target.className = `media-upload-feedback is-${tone}`;
    target.replaceChildren(make("strong", "", tone === "error" ? "Revise el video" : tone === "success" ? "Listo" : "Analizando"), make("span", "", text(message, "GIDEON está preparando el video.")));
  };

  const optionForAsset = (asset) => {
    // Compact catalog pages use ``status`` while the detail endpoint uses
    // ``state``.  Treat both as the same public contract so a READY video is
    // never rendered as an empty/disabled option.
    const state = text(asset.state || asset.status).toUpperCase();
    const name = text(asset.display_name || asset.name, "Video GIDEON");
    const option = new Option(
      `${name} · ${stateText(state)}${asset.resolution ? ` · ${asset.resolution}` : ""}`,
      text(asset.asset_id),
      false,
      false,
    );
    option.disabled = state !== "READY";
    option.dataset.assetName = name;
    option.dataset.assetState = state;
    option.dataset.assetResolution = text(asset.resolution);
    option.dataset.assetDuration = text(asset.duration_seconds);
    option.dataset.assetWarning = text(asset.warning || asset.playback_warning);
    return option;
  };

  const updateAssetOptions = (asset) => {
    if (!asset?.asset_id) return;
    document.querySelectorAll("[data-screen-asset]").forEach((select) => {
      const existing = Array.from(select.options).find((option) => option.value === asset.asset_id);
      const replacement = optionForAsset(asset);
      // A campaign can have many screens.  Do not append every uploaded
      // video to every picker: only refresh an option already selected or
      // shown by that picker.  The catalog is searched on demand below.
      if (existing) {
        replacement.selected = select.value === asset.asset_id;
        select.replaceChild(replacement, existing);
      }
    });
  };

  const adoptCampaignAsset = (asset) => {
    const form = document.querySelector("[data-media-campaign-form]");
    const assetId = text(asset?.asset_id);
    const state = text(asset?.state || asset?.status).toUpperCase();
    if (!(form instanceof HTMLFormElement) || !assetId || state !== "READY") return;
    const previousSuggestion = text(form.dataset.suggestedAssetId);
    const name = text(asset.display_name || asset.name, "Video GIDEON");
    form.dataset.suggestedAssetId = assetId;
    form.dataset.suggestedAssetName = name;

    const banner = document.querySelector("[data-campaign-selected-asset]");
    if (banner instanceof HTMLElement) {
      banner.hidden = false;
      const bannerName = banner.querySelector("[data-campaign-selected-asset-name]");
      const detail = banner.querySelector("[data-campaign-selected-asset-detail]");
      if (bannerName) bannerName.textContent = name;
      if (detail) detail.textContent = ["Listo para asignar", text(asset.resolution), text(asset.warning)].filter(Boolean).join(" · ");
    }

    form.querySelectorAll("[data-screen-asset]").forEach((select) => {
      if (!(select instanceof HTMLSelectElement)) return;
      const shouldAdopt = !select.value || select.value === previousSuggestion;
      const existing = Array.from(select.options).find((option) => option.value === assetId);
      const option = optionForAsset(asset);
      if (existing) select.replaceChild(option, existing); else select.add(option);
      if (shouldAdopt) {
        select.value = assetId;
        select.dataset.selectedAssetId = assetId;
        select.dispatchEvent(new Event("change", { bubbles: true }));
      }
    });
    form.dispatchEvent(new CustomEvent("gideon-asset-suggestion-change", { detail: asset }));
  };

  const initLibraryAssetPolling = () => {
    const pendingStates = new Set(["QUARANTINED", "ANALYZING"]);
    const rows = Array.from(document.querySelectorAll("[data-media-asset-row]"))
      .filter((row) => text(row.dataset.mediaAssetId)
        && pendingStates.has(text(row.dataset.mediaAssetState).toUpperCase()));
    if (!rows.length) return;

    let timer = 0;
    let stopped = false;
    let startedAt = Date.now();
    const endpointFor = (assetId) => `/api/v1/media/assets/${encodeURIComponent(assetId)}`;
    const schedule = (delay) => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => { void refresh(); }, delay);
    };
    const refresh = async () => {
      if (stopped) return;
      if (document.hidden) {
        schedule(10000);
        return;
      }
      try {
        const results = await Promise.all(rows.map(async (row) => {
          const response = await fetch(endpointFor(row.dataset.mediaAssetId), {
            credentials: "same-origin",
            headers: { Accept: "application/json" },
          });
          if (!response.ok) return "";
          const payload = await response.json().catch(() => ({}));
          return text(payload.state).toUpperCase();
        }));
        // A terminal transition changes actions, warning text and campaign
        // availability.  Reload the bounded current library page once rather
        // than trying to duplicate the server-rendered row in JavaScript.
        if (results.some((state) => state && !pendingStates.has(state))) {
          stopped = true;
          window.location.reload();
          return;
        }
      } catch (_) {
        // The durable analysis Job is server-side; a transient browser/network
        // failure must not be presented as a rejected video.
      }
      if (Date.now() - startedAt < 15 * 60 * 1000) schedule(4000);
    };
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden && !stopped) {
        startedAt = Math.min(startedAt, Date.now());
        schedule(150);
      }
    });
    void refresh();
  };

  const initUploadForms = () => {
    document.querySelectorAll("[data-media-upload-form]").forEach((form) => {
      const fileInput = form.querySelector("[data-media-file]");
      const fileName = form.querySelector("[data-media-file-name]");
      const submit = form.querySelector("[data-media-upload-submit]");
      const feedback = form.querySelector("[data-media-upload-feedback]");
      if (!(form instanceof HTMLFormElement) || !(fileInput instanceof HTMLInputElement)) return;

      const endpointFor = (assetId) => text(
        form.dataset.mediaStatusUrlTemplate,
        "/api/v1/media/assets/{asset_id}",
      ).replace("{asset_id}", encodeURIComponent(assetId));
      const refreshOnTerminal = form.dataset.mediaRefreshOnTerminal === "true";
      const finishTerminal = () => {
        if (refreshOnTerminal) window.setTimeout(() => window.location.reload(), 650);
      };
      const poll = async (assetId, tries = 0) => {
        try {
          const response = await fetch(endpointFor(assetId), { credentials: "same-origin", headers: { Accept: "application/json" } });
          const payload = await response.json().catch(() => ({}));
          if (!response.ok) throw new Error(text(payload.detail || payload.message, "No se pudo consultar el análisis del video."));
          const state = text(payload.state).toUpperCase();
          updateAssetOptions(payload);
          if (state === "READY") {
            const warning = text(payload.warning);
            showFeedback(feedback, `El video está listo para elegir en cada pantalla.${warning ? ` ${warning}` : ""} No se ha publicado ni distribuido todavía.`, "success");
            adoptCampaignAsset(payload);
            if (submit) { submit.disabled = false; submit.textContent = "Cargar y analizar"; }
            finishTerminal();
            return;
          }
          if (["REJECTED", "ERROR", "ARCHIVED"].includes(state)) {
            showFeedback(feedback, text(payload.message, "El video no pudo quedar disponible para campañas."), "error");
            if (submit) { submit.disabled = false; submit.textContent = "Cargar y analizar"; }
            finishTerminal();
            return;
          }
          showFeedback(feedback, text(payload.message, "GIDEON está analizando el video en segundo plano."), "progress");
          window.setTimeout(() => { void poll(assetId, tries + 1); }, Math.min(8000, 2000 + tries * 500));
        } catch (_) {
          // The Job continues in the server even if this tab briefly loses a
          // connection.  Do not convert a transient browser error into a
          // false video failure.
          if (tries < 4) window.setTimeout(() => { void poll(assetId, tries + 1); }, 4000);
          else {
            showFeedback(feedback, "El análisis continúa en segundo plano. Actualice la biblioteca más tarde para ver el resultado.", "progress");
            if (submit) { submit.disabled = false; submit.textContent = "Cargar y analizar"; }
          }
        }
      };

      fileInput.addEventListener("change", () => {
        const chosen = fileInput.files?.[0];
        if (!chosen) return;
        if (fileName) fileName.textContent = `${chosen.name} · ${Math.max(1, Math.round(chosen.size / 1024 / 1024))} MB`;
        if (!/\.mp4$/i.test(chosen.name)) showFeedback(feedback, "Seleccione un archivo MP4. GIDEON validará sus características antes de publicarlo.", "error");
        else if (feedback) feedback.hidden = true;
      });

      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const chosen = fileInput.files?.[0];
        if (!chosen || !/\.mp4$/i.test(chosen.name)) {
          showFeedback(feedback, "Seleccione un archivo MP4 para continuar.", "error");
          return;
        }
        if (submit) { submit.disabled = true; submit.textContent = "Cargando…"; }
        showFeedback(feedback, "GIDEON recibió el video y está creando el análisis seguro.", "progress");
        try {
          const response = await fetch(form.action, {
            method: "POST",
            body: new FormData(form),
            credentials: "same-origin",
            headers: { Accept: "application/json" },
          });
          const payload = await response.json().catch(() => ({}));
          if (!response.ok || !payload.asset_id) throw new Error(text(payload.detail || payload.message, "No se pudo iniciar el análisis del video."));
          showFeedback(feedback, text(payload.message, "Video recibido. GIDEON lo analiza en segundo plano."), "progress");
          form.reset();
          if (fileName) fileName.textContent = "MP4 con H.264/AVC, yuv420p y hasta 1080p. El audio es opcional; si existe, debe ser AAC-LC.";
          // The analysis is durable and happens server-side, therefore this
          // form can immediately accept another creativity for a different
          // screen instead of making Marketing wait for ffprobe/antivirus.
          if (submit) { submit.disabled = false; submit.textContent = "Cargar otro video"; }
          void poll(payload.asset_id);
        } catch (error) {
          showFeedback(feedback, text(error?.message, "No se pudo cargar el video. Intente nuevamente."), "error");
          if (submit) { submit.disabled = false; submit.textContent = "Cargar y analizar"; }
        }
      });
    });
  };

  // The campaign wizard may contain dozens of screens and the library may
  // contain hundreds of videos.  Load a compact READY-only page only after a
  // person opens or searches a particular screen picker.  This deliberately
  // avoids rendering the former screens × assets option matrix in HTML.
  const initLazyAssetPickers = (form, onChange) => {
    const catalogUrl = text(form?.dataset?.mediaAssetCatalogUrl);
    if (!(form instanceof HTMLFormElement) || !catalogUrl) return;
    const pageSize = 24;
    const compactPage = (payload) => ({
      items: Array.isArray(payload?.Assets) ? payload.Assets
        : Array.isArray(payload?.items) ? payload.items
          : Array.isArray(payload?.Items) ? payload.Items : [],
      pagination: payload?.Pagination || payload?.pagination || {},
    });
    const requestCatalog = async (query, page) => {
      const url = new URL(catalogUrl, window.location.origin);
      url.searchParams.set("state", "READY");
      url.searchParams.set("q", query);
      url.searchParams.set("page", String(Math.max(1, page)));
      url.searchParams.set("page_size", String(pageSize));
      const response = await fetch(url.toString(), {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(text(payload.detail || payload.message, "No se pudo consultar la biblioteca."));
      return compactPage(payload);
    };
    const requestAsset = async (assetId) => {
      const url = `${catalogUrl.replace(/\/$/, "")}/${encodeURIComponent(assetId)}`;
      const response = await fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" } });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(text(payload.detail || payload.message, "No se pudo recuperar el video elegido."));
      return payload;
    };

    const bindPicker = (picker) => {
      const card = picker.closest("[data-screen-choice]");
      const search = picker.querySelector("[data-screen-asset-search]");
      const select = picker.querySelector("[data-screen-asset]");
      const status = picker.querySelector("[data-selected-asset-status]");
      const actions = picker.querySelector("[data-screen-asset-actions]");
      const previous = picker.querySelector("[data-screen-asset-previous]");
      const next = picker.querySelector("[data-screen-asset-next]");
      const pageLabel = picker.querySelector("[data-screen-asset-page]");
      if (!(card instanceof HTMLElement) || !(search instanceof HTMLInputElement) || !(select instanceof HTMLSelectElement)) return;
      if (picker.dataset.lazyAssetReady === "true") return;
      picker.dataset.lazyAssetReady = "true";

      let query = "";
      let page = 1;
      let pagination = {};
      let searchTimer = 0;
      let pending = 0;
      let loaded = false;
      let initialLoaded = "";
      const setStatus = (value) => { if (status) status.textContent = value; };
      const currentOption = () => select.options[select.selectedIndex];
      const selectedAssetId = () => text(select.value || select.dataset.selectedAssetId);
      const renderPagination = () => {
        const total = Number(pagination.total || 0);
        const totalPages = Number(pagination.pages || 0);
        const current = Number(pagination.page || page || 1);
        if (actions instanceof HTMLElement) actions.hidden = !(totalPages > 1);
        if (pageLabel) pageLabel.textContent = totalPages > 1 ? `Página ${current} de ${totalPages} · ${total} video(s)` : total ? `${total} video(s) encontrados` : "";
        if (previous instanceof HTMLButtonElement) previous.disabled = !(pagination.has_previous || current > 1);
        if (next instanceof HTMLButtonElement) next.disabled = !(pagination.has_next || (totalPages > current));
      };
      const retainSelection = () => {
        const id = selectedAssetId();
        const previousOption = Array.from(select.options).find((option) => option.value === id);
        if (!id || !previousOption) return null;
        return optionForAsset({
          asset_id: id,
          display_name: previousOption.dataset.assetName || previousOption.textContent || "Video seleccionado",
          state: previousOption.dataset.assetState || "READY",
          resolution: previousOption.dataset.assetResolution || "",
          duration_seconds: previousOption.dataset.assetDuration || "",
          warning: previousOption.dataset.assetWarning || "",
        });
      };
      const replaceOptions = (items) => {
        const retained = retainSelection();
        select.replaceChildren(new Option("Buscar o abrir la lista de videos", ""));
        if (retained) {
          retained.selected = true;
          select.add(retained);
        }
        items.forEach((asset) => {
          const assetState = text(asset?.state || asset?.status).toUpperCase();
          if (!asset?.asset_id || assetState !== "READY") return;
          if (Array.from(select.options).some((option) => option.value === asset.asset_id)) return;
          select.add(optionForAsset(asset));
        });
      };
      const loadPage = async (nextQuery = query, nextPage = 1) => {
        const serial = ++pending;
        query = text(nextQuery);
        page = Math.max(1, Number(nextPage) || 1);
        setStatus(query ? "Buscando videos listos…" : "Cargando videos listos…");
        try {
          const result = await requestCatalog(query, page);
          if (serial !== pending) return;
          pagination = result.pagination || {};
          page = Number(pagination.page || page) || 1;
          replaceOptions(result.items);
          loaded = true;
          renderPagination();
          const selected = currentOption();
          if (selected?.value) setStatus(`${selected.dataset.assetName || "Video seleccionado"}${selected.dataset.assetResolution ? ` · ${selected.dataset.assetResolution}` : ""}${selected.dataset.assetDuration ? ` · ${formatDuration(selected.dataset.assetDuration)}` : ""}${selected.dataset.assetWarning ? ` · ${selected.dataset.assetWarning}` : ""}`);
          else if (result.items.length) setStatus("Elija un video listo de la lista.");
          else setStatus(query ? "No se encontraron videos listos con esa búsqueda." : "No hay videos listos todavía. Puede cargar uno arriba.");
        } catch (error) {
          if (serial !== pending) return;
          setStatus(text(error?.message, "No se pudo consultar la biblioteca. Intente nuevamente."));
          if (actions instanceof HTMLElement) actions.hidden = true;
        }
      };
      const ensureInitial = async () => {
        const assetId = selectedAssetId();
        if (!assetId || initialLoaded === assetId) return;
        initialLoaded = assetId;
        setStatus("Cargando el video ya elegido…");
        try {
          const asset = await requestAsset(assetId);
          const option = optionForAsset(asset);
          const existing = Array.from(select.options).find((item) => item.value === assetId);
          option.selected = true;
          if (existing) select.replaceChild(option, existing); else select.add(option);
          select.value = assetId;
          setStatus(`${option.dataset.assetName || "Video seleccionado"}${option.dataset.assetResolution ? ` · ${option.dataset.assetResolution}` : ""}${option.dataset.assetDuration ? ` · ${formatDuration(option.dataset.assetDuration)}` : ""}${option.dataset.assetWarning ? ` · ${option.dataset.assetWarning}` : ""}`);
          onChange?.();
        } catch (_) {
          // Keep the submitted identifier intact. The server remains the
          // authority for validation and gives the clear result on submit.
          setStatus("El video elegido se validará al publicar. Puede buscar otro video si lo desea.");
        }
      };
      card.addEventListener("gideon-screen-asset-activate", () => { void ensureInitial(); });
      search.addEventListener("input", () => {
        window.clearTimeout(searchTimer);
        const value = text(search.value);
        if (value && value.length < 2) {
          setStatus("Escriba al menos dos letras para buscar un video.");
          return;
        }
        searchTimer = window.setTimeout(() => { void loadPage(value, 1); }, 260);
      });
      search.addEventListener("search", () => { void loadPage(text(search.value), 1); });
      select.addEventListener("focus", () => {
        if (!loaded) void loadPage(text(search.value), 1);
      });
      select.addEventListener("change", () => {
        const option = currentOption();
        select.dataset.selectedAssetId = text(select.value);
        initialLoaded = select.value ? select.value : "";
        setStatus(option?.value
          ? `${option.dataset.assetName || option.textContent || "Video seleccionado"}${option.dataset.assetResolution ? ` · ${option.dataset.assetResolution}` : ""}${option.dataset.assetDuration ? ` · ${formatDuration(option.dataset.assetDuration)}` : ""}${option.dataset.assetWarning ? ` · ${option.dataset.assetWarning}` : ""}`
          : "Seleccione un video listo para esta pantalla.");
        onChange?.();
      });
      previous?.addEventListener("click", () => { if (page > 1) void loadPage(query, page - 1); });
      next?.addEventListener("click", () => { if (pagination.has_next || (pagination.pages && page < pagination.pages)) void loadPage(query, page + 1); });
    };
    form.querySelectorAll("[data-screen-asset-picker]").forEach(bindPicker);
    return { bind: bindPicker };
  };

  const initCampaignScheduleDesigner = (form, onChange) => {
    const designer = form.querySelector("[data-schedule-designer]");
    const startDate = form.querySelector("#startDate");
    const endDate = form.querySelector("#endDate");
    const startTime = form.querySelector("#startTime");
    const endTime = form.querySelector("#endTime");
    const timezone = form.querySelector("#timezone");
    const blackoutOutput = form.querySelector("[data-blackout-output]");
    const blackoutPicker = form.querySelector("[data-blackout-picker]");
    const blackoutChips = form.querySelector("[data-blackout-chips]");
    const calendar = form.querySelector("[data-schedule-calendar]");
    if (!(designer instanceof HTMLElement) || !(startDate instanceof HTMLInputElement)
      || !(endDate instanceof HTMLInputElement) || !(startTime instanceof HTMLInputElement)
      || !(endTime instanceof HTMLInputElement) || !(blackoutOutput instanceof HTMLInputElement)
      || !(calendar instanceof HTMLElement)) return { summary: () => "" };

    const grid = calendar.querySelector("[data-calendar-grid]");
    const monthTitle = calendar.querySelector("[data-calendar-month]");
    const help = calendar.querySelector("[data-calendar-help]");
    const summary = form.querySelector("[data-schedule-summary-text]");
    const presetOutput = form.querySelector("[data-schedule-preset-output]");
    const rangeOutput = form.querySelector("[data-schedule-range-output]");
    const startOutput = form.querySelector("[data-schedule-start-output]");
    const endOutput = form.querySelector("[data-schedule-end-output]");
    const weekdaysOutput = form.querySelector("[data-schedule-weekdays-output]");
    const weekdayInputs = Array.from(form.querySelectorAll("input[name=weekday]"));
    let cursor = parseCalendarDate(startDate.value) || parseCalendarDate(endDate.value) || peruToday();
    cursor = new Date(cursor.getFullYear(), cursor.getMonth(), 1, 12);
    let calendarMode = "range";
    let awaitingRangeEnd = false;
    let preset = text(presetOutput?.value, "CUSTOM");

    const datesInBlackout = () => Array.from(new Set(
      text(blackoutOutput.value).split(/[,;\n]+/).map((value) => text(value)).filter((value) => parseCalendarDate(value)),
    )).sort();
    const saveBlackoutDates = (dates) => {
      blackoutOutput.value = Array.from(new Set(dates.filter((value) => parseCalendarDate(value)))).sort().join(", ");
    };
    const activeWeekdays = () => weekdayInputs.filter((input) => input.checked).map((input) => Number(input.value));
    const humanWeekdays = () => {
      const labels = ["lunes", "martes", "miércoles", "jueves", "viernes", "sábado", "domingo"];
      const days = activeWeekdays();
      if (days.length === 7) return "todos los días";
      if (days.length === 5 && days.every((day, index) => day === index)) return "de lunes a viernes";
      if (days.length === 2 && days.includes(5) && days.includes(6)) return "fines de semana";
      return days.length ? days.map((day) => labels[day]).join(", ") : "ningún día seleccionado";
    };
    const timezoneLabel = () => ({
      "America/Lima": "hora de Perú", "America/Bogota": "hora de Colombia", "America/Santiago": "hora de Chile",
      "America/Mexico_City": "hora de México", "America/New_York": "hora de Estados Unidos - Este",
    }[text(timezone?.value)] || text(timezone?.value, "hora local de las pantallas"));
    const scheduleSummary = () => {
      const start = parseCalendarDate(startDate.value);
      const end = parseCalendarDate(endDate.value);
      const time = startTime.value && endTime.value ? `${startTime.value} a ${endTime.value}` : "horario por definir";
      if (!start || !end) return "Seleccione el primer y último día para programar la campaña.";
      if (start > end) return "Revise el periodo: el último día debe ser posterior al primer día.";
      const blocks = datesInBlackout();
      const blocked = blocks.length ? ` · ${blocks.length} fecha${blocks.length === 1 ? " bloqueada" : "s bloqueadas"}` : "";
      return `Del ${calendarDateLabel(startDate.value)} al ${calendarDateLabel(endDate.value)}, ${humanWeekdays()}, de ${time} (${timezoneLabel()})${blocked}.`;
    };
    const renderBlackoutChips = () => {
      if (!(blackoutChips instanceof HTMLElement)) return;
      blackoutChips.replaceChildren();
      const dates = datesInBlackout();
      if (!dates.length) {
        blackoutChips.append(make("span", "muted", "No hay fechas bloqueadas."));
        return;
      }
      dates.forEach((value) => {
        const chip = make("span", "media-blackout-chip");
        chip.append(make("span", "", calendarDateLabel(value)));
        const remove = make("button", "", "×");
        remove.type = "button";
        remove.setAttribute("aria-label", `Quitar bloqueo del ${calendarDateLabel(value)}`);
        remove.addEventListener("click", () => {
          saveBlackoutDates(dates.filter((date) => date !== value));
          notify();
        });
        chip.append(remove);
        blackoutChips.append(chip);
      });
    };
    const renderCalendar = () => {
      if (!(grid instanceof HTMLElement)) return;
      const start = parseCalendarDate(startDate.value);
      const end = parseCalendarDate(endDate.value);
      const blackouts = new Set(datesInBlackout());
      if (monthTitle) monthTitle.textContent = calendarMonthLabel(cursor);
      grid.replaceChildren();
      const firstWeekday = (cursor.getDay() + 6) % 7;
      for (let index = 0; index < firstWeekday; index += 1) {
        const empty = make("span", "media-calendar-empty");
        empty.setAttribute("aria-hidden", "true");
        grid.append(empty);
      }
      const days = new Date(cursor.getFullYear(), cursor.getMonth() + 1, 0).getDate();
      const today = calendarDateValue(peruToday());
      for (let day = 1; day <= days; day += 1) {
        const date = new Date(cursor.getFullYear(), cursor.getMonth(), day, 12);
        const value = calendarDateValue(date);
        const inRange = Boolean(start && end && date >= start && date <= end);
        const button = make("button", "media-calendar-day", String(day));
        button.type = "button";
        button.dataset.calendarDate = value;
        button.classList.toggle("is-range", inRange);
        button.classList.toggle("is-range-start", Boolean(start && value === calendarDateValue(start)));
        button.classList.toggle("is-range-end", Boolean(end && value === calendarDateValue(end)));
        button.classList.toggle("is-today", value === today);
        button.classList.toggle("is-blocked", blackouts.has(value));
        button.setAttribute("aria-selected", String(inRange));
        button.setAttribute("aria-label", `${calendarDateLabel(value)}${blackouts.has(value) ? ", bloqueada" : ""}`);
        grid.append(button);
      }
      if (help) help.textContent = calendarMode === "blackout"
        ? "Seleccione una fecha para bloquearla o quitar el bloqueo. Estas fechas no reproducirán la campaña."
        : awaitingRangeEnd ? "Ahora elija el último día del periodo." : "Elija el primer y el último día de la campaña.";
    };
    const updateClock = () => {
      const selected = `${startTime.value}|${endTime.value}`;
      form.querySelectorAll("[data-schedule-time]").forEach((button) => {
        const isSelected = button.dataset.scheduleTime === selected;
        button.classList.toggle("is-selected", isSelected);
        button.setAttribute("aria-pressed", String(isSelected));
      });
    };
    const updateOutputs = () => {
      const selectedDays = activeWeekdays();
      if (presetOutput) presetOutput.value = preset;
      if (rangeOutput) rangeOutput.value = startDate.value && endDate.value ? `${startDate.value}..${endDate.value}` : "";
      if (startOutput) startOutput.value = startDate.value && startTime.value ? `${startDate.value}T${startTime.value}` : "";
      if (endOutput) endOutput.value = endDate.value && endTime.value ? `${endDate.value}T${endTime.value}` : "";
      if (weekdaysOutput) weekdaysOutput.value = selectedDays.join(",");
    };
    const syncValidity = () => {
      const start = parseCalendarDate(startDate.value);
      const end = parseCalendarDate(endDate.value);
      endDate.min = startDate.value || "";
      if (start && end && start > end) endDate.setCustomValidity("El último día debe ser posterior al primer día.");
      else endDate.setCustomValidity("");
      if (start && end && calendarDateValue(start) === calendarDateValue(end) && startTime.value && endTime.value && endTime.value < startTime.value) {
        endTime.setCustomValidity("En una campaña de un solo día, la hora de fin no puede ser anterior a la hora de inicio.");
      } else endTime.setCustomValidity("");
    };
    const notify = () => {
      syncValidity();
      updateOutputs();
      renderBlackoutChips();
      renderCalendar();
      updateClock();
      if (summary) summary.textContent = scheduleSummary();
      onChange?.();
    };
    const setRange = (start, end, newPreset = "DATE_RANGE") => {
      startDate.value = start;
      endDate.value = end;
      preset = newPreset;
      awaitingRangeEnd = false;
      const parsed = parseCalendarDate(start);
      if (parsed) cursor = new Date(parsed.getFullYear(), parsed.getMonth(), 1, 12);
      notify();
    };
    const selectCalendarDate = (value) => {
      if (calendarMode === "blackout") {
        const dates = datesInBlackout();
        saveBlackoutDates(dates.includes(value) ? dates.filter((date) => date !== value) : [...dates, value]);
        preset = "CUSTOM";
        notify();
        return;
      }
      const selected = parseCalendarDate(value);
      const currentStart = parseCalendarDate(startDate.value);
      if (!awaitingRangeEnd || !currentStart) {
        startDate.value = value;
        endDate.value = value;
        awaitingRangeEnd = true;
      } else {
        if (selected < currentStart) {
          endDate.value = startDate.value;
          startDate.value = value;
        } else endDate.value = value;
        awaitingRangeEnd = false;
      }
      preset = "DATE_RANGE";
      notify();
    };
    calendar.querySelector("[data-calendar-previous]")?.addEventListener("click", () => {
      cursor = new Date(cursor.getFullYear(), cursor.getMonth() - 1, 1, 12);
      renderCalendar();
    });
    calendar.querySelector("[data-calendar-next]")?.addEventListener("click", () => {
      cursor = new Date(cursor.getFullYear(), cursor.getMonth() + 1, 1, 12);
      renderCalendar();
    });
    grid?.addEventListener("click", (event) => {
      const target = event.target instanceof Element ? event.target.closest("[data-calendar-date]") : null;
      if (target instanceof HTMLElement) selectCalendarDate(text(target.dataset.calendarDate));
    });
    calendar.querySelectorAll("[data-calendar-mode]").forEach((button) => button.addEventListener("click", () => {
      calendarMode = button.dataset.calendarMode === "blackout" ? "blackout" : "range";
      awaitingRangeEnd = false;
      calendar.querySelectorAll("[data-calendar-mode]").forEach((item) => {
        const selected = item.dataset.calendarMode === calendarMode;
        item.classList.toggle("is-selected", selected);
        item.setAttribute("aria-pressed", String(selected));
      });
      renderCalendar();
    }));
    form.querySelectorAll("[data-schedule-range]").forEach((button) => button.addEventListener("click", () => {
      const today = peruToday();
      const value = button.dataset.scheduleRange;
      if (value === "today") setRange(calendarDateValue(today), calendarDateValue(today));
      else if (value === "week" || value === "next-week") {
        const mondayOffset = (today.getDay() + 6) % 7;
        const monday = calendarDateAt(today, -mondayOffset + (value === "next-week" ? 7 : 0));
        setRange(calendarDateValue(monday), calendarDateValue(calendarDateAt(monday, 6)));
      } else if (value === "month") {
        const first = new Date(today.getFullYear(), today.getMonth(), 1, 12);
        const last = new Date(today.getFullYear(), today.getMonth() + 1, 0, 12);
        setRange(calendarDateValue(first), calendarDateValue(last));
      }
    }));
    form.querySelectorAll("[data-schedule-time]").forEach((button) => button.addEventListener("click", () => {
      const [from, until] = text(button.dataset.scheduleTime).split("|");
      if (!from || !until) return;
      startTime.value = from;
      endTime.value = until;
      preset = "CUSTOM";
      notify();
    }));
    form.querySelector("[data-blackout-add]")?.addEventListener("click", () => {
      const selected = text(blackoutPicker?.value);
      if (!parseCalendarDate(selected)) {
        blackoutPicker?.focus();
        return;
      }
      saveBlackoutDates([...datesInBlackout(), selected]);
      if (blackoutPicker) blackoutPicker.value = "";
      preset = "CUSTOM";
      notify();
    });
    [startDate, endDate, startTime, endTime, timezone, blackoutOutput, ...weekdayInputs].forEach((field) => {
      field.addEventListener("input", () => { awaitingRangeEnd = false; preset = "CUSTOM"; notify(); });
      field.addEventListener("change", () => { awaitingRangeEnd = false; preset = "CUSTOM"; notify(); });
    });
    notify();
    return { summary: scheduleSummary, refresh: notify };
  };

  // Screens are also a server-side catalogue.  A campaign form must not
  // render every physical display merely to let Marketing choose a few of
  // them, especially because each selected Screen owns its own video picker.
  const createCampaignScreenCard = (screen, suggestedAssetId = "", suggestedAssetName = "") => {
    const screenId = text(screen?.screen_id);
    if (!screenId) return null;
    const screenName = text(screen?.name, "Pantalla");
    const domKey = screenId.replace(/[^a-zA-Z0-9_-]/g, "-");
    const card = make("article", "media-screen-choice selected");
    card.dataset.screenChoice = "";
    card.dataset.screenName = screenName;
    card.dataset.screenId = screenId;

    const title = make("label", "media-screen-choice-title");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.name = "screen_id";
    checkbox.value = screenId;
    checkbox.checked = true;
    checkbox.dataset.screenCheckbox = "";
    const titleText = make("span");
    titleText.append(make("strong", "", screenName));
    const use = text(screen?.playback_policy).toUpperCase() === "SHARED_PAUSE_ON_HUMAN_ACTIVITY"
      ? "Pausa el contenido durante uso humano" : "Contenido continuo en pantalla dedicada";
    const location = [text(screen?.site_code), text(screen?.location), use].filter(Boolean).join(" · ");
    titleText.append(make("small", "", location));
    title.append(checkbox, titleText);
    card.append(title);

    const content = make("div", "media-screen-content");
    content.dataset.screenContent = "";
    const assetPicker = make("div", "field wide media-screen-asset-picker");
    assetPicker.dataset.screenAssetPicker = "";
    const assetLabel = make("label", "", "Video que verá esta pantalla");
    assetLabel.htmlFor = `asset-${domKey}`;
    const assetSearch = document.createElement("input");
    assetSearch.className = "input media-screen-asset-search";
    assetSearch.id = `asset-search-${domKey}`;
    assetSearch.type = "search";
    assetSearch.placeholder = "Buscar video por nombre";
    assetSearch.autocomplete = "off";
    assetSearch.dataset.screenAssetSearch = "";
    const assetSelect = document.createElement("select");
    assetSelect.className = "input";
    assetSelect.id = `asset-${domKey}`;
    assetSelect.name = `asset_id_${screenId}`;
    assetSelect.dataset.screenAsset = "";
    assetSelect.dataset.selectedAssetId = text(suggestedAssetId);
    assetSelect.add(new Option("Buscar o abrir la lista de videos", ""));
    if (text(suggestedAssetId)) {
      const selectedName = text(suggestedAssetName, "Video seleccionado");
      const selected = new Option(`${selectedName} · cargando detalle…`, text(suggestedAssetId), true, true);
      selected.dataset.assetName = selectedName;
      selected.dataset.assetState = "READY";
      assetSelect.add(selected);
    }
    const assetActions = make("div", "media-asset-picker-actions");
    assetActions.dataset.screenAssetActions = "";
    assetActions.hidden = true;
    const assetPrevious = make("button", "btn btn-small", "Anterior");
    assetPrevious.type = "button";
    assetPrevious.dataset.screenAssetPrevious = "";
    const assetPage = make("span", "muted");
    assetPage.dataset.screenAssetPage = "";
    const assetNext = make("button", "btn btn-small", "Siguiente");
    assetNext.type = "button";
    assetNext.dataset.screenAssetNext = "";
    assetActions.append(assetPrevious, assetPage, assetNext);
    const assetStatus = make("small", "media-selection-status", "Busque un video listo para esta pantalla.");
    assetStatus.dataset.selectedAssetStatus = "";
    assetPicker.append(assetLabel, assetSearch, assetSelect, assetActions, assetStatus);
    content.append(assetPicker);

    const addTextField = (name, labelText, placeholder, className = "field") => {
      const field = make("div", className);
      const label = make("label", "", labelText);
      const input = document.createElement("input");
      input.className = "input";
      input.id = `${name}-${domKey}`;
      input.name = `${name}_${screenId}`;
      input.maxLength = name === "content_note" ? 500 : name === "content_title" ? 180 : 120;
      input.placeholder = placeholder;
      label.htmlFor = input.id;
      field.append(label, input);
      content.append(field);
      return input;
    };
    addTextField("content_title", "Nombre interno del contenido", "Se completa a partir del video si lo deja vacío");
    addTextField("playlist_name", "Nombre de lista", "Ej. Promoción principal");

    const priorityField = make("div", "field");
    const priorityLabel = make("label", "", "Prioridad en esta pantalla");
    const priority = document.createElement("input");
    priority.className = "input";
    priority.id = `priority-${domKey}`;
    priority.type = "number";
    priority.name = `priority_${screenId}`;
    priority.min = "1";
    priority.max = "100";
    priority.value = "50";
    priorityLabel.htmlFor = priority.id;
    priorityField.append(priorityLabel, priority, make("small", "", "Use una prioridad distinta si hay campañas coincidentes."));
    content.append(priorityField);

    const emergencyField = make("div", "field media-emergency-field");
    const emergencyLabel = make("label");
    const emergency = document.createElement("input");
    emergency.type = "checkbox";
    emergency.name = `emergency_${screenId}`;
    emergency.value = "1";
    emergency.dataset.screenEmergency = "";
    emergencyLabel.append(emergency, document.createTextNode(" Emergencia"));
    emergencyField.append(emergencyLabel, make("small", "", "Da prioridad a este mensaje sobre la programación habitual de esa pantalla."));
    content.append(emergencyField);
    addTextField("content_note", "Nota para el equipo de Marketing (opcional)", "Ej. Usar creatividad vertical", "field wide");
    card.append(content);
    return card;
  };

  const initLazyScreenCatalog = (form, addScreen) => {
    const root = form.querySelector("[data-screen-catalog]");
    if (!(root instanceof HTMLElement) || typeof addScreen !== "function") return;
    const catalogUrl = text(root.dataset.screenCatalogUrl);
    const results = root.querySelector("[data-screen-catalog-results]");
    const status = root.querySelector("[data-screen-catalog-status]");
    const search = root.querySelector("[data-screen-catalog-search]");
    const site = root.querySelector("[data-screen-catalog-site]");
    const state = root.querySelector("[data-screen-catalog-state]");
    const refresh = root.querySelector("[data-screen-catalog-refresh]");
    const paginationPanel = root.querySelector("[data-screen-catalog-pagination]");
    const previous = root.querySelector("[data-screen-catalog-previous]");
    const next = root.querySelector("[data-screen-catalog-next]");
    const pageLabel = root.querySelector("[data-screen-catalog-page]");
    if (!catalogUrl || !(results instanceof HTMLElement)) return;
    const pageSize = Math.max(5, Math.min(50, Number(root.dataset.screenCatalogPageSize) || 12));
    let page = 1;
    let pagination = {};
    let requestSerial = 0;
    let searchTimer = 0;

    const selectedIds = () => new Set(Array.from(form.querySelectorAll("[data-screen-choice]"))
      .filter((card) => card.querySelector("[data-screen-checkbox]")?.checked)
      .map((card) => text(card.dataset.screenId || card.querySelector("[data-screen-checkbox]")?.value))
      .filter(Boolean));
    const syncResultButtons = () => {
      const selected = selectedIds();
      results.querySelectorAll("[data-screen-catalog-add]").forEach((button) => {
        const chosen = selected.has(text(button.dataset.screenCatalogAdd));
        button.disabled = chosen;
        button.textContent = chosen ? "Elegida" : "Añadir";
      });
    };
    const renderPage = (items) => {
      results.replaceChildren();
      if (!items.length) {
        results.append(make("p", "muted media-screen-catalog-empty", "No se encontraron pantallas con esos filtros."));
        return;
      }
      items.forEach((screen) => {
        if (!screen?.screen_id || screen.archived) return;
        const row = make("article", "media-screen-catalog-result");
        const description = make("div", "media-screen-catalog-description");
        description.append(make("strong", "", text(screen.name, "Pantalla")));
        description.append(make("small", "", [text(screen.site_code), text(screen.location), stateText(screen.state, {
          READY: "Lista", OFFLINE: "Sin conexión", NEEDS_REVIEW: "Requiere revisión", DISABLED: "Desactivada",
        })].filter(Boolean).join(" · ")));
        const button = make("button", "btn btn-small btn-primary", "Añadir");
        button.type = "button";
        button.dataset.screenCatalogAdd = text(screen.screen_id);
        button.addEventListener("click", () => {
          addScreen(screen);
          syncResultButtons();
        });
        row.append(description, button);
        results.append(row);
      });
      syncResultButtons();
    };
    const renderPagination = () => {
      const total = Number(pagination.total || 0);
      const pages = Number(pagination.pages || 0);
      const current = Number(pagination.page || page || 1);
      if (paginationPanel instanceof HTMLElement) paginationPanel.hidden = !(pages > 1);
      if (pageLabel) pageLabel.textContent = pages > 1 ? `Página ${current} de ${pages} · ${total} pantalla(s)` : total ? `${total} pantalla(s)` : "";
      if (previous instanceof HTMLButtonElement) previous.disabled = !(pagination.has_previous || current > 1);
      if (next instanceof HTMLButtonElement) next.disabled = !(pagination.has_next || (pages > current));
    };
    const loadPage = async (requestedPage = 1) => {
      const serial = ++requestSerial;
      page = Math.max(1, Number(requestedPage) || 1);
      if (status) status.textContent = "Buscando pantallas…";
      if (refresh instanceof HTMLButtonElement) refresh.disabled = true;
      try {
        const url = new URL(catalogUrl, window.location.origin);
        url.searchParams.set("page", String(page));
        url.searchParams.set("page_size", String(pageSize));
        if (text(search?.value)) url.searchParams.set("q", text(search.value));
        if (text(site?.value)) url.searchParams.set("site", text(site.value));
        if (text(state?.value)) url.searchParams.set("state", text(state.value));
        const response = await fetch(url.toString(), { credentials: "same-origin", headers: { Accept: "application/json" } });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(text(payload.detail || payload.message, "No se pudo consultar el inventario de pantallas."));
        if (serial !== requestSerial) return;
        const items = Array.isArray(payload.Screens) ? payload.Screens : [];
        pagination = payload.Pagination || {};
        page = Number(pagination.page || page) || 1;
        renderPage(items);
        renderPagination();
        if (status) status.textContent = items.length
          ? "Añada sólo las pantallas que formarán parte de esta campaña."
          : "No hay pantallas disponibles con esos filtros.";
      } catch (error) {
        if (serial !== requestSerial) return;
        results.replaceChildren();
        pagination = {};
        renderPagination();
        if (status) status.textContent = text(error?.message, "No se pudo consultar el inventario. Intente nuevamente.");
      } finally {
        if (serial === requestSerial && refresh instanceof HTMLButtonElement) refresh.disabled = false;
      }
    };
    refresh?.addEventListener("click", () => { void loadPage(1); });
    search?.addEventListener("input", () => {
      window.clearTimeout(searchTimer);
      const query = text(search.value);
      if (query && query.length < 2) {
        if (status) status.textContent = "Escriba al menos dos letras para buscar una pantalla.";
        return;
      }
      searchTimer = window.setTimeout(() => { void loadPage(1); }, 260);
    });
    search?.addEventListener("search", () => { void loadPage(1); });
    site?.addEventListener("change", () => { void loadPage(1); });
    state?.addEventListener("change", () => { void loadPage(1); });
    previous?.addEventListener("click", () => { if (page > 1) void loadPage(page - 1); });
    next?.addEventListener("click", () => { if (pagination.has_next || (pagination.pages && page < pagination.pages)) void loadPage(page + 1); });
    form.addEventListener("gideon-screen-selection-change", syncResultButtons);
    // Show the first bounded page immediately.  Lazy/paginated must not mean
    // hidden until Marketing happens to touch a filter.
    void loadPage(1);
  };

  const initCampaignWizard = () => {
    const form = document.querySelector("[data-media-campaign-form]");
    if (!(form instanceof HTMLFormElement)) return;
    const review = form.querySelector("[data-media-review]");
    const validation = form.querySelector("[data-wizard-validation]");
    const progress = document.querySelector("[data-campaign-progress]");
    let scheduleDesigner = { summary: () => "" };
    const selectedCards = () => Array.from(form.querySelectorAll("[data-screen-choice]")).filter((card) => card.querySelector("[data-screen-checkbox]")?.checked);
    let screenGroupMode = "grouped";
    const groupKeyFor = (card) => {
      const value = (selector, fallback = "") => text(card.querySelector(selector)?.value, fallback);
      return JSON.stringify([
        value("[data-screen-asset]", "__pending__"),
        value("input[name^='content_title_']"),
        value("input[name^='playlist_name_']"),
        value("input[name^='priority_']", "50"),
        Boolean(card.querySelector("[data-screen-emergency]")?.checked),
        value("input[name^='content_note_']"),
      ]);
    };
    const groupMembers = (card) => text(card.dataset.screenGroupMembers).split(",").map((value) => text(value)).filter(Boolean);
    const cardById = (screenId) => Array.from(form.querySelectorAll("[data-screen-choice]")).find((card) => text(card.dataset.screenId) === text(screenId));
    const ensureAssetOption = (target, source) => {
      if (!(target instanceof HTMLSelectElement) || !(source instanceof HTMLSelectElement)) return;
      const value = text(source.value);
      if (!value) return;
      const exists = Array.from(target.options).some((option) => option.value === value);
      if (!exists) {
        const sourceOption = source.options[source.selectedIndex];
        const option = new Option(sourceOption?.textContent || "Video seleccionado", value);
        option.dataset.assetName = text(sourceOption?.dataset.assetName, sourceOption?.textContent || "Video seleccionado");
        option.dataset.assetState = text(sourceOption?.dataset.assetState, "READY");
        option.dataset.assetResolution = text(sourceOption?.dataset.assetResolution);
        option.dataset.assetDuration = text(sourceOption?.dataset.assetDuration);
        target.add(option);
      }
    };
    const copyGroupConfiguration = (source, memberIds) => {
      const selectors = ["[data-screen-asset]", "input[name^='content_title_']", "input[name^='playlist_name_']", "input[name^='priority_']", "[data-screen-emergency]", "input[name^='content_note_']"];
      memberIds.map(cardById).filter((card) => card && card !== source).forEach((target) => {
        selectors.forEach((selector) => {
          const sourceField = source.querySelector(selector);
          const targetField = target.querySelector(selector);
          if (!sourceField || !targetField) return;
          if (sourceField instanceof HTMLSelectElement && targetField instanceof HTMLSelectElement) {
            ensureAssetOption(targetField, sourceField);
            targetField.value = sourceField.value;
            targetField.dataset.selectedAssetId = text(sourceField.value);
          } else if (sourceField instanceof HTMLInputElement && targetField instanceof HTMLInputElement && sourceField.type === "checkbox") {
            targetField.checked = sourceField.checked;
          } else if ("value" in sourceField && "value" in targetField) {
            targetField.value = sourceField.value;
          }
          refreshCard(target);
        });
      });
    };
    const renderScreenGroups = () => {
      const cards = Array.from(form.querySelectorAll("[data-screen-choice]")).filter((card) => card instanceof HTMLElement);
      cards.forEach((card) => {
        card.hidden = false;
        delete card.dataset.screenGroupMembers;
        delete card.dataset.screenGroupRepresentative;
        card.classList.remove("is-screen-group-representative");
        card.querySelector(".media-screen-group-summary")?.remove();
      });
      if (screenGroupMode !== "grouped") return;
      const groups = new Map();
      selectedCards().forEach((card) => {
        const key = groupKeyFor(card);
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(card);
      });
      groups.forEach((members) => {
        const representative = members[0];
        const ids = members.map((card) => text(card.dataset.screenId)).filter(Boolean);
        representative.dataset.screenGroupMembers = ids.join(",");
        representative.dataset.screenGroupRepresentative = "true";
        representative.classList.add("is-screen-group-representative");
        const title = representative.querySelector("[data-screen-choice-title]");
        if (title && members.length > 1) {
          const summary = make("small", "media-screen-group-summary", `${members.length} pantallas · esta configuración se aplicará a todas`);
          title.append(summary);
        }
        members.slice(1).forEach((card) => { card.hidden = true; });
      });
    };
    const setScreenGroupMode = (mode) => {
      screenGroupMode = mode === "individual" ? "individual" : "grouped";
      form.querySelectorAll("[data-screen-group-mode]").forEach((button) => {
        const selected = button.dataset.screenGroupMode === screenGroupMode;
        button.classList.toggle("is-selected", selected);
        button.setAttribute("aria-pressed", String(selected));
      });
      renderScreenGroups();
      renderReview();
    };
    const refreshCard = (card) => {
      const checkbox = card.querySelector("[data-screen-checkbox]");
      const selected = Boolean(checkbox?.checked);
      card.classList.toggle("selected", selected);
      card.querySelectorAll("input:not([type=checkbox]), textarea, select").forEach((field) => { field.disabled = !selected; });
      const select = card.querySelector("[data-screen-asset]");
      const status = card.querySelector("[data-selected-asset-status]");
      const option = select?.options?.[select.selectedIndex];
      if (status) {
        status.textContent = option?.value
          ? `${option.dataset.assetName || option.textContent || "Video"}${option.dataset.assetResolution ? ` · ${option.dataset.assetResolution}` : ""}${option.dataset.assetDuration ? ` · ${formatDuration(option.dataset.assetDuration)}` : ""}${option.dataset.assetWarning ? ` · ${option.dataset.assetWarning}` : ""}`
          : "Seleccione un video listo para esta pantalla.";
      }
      if (selected) card.dispatchEvent(new CustomEvent("gideon-screen-asset-activate"));
    };
    const updateProgress = () => {
      const cards = selectedCards();
      const complete = [
        Boolean(text(form.querySelector("[data-review-title]")?.value)),
        cards.length > 0 && cards.every((card) => Boolean(card.querySelector("[data-screen-asset]")?.value)),
        cards.length > 0,
        Boolean(form.querySelector("#startDate")?.value && form.querySelector("#endDate")?.value && form.querySelector("#startTime")?.value && form.querySelector("#endTime")?.value),
        false,
      ];
      const firstIncomplete = complete.findIndex((value) => !value);
      progress?.querySelectorAll("[data-wizard-step]").forEach((step, index) => {
        const isComplete = complete[index] && index !== 4;
        const isActive = index === (firstIncomplete === -1 ? 4 : firstIncomplete);
        step.classList.toggle("is-complete", isComplete);
        step.classList.toggle("is-active", isActive);
        if (isActive) step.setAttribute("aria-current", "step"); else step.removeAttribute("aria-current");
      });
    };
    const renderReview = () => {
      if (!review) return;
      const cards = selectedCards();
      review.replaceChildren();
      const title = text(form.querySelector("[data-review-title]")?.value, "Campaña sin nombre");
      review.append(make("h3", "", title));
      const objective = text(form.querySelector("[data-review-objective]")?.value);
      if (objective) review.append(make("p", "muted", objective));
      const list = make("ul", "media-review-list");
      const reviewGroups = new Map();
      cards.forEach((card) => {
        const select = card.querySelector("[data-screen-asset]");
        const option = select?.options?.[select.selectedIndex];
        const screenName = text(card.dataset.screenName, "Pantalla");
        const videoName = option?.value ? text(option.dataset.assetName, "Video seleccionado") : "Video pendiente de elegir";
        const emergency = card.querySelector("[data-screen-emergency]")?.checked ? " · Emergencia" : "";
        if (screenGroupMode === "grouped") {
          const key = groupKeyFor(card);
          if (!reviewGroups.has(key)) reviewGroups.set(key, { names: [], videoName, emergency });
          reviewGroups.get(key).names.push(screenName);
        } else list.append(make("li", "", `${screenName}: ${videoName}${emergency}`));
      });
      if (screenGroupMode === "grouped") reviewGroups.forEach((group) => {
        const label = group.names.length > 1 ? `${group.names.length} pantallas (${group.names.join(", ")})` : group.names[0];
        list.append(make("li", "", `${label}: ${group.videoName}${group.emergency}`));
      });
      if (cards.length) review.append(list);
      else review.append(make("p", "muted", "Aún no ha seleccionado una pantalla."));
      const schedule = text(scheduleDesigner.summary?.());
      if (schedule) review.append(make("p", "media-review-schedule", `Programación: ${schedule}`));
      updateProgress();
    };
    const showValidation = (messages) => {
      if (!(validation instanceof HTMLElement)) return;
      validation.replaceChildren();
      validation.hidden = !messages.length;
      if (!messages.length) return;
      validation.append(make("strong", "", "Antes de publicar, complete lo siguiente:"));
      const list = make("ul");
      messages.forEach((message) => list.append(make("li", "", message)));
      validation.append(list);
    };
    const assetPickers = initLazyAssetPickers(form, renderReview);
    const selectedList = form.querySelector("[data-screen-selected-list]");
    const selectedCount = form.querySelector("[data-screen-selected-count]");
    const selectedEmpty = form.querySelector("[data-screen-selection-empty]");
    const updateSelectedSummary = () => {
      const count = selectedCards().length;
      if (selectedCount) selectedCount.textContent = `${count} seleccionada(s)`;
      if (selectedEmpty instanceof HTMLElement) selectedEmpty.hidden = count > 0;
      renderScreenGroups();
      form.dispatchEvent(new CustomEvent("gideon-screen-selection-change"));
    };
    const bindCard = (card) => {
      if (!(card instanceof HTMLElement) || card.dataset.campaignScreenReady === "true") return;
      card.dataset.campaignScreenReady = "true";
      const checkbox = card.querySelector("[data-screen-checkbox]");
      const select = card.querySelector("[data-screen-asset]");
      checkbox?.addEventListener("change", () => { refreshCard(card); updateSelectedSummary(); renderReview(); });
      select?.addEventListener("change", () => { refreshCard(card); renderReview(); });
      card.querySelectorAll("[data-screen-emergency]").forEach((item) => item.addEventListener("change", renderReview));
      assetPickers?.bind?.(card.querySelector("[data-screen-asset-picker]"));
      refreshCard(card);
    };
    form.querySelectorAll("[data-screen-group-mode]").forEach((button) => button.addEventListener("click", () => setScreenGroupMode(button.dataset.screenGroupMode)));
    form.addEventListener("change", (event) => {
      if (screenGroupMode !== "grouped") return;
      const target = event.target instanceof Element ? event.target : null;
      const card = target?.closest("[data-screen-choice]");
      if (!(card instanceof HTMLElement) || card.dataset.screenGroupRepresentative !== "true") return;
      const ids = groupMembers(card);
      if (ids.length > 1) copyGroupConfiguration(card, ids);
      renderScreenGroups();
      renderReview();
    });
    form.querySelectorAll("[data-screen-choice]").forEach(bindCard);
    initLazyScreenCatalog(form, (screen) => {
      const screenId = text(screen?.screen_id);
      const existing = Array.from(form.querySelectorAll("[data-screen-choice]")).find((card) =>
        text(card.dataset.screenId || card.querySelector("[data-screen-checkbox]")?.value) === screenId);
      if (existing instanceof HTMLElement) {
        const checkbox = existing.querySelector("[data-screen-checkbox]");
        if (checkbox instanceof HTMLInputElement) checkbox.checked = true;
        refreshCard(existing);
        existing.scrollIntoView?.({ behavior: "smooth", block: "center" });
      } else if (selectedList instanceof HTMLElement) {
        const card = createCampaignScreenCard(screen, text(form.dataset.suggestedAssetId), text(form.dataset.suggestedAssetName));
        if (card) {
          selectedList.append(card);
          bindCard(card);
          card.scrollIntoView?.({ behavior: "smooth", block: "center" });
        }
      }
      updateSelectedSummary();
      renderReview();
    });
    form.querySelectorAll("[data-review-title], [data-review-objective]").forEach((field) => field.addEventListener("input", renderReview));
    scheduleDesigner = initCampaignScheduleDesigner(form, renderReview);
    form.addEventListener("submit", (event) => {
      const messages = [];
      const cards = selectedCards();
      if (!cards.length) messages.push("Seleccione al menos una pantalla.");
      const missingVideo = cards.filter((card) => !card.querySelector("[data-screen-asset]")?.value);
      if (missingVideo.length) messages.push(`Elija un video listo para ${missingVideo.length === 1 ? "la pantalla seleccionada" : "cada pantalla seleccionada"}.`);
      if (!form.querySelector("input[name=weekday]:checked")) messages.push("Seleccione al menos un día de reproducción.");
      const firstInvalid = cards.find((card) => !card.querySelector("[data-screen-asset]")?.value) || (!cards.length ? form.querySelector("[data-screen-choice]") : null);
      if (messages.length) {
        event.preventDefault();
        showValidation(messages);
        firstInvalid?.scrollIntoView?.({ behavior: "smooth", block: "center" });
      } else showValidation([]);
    });
    updateSelectedSummary();
    renderReview();
  };

  const initLibrarySearch = () => {
    const input = document.querySelector("[data-media-library-search]");
    const rows = Array.from(document.querySelectorAll("[data-media-asset-row]"));
    const count = document.querySelector("[data-media-library-count]");
    if (!(input instanceof HTMLInputElement) || !rows.length) return;
    input.addEventListener("input", () => {
      const needle = input.value.trim().toLocaleLowerCase();
      let visible = 0;
      rows.forEach((row) => {
        const matches = !needle || text(row.dataset.mediaSearch).toLocaleLowerCase().includes(needle);
        row.hidden = !matches;
        if (matches) visible += 1;
      });
      if (count) count.textContent = needle ? `${visible} video(s) coinciden con la búsqueda.` : `${rows.length} video(s) en la biblioteca.`;
    });
  };

  const initDistribution = () => {
    const panel = document.querySelector("[data-media-distribution]");
    if (!(panel instanceof HTMLElement) || !panel.dataset.url) return;
    const body = panel.querySelector("[data-distribution-rows]");
    const indicator = panel.querySelector("[data-distribution-live]");
    if (!(body instanceof HTMLTableSectionElement)) return;
    const keyFor = (screen, video) => `${text(screen)}\u0000${text(video)}`;
    const buildRow = (target) => {
      const row = document.createElement("tr");
      row.dataset.distributionRow = "";
      row.dataset.distributionScreen = text(target.screen, "Pantalla");
      row.dataset.distributionVideo = text(target.video, "Video GIDEON");
      const screen = make("td"); screen.append(make("strong", "", text(target.screen, "Pantalla")), make("small", "muted block", text(target.site)));
      const video = make("td"); video.append(make("strong", "", text(target.video, "Video GIDEON")));
      const state = make("td"); state.append(make("span", "chip media-distribution-state", ""), make("small", "muted block", "")); state.querySelector("span").dataset.distributionState = ""; state.querySelector("small").dataset.distributionMessage = "";
      const updated = make("td", "", "Pendiente"); updated.dataset.distributionUpdated = "";
      const job = make("td"); job.dataset.distributionJob = "";
      row.append(screen, video, state, updated, job);
      return row;
    };
    const updateRow = (row, target) => {
      const state = text(target.state, "PENDING").toUpperCase();
      const chip = row.querySelector("[data-distribution-state]");
      const message = row.querySelector("[data-distribution-message]");
      const updated = row.querySelector("[data-distribution-updated]");
      const job = row.querySelector("[data-distribution-job]");
      if (chip) { chip.className = `chip media-distribution-state media-distribution-${state.toLowerCase()}`; chip.textContent = stateText(state, distributionLabels); }
      if (message) message.textContent = text(target.message);
      if (updated) updated.textContent = text(target.updated_at, "Pendiente");
      if (job) {
        job.replaceChildren();
        if (target.job_url) {
          const link = make("a", "btn btn-small", "Ver Job");
          link.href = text(target.job_url);
          job.append(link);
        } else job.append(make("span", "muted", state === "PENDING" ? "En preparación" : "Seguimiento en campaña"));
      }
    };
    let failures = 0;
    const refresh = async () => {
      if (document.hidden) return;
      try {
        const response = await fetch(panel.dataset.url, { credentials: "same-origin", headers: { Accept: "application/json" } });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error();
        const targets = Array.isArray(payload.Targets) ? payload.Targets : [];
        const existing = new Map(Array.from(body.querySelectorAll("[data-distribution-row]")).map((row) => [keyFor(row.dataset.distributionScreen, row.dataset.distributionVideo), row]));
        body.querySelector("[data-distribution-empty]")?.remove();
        targets.forEach((target) => {
          const key = keyFor(target.screen, target.video);
          const row = existing.get(key) || buildRow(target);
          if (!existing.has(key)) body.append(row);
          updateRow(row, target);
        });
        failures = 0;
        if (indicator) indicator.textContent = "Actualización automática";
      } catch (_) {
        failures += 1;
        if (indicator) indicator.textContent = failures >= 3 ? "Actualización en pausa; vuelva a intentar más tarde" : "Actualización temporalmente no disponible";
      }
    };
    void refresh();
    window.setInterval(() => { void refresh(); }, 12000);
    document.addEventListener("visibilitychange", () => { if (!document.hidden) void refresh(); });
  };

  const initScreenAgentSelector = () => {
    const siteSelect = document.querySelector("select[name='site_code']");
    const agentSelect = document.querySelector("[data-agent-select]");
    if (!(siteSelect instanceof HTMLSelectElement) || !(agentSelect instanceof HTMLSelectElement)) return;
    const hasAvailableOutput = (option) => {
      let outputs = [];
      let registered = [];
      try { outputs = JSON.parse(option.dataset.outputs || "[]"); } catch (_) { outputs = []; }
      try { registered = JSON.parse(option.dataset.registeredOutputs || "[]").map(String); } catch (_) { registered = []; }
      const candidates = outputs.length ? outputs.map((item) => text(item?.output_key)) : ["SCREEN-1", "SCREEN-2", "SCREEN-3"];
      const selectedOutput = text(document.querySelector("[data-output-select]")?.dataset.selectedOutput);
      return candidates.some((candidate) => candidate && (!registered.includes(candidate) || (option.value === agentSelect.value && candidate === selectedOutput)));
    };
    const syncAgents = () => {
      const site = text(siteSelect.value).toUpperCase();
      const previous = agentSelect.value;
      Array.from(agentSelect.options).forEach((option, index) => {
        if (index === 0) { option.hidden = false; return; }
        const matchesSite = Boolean(site) && text(option.dataset.siteCode).toUpperCase() === site;
        option.hidden = !(matchesSite && hasAvailableOutput(option));
      });
      if (agentSelect.value && agentSelect.selectedOptions[0]?.hidden) agentSelect.value = "";
      if (!site) agentSelect.options[0].textContent = "Seleccione primero una sede";
      else if (!Array.from(agentSelect.options).some((option, index) => index > 0 && !option.hidden)) agentSelect.options[0].textContent = "No hay equipos o salidas disponibles en esta sede";
      else agentSelect.options[0].textContent = "Seleccione un equipo";
      if (previous !== agentSelect.value) agentSelect.dispatchEvent(new Event("change", { bubbles: true }));
    };
    siteSelect.addEventListener("change", () => { if (!siteSelect.disabled) agentSelect.value = ""; syncAgents(); agentSelect.dispatchEvent(new Event("change", { bubbles: true })); });
    agentSelect.addEventListener("change", syncAgents);
    syncAgents();
  };

  const initScreenOutputSelector = () => {
    const agentSelect = document.querySelector("[data-agent-select]");
    const outputSelect = document.querySelector("[data-output-select]");
    const identityInput = document.querySelector("[data-output-identity]");
    const targetKindInput = document.querySelector("[data-target-kind]");
    const sessionHint = document.querySelector("[data-agent-session-hint]");
    const nameInput = document.querySelector("[data-screen-name-input]");
    const resolutionInput = document.querySelector("[data-screen-resolution]");
    const resolutionHint = document.querySelector("[data-resolution-hint]");
    if (!(agentSelect instanceof HTMLSelectElement) || !(outputSelect instanceof HTMLSelectElement)
      || !(identityInput instanceof HTMLInputElement) || !(targetKindInput instanceof HTMLInputElement)) return;
    const selectTarget = () => {
      const selected = outputSelect.options[outputSelect.selectedIndex];
      identityInput.value = text(selected?.dataset.outputIdentity);
      targetKindInput.value = text(selected?.dataset.targetKind) || "PHYSICAL_CONNECTOR";
    };
    const updateOutputs = () => {
      const option = agentSelect.options[agentSelect.selectedIndex];
      let outputs = [];
      let registeredOutputs = [];
      try { outputs = JSON.parse(option?.dataset.outputs || "[]"); } catch (_) { outputs = []; }
      try { registeredOutputs = JSON.parse(option?.dataset.registeredOutputs || "[]").map(String); } catch (_) { registeredOutputs = []; }
      if (sessionHint) sessionHint.textContent = text(option?.dataset.sessionSummary, "Seleccione un Agent para consultar su sesión gráfica y salidas.");
      if (nameInput && (!nameInput.value.trim() || nameInput.dataset.autoName === "true") && option?.value) {
        nameInput.value = text(option.dataset.deviceName, option.textContent?.split(" · ")[2] || "Pantalla");
        nameInput.dataset.autoName = "true";
      }
      outputSelect.replaceChildren();
      outputSelect.add(new Option(outputs.length ? "Seleccione una salida" : "Salida manual temporal", ""));
      outputs.forEach((output) => {
        const outputKey = text(output.output_key);
        const selectedOutput = text(outputSelect.dataset.selectedOutput);
        if (registeredOutputs.includes(outputKey) && outputKey !== selectedOutput) return;
        const typeLabel = output.target_kind_label || (output.target_kind === "LOCAL_WAYLAND_SESSION" ? "Sesión gráfica local" : "HDMI físico");
        const label = `${output.label || "Pantalla"} · ${typeLabel}${output.resolution ? ` · ${output.resolution}` : ""}${output.last_known ? " · última salida registrada" : (output.connected ? "" : " · no disponible")}`;
        const entry = new Option(label, outputKey);
        entry.dataset.outputIdentity = text(output.output_identity);
        entry.dataset.targetKind = text(output.target_kind) || "PHYSICAL_CONNECTOR";
        entry.dataset.outputResolution = text(output.resolution);
        outputSelect.add(entry);
      });
      if (!outputs.length && agentSelect.value) {
        ["SCREEN-1", "SCREEN-2", "SCREEN-3"].forEach((value, index) => {
          const selectedOutput = text(outputSelect.dataset.selectedOutput);
          if (registeredOutputs.includes(value) && value !== selectedOutput) return;
          const entry = new Option(`Pantalla manual ${index + 1} · requiere revisión`, value);
          entry.dataset.targetKind = "PHYSICAL_CONNECTOR";
          outputSelect.add(entry);
        });
      }
      const selected = outputSelect.dataset.selectedOutput || "";
      if (selected) {
        const exists = Array.from(outputSelect.options).some((entry) => entry.value === selected);
        if (!exists) {
          const entry = new Option("Salida actualmente configurada", selected);
          entry.dataset.outputIdentity = text(outputSelect.dataset.selectedOutputIdentity);
          entry.dataset.targetKind = text(targetKindInput.dataset.selectedTargetKind) || "PHYSICAL_CONNECTOR";
          outputSelect.add(entry);
        }
        outputSelect.value = selected;
      }
      selectTarget();
      const selectedEntry = outputSelect.options[outputSelect.selectedIndex];
      const detectedResolution = text(selectedEntry?.dataset.outputResolution);
      if (resolutionInput && detectedResolution && (resolutionInput.dataset.autoResolution === "true" || !resolutionInput.value.trim())) {
        resolutionInput.value = detectedResolution;
        resolutionInput.dataset.autoResolution = "true";
        if (resolutionHint) resolutionHint.textContent = `Resolución detectada: ${detectedResolution}. Puede corregirla si el monitor usa otro modo.`;
      } else if (resolutionHint && !detectedResolution) {
        resolutionHint.textContent = "Se usará la resolución reportada por el destino físico o la sesión gráfica.";
      }
    };
    agentSelect.addEventListener("change", updateOutputs);
    outputSelect.addEventListener("change", selectTarget);
    outputSelect.addEventListener("change", () => {
      const selected = outputSelect.options[outputSelect.selectedIndex];
      const detectedResolution = text(selected?.dataset.outputResolution);
      if (resolutionInput && detectedResolution && (resolutionInput.dataset.autoResolution === "true" || !resolutionInput.value.trim())) {
        resolutionInput.value = detectedResolution;
        resolutionInput.dataset.autoResolution = "true";
        if (resolutionHint) resolutionHint.textContent = `Resolución detectada: ${detectedResolution}. Puede corregirla si el monitor usa otro modo.`;
      }
    });
    nameInput?.addEventListener("input", () => { nameInput.dataset.autoName = "false"; });
    resolutionInput?.addEventListener("input", () => { resolutionInput.dataset.autoResolution = "false"; });
    updateOutputs();
  };

  ready(() => {
    initLocalizedDatePickers();
    initUploadForms();
    initLibraryAssetPolling();
    initCampaignWizard();
    initLibrarySearch();
    initDistribution();
    initScreenOutputSelector();
    initScreenAgentSelector();
  });
})();
