(() => {
  const TOKEN_KEY = "qwdtt.adminToken";
  const SERVER_ADDRESS_KEY = "qwdtt.serverAddress";
  const state = {
    token: sessionStorage.getItem(TOKEN_KEY) || "",
    serverAddress: localStorage.getItem(SERVER_ADDRESS_KEY) || "",
    entries: [],
    filter: "all",
    query: "",
    selected: null,
    editing: null,
    createKey: "",
    qrObjectURL: "",
    toastTimer: 0,
  };
  const byId = (id) => document.getElementById(id);
  const loginView = byId("login-view");
  const appView = byId("app-view");
  const rows = byId("key-rows");
  const listButton = byId("refresh-button");
  const editor = byId("editor-dialog");
  const details = byId("details-dialog");

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  async function request(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set("Authorization", `Bearer ${state.token}`);
    if (options.body && !(options.body instanceof URLSearchParams))
      headers.set("Content-Type", "application/x-www-form-urlencoded");
    const response = await fetch(path, {
      ...options,
      headers,
      cache: "no-store",
    });
    const text = await response.text();
    let payload = {};
    if (text) {
      try {
        payload = JSON.parse(text);
      } catch {
        payload = { error: text.trim() };
      }
    }
    if (!response.ok) {
      if (response.status === 401) logout(false);
      throw new Error(payload.error || `HTTP ${response.status}`);
    }
    return payload;
  }

  function setLoginError(message) {
    byId("login-error").textContent = message || "";
  }

  function setBanner(message) {
    const banner = byId("error-banner");
    banner.textContent = message || "";
    banner.hidden = !message;
  }

  function toast(message, failed = false) {
    const node = byId("toast");
    node.textContent = message;
    node.classList.toggle("error", failed);
    node.classList.add("show");
    window.clearTimeout(state.toastTimer);
    state.toastTimer = window.setTimeout(
      () => node.classList.remove("show"),
      2800,
    );
  }

  function normalizeServerAddress(value) {
    let address = value.trim();
    if (address.startsWith("[") && address.endsWith("]")) {
      address = address.slice(1, -1).trim();
    }
    if (
      !address ||
      /[\s/?#@]/.test(address) ||
      address.includes("\\") ||
      address.startsWith(".") ||
      address.endsWith(".") ||
      (address.indexOf(":") === address.lastIndexOf(":") && address.includes(":"))
    ) {
      return "";
    }
    return address;
  }

  function setServerAddressStatus(message, failed = false) {
    const status = byId("server-address-status");
    status.textContent = message || "";
    status.classList.toggle("error", failed);
  }

  function saveServerAddress() {
    const address = normalizeServerAddress(byId("server-address").value);
    if (!address) {
      setServerAddressStatus("Введите IP-адрес или hostname без схемы и порта.", true);
      return false;
    }
    state.serverAddress = address;
    localStorage.setItem(SERVER_ADDRESS_KEY, address);
    byId("server-address").value = address;
    setServerAddressStatus("Адрес сохранён. Новые ссылки будут использовать его.");
    if (state.selected) renderDetails();
    return true;
  }

  async function detectServerAddress() {
    const button = byId("detect-server-address");
    button.disabled = true;
    setServerAddressStatus("Определяем внешний IP…");
    try {
      const response = await fetch("/admin/public-address", {
        headers: { Authorization: `Bearer ${state.token}` },
        cache: "no-store",
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const payload = await response.json();
      const address = normalizeServerAddress(payload.address || "");
      if (!address) throw new Error("Сервис вернул некорректный адрес.");
      byId("server-address").value = address;
      saveServerAddress();
    } catch (error) {
      setServerAddressStatus(
        `Не удалось определить адрес: ${error.message || "проверьте соединение"}. Укажите его вручную.`,
        true,
      );
    } finally {
      button.disabled = false;
    }
  }

  function showApp() {
    loginView.hidden = true;
    appView.hidden = false;
  }

  function logout(showMessage = true) {
    state.token = "";
    sessionStorage.removeItem(TOKEN_KEY);
    appView.hidden = true;
    loginView.hidden = false;
    byId("admin-token").value = "";
    setLoginError(
      showMessage
        ? "Сессия завершена. Войдите снова."
        : "Токен не принят или сессия истекла.",
    );
    setBanner("");
  }

  async function connect(token) {
    state.token = token.trim();
    if (!state.token) throw new Error("Введите admin token.");
    const payload = await request("/admin/passwords");
    state.entries = Array.isArray(payload.passwords) ? payload.passwords : [];
    sessionStorage.setItem(TOKEN_KEY, state.token);
    setLoginError("");
    showApp();
    render();
    await refreshHealth();
  }

  async function refresh() {
    if (!state.token) return;
    listButton.disabled = true;
    setBanner("");
    byId("loading-state").hidden = state.entries.length > 0;
    try {
      const payload = await request("/admin/passwords");
      state.entries = Array.isArray(payload.passwords) ? payload.passwords : [];
      byId("last-updated").textContent = new Intl.DateTimeFormat("ru-RU", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }).format(new Date());
      render();
      if (state.selected) {
        state.selected =
          state.entries.find(
            (entry) => entry.password === state.selected.password,
          ) || null;
        if (state.selected && details.open) renderDetails();
        else if (details.open) details.close();
      }
    } catch (error) {
      setBanner(error.message || "Не удалось получить список ключей.");
    } finally {
      byId("loading-state").hidden = true;
      listButton.disabled = false;
    }
  }

  async function refreshHealth() {
    const pill = byId("server-health");
    const label = pill.querySelector("span:last-child");
    try {
      const response = await fetch("/healthz", { cache: "no-store" });
      const result = await response.json();
      pill.classList.toggle("offline", !response.ok);
      pill.classList.remove("warning");
      label.textContent = response.ok ? "API узла работает" : "Узел не готов";
      byId("api-state").textContent = response.ok ? "Работает" : "Не готов";
      byId("api-state").classList.toggle("state-good", response.ok);
      byId("api-state").classList.toggle("state-bad", !response.ok);
      if (!result.status) throw new Error("invalid health response");
    } catch {
      pill.classList.add("offline");
      label.textContent = "Нет связи с API";
      byId("api-state").textContent = "Нет связи";
      byId("api-state").classList.remove("state-good");
      byId("api-state").classList.add("state-bad");
    }
  }

  function entryStatus(entry) {
    if (entry.is_deactivated)
      return { label: "Отключён", className: "disabled" };
    if (entry.expires_at && entry.expires_at * 1000 < Date.now())
      return { label: "Истёк", className: "expired" };
    return { label: "Активен", className: "enabled" };
  }

  function formatDate(seconds) {
    if (!seconds) return "Без срока";
    return new Intl.DateTimeFormat("ru-RU", {
      day: "2-digit",
      month: "short",
      year: "numeric",
    }).format(new Date(seconds * 1000));
  }

  function formatBytes(value) {
    const bytes = Number(value) || 0;
    if (bytes < 1024) return `${bytes} Б`;
    const units = ["КБ", "МБ", "ГБ", "ТБ"];
    let size = bytes / 1024;
    let index = 0;
    while (size >= 1024 && index < units.length - 1) {
      size /= 1024;
      index++;
    }
    return `${size.toFixed(size >= 100 ? 0 : 1)} ${units[index]}`;
  }

  function filteredEntries() {
    const needle = state.query.trim().toLocaleLowerCase("ru-RU");
    return state.entries.filter((entry) => {
      const status = entryStatus(entry);
      if (state.filter === "enabled" && status.className !== "enabled")
        return false;
      if (state.filter === "disabled" && status.className !== "disabled")
        return false;
      if (!needle) return true;
      return [
        entry.label,
        entry.password,
        entry.vk_hash,
        ...(entry.device_ids || []),
      ].some((value) =>
        String(value || "")
          .toLocaleLowerCase("ru-RU")
          .includes(needle),
      );
    });
  }

  function render() {
    const entries = state.entries;
    const enabled = entries.filter(
      (entry) =>
        !entry.is_deactivated &&
        (!entry.expires_at || entry.expires_at * 1000 >= Date.now()),
    );
    const disabled = entries.filter((entry) => entry.is_deactivated);
    const activeDevices = entries.reduce(
      (sum, entry) => sum + (Number(entry.active_devices) || 0),
      0,
    );
    byId("total-count").textContent = String(entries.length);
    byId("enabled-count").textContent = String(enabled.length);
    byId("active-count").textContent = String(activeDevices);
    byId("all-tab-count").textContent = String(entries.length);
    byId("enabled-tab-count").textContent = String(enabled.length);
    byId("disabled-tab-count").textContent = String(disabled.length);

    const visible = filteredEntries();
    rows.replaceChildren();
    byId("result-count").textContent =
      `${visible.length} ${plural(visible.length, "запись", "записи", "записей")}`;
    byId("table-wrap").hidden = visible.length === 0;
    byId("empty-state").hidden = visible.length !== 0;
    if (!entries.length) {
      byId("empty-title").textContent = "Ключей пока нет";
      byId("empty-copy").textContent = "Создайте первый ключ доступа.";
      byId("empty-create-button").hidden = false;
    } else if (!visible.length) {
      byId("empty-title").textContent = "Ничего не найдено";
      byId("empty-copy").textContent = "Измените поисковый запрос или фильтр.";
      byId("empty-create-button").hidden = true;
    }
    for (const entry of visible) rows.append(makeRow(entry));
  }

  function plural(count, one, few, many) {
    const tens = count % 100;
    const units = count % 10;
    if (tens > 10 && tens < 20) return many;
    if (units > 1 && units < 5) return few;
    if (units === 1) return one;
    return many;
  }

  function makeRow(entry) {
    const row = document.createElement("tr");
    const keyCell = element("td", "key-cell");
    const keyName = element("span", "key-name", entry.label || "Без имени");
    const keyId = element("span", "key-id", entry.password);
    keyId.title = entry.password;
    keyCell.append(keyName, keyId);

    const statusCell = element("td", "status-cell");
    const status = entryStatus(entry);
    statusCell.append(
      element("span", `status-badge ${status.className}`, status.label),
      element("span", "status-detail", formatDate(entry.expires_at)),
    );

    const deviceCell = element("td", "device-cell");
    const bound = (entry.device_ids || []).length;
    deviceCell.append(
      element("span", "device-count", `${bound} / ${entry.max_devices || 1}`),
      element(
        "span",
        "device-active",
        `${entry.active_devices || 0} подключено`,
      ),
    );

    const trafficCell = element("td", "traffic-cell");
    trafficCell.append(
      element("div", "", `↓ ${formatBytes(entry.down_bytes)}`),
      element("div", "", `↑ ${formatBytes(entry.up_bytes)}`),
    );

    const actionsCell = element("td", "actions-cell");
    const actions = element("div", "row-actions");
    actions.append(actionButton("Открыть", () => openDetails(entry)));
    actions.append(actionButton("Изменить", () => openEditor(entry)));
    actions.append(
      actionButton(entry.is_deactivated ? "Включить" : "Отключить", () =>
        toggleEntry(entry),
      ),
    );
    actions.append(actionButton("Удалить", () => deleteEntry(entry), "danger"));
    actionsCell.append(actions);
    row.append(keyCell, statusCell, deviceCell, trafficCell, actionsCell);
    return row;
  }

  function actionButton(label, action, extraClass = "") {
    const button = element("button", `row-action ${extraClass}`, label);
    button.type = "button";
    button.addEventListener("click", action);
    return button;
  }

  function setFormError(id, message) {
    byId(id).textContent = message || "";
  }

  function openEditor(entry = null) {
    state.editing = entry;
    state.createKey = entry ? "" : crypto.randomUUID();
    byId("editor-title").textContent = entry ? "Изменить ключ" : "Новый ключ";
    byId("save-button").textContent = entry
      ? "Сохранить изменения"
      : "Создать ключ";
    byId("field-label").value = entry?.label || "";
    byId("field-vk-hash").value = entry?.vk_hash || "";
    byId("field-days").value = entry ? "" : "30";
    byId("field-days").required = !entry;
    byId("days-label").textContent = entry ? "Продлить, дней" : "Срок, дней";
    byId("field-max-devices").value = String(entry?.max_devices || 1);
    byId("field-ports").value = entry?.ports || "";
    byId("ports-field").hidden = Boolean(entry);
    setFormError("editor-error", "");
    editor.showModal();
  }

  async function saveEntry(event) {
    event.preventDefault();
    const button = byId("save-button");
    button.disabled = true;
    setFormError("editor-error", "");
    const body = new URLSearchParams();
    body.set("label", byId("field-label").value.trim());
    body.set(
      "vk_hash",
      byId("field-vk-hash")
        .value.trim()
        .replace(/[;\n]+/g, ","),
    );
    body.set("max_devices", byId("field-max-devices").value || "1");
    if (byId("field-days").value) body.set("days", byId("field-days").value);
    const editing = state.editing;
    const path = editing ? "/admin/passwords/update" : "/admin/passwords";
    if (editing) body.set("password", editing.password);
    else {
      body.set("ports", byId("field-ports").value.trim());
      body.set("days", byId("field-days").value || "30");
    }
    const headers = editing ? {} : { "Idempotency-Key": state.createKey };
    try {
      const saved = await request(path, { method: "POST", body, headers });
      editor.close();
      toast(editing ? "Изменения сохранены" : "Ключ создан");
      await refresh();
      if (!editing) {
        const created =
          state.entries.find((entry) => entry.password === saved.password) ||
          saved;
        openDetails(created);
      }
    } catch (error) {
      setFormError(
        "editor-error",
        error.message || "Не удалось сохранить ключ.",
      );
    } finally {
      button.disabled = false;
    }
  }

  function openDetails(entry) {
    state.selected = entry;
    byId("quick-link-panel").hidden = true;
    byId("qr-panel").hidden = true;
    byId("qr-image").hidden = true;
    setFormError("qr-error", "");
    renderDetails();
    details.showModal();
  }

  function quickLink(entry) {
    const configuredPorts = (entry.ports || "56000,56001,9000")
      .split(",")
      .map((value) => Number.parseInt(value.trim(), 10));
    const dtlsPort = configuredPorts[0] > 0 ? configuredPorts[0] : 56000;
    const appPort = configuredPorts[2] > 0 ? configuredPorts[2] : 9000;
    const host = state.serverAddress || window.location.hostname;
    const peerHost =
      host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
    const params = new URLSearchParams({
      name: entry.label || entry.password,
      peer: `${peerHost}:${dtlsPort}`,
      hashes: entry.vk_hash || "",
      workers: "18",
      port: String(appPort),
      pass: entry.password,
    });
    return `qwdtt://config?${params.toString()}`;
  }

  function renderDetails() {
    const entry = state.selected;
    if (!entry) return;
    const status = entryStatus(entry);
    byId("detail-label").textContent = entry.label || "Без имени";
    byId("detail-password").textContent = entry.password;
    byId("detail-status").textContent = status.label;
    byId("detail-expiry").textContent = formatDate(entry.expires_at);
    byId("detail-devices-count").textContent =
      `${(entry.device_ids || []).length} / ${entry.max_devices || 1}`;
    byId("detail-active-count").textContent = String(entry.active_devices || 0);
    byId("detail-down").textContent = formatBytes(entry.down_bytes);
    byId("detail-up").textContent = formatBytes(entry.up_bytes);
    byId("device-subtitle").textContent =
      `${(entry.device_ids || []).length} из ${entry.max_devices || 1} слотов занято`;
    byId("detail-toggle").textContent = entry.is_deactivated
      ? "Включить"
      : "Отключить";
    byId("quick-link-value").textContent = quickLink(entry);
    setFormError("detail-error", "");
    const list = byId("device-list");
    list.replaceChildren();
    if (!entry.device_ids?.length) {
      list.append(
        element("div", "no-devices", "Пока нет привязанных устройств."),
      );
    } else {
      for (const deviceId of entry.device_ids) {
        const item = element("div", "device-row");
        const code = element("code", "", deviceId);
        code.title = deviceId;
        const unbind = element(
          "button",
          "button button-danger-quiet",
          "Отвязать",
        );
        unbind.type = "button";
        unbind.addEventListener("click", () => unbindDevice(entry, deviceId));
        item.append(code, unbind);
        list.append(item);
      }
    }
    byId("unbind-all-button").disabled = !entry.device_ids?.length;
  }

  async function toggleEntry(entry) {
    const action = entry.is_deactivated ? "activate" : "deactivate";
    try {
      await postPasswordAction(`/admin/passwords/${action}`, entry.password);
      toast(entry.is_deactivated ? "Ключ активирован" : "Ключ отключён");
      await refresh();
    } catch (error) {
      toast(error.message, true);
    }
  }

  async function deleteEntry(entry) {
    const label = entry.label || entry.password;
    if (
      !window.confirm(
        `Удалить ключ «${label}» и все связанные устройства? Это действие нельзя отменить.`,
      )
    )
      return;
    try {
      const body = new URLSearchParams({ password: entry.password });
      await request("/admin/passwords/delete", { method: "POST", body });
      if (state.selected?.password === entry.password) details.close();
      toast("Ключ удалён");
      await refresh();
    } catch (error) {
      toast(error.message, true);
    }
  }

  async function unbindDevice(entry, deviceId) {
    if (!window.confirm(`Отвязать устройство ${deviceId}?`)) return;
    try {
      const body = new URLSearchParams({
        password: entry.password,
        device_id: deviceId,
      });
      await request("/admin/passwords/unbind-device", { method: "POST", body });
      toast("Устройство отвязано");
      await refresh();
    } catch (error) {
      setFormError("detail-error", error.message);
    }
  }

  async function unbindAll() {
    const entry = state.selected;
    if (!entry || !entry.device_ids?.length) return;
    if (
      !window.confirm(
        `Отвязать все ${entry.device_ids.length} устройств от этого ключа?`,
      )
    )
      return;
    try {
      const body = new URLSearchParams({
        password: entry.password,
        device_id: "",
      });
      await request("/admin/passwords/unbind-device", { method: "POST", body });
      toast("Все устройства отвязаны");
      await refresh();
    } catch (error) {
      setFormError("detail-error", error.message);
    }
  }

  async function postPasswordAction(path, password) {
    const body = new URLSearchParams({ password });
    return request(path, { method: "POST", body });
  }

  async function copyPassword() {
    if (!state.selected) return;
    try {
      await navigator.clipboard.writeText(state.selected.password);
      toast("Пароль скопирован");
    } catch {
      toast("Не удалось скопировать пароль", true);
    }
  }

  async function copyQuickLink() {
    if (!state.selected) return;
    try {
      await navigator.clipboard.writeText(quickLink(state.selected));
      toast("Быстрая ссылка скопирована");
    } catch {
      toast("Не удалось скопировать ссылку", true);
    }
  }

  async function showQRCode() {
    if (!state.selected) return;
    const panel = byId("qr-panel");
    const image = byId("qr-image");
    const download = byId("download-qr");
    panel.hidden = false;
    image.hidden = true;
    download.hidden = true;
    byId("qr-loading").hidden = false;
    setFormError("qr-error", "");
    try {
      const response = await fetch("/admin/qrcode", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${state.token}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({ payload: quickLink(state.selected) }),
        cache: "no-store",
      });
      if (!response.ok) {
        let message = `HTTP ${response.status}`;
        try {
          const data = await response.json();
          message = data.error || message;
        } catch {
          // Keep the HTTP status as the fallback message.
        }
        throw new Error(message);
      }
      const imageURL = URL.createObjectURL(await response.blob());
      if (state.qrObjectURL) URL.revokeObjectURL(state.qrObjectURL);
      state.qrObjectURL = imageURL;
      image.src = imageURL;
      image.hidden = false;
      download.href = imageURL;
      download.hidden = false;
    } catch (error) {
      setFormError("qr-error", error.message || "Не удалось создать QR-код.");
    } finally {
      byId("qr-loading").hidden = true;
    }
  }

  byId("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.submitter;
    button.disabled = true;
    setLoginError("");
    try {
      await connect(byId("admin-token").value);
    } catch (error) {
      setLoginError(error.message || "Не удалось подключиться.");
    } finally {
      button.disabled = false;
    }
  });
  byId("token-visibility").addEventListener("click", () => {
    const field = byId("admin-token");
    field.type = field.type === "password" ? "text" : "password";
    byId("token-visibility").textContent =
      field.type === "password" ? "Показать" : "Скрыть";
  });
  byId("create-button").addEventListener("click", () => openEditor());
  byId("empty-create-button").addEventListener("click", () => openEditor());
  byId("credential-form").addEventListener("submit", saveEntry);
  byId("refresh-button").addEventListener("click", refresh);
  byId("logout-button").addEventListener("click", () => logout());
  byId("search-input").addEventListener("input", (event) => {
    state.query = event.target.value;
    render();
  });
  document.querySelectorAll(".filter-tab").forEach((tab) =>
    tab.addEventListener("click", () => {
      state.filter = tab.dataset.filter;
      document
        .querySelectorAll(".filter-tab")
        .forEach((item) => item.classList.toggle("active", item === tab));
      render();
    }),
  );
  document
    .querySelectorAll("[data-close]")
    .forEach((button) =>
      button.addEventListener("click", () =>
        byId(button.dataset.close).close(),
      ),
    );
  byId("copy-password").addEventListener("click", copyPassword);
  byId("server-address").value = state.serverAddress;
  byId("save-server-address").addEventListener("click", saveServerAddress);
  byId("detect-server-address").addEventListener("click", detectServerAddress);
  byId("show-link-button").addEventListener("click", () => {
    byId("quick-link-panel").hidden = !byId("quick-link-panel").hidden;
    byId("qr-panel").hidden = true;
  });
  byId("copy-quick-link").addEventListener("click", copyQuickLink);
  byId("show-qr-button").addEventListener("click", () => {
    byId("quick-link-panel").hidden = true;
    showQRCode();
  });
  byId("detail-edit").addEventListener("click", () => {
    const entry = state.selected;
    details.close();
    openEditor(entry);
  });
  byId("detail-toggle").addEventListener("click", async () => {
    if (state.selected) {
      await toggleEntry(state.selected);
      await refresh();
      if (state.selected) renderDetails();
    }
  });
  byId("detail-delete").addEventListener("click", () => {
    if (state.selected) deleteEntry(state.selected);
  });
  byId("unbind-all-button").addEventListener("click", unbindAll);
  details.addEventListener("close", () => {
    byId("qr-image").removeAttribute("src");
    byId("download-qr").removeAttribute("href");
    if (state.qrObjectURL) URL.revokeObjectURL(state.qrObjectURL);
    state.qrObjectURL = "";
  });
  byId("search-input").addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      event.target.value = "";
      state.query = "";
      render();
    }
  });
  document.addEventListener("keydown", (event) => {
    if (
      event.key === "/" &&
      !["INPUT", "TEXTAREA"].includes(document.activeElement.tagName) &&
      !editor.open &&
      !details.open
    ) {
      event.preventDefault();
      byId("search-input").focus();
    }
  });

  if (state.token) {
    connect(state.token).catch(() => logout(false));
  }
  window.setInterval(() => {
    if (!app.hidden && !document.hidden) refreshHealth();
  }, 15000);
  window.setInterval(() => {
    if (!app.hidden && !document.hidden) refresh();
  }, 30000);
})();
