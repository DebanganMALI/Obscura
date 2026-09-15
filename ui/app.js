const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;

const $ = (id) => document.getElementById(id);

const state = {
  info: null,
  entries: [],
  selected: null,
  editing: null,
  totpTimer: null,
};

function h(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function icon(name, className) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  if (className) svg.setAttribute("class", className);
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", "#" + name);
  svg.appendChild(use);
  return svg;
}

let toastTimer = null;
function toast(message, kind) {
  const el = $("toast");
  $("toast-text").textContent = message;
  el.classList.toggle("toast--warn", kind === "warn");
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 2200);
}

function strength(password) {
  if (!password) return 0;
  let classes = 0;
  if (/[a-z]/.test(password)) classes++;
  if (/[A-Z]/.test(password)) classes++;
  if (/[0-9]/.test(password)) classes++;
  if (/[^a-zA-Z0-9]/.test(password)) classes++;
  const bits = password.length * Math.log2(Math.max(classes * 20, 2));
  if (bits < 45) return 1;
  if (bits < 70) return 2;
  if (bits < 100) return 3;
  return 4;
}

function paintMeter(container, score) {
  const band = score <= 1 ? "on-weak" : score <= 2 ? "on-fair" : "on-strong";
  [...container.children].forEach((seg, i) => {
    seg.className = "meter__seg" + (i < score ? " " + band : "");
  });
}

function initials(title) {
  const words = title.trim().split(/\s+/).filter(Boolean);
  if (!words.length) return "?";
  if (words.length === 1) return words[0].slice(0, 2);
  return words[0][0] + words[1][0];
}

let gateMode = "unlock";
let gatePath = null;
let gateProbe = null;
let gateBlocked = false;

async function refreshGate() {
  try {
    gateProbe = await invoke("probe_location", { path: gatePath });
  } catch (err) {
    $("gate-error").textContent = String(err);
    return;
  }

  const probe = gateProbe;
  gateMode = probe.exists && probe.isVault ? "unlock" : "create";
  gateBlocked =
    !probe.parentExists || (probe.exists && !probe.isVault) || (!probe.exists && !probe.writable);

  $("loc-path").textContent = probe.path;
  $("loc-default").hidden = probe.isDefault;
  $("loc-alt").textContent = gateMode === "unlock"
    ? "Create a new vault somewhere else"
    : "I already have a vault - find it";

  const note = $("loc-note");
  note.className = "loc__note";
  if (probe.warning) {
    note.textContent = probe.warning;
    note.classList.add(probe.parentExists && probe.writable ? "loc__note--warn" : "loc__note--bad");
  } else if (gateMode === "unlock") {
    note.textContent = "An Obscura vault is here.";
    note.classList.add("loc__note--ok");
  } else {
    note.textContent = "Nothing here yet. A new vault will be created.";
  }

  applyGateMode();
  $("gate-error").textContent = "";
}

function applyGateMode() {
  const creating = gateMode === "create";

  $("gate-creds").hidden = gateBlocked;
  $("gate-submit").hidden = gateBlocked;
  $("gate-confirm-field").hidden = gateBlocked || !creating;
  $("gate-meter").hidden = !creating;
  $("gate-form").classList.toggle("gate__form--blocked", gateBlocked);

  if (gateBlocked) {
    $("gate-eyebrow").textContent = "Vault unavailable";
    $("gate-tagline").textContent = "Obscura cannot reach a vault at this location.";
    return;
  }

  $("gate-eyebrow").textContent = creating ? "First run" : "Vault locked";
  $("gate-tagline").textContent = creating
    ? "Choose where the vault lives, then a master password."
    : "Everything you keep, kept to yourself.";
  $("gate-label").textContent = creating ? "New master password" : "Master password";
  $("gate-submit").textContent = creating ? "Create vault" : "Unlock";
  $("gate-submit").disabled = false;
  if (!creating) $("gate-confirm").value = "";
}

async function chooseLocation(command) {
  try {
    const picked = await invoke(command);
    if (!picked) return;
    gatePath = picked;
    await refreshGate();
  } catch (err) {
    $("gate-error").textContent = String(err);
  }
}

$("loc-change").addEventListener("click", () =>
  chooseLocation(gateMode === "unlock" ? "pick_existing_vault" : "pick_new_location"));

$("loc-alt").addEventListener("click", () =>
  chooseLocation(gateMode === "unlock" ? "pick_new_location" : "pick_existing_vault"));

$("loc-default").addEventListener("click", async () => {
  try {
    gatePath = await invoke("default_path");
    await refreshGate();
  } catch (err) {
    $("gate-error").textContent = String(err);
  }
});

$("gate-password").addEventListener("input", (e) => {
  if (gateMode === "create") paintMeter($("gate-meter"), strength(e.target.value));
});

$("gate-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = $("gate-password").value;
  const error = $("gate-error");
  const submit = $("gate-submit");
  error.textContent = "";

  if (!password) return;

  if (gateMode === "create") {
    if (password.length < 8) {
      error.textContent = "Use at least 8 characters.";
      return;
    }
    if (password !== $("gate-confirm").value) {
      error.textContent = "The two passwords do not match.";
      return;
    }
  }

  const creating = gateMode === "create";
  submit.disabled = true;
  submit.textContent = creating ? "Calibrating..." : "Unlocking...";

  try {
    const args = {
      path: gateProbe ? gateProbe.path : null,
      password,
      remember: $("loc-remember").checked,
    };
    if (creating) args.calibrateMs = 900;

    state.info = await invoke(creating ? "create_vault" : "unlock", args);
    $("gate-password").value = "";
    $("gate-confirm").value = "";
    enterApp();
  } catch (err) {
    error.textContent = String(err);
    $("gate-password").select();
  } finally {
    submit.disabled = false;
    applyGateMode();
  }
});

function enterApp() {
  $("gate").hidden = true;
  $("app").hidden = false;
  $("vault-path").textContent = state.info.path;
  $("search").value = "";
  refresh();
  $("search").focus();
}

async function leaveApp(message) {
  clearInterval(state.totpTimer);
  state.entries = [];
  state.selected = null;
  $("app").hidden = true;
  $("gate").hidden = false;
  await refreshGate();
  $("gate-error").textContent = message || "";
  $("gate-password").focus();
}

async function refresh() {
  try {
    state.entries = await invoke("list_entries", { query: $("search").value || null });
    state.info = await invoke("vault_info");
  } catch (err) {
    if (String(err).includes("locked")) return leaveApp("Locked. Unlock to continue.");
    toast(String(err), "warn");
    return;
  }
  $("entry-count").textContent =
    state.entries.length + (state.entries.length === 1 ? " entry" : " entries");
  renderList();
  renderDetail();
}

function renderList() {
  const list = $("list");
  list.replaceChildren();

  if (!state.entries.length) {
    const empty = h("div", "empty");
    empty.append(
      h("p", "serif-it", $("search").value ? "Nothing matches." : "No entries yet.")
    );
    list.append(empty);
    return;
  }

  for (const entry of state.entries) {
    const row = h("button", "row");
    row.type = "button";
    row.setAttribute("aria-selected", String(entry.id === state.selected));

    row.append(h("span", "row__mark", initials(entry.title)));

    const middle = h("span", "row__body");
    middle.append(
      h("span", "row__title", entry.title),
      h("span", "row__sub", entry.username || "No username")
    );
    row.append(middle);

    const flags = h("span", "row__flags");
    if (entry.favorite) flags.append(icon("i-star", "fav"));
    if (entry.hasTotp) flags.append(icon("i-clock"));
    row.append(flags);

    row.addEventListener("click", () => select(entry.id));
    list.append(row);
  }
}

function select(id) {
  state.selected = id;
  renderList();
  renderDetail();
}

async function renderDetail() {
  const pane = $("detail");
  clearInterval(state.totpTimer);
  pane.replaceChildren();

  const entry = state.entries.find((e) => e.id === state.selected);
  if (!entry) {
    const empty = h("div", "empty");
    empty.append(
      h("p", "empty__mark", "Obscura"),
      h("p", "serif-it", state.entries.length
        ? "Select an entry."
        : "Add your first credential to begin.")
    );
    pane.append(empty);
    return;
  }

  let detail;
  try {
    detail = await invoke("get_entry", { id: entry.id });
  } catch (err) {
    if (String(err).includes("locked")) return leaveApp("Locked. Unlock to continue.");
    pane.append(h("p", "error", String(err)));
    return;
  }

  const head = h("div", "detail__head");
  const titles = h("div");
  titles.append(h("h2", "detail__title", detail.title));
  titles.append(h("p", "detail__sub", detail.username || "No username"));
  head.append(titles);

  const actions = h("div", "detail__actions");
  const edit = h("button", "icon-btn");
  edit.title = "Edit";
  edit.append(icon("i-edit"));
  edit.addEventListener("click", () => openEditor(detail));

  const remove = h("button", "icon-btn");
  remove.title = "Delete";
  remove.append(icon("i-trash"));
  remove.addEventListener("click", () => confirmDelete(detail));

  actions.append(edit, remove);
  head.append(actions);
  pane.append(head);

  const credentials = h("section", "section");
  credentials.append(h("p", "section__label", "Credentials"));
  const card = h("div", "card");

  if (detail.username) {
    card.append(kv("Username", detail.username, [
      copyButton("Copy username", () => invoke("copy_text", {
        text: detail.username, clearAfter: 30,
      }), "Username copied"),
    ]));
  }

  const dots = "\u2022".repeat(Math.min(detail.passwordLen, 28));
  const passwordValue = h("span", "kv__v secret", dots);

  const reveal = h("button", "icon-btn");
  reveal.title = "Reveal";
  reveal.append(icon("i-eye"));
  let shown = false;
  reveal.addEventListener("click", async () => {
    if (shown) {
      passwordValue.textContent = dots;
      shown = false;
      return;
    }
    try {
      passwordValue.textContent = await invoke("reveal_password", { id: detail.id });
      shown = true;
      setTimeout(() => {
        if (shown) { passwordValue.textContent = dots; shown = false; }
      }, 20000);
    } catch (err) {
      toast(String(err), "warn");
    }
  });

  const passwordRow = kv("Password", null, [
    reveal,
    copyButton("Copy password", () => invoke("copy_password", {
      id: detail.id, clearAfter: 30,
    }), "Password copied - clipboard clears in 30s"),
  ]);
  passwordRow.insertBefore(passwordValue, passwordRow.lastChild);
  card.append(passwordRow);

  if (detail.passwordAgeDays !== null && detail.passwordAgeDays !== undefined) {
    const days = detail.passwordAgeDays;
    const stale = days > 365;
    const label = days === 0 ? "Changed today"
      : days === 1 ? "Changed yesterday"
      : "Changed " + days + " days ago";
    const ageRow = kv("Age", null, []);
    ageRow.insertBefore(h("span", "kv__v age" + (stale ? " age--stale" : ""), label),
                        ageRow.lastChild);
    card.append(ageRow);
  }

  credentials.append(card);
  pane.append(credentials);

  if (detail.hasTotp) {
    const section = h("section", "section");
    section.append(h("p", "section__label", "Two-factor"));
    const totpCard = h("div", "card");
    const wrap = h("div", "totp");

    const code = h("span", "totp__code", "------");
    const ring = buildRing();
    const copy = copyButton("Copy code", async () => {
      const current = await invoke("totp_code", { id: detail.id });
      return invoke("copy_text", { text: current.code, clearAfter: 30 });
    }, "Code copied");

    wrap.append(ring.node, code, copy);
    totpCard.append(wrap);
    section.append(totpCard);
    pane.append(section);

    const tick = async () => {
      try {
        const current = await invoke("totp_code", { id: detail.id });
        code.textContent = current.code.replace(/(\d{3})(?=\d)/g, "$1 ");
        ring.set(current.remaining, current.period);
      } catch {
        clearInterval(state.totpTimer);
      }
    };
    tick();
    state.totpTimer = setInterval(tick, 1000);
  }

  if (detail.urls.length) {
    const section = h("section", "section");
    section.append(h("p", "section__label", "Website"));
    const urlCard = h("div", "card");
    for (const url of detail.urls) {
      urlCard.append(kv("URL", url, [
        copyButton("Copy link", () => invoke("copy_text", { text: url, clearAfter: 60 }),
                   "Link copied"),
      ]));
    }
    section.append(urlCard);
    pane.append(section);
  }

  if (detail.notes) {
    const section = h("section", "section");
    section.append(h("p", "section__label", "Notes"));
    const noteCard = h("div", "card");
    const text = h("p", null, detail.notes);
    noteCard.append(text);
    section.append(noteCard);
    pane.append(section);
  }

  if (detail.tags.length) {
    const section = h("section", "section");
    section.append(h("p", "section__label", "Tags"));
    section.append(h("p", "serif-it", detail.tags.join("  -  ")));
    pane.append(section);
  }
}

function kv(key, value, actions) {
  const row = h("div", "kv");
  row.append(h("span", "kv__k", key));
  if (value !== null && value !== undefined) row.append(h("span", "kv__v", value));
  const group = h("span", "kv__actions");
  actions.forEach((a) => group.append(a));
  row.append(group);
  return row;
}

function copyButton(title, action, message) {
  const button = h("button", "icon-btn");
  button.title = title;
  button.append(icon("i-copy"));
  button.addEventListener("click", async () => {
    try {
      await action();
      toast(message);
    } catch (err) {
      toast(String(err), "warn");
    }
  });
  return button;
}

function buildRing() {
  const node = h("span", "ring");
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 34 34");
  svg.setAttribute("width", "34");
  svg.setAttribute("height", "34");
  const mk = (cls) => {
    const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    c.setAttribute("cx", "17"); c.setAttribute("cy", "17"); c.setAttribute("r", "14");
    c.setAttribute("class", cls);
    return c;
  };
  const track = mk("track");
  const bar = mk("bar");
  const circumference = 2 * Math.PI * 14;
  bar.setAttribute("stroke-dasharray", String(circumference));
  svg.append(track, bar);
  const label = h("span", null, "");
  node.append(svg, label);
  return {
    node,
    set(remaining, period) {
      label.textContent = String(remaining);
      const fraction = Math.max(0, Math.min(1, remaining / period));
      bar.setAttribute("stroke-dashoffset", String(circumference * (1 - fraction)));
    },
  };
}

function openEditor(detail) {
  state.editing = detail ? detail.id : null;
  $("editor-title").textContent = detail ? "Edit entry" : "New entry";
  $("editor-error").textContent = "";

  $("e-title").value = detail ? detail.title : "";
  $("e-username").value = detail ? detail.username : "";
  $("e-password").value = "";
  $("e-url").value = detail && detail.urls.length ? detail.urls[0] : "";
  $("e-totp").value = "";
  $("e-notes").value = detail ? detail.notes : "";
  $("e-tags").value = detail ? detail.tags.join(", ") : "";
  $("e-favorite").checked = detail ? detail.favorite : false;
  $("e-password-hint").textContent = detail
    ? "Leave blank to keep the stored password unchanged."
    : "";

  $("editor-scrim").hidden = false;
  $("e-title").focus();
}

$("editor-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = $("e-password").value;
  const url = $("e-url").value.trim();
  const totp = $("e-totp").value.trim();

  const input = {
    id: state.editing,
    kind: "login",
    title: $("e-title").value.trim(),
    username: $("e-username").value.trim(),
    password: password ? password : null,
    urls: url ? [url] : [],
    notes: $("e-notes").value,
    tags: $("e-tags").value.split(",").map((t) => t.trim()).filter(Boolean),
    favorite: $("e-favorite").checked,
    totpUri: totp ? totp : null,
  };

  try {
    const id = await invoke("save_entry", { input });
    $("editor-scrim").hidden = true;
    $("e-password").value = "";
    state.selected = id;
    await refresh();
    toast("Saved");
  } catch (err) {
    $("editor-error").textContent = String(err);
  }
});

async function confirmDelete(detail) {
  const button = $("detail").querySelector('[title="Delete"]');
  if (button && button.dataset.armed !== "1") {
    button.dataset.armed = "1";
    button.classList.add("btn--danger");
    toast("Click delete again to confirm", "warn");
    setTimeout(() => {
      button.dataset.armed = "0";
      button.classList.remove("btn--danger");
    }, 4000);
    return;
  }
  try {
    await invoke("delete_entry", { id: detail.id });
    state.selected = null;
    await refresh();
    toast("Entry deleted");
  } catch (err) {
    toast(String(err), "warn");
  }
}

async function generate() {
  try {
    const result = await invoke("generate", {
      length: Number($("gen-length").value),
      lowercase: $("gen-lower").checked,
      uppercase: $("gen-upper").checked,
      digits: $("gen-digits").checked,
      symbols: $("gen-symbols").checked,
      excludeAmbiguous: $("gen-ambiguous").checked,
      requireEachClass: $("gen-each").checked,
    });
    $("gen-out").textContent = result.password;
    $("gen-bits").textContent = Math.round(result.entropyBits);
  } catch (err) {
    $("gen-out").textContent = "";
    $("gen-bits").textContent = "0";
    toast(String(err), "warn");
  }
}

$("gen-length").addEventListener("input", () => {
  $("gen-length-val").textContent = $("gen-length").value;
  generate();
});
["gen-lower", "gen-upper", "gen-digits", "gen-symbols", "gen-ambiguous", "gen-each"]
  .forEach((id) => $(id).addEventListener("change", generate));
$("gen-again").addEventListener("click", generate);

$("gen-copy").addEventListener("click", async () => {
  const value = $("gen-out").textContent;
  if (!value.trim()) return;
  try {
    await invoke("copy_text", { text: value, clearAfter: 30 });
    toast("Copied - clipboard clears in 30s");
  } catch (err) {
    toast(String(err), "warn");
  }
});

$("e-generate").addEventListener("click", async () => {
  await generate();
  $("e-password").value = $("gen-out").textContent;
  $("e-password").type = "text";
  setTimeout(() => { $("e-password").type = "password"; }, 6000);
  toast("Generated");
});

async function openSettings() {
  const info = state.info;
  $("s-path").textContent = info.path;
  $("s-count").textContent = String(info.entryCount);
  $("s-revision").textContent = String(info.revision);
  $("s-slots").textContent = info.slots.map((s) => s.label).join(", ");
  $("s-autolock").value = String(Math.round(info.autoLockSecs / 60));
  $("s-autolock-val").textContent = $("s-autolock").value;
  $("s-error").textContent = "";
  $("s-current").value = "";
  $("s-new").value = "";
  paintMeter($("s-meter"), 0);
  $("s-loc-error").textContent = "";
  try {
    const remembered = await invoke("remembered_location");
    $("s-remembered").textContent = remembered
      ? "Yes"
      : "No - Obscura will ask at next launch";
  } catch {
    $("s-remembered").textContent = "Unknown";
  }
  $("settings-scrim").hidden = false;
}

$("s-move").addEventListener("click", async () => {
  const error = $("s-loc-error");
  error.textContent = "";
  try {
    const destination = await invoke("pick_new_location");
    if (!destination) return;
    const result = await invoke("relocate_vault", { destination, remember: true });
    state.info = result.info;
    $("s-path").textContent = result.info.path;
    $("vault-path").textContent = result.info.path;
    if (result.previousRemoved) {
      toast("Vault moved");
    } else {
      toast("Moved, but the old file remains at " + result.previous, "warn");
    }
    await refresh();
  } catch (err) {
    error.textContent = String(err);
  }
});

$("s-forget").addEventListener("click", async () => {
  const error = $("s-loc-error");
  error.textContent = "";
  try {
    await invoke("forget_location");
    $("s-remembered").textContent = "No - Obscura will ask at next launch";
    toast("Location forgotten");
  } catch (err) {
    error.textContent = String(err);
  }
});

$("s-autolock").addEventListener("input", async () => {
  $("s-autolock-val").textContent = $("s-autolock").value;
  await invoke("set_auto_lock", { seconds: Number($("s-autolock").value) * 60 });
});

$("s-new").addEventListener("input", (e) => paintMeter($("s-meter"), strength(e.target.value)));

$("s-change").addEventListener("click", async () => {
  const error = $("s-error");
  error.textContent = "";
  try {
    await invoke("change_master_password", {
      current: $("s-current").value,
      new: $("s-new").value,
    });
    $("s-current").value = "";
    $("s-new").value = "";
    paintMeter($("s-meter"), 0);
    toast("Master password changed");
    await refresh();
  } catch (err) {
    error.textContent = String(err);
  }
});

$("btn-new").addEventListener("click", () => openEditor(null));
$("btn-generator").addEventListener("click", () => { $("gen-scrim").hidden = false; generate(); });
$("btn-settings").addEventListener("click", openSettings);
$("btn-lock").addEventListener("click", async () => {
  await invoke("lock");
  leaveApp("Locked.");
});

document.querySelectorAll("[data-close]").forEach((button) => {
  button.addEventListener("click", () => { $(button.dataset.close).hidden = true; });
});

document.querySelectorAll(".scrim").forEach((scrim) => {
  scrim.addEventListener("mousedown", (event) => {
    if (event.target === scrim) scrim.hidden = true;
  });
});

let searchTimer = null;
$("search").addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(refresh, 110);
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    const open = [...document.querySelectorAll(".scrim")].find((s) => !s.hidden);
    if (open) { open.hidden = true; return; }
  }
  if (!event.ctrlKey && !event.metaKey) return;
  const key = event.key.toLowerCase();
  if (key === "l") { event.preventDefault(); $("btn-lock").click(); }
  if (key === "n" && !$("app").hidden) { event.preventDefault(); openEditor(null); }
  if (key === "g" && !$("app").hidden) { event.preventDefault(); $("btn-generator").click(); }
  if (key === "f" && !$("app").hidden) { event.preventDefault(); $("search").focus(); }
});

let lastTouch = 0;
["pointerdown", "keydown"].forEach((type) => {
  document.addEventListener(type, () => {
    const now = Date.now();
    if (now - lastTouch < 5000 || $("app").hidden) return;
    lastTouch = now;
    invoke("touch").catch(() => {});
  });
});

listen("obscura://locked", () => leaveApp("Locked after inactivity."));

refreshGate().then(() => { if (!gateBlocked) $("gate-password").focus(); });
