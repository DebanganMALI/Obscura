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

function paintMeter(container, score) {
  const band = score <= 1 ? "on-weak" : score <= 2 ? "on-fair" : "on-strong";
  [...container.children].forEach((seg, i) => {
    seg.className = "meter__seg" + (i < score ? " " + band : "");
  });
}

function sentence(text) {
  return text ? text.charAt(0).toUpperCase() + text.slice(1) + "." : "";
}

const meterTurns = new WeakMap();

async function measure(password, meter, note) {
  const turn = (meterTurns.get(meter) || 0) + 1;
  meterTurns.set(meter, turn);
  if (!password) {
    paintMeter(meter, 0);
    note.textContent = "";
    return;
  }
  let check;
  try {
    check = await invoke("assess_password", { password });
  } catch {
    return;
  }
  if (meterTurns.get(meter) !== turn) return;
  paintMeter(meter, check.score);
  note.textContent = sentence(check.problem);
}

function initials(title) {
  const words = title.trim().split(/\s+/).filter(Boolean);
  if (!words.length) return "?";
  if (words.length === 1) return words[0].slice(0, 2);
  return words[0][0] + words[1][0];
}

function errText(err) {
  if (err && typeof err === "object" && typeof err.message === "string") return err.message;
  return String(err);
}

function confirmRevision(detail) {
  return new Promise((resolve) => {
    const scrim = $("rb-scrim");
    const typed = $("rb-typed");
    const error = $("rb-error");
    const accept = $("rb-accept");
    const cancel = $("rb-cancel");
    const expected = detail.confirm.expected;
    const wording = {
      rollback: [
        "This vault looks older than it should",
        "Obscura has seen a newer version of this vault on this computer.",
      ],
      unreadable: [
        "The rollback record could not be read",
        "Obscura cannot tell whether this file has been rolled back.",
      ],
      damaged: [
        "The rollback record does not match",
        "Obscura cannot tell whether this file has been rolled back.",
      ],
    };
    const [title, lede] = wording[detail.confirm.reason] || wording.damaged;

    $("rb-title").textContent = title;
    $("rb-lede").textContent = lede;
    $("rb-found").textContent = String(detail.confirm.found);
    $("rb-expected").textContent = expected === null || expected === undefined ? "-" : String(expected);
    $("rb-expected-box").hidden = expected === null || expected === undefined;
    $("rb-why").textContent = detail.message;

    typed.value = "";
    error.textContent = "";
    scrim.hidden = false;
    typed.focus();

    function close(value) {
      scrim.hidden = true;
      accept.removeEventListener("click", onAccept);
      cancel.removeEventListener("click", onCancel);
      typed.removeEventListener("keydown", onKey);
      resolve(value);
    }
    function onAccept() {
      if (typed.value.trim() !== String(detail.confirm.found)) {
        error.textContent = "Type " + detail.confirm.found + " exactly to continue.";
        typed.select();
        return;
      }
      close(detail.confirm.found);
    }
    function onCancel() {
      close(null);
    }
    function onKey(event) {
      if (event.key === "Enter") {
        event.preventDefault();
        onAccept();
      }
    }

    accept.addEventListener("click", onAccept);
    cancel.addEventListener("click", onCancel);
    typed.addEventListener("keydown", onKey);
  });
}

let gateMode = "unlock";
let gatePath = null;
let gateProbe = null;
let gateBlocked = false;
let gateRecoveryMode = false;
let helloAvailable = false;
let passkeyAvailable = false;

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
  $("gate-meter-note").hidden = !creating;
  $("gate-form").classList.toggle("gate__form--blocked", gateBlocked);

  if (gateBlocked) {
    $("gate-eyebrow").textContent = "Vault unavailable";
    $("gate-tagline").textContent = "Obscura cannot reach a vault at this location.";
    return;
  }

  $("gate-use-recovery").hidden = creating;
  $("gate-use-hello").hidden = creating || !helloAvailable;
  $("gate-use-passkey").hidden = creating || !passkeyAvailable;
  if (creating) gateRecoveryMode = false;

  $("gate-eyebrow").textContent = creating ? "First run" : "Vault locked";
  $("gate-tagline").textContent = creating
    ? "Choose where the vault lives, then a master password."
    : "Everything you keep, kept to yourself.";
  $("gate-label").textContent = creating
    ? "New master password"
    : gateRecoveryMode
      ? "Recovery code"
      : "Master password";
  $("gate-submit").textContent = creating
    ? "Create vault"
    : gateRecoveryMode
      ? "Unlock with code"
      : "Unlock";
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

$("gate-use-recovery").addEventListener("click", () => {
  $("gate-error").textContent = "";
  openRecoveryUnlock();
});

$("gate-use-hello").addEventListener("click", async () => {
  const error = $("gate-error");
  const button = $("gate-use-hello");
  error.textContent = "";
  button.disabled = true;
  button.textContent = "Waiting for Windows Hello...";

  const args = {
    path: gateProbe ? gateProbe.path : null,
    remember: $("loc-remember").checked,
  };

  try {
    let info;
    try {
      info = await invoke("unlock_with_hello", args);
    } catch (err) {
      if (!err || !err.confirm) throw err;
      const accepted = await confirmRevision(err);
      if (accepted === null) {
        error.textContent = "Left as it is. Nothing was opened or changed.";
        return;
      }
      args.acceptRevision = accepted;
      info = await invoke("unlock_with_hello", args);
    }
    state.info = info;
    $("gate-password").value = "";
    enterApp();
    if (!hasRecoverySlot()) await openRecovery(true);
  } catch (err) {
    error.textContent = errText(err);
  } finally {
    button.disabled = false;
    button.textContent = "Unlock with Windows Hello";
  }
});

$("gate-use-passkey").addEventListener("click", async () => {
  const error = $("gate-error");
  const button = $("gate-use-passkey");
  error.textContent = "";
  button.disabled = true;
  button.textContent = "Scan the QR code with your phone...";

  const args = {
    path: gateProbe ? gateProbe.path : null,
    remember: $("loc-remember").checked,
  };

  try {
    let info;
    try {
      info = await invoke("unlock_with_passkey", args);
    } catch (err) {
      if (!err || !err.confirm) throw err;
      const accepted = await confirmRevision(err);
      if (accepted === null) {
        error.textContent = "Left as it is. Nothing was opened or changed.";
        return;
      }
      args.acceptRevision = accepted;
      info = await invoke("unlock_with_passkey", args);
    }
    state.info = info;
    $("gate-password").value = "";
    enterApp();
    if (!hasRecoverySlot()) await openRecovery(true);
  } catch (err) {
    error.textContent = errText(err);
  } finally {
    button.disabled = false;
    button.textContent = "Unlock with a phone passkey";
  }
});

(async () => {
  try {
    passkeyAvailable = await invoke("passkey_available");
  } catch (err) {
    passkeyAvailable = false;
  }
  if (!passkeyAvailable) {
    $("gate-use-passkey").hidden = true;
    $("s-add-passkey").hidden = true;
  }
})();

(async () => {
  try {
    helloAvailable = await invoke("hello_available");
  } catch (err) {
    helloAvailable = false;
  }
  if (!helloAvailable) {
    $("gate-use-hello").hidden = true;
    $("s-add-hello").hidden = true;
  }
})();

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
  if (gateMode === "create") measure(e.target.value, $("gate-meter"), $("gate-meter-note"));
});

$("gate-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = $("gate-password").value;
  const error = $("gate-error");
  const submit = $("gate-submit");
  error.textContent = "";

  if (!password) return;

  if (gateMode === "create") {
    const check = await invoke("assess_password", { password }).catch(() => ({ problem: null }));
    if (check.problem) {
      error.textContent = sentence(check.problem) + " Four or five unrelated words are easier to remember than a short, clever password.";
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

    let command = creating ? "create_vault" : "unlock";
    if (!creating && gateRecoveryMode) {
      command = "unlock_with_recovery";
      args.code = args.password;
      delete args.password;
    }

    let info;
    try {
      info = await invoke(command, args);
    } catch (err) {
      if (!err || !err.confirm) throw err;
      const accepted = await confirmRevision(err);
      if (accepted === null) {
        error.textContent = "Left as it is. Nothing was opened or changed.";
        return;
      }
      args.acceptRevision = accepted;
      info = await invoke(command, args);
    }

    state.info = info;
    $("gate-password").value = "";
    $("gate-confirm").value = "";
    enterApp();
    if (creating || !hasRecoverySlot()) await openRecovery(true);
  } catch (err) {
    error.textContent = errText(err);
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

function wipe() {
  clearInterval(state.totpTimer);
  state.totpTimer = null;
  state.info = null;
  state.entries = [];
  state.selected = null;
  state.editing = null;

  document.querySelectorAll(".scrim").forEach((scrim) => {
    scrim.hidden = true;
  });

  $("detail").innerHTML = "";
  $("list").innerHTML = "";
  $("entry-count").textContent = "0 entries";
  $("search").value = "";
  $("gen-out").textContent = "\u00a0";
  $("gen-bits").textContent = "0";
  $("rc-code").textContent = "\u00a0";

  document.querySelectorAll("#app input, #app textarea, .scrim input, .scrim textarea")
    .forEach((field) => {
      if (field.type !== "checkbox" && field.type !== "range") field.value = "";
    });

  document.querySelectorAll(".error").forEach((line) => {
    line.textContent = "";
  });
}

async function leaveApp(message) {
  wipe();
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

  if (detail.customFields.length) {
    const section = h("section", "section");
    section.append(h("p", "section__label", "Custom fields"));
    const card = h("div", "card");
    for (const field of detail.customFields) {
      const actions = [];
      if (field.hidden) {
        actions.push(revealButton(detail.id, field.name));
      }
      actions.push(copyButton("Copy", async () => {
        const value = field.hidden
          ? await invoke("reveal_field", { id: detail.id, name: field.name })
          : field.value;
        await invoke("copy_text", { text: value, clearAfter: 60 });
      }, "Copied - clipboard clears in a minute"));
      card.append(kv(field.name, field.hidden ? "\u2022".repeat(10) : field.value, actions));
    }
    section.append(card);
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

function revealButton(id, name) {
  const button = h("button", "icon-btn", null);
  button.title = "Reveal";
  button.append(icon("i-eye"));
  let shown = false;
  button.addEventListener("click", async (event) => {
    const row = event.currentTarget.closest(".kv");
    const cell = row && row.querySelector(".kv__v");
    if (!cell) return;
    try {
      if (shown) {
        cell.textContent = "\u2022".repeat(10);
      } else {
        cell.textContent = await invoke("reveal_field", { id, name });
      }
      shown = !shown;
    } catch (err) {
      toast(errText(err), "warn");
    }
  });
  return button;
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

function addFieldRow(field) {
  const row = h("div", "fieldrow");

  const name = h("input", "input fieldrow__name");
  name.placeholder = "Name";
  name.spellcheck = false;
  name.value = field ? field.name : "";

  const value = h("input", "input input--mono");
  value.placeholder = field && field.hidden ? "kept" : "Value";
  value.type = field && field.hidden ? "password" : "text";
  value.autocomplete = "off";
  value.spellcheck = false;
  value.value = field && !field.hidden ? field.value : "";
  value.dataset.kept = field && field.hidden ? "1" : "";
  value.addEventListener("input", () => {
    value.dataset.kept = "";
  });

  const box = h("input");
  box.type = "checkbox";
  box.checked = Boolean(field && field.hidden);
  box.addEventListener("change", () => {
    value.type = box.checked ? "password" : "text";
  });
  const hide = h("label", "check");
  hide.append(box, document.createTextNode(" Hide"));

  const remove = h("button", "icon-btn", null);
  remove.type = "button";
  remove.title = "Remove";
  remove.append(icon("i-trash"));
  remove.addEventListener("click", () => row.remove());

  row.append(name, value, hide, remove);
  $("e-fields").append(row);
}

function collectFields() {
  return [...$("e-fields").querySelectorAll(".fieldrow")]
    .map((row) => {
      const [name, value] = row.querySelectorAll("input.input");
      const hidden = row.querySelector('input[type="checkbox"]').checked;
      const keep = value.dataset.kept === "1" && !value.value;
      return { name: name.value.trim(), value: keep ? null : value.value, hidden };
    })
    .filter((field) => field.name);
}

function openEditor(detail) {
  state.editing = detail ? detail.id : null;
  $("editor-title").textContent = detail ? "Edit entry" : "New entry";
  $("editor-error").textContent = "";

  $("e-title").value = detail ? detail.title : "";
  $("e-username").value = detail ? detail.username : "";
  $("e-password").value = "";
  $("e-kind").value = detail ? detail.kind : "login";
  $("e-url").value = detail ? detail.urls.join("\n") : "";
  $("e-totp").value = "";
  const carries = Boolean(detail && detail.hasTotp);
  $("e-totp-hint").textContent = carries
    ? "This entry already has a code. Leave this blank to keep it, or paste a new URI to replace it."
    : "";
  $("e-totp-drop-row").hidden = !carries;
  $("e-totp-drop").checked = false;
  $("e-fields").replaceChildren();
  if (detail) for (const field of detail.customFields) addFieldRow(field);
  $("e-notes").value = detail ? detail.notes : "";
  $("e-tags").value = detail ? detail.tags.join(", ") : "";
  $("e-favorite").checked = detail ? detail.favorite : false;
  $("e-password-hint").textContent = detail
    ? "Leave blank to keep the stored password unchanged."
    : "";

  $("editor-scrim").hidden = false;
  $("e-title").focus();
}

$("e-field-add").addEventListener("click", () => addFieldRow(null));

$("editor-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = $("e-password").value;
  const totp = $("e-totp").value.trim();
  const dropping = $("e-totp-drop").checked;

  const input = {
    id: state.editing,
    kind: $("e-kind").value,
    title: $("e-title").value.trim(),
    username: $("e-username").value.trim(),
    password: password ? password : null,
    urls: $("e-url").value.split("\n").map((u) => u.trim()).filter(Boolean),
    notes: $("e-notes").value,
    tags: $("e-tags").value.split(",").map((t) => t.trim()).filter(Boolean),
    favorite: $("e-favorite").checked,
    totpUri: totp ? totp : dropping ? "" : null,
    customFields: collectFields(),
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
  renderSlots(info.slots);
  $("s-autolock").value = String(Math.round(info.autoLockSecs / 60));
  $("s-autolock-val").textContent = $("s-autolock").value;
  $("s-error").textContent = "";
  $("s-current").value = "";
  $("s-new").value = "";
  measure("", $("s-meter"), $("s-meter-note"));
  paintPasswordSection(info.hasPassword, info.unlockedByRecovery);
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

const SLOT_KINDS = {
  password: "master password",
  recovery: "recovery code",
  passkey: "passkey",
  hardware: "this computer",
};

function renderSlots(slots) {
  const host = $("s-slots");
  host.replaceChildren();
  const portable = slots.filter((s) => s.portable).length;

  for (const slot of slots) {
    const row = h("div", "slot");

    const body = h("span", "slot__body");
    body.append(h("span", "slot__label", slot.label));
    const added = slot.createdAt ? slot.createdAt.slice(0, 10) : "";
    const kindText = SLOT_KINDS[slot.kind] || slot.kind;
    body.append(h("span", "slot__meta", kindText + (added ? "  -  added " + added : "")));
    row.append(body);

    row.append(
      h("span", "slot__tag" + (slot.portable ? " slot__tag--portable" : ""),
        slot.portable ? "portable" : "this machine")
    );

    const remove = h("button", "icon-btn");
    remove.append(icon("i-trash"));
    const permanent = slot.kind === "password";
    const lastPortable = slot.portable && portable <= 1;
    const onlySlot = slots.length <= 1;
    if (permanent || lastPortable || onlySlot) {
      remove.disabled = true;
      remove.title = permanent
        ? "The master password can be changed below, but never removed."
        : onlySlot
          ? "This is the only way into the vault."
          : "The last portable credential. Add a recovery code first, then this can go.";
      remove.classList.add("icon-btn--off");
    } else {
      remove.title = "Remove " + slot.label;
      remove.addEventListener("click", () => removeSlot(slot, remove));
    }
    row.append(remove);
    host.append(row);
  }
}

async function removeSlot(slot, button) {
  const error = $("s-slots-error");
  error.textContent = "";
  if (button && button.dataset.armed !== "1") {
    for (const other of $("s-slots").querySelectorAll('[data-armed="1"]')) {
      other.dataset.armed = "0";
      other.classList.remove("btn--danger");
    }
    button.dataset.armed = "1";
    button.classList.add("btn--danger");
    toast("Click again to remove " + slot.label, "warn");
    setTimeout(() => {
      button.dataset.armed = "0";
      button.classList.remove("btn--danger");
    }, 4000);
    return;
  }
  try {
    const command = slot.kind === "hardware" ? "hello_forget" : "remove_slot";
    state.info = await invoke(command, { id: slot.id });
    renderSlots(state.info.slots);
    toast(
      slot.kind === "passkey"
        ? slot.label + " removed. The credential is still on the phone until you delete it there."
        : slot.label + " removed"
    );
  } catch (err) {
    error.textContent = String(err);
  }
}

$("s-add-recovery").addEventListener("click", async () => {
  $("s-slots-error").textContent = "";
  await openRecovery(false);
});

$("s-add-hello").addEventListener("click", async () => {
  const error = $("s-slots-error");
  const button = $("s-add-hello");
  error.textContent = "";
  button.disabled = true;
  try {
    state.info = await invoke("hello_enroll", { label: "Windows Hello" });
    renderSlots(state.info.slots);
    toast("Windows Hello is set up on this PC");
  } catch (err) {
    error.textContent = String(err);
  } finally {
    button.disabled = false;
  }
});

$("s-add-passkey").addEventListener("click", async () => {
  const error = $("s-slots-error");
  const button = $("s-add-passkey");
  error.textContent = "";
  button.disabled = true;
  button.textContent = "Scan the QR code twice...";
  try {
    state.info = await invoke("passkey_enroll", { label: "" });
    renderSlots(state.info.slots);
    toast("This phone can now open the vault");
  } catch (err) {
    error.textContent = String(err);
  } finally {
    button.disabled = false;
    button.textContent = "Add a phone passkey";
  }
});

$("s-export").addEventListener("click", () => {
  $("ex-error").textContent = "";
  $("ex-scrim").hidden = false;
});

$("ex-go").addEventListener("click", async () => {
  const error = $("ex-error");
  const button = $("ex-go");
  error.textContent = "";
  button.disabled = true;
  try {
    const result = await invoke("export_entries");
    if (!result) return;
    $("ex-scrim").hidden = true;
    toast(result.entries + " entries written to " + result.path, "warn");
  } catch (err) {
    error.textContent = errText(err);
  } finally {
    button.disabled = false;
  }
});

$("s-import").addEventListener("click", async () => {
  const error = $("s-backup-error");
  const button = $("s-import");
  error.textContent = "";
  button.disabled = true;
  try {
    const result = await invoke("import_entries");
    if (!result) return;
    state.info = result.info;
    $("s-count").textContent = String(result.info.entryCount);
    const many = (n, one, more) => n + " " + (n === 1 ? one : more);
    const asides = [];
    if (result.renumbered) {
      asides.push(many(result.renumbered, "was given a new id", "were given a new id"));
    }
    if (result.skipped) {
      asides.push(many(result.skipped, "row was skipped", "rows were skipped"));
    }
    if (result.totpDropped) {
      asides.push(many(result.totpDropped,
        "two-factor secret could not be read", "two-factor secrets could not be read"));
    }
    const tail = asides.length ? " - " + asides.join(", ") : "";
    toast("Added " + many(result.added, "entry", "entries") + " from " + result.source + tail,
      result.totpDropped || result.skipped ? "warn" : undefined);
    await refresh();
  } catch (err) {
    error.textContent = errText(err);
  } finally {
    button.disabled = false;
  }
});

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

function paintPasswordSection(hasPassword, recovered) {
  const resetting = hasPassword && Boolean(recovered);
  $("s-current-field").hidden = !hasPassword || resetting;
  $("s-password-label").textContent = resetting
    ? "Reset master password"
    : hasPassword ? "Master password" : "No master password";
  $("s-password-hint").textContent = resetting
    ? "You unlocked with your recovery code, so you can set a new master password without the old one."
    : hasPassword
      ? ""
      : "This vault opens with a recovery code only. Setting a master password gives you a second way in, and keeps the code as a spare.";
  $("s-new-label").textContent = hasPassword ? "New password" : "Master password";
  $("s-change").textContent = resetting
    ? "Reset password"
    : hasPassword ? "Change password" : "Set a master password";
}

$("s-new").addEventListener("input", (e) => measure(e.target.value, $("s-meter"), $("s-meter-note")));

$("s-change").addEventListener("click", async () => {
  const error = $("s-error");
  error.textContent = "";
  const adding = !(state.info && state.info.hasPassword);
  const resetting = !adding && Boolean(state.info.unlockedByRecovery);
  try {
    if (adding) {
      state.info = await invoke("set_master_password", { password: $("s-new").value });
    } else if (resetting) {
      state.info = await invoke("reset_master_password", { new: $("s-new").value });
    } else {
      await invoke("change_master_password", {
        current: $("s-current").value,
        new: $("s-new").value,
      });
    }
    $("s-current").value = "";
    $("s-new").value = "";
    measure("", $("s-meter"), $("s-meter-note"));
    toast(adding ? "Master password set" : resetting ? "Master password reset" : "Master password changed");
    await refresh();
    if (state.info) paintPasswordSection(state.info.hasPassword, state.info.unlockedByRecovery);
  } catch (err) {
    error.textContent = String(err);
  }
});

let rcPendingSlot = null;
let rcMandatory = false;

function hasRecoverySlot() {
  const slots = state.info && state.info.slots;
  return Array.isArray(slots) && slots.some((slot) => slot.kind === "recovery");
}

async function openRecovery(mandatory) {
  rcMandatory = Boolean(mandatory);
  rcPendingSlot = null;
  $("rc-error").textContent = "";
  $("rc-typed").value = "";
  showCode("");
  $("rc-cancel").hidden = rcMandatory;
  $("rc-lede").textContent = rcMandatory
    ? "Take this down before you go on. Without it, a forgotten master password ends the vault."
    : "Write this down. It is shown once.";
  $("rc-scrim").hidden = false;

  try {
    const issued = await invoke("create_recovery_code", { label: "Recovery code" });
    rcPendingSlot = issued.slot;
    showCode(issued.code);
    $("rc-typed").focus();
  } catch (err) {
    showCode("");
    $("rc-error").textContent =
      String(err) + " - the vault itself is safe; close Obscura and reopen it with your master password, then try again from Settings.";
    $("rc-cancel").hidden = false;
  }
}

function showCode(code) {
  const host = $("rc-code");
  host.replaceChildren();
  host.dataset.code = code;
  for (const group of code.split("-").filter(Boolean)) {
    host.append(h("span", "rc__group", group));
  }
}

$("rc-copy").addEventListener("click", async () => {
  const value = $("rc-code").dataset.code || "";
  if (!value.trim()) return;
  try {
    await invoke("copy_text", { text: value, clearAfter: 120 });
    toast("Copied - clipboard clears in two minutes");
  } catch (err) {
    toast(String(err), "warn");
  }
});

$("rc-confirm").addEventListener("click", async () => {
  const typed = $("rc-typed").value;
  const error = $("rc-error");
  error.textContent = "";
  if (!typed.trim()) {
    error.textContent = "Type the code above to confirm you have it.";
    return;
  }
  try {
    state.info = await invoke("confirm_recovery_code", { code: typed });
    $("rc-scrim").hidden = true;
    showCode("");
    $("rc-typed").value = "";
    rcPendingSlot = null;
    rcMandatory = false;
    await refresh();
    toast("Recovery code confirmed");
  } catch (err) {
    error.textContent = String(err);
  }
});

$("rc-cancel").addEventListener("click", async () => {
  if (rcPendingSlot) {
    try {
      state.info = await invoke("discard_recovery_code", { id: rcPendingSlot });
    } catch (err) {
      toast(String(err), "warn");
    }
  }
  rcPendingSlot = null;
  showCode("");
  $("rc-typed").value = "";
  $("rc-scrim").hidden = true;
  await refresh();
});

function openRecoveryUnlock() {
  gateRecoveryMode = !gateRecoveryMode;
  const on = gateRecoveryMode;
  $("gate-label").textContent = on ? "Recovery code" : "Master password";
  $("gate-password").type = on ? "text" : "password";
  $("gate-password").value = "";
  $("gate-password").placeholder = on ? "XXXXXXXX-XXXXXXXX-..." : "................";
  $("gate-submit").textContent = on ? "Unlock with code" : "Unlock";
  $("gate-use-recovery").textContent = on
    ? "Use the master password instead"
    : "Use a recovery code instead";
  $("gate-password").focus();
}

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
    if (event.target === scrim && scrim.dataset.locked !== "true") scrim.hidden = true;
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
    if (open && open.dataset.locked !== "true") { open.hidden = true; return; }
    if (open) return;
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
