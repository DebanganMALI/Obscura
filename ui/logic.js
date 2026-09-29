const ObscuraLogic = (() => {
  "use strict";

  const MASK = "•";

  function meterBand(score) {
    if (score <= 1) return "on-weak";
    if (score <= 2) return "on-fair";
    return "on-strong";
  }

  function sentence(text) {
    return text ? text.charAt(0).toUpperCase() + text.slice(1) + "." : "";
  }

  function initials(title) {
    const words = String(title || "").trim().split(/\s+/).filter(Boolean);
    if (!words.length) return "?";
    if (words.length === 1) return [...words[0]].slice(0, 2).join("");
    return [...words[0]][0] + [...words[1]][0];
  }

  function errText(err) {
    if (err && typeof err === "object" && typeof err.message === "string") return err.message;
    return String(err);
  }

  function isLocked(err) {
    return String(err).includes("locked");
  }

  function entryCount(n) {
    return n + (n === 1 ? " entry" : " entries");
  }

  function gate(probe) {
    const mode = probe.exists && probe.isVault ? "unlock" : "create";
    const blocked =
      !probe.parentExists || (probe.exists && !probe.isVault) || (!probe.exists && !probe.writable);
    let note;
    if (probe.warning) {
      note = {
        text: probe.warning,
        tone: probe.parentExists && probe.writable ? "warn" : "bad",
      };
    } else if (mode === "unlock") {
      note = { text: "An Obscura vault is here.", tone: "ok" };
    } else {
      note = { text: "Nothing here yet. A new vault will be created.", tone: "" };
    }
    return { mode, blocked, note };
  }

  function gateWords(creating, recovery) {
    const byCode = !creating && recovery;
    return {
      eyebrow: creating ? "First run" : "Vault locked",
      tagline: creating
        ? "Choose where the vault lives, then a master password."
        : "Everything you keep, kept to yourself.",
      label: creating ? "New master password" : byCode ? "Recovery code" : "Master password",
      submit: creating ? "Create vault" : byCode ? "Unlock with code" : "Unlock",
    };
  }

  const REVISION_WORDING = {
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

  function revisionWording(reason) {
    return Object.prototype.hasOwnProperty.call(REVISION_WORDING, reason)
      ? REVISION_WORDING[reason]
      : REVISION_WORDING.damaged;
  }

  function revisionConfirmed(typed, found) {
    return String(typed).trim() === String(found);
  }

  function mask(length) {
    return MASK.repeat(Math.max(0, Math.min(Number(length) || 0, 28)));
  }

  function passwordAge(days) {
    if (days === null || days === undefined) return null;
    const label = days === 0 ? "Changed today"
      : days === 1 ? "Changed yesterday"
      : "Changed " + days + " days ago";
    return { label, stale: days > 365 };
  }

  function totpGroups(code) {
    return String(code).replace(/(\d{3})(?=\d)/g, "$1 ");
  }

  function ringFraction(remaining, period) {
    if (!(period > 0)) return 0;
    return Math.max(0, Math.min(1, remaining / period));
  }

  function lines(text) {
    return String(text || "").split("\n").map((line) => line.trim()).filter(Boolean);
  }

  function tags(text) {
    return String(text || "").split(",").map((tag) => tag.trim()).filter(Boolean);
  }

  function totpUri(typed, dropping) {
    const uri = String(typed || "").trim();
    if (uri) return uri;
    return dropping ? "" : null;
  }

  function customField(row) {
    const keep = row.kept && !row.value;
    return { name: String(row.name || "").trim(), value: keep ? null : row.value, hidden: Boolean(row.hidden) };
  }

  function customFields(rows) {
    return rows.map(customField).filter((field) => field.name);
  }

  function entryInput(form) {
    return {
      id: form.id || null,
      kind: form.kind,
      title: String(form.title || "").trim(),
      username: String(form.username || "").trim(),
      password: form.password ? form.password : null,
      urls: lines(form.urls),
      notes: form.notes || "",
      tags: tags(form.tags),
      favorite: Boolean(form.favorite),
      totpUri: totpUri(form.totp, form.dropping),
      customFields: customFields(form.fields || []),
    };
  }

  const SLOT_KINDS = {
    password: "master password",
    recovery: "recovery code",
    passkey: "passkey",
    hardware: "this computer",
  };

  function slotKind(kind) {
    return Object.prototype.hasOwnProperty.call(SLOT_KINDS, kind) ? SLOT_KINDS[kind] : kind;
  }

  function slotMeta(slot) {
    const added = slot.createdAt ? String(slot.createdAt).slice(0, 10) : "";
    return slotKind(slot.kind) + (added ? "  -  added " + added : "");
  }

  function slotRemoval(slot, slots) {
    const portable = slots.filter((s) => s.portable).length;
    if (slot.kind === "password") {
      return { allowed: false, reason: "The master password can be changed below, but never removed." };
    }
    if (slots.length <= 1) {
      return { allowed: false, reason: "This is the only way into the vault." };
    }
    if (slot.portable && portable <= 1) {
      return {
        allowed: false,
        reason: "The last portable credential. Add a recovery code first, then this can go.",
      };
    }
    return { allowed: true, reason: "Remove " + slot.label };
  }

  function slotCommand(slot) {
    return slot.kind === "hardware" ? "hello_forget" : "remove_slot";
  }

  function slotRemoved(slot) {
    return slot.kind === "passkey"
      ? slot.label + " removed. The credential is still on the phone until you delete it there."
      : slot.label + " removed";
  }

  function many(n, one, more) {
    return n + " " + (n === 1 ? one : more);
  }

  function importMessage(result) {
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
    return "Added " + many(result.added, "entry", "entries") + " from " + result.source + tail;
  }

  function importWarns(result) {
    return Boolean(result.totpDropped || result.skipped);
  }

  function codeGroups(code) {
    return String(code || "").split("-").filter(Boolean);
  }

  function shortcut(event, appOpen) {
    if (!event.ctrlKey && !event.metaKey) return null;
    const key = String(event.key).toLowerCase();
    if (key === "l") return "lock";
    if (!appOpen) return null;
    if (key === "n") return "new";
    if (key === "g") return "generator";
    if (key === "f") return "search";
    return null;
  }

  return Object.freeze({
    meterBand,
    sentence,
    initials,
    errText,
    isLocked,
    entryCount,
    gate,
    gateWords,
    revisionWording,
    revisionConfirmed,
    mask,
    passwordAge,
    totpGroups,
    ringFraction,
    lines,
    tags,
    totpUri,
    customFields,
    entryInput,
    slotKind,
    slotMeta,
    slotRemoval,
    slotCommand,
    slotRemoved,
    importMessage,
    importWarns,
    codeGroups,
    shortcut,
  });
})();

if (typeof module === "object" && module !== null) module.exports = ObscuraLogic;
