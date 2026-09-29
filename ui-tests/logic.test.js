"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const L = require("../ui/logic.js");

test("the meter colours weak, fair and strong scores apart", () => {
  assert.equal(L.meterBand(0), "on-weak");
  assert.equal(L.meterBand(1), "on-weak");
  assert.equal(L.meterBand(2), "on-fair");
  assert.equal(L.meterBand(3), "on-strong");
  assert.equal(L.meterBand(4), "on-strong");
});

test("a message from Rust becomes a sentence, and nothing stays nothing", () => {
  assert.equal(
    L.sentence("the password is on a list of commonly used passwords"),
    "The password is on a list of commonly used passwords."
  );
  assert.equal(L.sentence(""), "");
  assert.equal(L.sentence(null), "");
  assert.equal(L.sentence(undefined), "");
});

test("initials come from the first two words, or the first two letters of one", () => {
  assert.equal(L.initials("GitHub"), "Gi");
  assert.equal(L.initials("Bank of India"), "Bo");
  assert.equal(L.initials("   spaced    out  "), "so");
  assert.equal(L.initials(""), "?");
  assert.equal(L.initials("   "), "?");
});

test("initials never split a character in half", () => {
  assert.equal(L.initials("\u{1F510}\u{1F511} keys"), "\u{1F510}k");
  assert.equal(L.initials("\u{1F510}\u{1F511}"), "\u{1F510}\u{1F511}");
  assert.equal(L.initials("আমার"), "আম");
});

test("an error object shows its message and anything else shows itself", () => {
  assert.equal(L.errText({ message: "that password does not open this vault" }),
    "that password does not open this vault");
  assert.equal(L.errText("plain text"), "plain text");
  assert.equal(L.errText({ message: 42 }), "[object Object]");
  assert.equal(L.errText(null), "null");
});

test("a locked vault is recognised from the error Rust sends", () => {
  assert.equal(L.isLocked("the vault is locked"), true);
  assert.equal(L.isLocked("something else went wrong"), false);
});

test("the entry count says entry once and entries otherwise", () => {
  assert.equal(L.entryCount(0), "0 entries");
  assert.equal(L.entryCount(1), "1 entry");
  assert.equal(L.entryCount(2), "2 entries");
});

test("an existing vault is opened and an empty writable place is offered for a new one", () => {
  const vault = L.gate({ exists: true, isVault: true, parentExists: true, writable: true });
  assert.equal(vault.mode, "unlock");
  assert.equal(vault.blocked, false);
  assert.deepEqual(vault.note, { text: "An Obscura vault is here.", tone: "ok" });

  const empty = L.gate({ exists: false, isVault: false, parentExists: true, writable: true });
  assert.equal(empty.mode, "create");
  assert.equal(empty.blocked, false);
  assert.equal(empty.note.tone, "");
});

test("a place that cannot hold a vault blocks the gate rather than failing later", () => {
  assert.equal(L.gate({ exists: true, isVault: false, parentExists: true, writable: true }).blocked, true,
    "a file that is not a vault must never be offered for overwriting");
  assert.equal(L.gate({ exists: false, isVault: false, parentExists: false, writable: false }).blocked, true);
  assert.equal(L.gate({ exists: false, isVault: false, parentExists: true, writable: false }).blocked, true);
});

test("a warning from Rust wins over the ordinary note, and its tone follows the folder", () => {
  const syncing = L.gate({
    exists: true, isVault: true, parentExists: true, writable: true, warning: "This folder syncs.",
  });
  assert.deepEqual(syncing.note, { text: "This folder syncs.", tone: "warn" });

  const readOnly = L.gate({
    exists: false, isVault: false, parentExists: true, writable: false, warning: "Read only.",
  });
  assert.deepEqual(readOnly.note, { text: "Read only.", tone: "bad" });
});

test("the gate words follow creating, unlocking and unlocking by recovery code", () => {
  assert.deepEqual(L.gateWords(true, false), {
    eyebrow: "First run",
    tagline: "Choose where the vault lives, then a master password.",
    label: "New master password",
    submit: "Create vault",
  });
  assert.equal(L.gateWords(false, false).label, "Master password");
  assert.equal(L.gateWords(false, false).submit, "Unlock");
  assert.equal(L.gateWords(false, true).label, "Recovery code");
  assert.equal(L.gateWords(false, true).submit, "Unlock with code");
  assert.equal(L.gateWords(true, true).label, "New master password",
    "creating a vault never asks for a recovery code");
});

test("every revision question Rust can ask has its own wording", () => {
  for (const reason of ["rollback", "unreadable", "damaged"]) {
    const [title, lede] = L.revisionWording(reason);
    assert.ok(title.length > 0 && lede.length > 0, reason);
  }
  assert.notDeepEqual(L.revisionWording("rollback"), L.revisionWording("damaged"));
  assert.deepEqual(L.revisionWording("something new"), L.revisionWording("damaged"));
  assert.deepEqual(L.revisionWording("toString"), L.revisionWording("damaged"),
    "a reason that happens to name an object property must not slip through");
});

test("a revision is confirmed only by typing exactly that number", () => {
  assert.equal(L.revisionConfirmed("12", 12), true);
  assert.equal(L.revisionConfirmed("  12 ", 12), true);
  assert.equal(L.revisionConfirmed("11", 12), false);
  assert.equal(L.revisionConfirmed("012", 12), false);
  assert.equal(L.revisionConfirmed("", 12), false);
});

test("a hidden password shows its length only up to a cap", () => {
  assert.equal(L.mask(5), "•".repeat(5));
  assert.equal(L.mask(28), "•".repeat(28));
  assert.equal(L.mask(200), "•".repeat(28));
  assert.equal(L.mask(0), "");
  assert.equal(L.mask(-3), "");
  assert.equal(L.mask(undefined), "");
});

test("a password age reads like a person would say it and goes stale after a year", () => {
  assert.equal(L.passwordAge(null), null);
  assert.equal(L.passwordAge(undefined), null);
  assert.deepEqual(L.passwordAge(0), { label: "Changed today", stale: false });
  assert.deepEqual(L.passwordAge(1), { label: "Changed yesterday", stale: false });
  assert.deepEqual(L.passwordAge(365), { label: "Changed 365 days ago", stale: false });
  assert.deepEqual(L.passwordAge(366), { label: "Changed 366 days ago", stale: true });
});

test("a one time code is split into groups of three", () => {
  assert.equal(L.totpGroups("123456"), "123 456");
  assert.equal(L.totpGroups("12345678"), "123 456 78");
  assert.equal(L.totpGroups("1234567890"), "123 456 789 0");
});

test("the countdown ring stays inside a full circle", () => {
  assert.equal(L.ringFraction(15, 30), 0.5);
  assert.equal(L.ringFraction(30, 30), 1);
  assert.equal(L.ringFraction(45, 30), 1);
  assert.equal(L.ringFraction(-1, 30), 0);
  assert.equal(L.ringFraction(10, 0), 0);
});

test("addresses are one per line and tags are comma separated, blanks dropped", () => {
  assert.deepEqual(L.lines(" https://a.example \n\n https://b.example\n"),
    ["https://a.example", "https://b.example"]);
  assert.deepEqual(L.tags(" work, ,bank ,"), ["work", "bank"]);
  assert.deepEqual(L.lines(""), []);
  assert.deepEqual(L.tags(undefined), []);
});

test("a blank two factor box keeps the code unless removal was asked for", () => {
  assert.equal(L.totpUri("", false), null, "null means leave the stored code alone");
  assert.equal(L.totpUri("   ", false), null);
  assert.equal(L.totpUri("", true), "", "an empty string means remove it");
  assert.equal(L.totpUri(" otpauth://totp/x?secret=ABC ", true), "otpauth://totp/x?secret=ABC",
    "a new code wins over the removal box");
});

test("a hidden custom field the editor never saw is kept rather than blanked", () => {
  assert.deepEqual(
    L.customFields([
      { name: " PIN ", value: "", hidden: true, kept: true },
      { name: "Account", value: "12345", hidden: false, kept: false },
      { name: "  ", value: "orphan", hidden: false, kept: false },
      { name: "Answer", value: "new", hidden: true, kept: true },
    ]),
    [
      { name: "PIN", value: null, hidden: true },
      { name: "Account", value: "12345", hidden: false },
      { name: "Answer", value: "new", hidden: true },
    ]
  );
});

test("the editor sends exactly the shape save_entry expects", () => {
  const input = L.entryInput({
    id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
    kind: "login",
    title: "  GitHub ",
    username: " saheb ",
    password: "",
    urls: "https://github.com\n",
    notes: "  kept as typed  ",
    tags: "code, work",
    favorite: 1,
    totp: "",
    dropping: false,
    fields: [],
  });
  assert.deepEqual(input, {
    id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
    kind: "login",
    title: "GitHub",
    username: "saheb",
    password: null,
    urls: ["https://github.com"],
    notes: "  kept as typed  ",
    tags: ["code", "work"],
    favorite: true,
    totpUri: null,
    customFields: [],
  });
});

test("a new entry has no id and a typed password is sent untrimmed", () => {
  const input = L.entryInput({ kind: "login", title: "x", password: "  spaces count  " });
  assert.equal(input.id, null);
  assert.equal(input.password, "  spaces count  ");
});

test("unlock methods are named in words", () => {
  assert.equal(L.slotKind("password"), "master password");
  assert.equal(L.slotKind("recovery"), "recovery code");
  assert.equal(L.slotKind("hardware"), "this computer");
  assert.equal(L.slotKind("other"), "other");
  assert.equal(L.slotKind("constructor"), "constructor");
  assert.equal(L.slotMeta({ kind: "passkey", createdAt: "2026-09-26T10:00:00Z" }),
    "passkey  -  added 2026-09-26");
  assert.equal(L.slotMeta({ kind: "passkey" }), "passkey");
});

const password = { id: "p", kind: "password", label: "Master password", portable: true };
const code = { id: "r", kind: "recovery", label: "Recovery code", portable: true };
const phone = { id: "k", kind: "passkey", label: "Pixel", portable: true };
const hello = { id: "h", kind: "hardware", label: "Windows Hello", portable: false };

test("the master password can never be removed from the list", () => {
  const verdict = L.slotRemoval(password, [password, code, phone, hello]);
  assert.equal(verdict.allowed, false);
  assert.match(verdict.reason, /never removed/);
});

test("the only way in and the last portable way in are kept", () => {
  assert.equal(L.slotRemoval(code, [code]).allowed, false);
  assert.match(L.slotRemoval(code, [code]).reason, /only way into the vault/);

  const lastPortable = L.slotRemoval(code, [code, hello]);
  assert.equal(lastPortable.allowed, false);
  assert.match(lastPortable.reason, /last portable/);
});

test("anything else can be removed, and says what it removes", () => {
  assert.deepEqual(L.slotRemoval(phone, [password, code, phone]),
    { allowed: true, reason: "Remove Pixel" });
  assert.equal(L.slotRemoval(hello, [password, hello]).allowed, true);
  assert.equal(L.slotRemoval(code, [password, code, hello]).allowed, true);
});

test("windows hello is forgotten through its own command", () => {
  assert.equal(L.slotCommand(hello), "hello_forget");
  assert.equal(L.slotCommand(phone), "remove_slot");
  assert.equal(L.slotCommand(code), "remove_slot");
});

test("removing a passkey reminds you the phone still holds it", () => {
  assert.match(L.slotRemoved(phone), /still on the phone/);
  assert.equal(L.slotRemoved(code), "Recovery code removed");
});

test("an import reports what it added and everything it could not", () => {
  assert.equal(L.importMessage({ added: 1, source: "Bitwarden" }), "Added 1 entry from Bitwarden");
  assert.equal(
    L.importMessage({ added: 12, source: "Chrome", renumbered: 1, skipped: 2, totpDropped: 1 }),
    "Added 12 entries from Chrome - 1 was given a new id, 2 rows were skipped, "
      + "1 two-factor secret could not be read"
  );
  assert.equal(L.importWarns({ skipped: 0, totpDropped: 0 }), false);
  assert.equal(L.importWarns({ skipped: 3 }), true);
  assert.equal(L.importWarns({ totpDropped: 1 }), true);
  assert.equal(L.importWarns({ renumbered: 4 }), false);
});

test("a recovery code is shown in the groups it is printed in", () => {
  assert.deepEqual(L.codeGroups("GCGTKCC3-7N838YC8-TSJE6QB0"), ["GCGTKCC3", "7N838YC8", "TSJE6QB0"]);
  assert.deepEqual(L.codeGroups(""), []);
  assert.deepEqual(L.codeGroups(undefined), []);
});

test("shortcuts need control or command, and only lock works outside the vault", () => {
  assert.equal(L.shortcut({ key: "l", ctrlKey: true }, false), "lock");
  assert.equal(L.shortcut({ key: "L", metaKey: true }, true), "lock");
  assert.equal(L.shortcut({ key: "n", ctrlKey: true }, true), "new");
  assert.equal(L.shortcut({ key: "g", ctrlKey: true }, true), "generator");
  assert.equal(L.shortcut({ key: "f", ctrlKey: true }, true), "search");
  assert.equal(L.shortcut({ key: "n", ctrlKey: true }, false), null);
  assert.equal(L.shortcut({ key: "n" }, true), null);
  assert.equal(L.shortcut({ key: "x", ctrlKey: true }, true), null);
});

test("the logic module cannot be changed from outside", () => {
  assert.ok(Object.isFrozen(L));
});
