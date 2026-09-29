"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");

const html = read("ui/index.html");
const scripts = ["ui/logic.js", "ui/app.js"].map((file) => [file, read(file)]);

test("the page loads the logic before the code that uses it, and nothing else", () => {
  const sources = [...html.matchAll(/<script\b([^>]*)>/g)].map((match) => match[1]);
  assert.deepEqual(sources.map((attrs) => (attrs.match(/src="([^"]+)"/) || [])[1]),
    ["logic.js", "app.js"]);
});

test("the page carries no inline script or inline event handler", () => {
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/);
  assert.doesNotMatch(html, /\son[a-z]+\s*=/i);
});

test("the content security policy still denies by default", () => {
  const config = JSON.parse(read("src-tauri/tauri.conf.json"));
  const csp = config.app.security.csp;
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /script-src 'self'(;|$)/);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval|https?:\/\/(?!ipc\.localhost)/);
});

test("the interface has no way to reach the network or run strings as code", () => {
  for (const [file, source] of scripts) {
    for (const banned of [/\bfetch\s*\(/, /XMLHttpRequest/, /WebSocket/, /EventSource/,
      /sendBeacon/, /\beval\s*\(/, /new\s+Function\s*\(/, /\.innerHTML\s*=/, /localStorage/]) {
      assert.doesNotMatch(source, banned, file + " uses " + banned);
    }
    const urls = [...source.matchAll(/https?:\/\/[^\s"'`]+/g)].map((match) => match[0]);
    assert.deepEqual(urls.filter((url) => url !== "http://www.w3.org/2000/svg"), [], file);
  }
});

test("every Rust command the interface calls is registered", () => {
  const registered = new Set(
    [...read("src-tauri/src/lib.rs").matchAll(/commands::(\w+),/g)].map((match) => match[1])
  );
  const called = new Set();
  for (const [, source] of scripts) {
    for (const match of source.matchAll(/invoke\(\s*"(\w+)"/g)) called.add(match[1]);
    for (const match of source.matchAll(/command\s*=\s*"(\w+)"/g)) called.add(match[1]);
    const commandLike = (name) => registered.has(name) || name.includes("_");
    for (const match of source.matchAll(/\?\s*"(\w+)"\s*:\s*"(\w+)"/g)) {
      if (commandLike(match[1]) && commandLike(match[2])) {
        called.add(match[1]);
        called.add(match[2]);
      }
    }
  }
  assert.ok(called.size > 20, "found " + called.size + " commands");
  const missing = [...called].filter((name) => !registered.has(name));
  assert.deepEqual(missing, []);
});

test("every element the code looks up by id exists in the page", () => {
  const ids = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]));
  const wanted = new Set();
  for (const [, source] of scripts) {
    for (const match of source.matchAll(/\$\("([\w-]+)"\)/g)) wanted.add(match[1]);
  }
  assert.ok(wanted.size > 50, "found " + wanted.size + " lookups");
  const missing = [...wanted].filter((id) => !ids.has(id));
  assert.deepEqual(missing, []);
});
