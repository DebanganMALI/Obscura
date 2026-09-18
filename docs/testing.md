# Testing

`cargo nextest run --workspace --all-features`

Most of this project is tested through plain functions rather than through the
application. Where a piece of logic needed an `AppHandle` only to find a
directory, it was given a twin that takes a path, and the `AppHandle` version
became a one-line wrapper. `watermark`'s rollback detection and `location`'s
settings file both work that way, so their tests run against a temporary
directory and can never reach the real config.

That pattern is not only cheaper than a harness. Every defect found in this
project so far has been in a sequence, and every one of them was reachable
once the sequence was a function taking values instead of a handle.

## The mock-runtime tests do not run on Windows

`commands::wiring` drives thirteen commands end-to-end on Tauri's
`MockRuntime`, covering create, unlock, save, relocate, the rollback refusal and
the auto-lock round trip. It is compiled and run on Linux only.

On Windows the library test binary aborts before `main` with
`0xc0000139`, `STATUS_ENTRYPOINT_NOT_FOUND`. All of its imports are system
libraries, so one of them resolves to a copy that lacks an export it wants. The
most likely candidate is `comctl32.dll`: tao imports functions that exist only
in version 6, and an executable gets version 6 only by carrying a manifest that
asks for it. `tauri-build` emits that manifest for binary targets, not for test
targets, which is why `obscura-app.exe` runs and the test binary does not, and
why this appeared exactly when enabling the `test` feature changed which tao
code was linked in.

It was not confirmed. An external manifest could not be used to test the theory
because rustc embeds its own, and Windows then ignores the external one.

So the dev-dependency is declared for non-Windows targets only and the module is
gated to match. A Windows test build is therefore identical to what it was
before any of this, and `cargo nextest run --workspace` passes on both
platforms. What it costs: a regression in the command sequences would be caught
on Linux and not on Windows. Worth knowing rather than worth hiding.

If someone wants to fix it properly, the thing to try is emitting the manifest
for test targets from `build.rs` with `cargo:rustc-link-arg-tests`.