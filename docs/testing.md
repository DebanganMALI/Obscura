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

## The mock-runtime tests run on Windows too

`commands::wiring` drives thirteen commands end-to-end on Tauri's
`MockRuntime`, covering create, unlock, save, relocate, the rollback refusal and
the auto-lock round trip. It runs on Linux and Windows.

For a while it ran on Linux only. On Windows the library test binary aborted
before `main` with `0xc0000139`, `STATUS_ENTRYPOINT_NOT_FOUND`: the dialog code
imports functions that exist only in version 6 of `comctl32.dll`, and a Windows
program gets version 6 only if its manifest asks for it. `tauri-build` puts that
manifest into a resource linked into binaries alone, so `obscura-app.exe`
started and the test binary did not. `cargo:rustc-link-arg-tests` would not
have helped, because it reaches only the targets under `tests/`, not the unit
test harness built from the library.

`src-tauri/build.rs` now turns off `tauri-build`'s manifest and has the MSVC
linker write one instead, through `/MANIFEST:EMBED` and a
`/MANIFESTDEPENDENCY` on Common Controls 6. Those flags apply to every artifact
the package links - the application, the library and its test harness alike -
so all of them ask for the same version of the same library. Two embedded
manifests would collide, which is why the resource copy has to go rather than
sit beside it.

## The interface

`node --test ui-tests/logic.test.js ui-tests/shell.test.js`

The interface follows the same rule as the Rust side. Everything it decides
without touching the page - which unlock methods may be removed and why, what
the editor sends to `save_entry`, how a two-factor box that was left blank is
read, how a rollback confirmation is checked, what an import reports - lives in
`ui/logic.js` as plain functions, and `app.js` only paints their answers.
`logic.js` is a classic script that also exports itself to Node, so the same
file runs in the window and under the test runner with nothing in between.

`shell.test.js` reads the files instead of running them. It fails if the page
loads any script but its own two, gains an inline script or handler, loosens
the content security policy, calls the network or `eval`, calls a Rust command
that is not registered, or looks up an element id the page does not have.

No npm package is involved. What is still not tested: the DOM work in `app.js`
itself. A browser harness would cover it, at the cost of a dependency this
project has so far managed without.

## The terminal browser

`obscura` with no command opens a browser drawn with ratatui. Its tests in
`crates/obscura-cli/src/tui.rs` render it into ratatui's `TestBackend`, a
screen held in memory, and read the screen back as text. They press keys the
way a person would and check what ends up on screen: a password appears only
after `r` and only for the selected entry, `q` typed into the filter is a
letter rather than quit, the key that closes the help overlay does nothing
else, and an idle browser reports itself locked.

The tests never touch the system clipboard. The browser takes its clipboard as
an argument, the tests pass none, and the copy keys are checked through the
message they show instead.
