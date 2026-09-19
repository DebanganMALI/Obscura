# Mutation testing

`cargo mutants` runs on Linux from the Actions tab: **Mutants** -> Run workflow.
It is manual because it takes about 70 minutes.

It does not inherit the `-D warnings` that `ci.yml` sets. cargo-mutants tells a
caught mutant from an unviable one by whether the mutated code compiles, so
turning warnings into errors would count mutants that merely trip an unused
variable as unviable and quietly hollow out the run.

The job exits non-zero whenever any mutant survives, so a red X on this workflow
means "read the list", not "something is broken".

## The run of 2026-09-19

`obscura-vault`, 544 mutants in 69 minutes: **464 caught, 15 missed, 65
unviable.**

Of the 15 survivors, 14 are equivalent mutants - the mutated code behaves
identically to the original, so no test can kill them and none should try. One
is a real gap that safe Rust cannot express.

### What the run was for

`restrict_to_owner -> Ok(())` does **not** appear in the missed list. On Windows
cargo-mutants reports it as MISSED because it patches `#[cfg(unix)]` source that
never compiles there. On Linux it is caught, which confirms the test asserting
the vault file is `0600` actually holds it to that. That guarantee is what stops
another account on a shared machine reading the encrypted vault.

### The seven bit-packing survivors

`replace | with ^` at `recovery.rs:123`, `recovery.rs:139`, `recovery.rs:174`,
`totp.rs:249` (three sites), `totp.rs:277`, `totp.rs:302`.

Every one is of the form `(acc << n) | value` where `value` is masked to fit in
exactly the `n` bits the shift just vacated. When the operands share no set bits,
OR and XOR are the same operation. Equivalent.

### The five comparison survivors

**`generator.rs:90`**, `<` replaced by `==` and by `<=`, in
`PasswordPolicy::validate`. With `AMBIGUOUS` removing `0O1lI|`, the four classes
are 25, 24, 8 and 27 members after filtering, and `enabled == 0` is already
refused above. The smallest reachable charset is therefore 8, so
`charset().len() < 2` can never fire and neither can `== 2` or `<= 2`. Lines
90-92 are unreachable defensive code. They are worth keeping - they would start
mattering the moment someone shrinks a class - but no test can reach them today.

**`recovery.rs:155`**, `>` replaced by `>=`. `bits` is `u32`, so `bits >= 0` is
always true, but when `bits == 0` the guard becomes `acc & ((1 << 0) - 1) != 0`,
which is `acc & 0 != 0`, which is always false. The mutant runs a check that
cannot fire. Equivalent.

**`recovery.rs:173`**, `<` replaced by `<=`, in `checksum`. `CHECK_CHARS` is 4,
so the loop runs four times and `bits` takes the values 0, 3, 6, 1 at the test.
It never reaches 5, so the two operators never diverge.

**`recovery.rs:120`**, `<` replaced by `<=`, in `encode`. This one looks
reachable and is not equivalent for the reason it first appears. `DATA_CHARS` is
52 and `bits` cycles 0, 3, 6, 1, 4, 7, 2, 5, so on every eighth iteration
`bits == 5` and the mutant pulls a byte the original does not.

It is still equivalent, because pulling a byte early changes *when* bits enter
the accumulator, not *which bits come out*. `symbol` masks with `& 0x1f`, so the
emitted five bits are the next five bits of the stream either way, and the
accumulator peaks at 13 bits under the mutation - well inside `u16`. Verified by
applying the mutation and running the recovery suite: all 21 tests pass.

**`vault.rs:525`**, `format_version -> u16` replaced with `1`. `FORMAT_VERSION`
is `1`, so the mutant replaces a getter with the constant it returns.

### The one real survivor

`entry.rs:150`, `replace <impl Drop for Entry>::drop with ()`.

`Drop` delegates to `wipe_plain_fields`, which is directly tested by
`wiping_an_entry_clears_every_plain_text_field`. So the wiping logic is covered.
What the mutant shows is that the delegation itself is not: delete the four-line
`impl Drop` block and no test fails.

There is no way to test it in safe Rust. A value cannot be inspected after it is
dropped, and `mem::needs_drop::<Entry>()` is true regardless because `String` and
`Vec` carry their own drop glue. Reaching for `unsafe` to observe freed memory
would introduce more risk than it removes in a crate whose whole job is holding
secrets.

Accepted, deliberately. Anyone editing `entry.rs` should know that the four
lines of `impl Drop` are load-bearing and untested.

## Reading a future run

A new survivor is worth one question before any test is written: can the mutated
code behave differently from the original, for any input the program can
actually produce? Fourteen of fifteen here could not. Writing a test per
surviving mutant without asking would have produced fourteen tests that assert
whatever the code happens to do, which is worse than no test at all.