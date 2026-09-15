fn main() -> anyhow::Result<()> {
    #![allow(clippy::unnecessary_wraps)]

    println!("obscura {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}
