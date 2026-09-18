#[cfg(target_os = "windows")]
#[allow(clippy::print_stdout)]
fn main() {
    const RP_ID: &str = "spike.obscura.invalid";
    const SALT: [u8; 32] = [0x5a; 32];

    println!("Obscura - passkey PRF probe\n");
    println!("WebAuthn API version: {}", obscura_webauthn::api_version());

    let hwnd = obscura_webauthn::console_window();

    println!("\nCreating a passkey. Windows will offer a list of places to save it -");
    println!("choose the phone option and scan the QR code with your handset.\n");

    let enrolled = match obscura_webauthn::enroll(
        hwnd,
        RP_ID,
        "Obscura spike",
        "spike",
        b"obscura-spike-user",
    ) {
        Ok(enrolled) => enrolled,
        Err(error) => {
            println!("enrol:           FAILED - {error}");
            return;
        }
    };

    println!("enrol:           ok");
    println!("credential id:   {} bytes", enrolled.credential_id.len());
    println!("prf enabled:     {}", enrolled.prf_enabled);
    println!(
        "transport:       {}",
        obscura_webauthn::transport_name(enrolled.transport)
    );

    if !enrolled.prf_enabled {
        println!("\nThis authenticator did not enable PRF, so it cannot hold an Obscura slot.");
        println!("The passkey itself works - it just cannot produce a reproducible secret.");
        return;
    }

    println!("\nAsking for the same salt twice. Expect two prompts on the phone.\n");

    let first = match obscura_webauthn::prf_secret(hwnd, RP_ID, &SALT) {
        Ok(secret) => secret,
        Err(error) => {
            println!("first secret:    FAILED - {error}");
            return;
        }
    };
    println!("first secret:    ok");

    let second = match obscura_webauthn::prf_secret(hwnd, RP_ID, &SALT) {
        Ok(secret) => secret,
        Err(error) => {
            println!("second secret:   FAILED - {error}");
            return;
        }
    };
    println!("second secret:   ok");

    let same = first == second;
    println!("\nsecrets match:   {}", if same { "YES" } else { "NO" });

    if same {
        println!("\nA passkey on this phone can hold an Obscura slot.");
    } else {
        println!("\nThe secret changed between calls, so a passkey slot cannot work here.");
    }

    println!("\nDelete the 'spike.obscura.invalid' passkey from your phone when you are done.");
}

#[cfg(not(target_os = "windows"))]
fn main() {}
