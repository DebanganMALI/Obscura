#![allow(clippy::print_stdout, clippy::expect_used)]

use obscura_platform::hello;

const PROBE_ID: &str = "probe-0000-0000-0000-000000000000";

fn main() {
    println!("Obscura - Windows Hello probe\n");
    println!("credential name: {}", hello::credential_name(PROBE_ID));

    match hello::is_available() {
        Ok(true) => println!("available:       yes"),
        Ok(false) => {
            println!("available:       no");
            println!("\nThis machine has no usable Hello provider. Set up a PIN, fingerprint");
            println!("or face in Windows Settings, then run this again.");
            return;
        }
        Err(e) => {
            println!("available:       error - {e}");
            return;
        }
    }

    println!("\nEnrolling. Windows will prompt twice - the second prompt is the");
    println!("determinism check, and it is the entire point of this probe.\n");

    let enrolled = match hello::enroll(PROBE_ID) {
        Ok(seed) => {
            println!("enrol:           ok");
            seed
        }
        Err(e) => {
            println!("enrol:           FAILED - {e}");
            println!("\nIf that says signatures are not reproducible, hardware unlock cannot");
            println!("work on this machine and Obscura will refuse to offer it. Nothing was");
            println!("written to any vault.");
            return;
        }
    };

    println!("\nNow reproducing the seed the way an unlock would.\n");

    match hello::unlock(PROBE_ID) {
        Ok(again) => {
            let same = again.expose() == enrolled.expose();
            println!("unlock:          ok");
            println!("\nseeds match:     {}", if same { "YES" } else { "NO" });
            if same {
                println!("\nHardware unlock will work on this machine.");
            } else {
                println!("\nThe seed changed between enrolment and unlock. Hardware unlock");
                println!("cannot work here - please send me this output.");
            }
        }
        Err(e) => println!("unlock:          FAILED - {e}"),
    }

    match hello::forget(PROBE_ID) {
        Ok(()) => println!("\ncleanup:         probe credential removed"),
        Err(e) => println!("\ncleanup:         could not remove probe credential - {e}"),
    }
}
