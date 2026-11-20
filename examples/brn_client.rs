use std::fs;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use brn::{ConnectionTimeouts, PendingClient};

const ADDRESS: &str = "127.0.0.1:7443";
const EXPECTED_SERVER_NAME: &str = "localhost";

// Development demonstration only.
const DEMO_CREDENTIAL: &[u8] = b"brn-local-demo-only";

fn development_file(name: &str) -> io::Result<Vec<u8>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("certs")
        .join(name);

    fs::read(&path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot read {}: {error}", path.display()),
        )
    })
}

fn main() -> io::Result<()> {
    let ca = development_file("ca.cert.der")?;

    let address: SocketAddr = ADDRESS
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

    let timeouts = ConnectionTimeouts::new(
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )?;

    println!("BRN interactive development client");
    println!("Connecting to {address}...");

    let pending = PendingClient::connect(
        address,
        EXPECTED_SERVER_NAME,
        &[ca.as_slice()],
        Duration::from_secs(5),
        timeouts,
    )?;

    println!("TLS and BRN negotiation completed.");

    let authenticated = pending.authenticate(DEMO_CREDENTIAL, Duration::from_secs(5))?;

    println!("Application authentication completed.");

    let mut ready = authenticated.establish_keys(Duration::from_secs(5))?;

    println!("Application keys confirmed.");
    println!();
    println!("Type a message and press Enter.");
    println!("An empty line sends an empty application message.");
    println!("Type quit to end the demonstration.");
    println!("The demo server closes idle connections after about 30 seconds.");
    println!();

    let result = (|| -> io::Result<()> {
        let stdin = io::stdin();
        let mut line = String::new();
        let mut completed = 0usize;

        loop {
            print!("brn> ");
            io::stdout().flush()?;

            line.clear();

            if stdin.read_line(&mut line)? == 0 {
                println!();
                println!("Input closed.");
                break;
            }

            // Remove terminal line endings without stripping spaces
            // from the actual application message.
            while line.ends_with('\n') || line.ends_with('\r') {
                line.pop();
            }

            let started = Instant::now();

            let response = ready.request(line.as_bytes(), Duration::from_secs(5))?;

            let elapsed = started.elapsed();

            if response.as_slice() != line.as_bytes() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "echo response did not match the request",
                ));
            }

            completed += 1;

            println!("server: {}", String::from_utf8_lossy(&response));

            println!(
                "Verified {} bytes | {:.2} ms | exchange #{}",
                response.len(),
                elapsed.as_secs_f64() * 1000.0,
                completed
            );

            println!();

            if line == "quit" {
                break;
            }
        }

        Ok(())
    })();

    ready.close();

    match result {
        Ok(()) => {
            println!("Client closed.");
            Ok(())
        }
        Err(error) => {
            eprintln!("Exchange failed with {:?}: {error}", error.kind());

            eprintln!("This connection is closed. Restart the client to reconnect.");

            Err(error)
        }
    }
}
