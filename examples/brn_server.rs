use std::fs;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::Duration;

use brn::{AuthenticationError, Authenticator, ClientIdentity, ConnectionTimeouts, Server};

const ADDRESS: &str = "127.0.0.1:7443";

// Development demonstration only.
// Do not use this fixed credential or verifier in production.
const DEMO_CREDENTIAL: &[u8] = b"brn-local-demo-only";

struct DemoAuthenticator;

impl Authenticator for DemoAuthenticator {
    fn authenticate(&self, credentials: &[u8]) -> Result<ClientIdentity, AuthenticationError> {
        if credentials != DEMO_CREDENTIAL {
            // Coarse fail-closed result for this demonstration.
            // A production verifier should use the appropriate
            // authentication errors and credential-verification logic.
            return Err(AuthenticationError::Unavailable);
        }

        ClientIdentity::new("local-demo-client").map_err(|_| AuthenticationError::Unavailable)
    }
}

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

fn handle_connection(server: &Server, socket: TcpStream) -> io::Result<()> {
    println!("  Performing TLS and BRN negotiation...");

    let pending = server.accept(socket)?;

    println!("  Authenticating client...");

    let authenticated = pending.authenticate(&DemoAuthenticator, Duration::from_secs(5))?;

    println!(
        "  Authenticated identity: {}",
        authenticated.identity().as_str()
    );

    println!("  Establishing application keys...");

    let mut ready = authenticated.establish_keys(Duration::from_secs(5))?;

    println!("  Ready for encrypted application messages.");

    let result = (|| -> io::Result<()> {
        let mut message_number = 0usize;

        loop {
            let request = ready.receive_request(Duration::from_secs(30))?;

            message_number += 1;

            println!(
                "  Request #{message_number}: {} application bytes",
                request.len()
            );

            // Echo the authenticated application payload.
            ready.respond(&request, Duration::from_secs(5))?;

            println!("  Response #{message_number} sent.");

            // Demo application convention, not a BRN control message.
            if request.as_slice() == b"quit" {
                println!("  Demo exchange completed.");
                break;
            }
        }

        Ok(())
    })();

    ready.close();

    result
}

fn main() -> io::Result<()> {
    let certificate = development_file("server.cert.der")?;
    let private_key = development_file("server.key.der")?;

    let timeouts = ConnectionTimeouts::new(
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(30),
    )?;

    let server = Server::new(&[certificate.as_slice()], &private_key, timeouts)?;

    let listener = TcpListener::bind(ADDRESS)?;

    println!("BRN development echo server");
    println!("Listening on {ADDRESS}");
    println!("Local demonstration only; development credentials.");
    println!("Press Ctrl+C to stop.");
    println!();

    loop {
        let (socket, peer) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                continue;
            }
            Err(error) => return Err(error),
        };

        println!("Connection from {peer}");

        match handle_connection(&server, socket) {
            Ok(()) => println!("Connection finished successfully."),
            Err(error) => {
                eprintln!("Connection ended with {:?}: {error}", error.kind());
            }
        }

        println!("Waiting for another client...");
        println!();
    }
}
