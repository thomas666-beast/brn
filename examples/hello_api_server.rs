use std::fs;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::time::Duration;

use brn::{AuthenticationError, Authenticator, ClientIdentity, ConnectionTimeouts, Server};
use zeroize::Zeroizing;

const OPERATION_BUDGET: Duration = Duration::from_secs(30);
const MAX_NAME_BYTES: usize = 256;

// Demonstration only: this shared-token equality check is not a production
// credential-verification system. Do not reuse the sample token in production.
struct DemoAuthenticator {
    token: Zeroizing<Vec<u8>>,
}

impl Authenticator for DemoAuthenticator {
    fn authenticate(&self, credentials: &[u8]) -> Result<ClientIdentity, AuthenticationError> {
        if credentials != self.token.as_slice() {
            return Err(AuthenticationError::Rejected);
        }
        ClientIdentity::new("hello-api-demo-client").map_err(|_| AuthenticationError::Unavailable)
    }
}

fn hello() -> &'static str {
    "Hello from BRN!"
}

fn welcome(name: &str) -> Result<String, &'static str> {
    if name.len() > MAX_NAME_BYTES || name.chars().any(char::is_control) {
        return Err("name must be at most 256 bytes and contain no control characters");
    }
    let name = name.trim();
    if name.is_empty() {
        return Err("name must not be empty");
    }
    Ok(format!("Welcome, {name}!"))
}

fn dispatch(request: &[u8]) -> Vec<u8> {
    let request = match std::str::from_utf8(request) {
        Ok(request) => request,
        Err(_) => return b"ERR\trequest must be UTF-8".to_vec(),
    };
    let result = if request == "hello" {
        Ok(hello().to_owned())
    } else if let Some(name) = request.strip_prefix("welcome\t") {
        welcome(name)
    } else {
        Err("unknown method; use hello or welcome followed by a tab and a name")
    };
    match result {
        Ok(value) => format!("OK\t{value}").into_bytes(),
        Err(message) => format!("ERR\t{message}").into_bytes(),
    }
}

fn read_fixture(name: &str) -> io::Result<Vec<u8>> {
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join(name),
    )
}

fn handle_connection(
    server: &Server,
    socket: TcpStream,
    authenticator: &DemoAuthenticator,
) -> io::Result<()> {
    let mut connection = server
        .accept(socket)?
        .authenticate(authenticator, Duration::from_secs(5))?
        .establish_keys(Duration::from_secs(5))?;
    loop {
        let request = match connection.receive_request(OPERATION_BUDGET) {
            Ok(request) => request,
            Err(error) => {
                // Includes normal peer closure; BRN releases this session.
                eprintln!("Connection ended: {error}");
                break;
            }
        };
        let response = dispatch(&request);
        connection.respond(&response, OPERATION_BUDGET)?;
    }
    connection.close();
    Ok(())
}

fn main() -> io::Result<()> {
    let address: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9000".to_owned())
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let token = std::env::var("BRN_DEMO_TOKEN").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "set BRN_DEMO_TOKEN in both terminals",
        )
    })?;
    if token.is_empty() || token.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "BRN_DEMO_TOKEN must contain 1..=4096 bytes",
        ));
    }
    let authenticator = DemoAuthenticator {
        token: Zeroizing::new(token.into_bytes()),
    };
    let certificate = read_fixture("server.cert.der")?;
    let key = Zeroizing::new(read_fixture("server.key.der")?);
    let timeouts = ConnectionTimeouts::new(
        Duration::from_secs(5),
        Duration::from_secs(3),
        Duration::from_secs(5),
    )?;
    let server = Server::new(&[certificate.as_slice()], key.as_slice(), timeouts)?;
    let listener = TcpListener::bind(address)?;
    println!("BRN hello API listening on {}", listener.local_addr()?);
    println!("Methods: hello(), welcome(name). One connection is handled at a time.");
    for socket in listener.incoming() {
        match socket {
            Ok(socket) => {
                if let Err(error) = handle_connection(&server, socket, &authenticator) {
                    eprintln!("Connection failed: {error}");
                }
            }
            Err(error) => eprintln!("Accept failed: {error}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_and_welcome_dispatch_correctly() {
        assert_eq!(dispatch(b"hello"), b"OK\tHello from BRN!");
        assert_eq!(dispatch(b"welcome\tAlice"), b"OK\tWelcome, Alice!");
    }

    #[test]
    fn invalid_requests_return_application_errors() {
        for request in [
            b"unknown".as_slice(),
            b"welcome\t",
            b"welcome\tAlice\n",
            &[0xff],
        ] {
            assert!(dispatch(request).starts_with(b"ERR\t"));
        }
    }

    #[test]
    fn name_length_boundary_is_enforced() {
        assert!(welcome(&"x".repeat(MAX_NAME_BYTES)).is_ok());
        assert!(welcome(&"x".repeat(MAX_NAME_BYTES + 1)).is_err());
    }
}
