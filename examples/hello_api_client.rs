use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use brn::{ConnectionTimeouts, PendingClient, ReadyClient};
use zeroize::Zeroizing;

struct HelloApi {
    connection: ReadyClient,
}

impl HelloApi {
    fn connect(address: SocketAddr, ca: &[u8], credentials: &[u8]) -> io::Result<Self> {
        let timeouts = ConnectionTimeouts::new(
            Duration::from_secs(5),
            Duration::from_secs(3),
            Duration::from_secs(5),
        )?;
        let connection = PendingClient::connect(
            address,
            "localhost",
            &[ca],
            Duration::from_secs(3),
            timeouts,
        )?
        .authenticate(credentials, Duration::from_secs(5))?
        .establish_keys(Duration::from_secs(5))?;
        Ok(Self { connection })
    }

    fn hello(&mut self) -> io::Result<String> {
        self.call(b"hello")
    }

    fn welcome(&mut self, name: &str) -> io::Result<String> {
        self.call(format!("welcome\t{name}").as_bytes())
    }

    fn call(&mut self, request: &[u8]) -> io::Result<String> {
        let response = self.connection.request(request, Duration::from_secs(5))?;
        let response = String::from_utf8(response)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if let Some(value) = response.strip_prefix("OK\t") {
            return Ok(value.to_owned());
        }
        if let Some(message) = response.strip_prefix("ERR\t") {
            // The BRN exchange succeeded; this is an application error.
            return Err(io::Error::other(format!(
                "server rejected request: {message}"
            )));
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid application response",
        ))
    }

    fn close(self) {
        self.connection.close();
    }
}

fn main() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let name = args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: cargo run --example hello_api_client -- <name> [127.0.0.1:9000]",
        )
    })?;
    let address: SocketAddr = args
        .next()
        .unwrap_or_else(|| "127.0.0.1:9000".to_owned())
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let token = Zeroizing::new(
        std::env::var("BRN_DEMO_TOKEN")
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "set BRN_DEMO_TOKEN in both terminals",
                )
            })?
            .into_bytes(),
    );
    let ca = fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("certs/ca.cert.der"))?;
    let mut api = HelloApi::connect(address, &ca, token.as_slice())?;
    drop(token);
    println!("hello() -> {}", api.hello()?);
    println!("welcome({name:?}) -> {}", api.welcome(&name)?);
    api.close();
    Ok(())
}
