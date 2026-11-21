use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use brn::{
    ConnectionTimeouts, FileUploadConnection, FileUploadRotation, FileUploadSource,
    FileUploadStatus, PendingClient, ReadyClient,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const SETUP_BUDGET: Duration = Duration::from_secs(10);
const OPERATION_BUDGET: Duration = Duration::from_secs(10);
const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const POLL_INTERVAL: Duration = Duration::from_millis(250);

// Example policy, matching the server example.
// This is not a claim that 10 GB transfers have been validated.
const MAX_FILE_SIZE: u64 = 10_000_000_000;

const UPLOAD_ROUTE: &[u8] = b"EXAMPLE-UPLOAD-1";
const PUBLISH_PREFIX: &[u8] = b"EXAMPLE-PUBLISH-1";

// Must match DemoAuthenticator in file_server.rs.
// These are public demonstration credentials, not a deployment secret.
const DEMO_CREDENTIALS: &[u8] = b"brn-file-example-only";

struct Arguments {
    address: SocketAddr,
    server_name: String,
    ca_certificate: PathBuf,
    source: PathBuf,
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn arguments() -> io::Result<Arguments> {
    let mut args = env::args_os().skip(1);

    let usage = "usage: file_client upload \
        <server-address> <server-name> <ca-cert.der> <local-file>";

    let command = args.next().ok_or_else(|| invalid_input(usage))?;

    if command != "upload" {
        return Err(invalid_input(usage));
    }

    let address = args.next().ok_or_else(|| invalid_input(usage))?;
    let server_name = args.next().ok_or_else(|| invalid_input(usage))?;
    let ca_certificate = args.next().ok_or_else(|| invalid_input(usage))?;
    let source = args.next().ok_or_else(|| invalid_input(usage))?;

    if args.next().is_some() {
        return Err(invalid_input(usage));
    }

    let address = address
        .to_str()
        .ok_or_else(|| invalid_input("server address must be valid UTF-8"))?
        .parse::<SocketAddr>()
        .map_err(|error| invalid_input(format!("invalid server address: {error}")))?;

    let server_name = server_name
        .into_string()
        .map_err(|_| invalid_input("server name must be valid UTF-8"))?;

    Ok(Arguments {
        address,
        server_name,
        ca_certificate: PathBuf::from(ca_certificate),
        source: PathBuf::from(source),
    })
}

fn valid_filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn connect_raw(
    address: SocketAddr,
    server_name: &str,
    trusted_ca_der: &[u8],
) -> io::Result<ReadyClient> {
    let timeouts = ConnectionTimeouts::new(
        Duration::from_secs(10),
        Duration::from_secs(10),
        Duration::from_secs(10),
    )?;

    PendingClient::connect(
        address,
        server_name,
        &[trusted_ca_der],
        CONNECT_TIMEOUT,
        timeouts,
    )?
    .authenticate(DEMO_CREDENTIALS, SETUP_BUDGET)?
    .establish_keys(SETUP_BUDGET)
}

fn connect_upload(
    address: SocketAddr,
    server_name: &str,
    trusted_ca_der: &[u8],
) -> io::Result<ReadyClient> {
    let mut connection = connect_raw(address, server_name, trusted_ca_der)?;

    let response = connection.request(UPLOAD_ROUTE, OPERATION_BUDGET)?;

    if response.as_slice() != b"OK" {
        connection.close();

        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "server rejected upload routing handshake",
        ));
    }

    Ok(connection)
}

fn request_publication(
    address: SocketAddr,
    server_name: &str,
    trusted_ca_der: &[u8],
    upload_id: [u8; 16],
    filename: &str,
) -> io::Result<()> {
    if !valid_filename(filename) {
        return Err(invalid_input("invalid publication filename"));
    }

    let mut connection = connect_raw(address, server_name, trusted_ca_der)?;

    let mut request = Vec::with_capacity(PUBLISH_PREFIX.len() + upload_id.len() + filename.len());

    request.extend_from_slice(PUBLISH_PREFIX);
    request.extend_from_slice(&upload_id);
    request.extend_from_slice(filename.as_bytes());

    let result = connection.request(&request, OPERATION_BUDGET);
    connection.close();

    let response = match result {
        Ok(response) => response,
        Err(error) => {
            eprintln!(
                "Publication response was not confirmed. The named file \
                 may already exist on the server."
            );
            eprintln!(
                "Inspect the server output before retrying; this example \
                 does not implement publication-status queries."
            );

            return Err(error);
        }
    };

    match response.as_slice() {
        b"OK" => Ok(()),
        b"ERROR" => Err(io::Error::other(
            "upload was verified, but publication failed; inspect the server log",
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected publication response; inspect the server before retrying",
        )),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        // Writing to String is infallible.
        write!(&mut output, "{byte:02x}").expect("writing to String failed");
    }

    output
}

fn main() -> io::Result<()> {
    let args = arguments()?;

    let filename = args
        .source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid_input("source must have a UTF-8 filename"))?
        .to_owned();

    if !valid_filename(&filename) {
        return Err(invalid_input(
            "filename must contain 1..=128 ASCII letters, digits, dots, \
             underscores or hyphens, and must not start with a dot",
        ));
    }

    let trusted_ca_der = fs::read(&args.ca_certificate)?;

    println!("Hashing {}", args.source.display());
    println!("Original filename: {filename}");

    // The source retains a reusable chunk buffer, not the whole file.
    // Keep the source unchanged until the upload finishes.
    let mut source = FileUploadSource::open(&args.source, MAX_FILE_SIZE)?;

    println!("Size: {} bytes", source.size());
    println!("SHA-256: {}", hex(source.sha256()));

    let mut connections = 0_u64;

    let connector = || -> io::Result<ReadyClient> {
        let connection = connect_upload(args.address, &args.server_name, &trusted_ca_der)?;

        connections += 1;
        eprintln!("Established authenticated upload connection {connections}");

        Ok(connection)
    };

    let mut transfer = FileUploadConnection::new(connector, FileUploadRotation::default())?;

    let upload = transfer.begin(&source, OPERATION_BUDGET)?;

    println!("Upload ID: {}", hex(&upload.upload_id()));

    // This example does not persist a checkpoint file or implement
    // cross-process resume.
    println!("Checkpoint size: {}", upload.size());
    println!("Checkpoint SHA-256: {}", hex(upload.sha256()));

    let started = Instant::now();
    let mut last_report = Instant::now();
    let mut offset = 0_u64;
    let mut chunks = 0_u64;

    while offset < source.size() {
        offset = match transfer.send_next(&mut source, &upload, offset, OPERATION_BUDGET) {
            Ok(next_offset) => next_offset,
            Err(error) => {
                eprintln!("Upload stopped after {offset} previously acknowledged bytes.");
                eprintln!("The failed chunk may already have been accepted.");
                eprintln!(
                    "Query this upload's status on a fresh authenticated \
                     connection before resuming."
                );

                return Err(error);
            }
        };

        chunks += 1;

        if last_report.elapsed() >= Duration::from_secs(1) || offset == source.size() {
            let elapsed = started.elapsed().as_secs_f64();
            let mib_per_second = offset as f64 / (1024.0 * 1024.0) / elapsed.max(f64::EPSILON);

            println!(
                "{offset}/{} bytes, {chunks} chunks, \
                 {mib_per_second:.2} MiB/s average",
                source.size(),
            );

            last_report = Instant::now();
        }
    }

    println!("All bytes acknowledged; requesting server verification");

    let verification_started = Instant::now();
    let mut status = transfer.finish(&upload, OPERATION_BUDGET)?;

    loop {
        match status {
            FileUploadStatus::Complete => break,
            FileUploadStatus::Verifying => {
                if verification_started.elapsed() >= VERIFICATION_TIMEOUT {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "stopped waiting for verification; \
                         this does not cancel the server upload",
                    ));
                }

                thread::sleep(POLL_INTERVAL);
                status = transfer.status(&upload, OPERATION_BUDGET)?;
            }
            FileUploadStatus::Receiving { confirmed_offset } => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "server unexpectedly reported Receiving at \
                         offset {confirmed_offset} during verification"
                    ),
                ));
            }
        }
    }

    transfer.close();

    println!(
        "Server verified upload {}: {} bytes, {chunks} chunks, {:?}",
        hex(&upload.upload_id()),
        upload.size(),
        started.elapsed(),
    );

    println!("Requesting publication as {filename}");

    request_publication(
        args.address,
        &args.server_name,
        &trusted_ca_der,
        upload.upload_id(),
        &filename,
    )?;

    println!("Published as {filename}");
    println!(
        "Server attempts private-upload cleanup after publication; \
         check its log for cleanup failures."
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::valid_filename;

    #[test]
    fn accepts_example_filenames() {
        for name in ["james.mp4", "file.bin", "my-video_01.mp4"] {
            assert!(valid_filename(name));
        }
    }

    #[test]
    fn rejects_paths_and_unsupported_names() {
        for name in [
            "",
            ".",
            "..",
            ".hidden",
            "../james.mp4",
            "folder/james.mp4",
            r"folder\james.mp4",
            "james video.mp4",
            "name:stream",
        ] {
            assert!(!valid_filename(name));
        }

        assert!(!valid_filename(&"a".repeat(129)));
    }
}
