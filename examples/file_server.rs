use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use brn::file_download::{DownloadCatalog, is_download_request};
use brn::{
    AuthenticationError, Authenticator, ClientIdentity, ConnectionTimeouts, FileTransferLimits,
    FileTransferService, ReadyServer, Server,
};

const SETUP_BUDGET: Duration = Duration::from_secs(10);
const FILE_OPERATION_BUDGET: Duration = Duration::from_secs(10);
const IDLE_UPLOAD_TIMEOUT: Duration = Duration::from_secs(30 * 60);

const UPLOAD_ROUTE: &[u8] = b"EXAMPLE-UPLOAD-1";
const PUBLISH_PREFIX: &[u8] = b"EXAMPLE-PUBLISH-1";

const DEMO_IDENTITY: &str = "example:file-client";
const DEMO_CREDENTIALS: &[u8] = b"brn-file-example-only";

static NEXT_STAGING_FILE: AtomicU64 = AtomicU64::new(0);

/// Demonstration credentials only. Replace this authenticator before deployment.
struct DemoAuthenticator;

impl Authenticator for DemoAuthenticator {
    fn authenticate(&self, credentials: &[u8]) -> Result<ClientIdentity, AuthenticationError> {
        if credentials != DEMO_CREDENTIALS {
            return Err(AuthenticationError::Rejected);
        }

        ClientIdentity::new(DEMO_IDENTITY).map_err(|_| AuthenticationError::Unavailable)
    }
}

struct Arguments {
    address: SocketAddr,
    certificate: PathBuf,
    private_key: PathBuf,
    upload_directory: PathBuf,
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn arguments() -> io::Result<Arguments> {
    let mut args = env::args_os().skip(1);

    let usage = "usage: file_server \
        <listen-address> <server-cert.der> <server-key.der> \
        <new-upload-directory>";

    let address = args.next().ok_or_else(|| invalid_input(usage))?;
    let certificate = args.next().ok_or_else(|| invalid_input(usage))?;
    let private_key = args.next().ok_or_else(|| invalid_input(usage))?;
    let upload_directory = args.next().ok_or_else(|| invalid_input(usage))?;

    if args.next().is_some() {
        return Err(invalid_input(usage));
    }

    let address = address
        .to_str()
        .ok_or_else(|| invalid_input("listen address must be valid UTF-8"))?
        .parse::<SocketAddr>()
        .map_err(|error| invalid_input(format!("invalid listen address: {error}")))?;

    Ok(Arguments {
        address,
        certificate: PathBuf::from(certificate),
        private_key: PathBuf::from(private_key),
        upload_directory: PathBuf::from(upload_directory),
    })
}

fn authorized(identity: &ClientIdentity) -> bool {
    identity.as_str() == DEMO_IDENTITY
}

fn valid_filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn create_private_directory(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        builder.mode(0o700);
    }

    builder.create(path)
}

fn publication_directory(upload_directory: &Path) -> PathBuf {
    let mut value = upload_directory.as_os_str().to_os_string();
    value.push(".published");
    PathBuf::from(value)
}

fn publish_copy(source: &mut fs::File, directory: &Path, name: &str) -> io::Result<PathBuf> {
    if !valid_filename(name) {
        return Err(invalid_input("invalid publication filename"));
    }

    // Both directories and their parents must remain protected.
    // The completed source must not be modified during this copy.
    let source_metadata = source.metadata()?;

    if !source_metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "completed source is not a regular file",
        ));
    }

    let expected_size = source_metadata.len();
    let number = NEXT_STAGING_FILE.fetch_add(1, Ordering::Relaxed);

    let staging = directory.join(format!(".publish-{}-{number}.part", std::process::id(),));

    let destination = directory.join(name);

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }

    // If creation fails, do not remove a pre-existing staging path.
    let mut output = options.open(&staging).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "creating publication staging file {}: {error}",
                staging.display(),
            ),
        )
    })?;

    let copy_result = (|| -> io::Result<()> {
        let mut copied = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];

        loop {
            let count = match source.read(&mut buffer) {
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(error) => return Err(error),
            };

            if count == 0 {
                break;
            }

            copied = copied
                .checked_add(count as u64)
                .filter(|size| *size <= expected_size)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "completed source grew during publication",
                    )
                })?;

            output.write_all(&buffer[..count])?;
        }

        if copied != expected_size || source.metadata()?.len() != expected_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "completed source changed during publication",
            ));
        }

        output.sync_all()
    })();

    drop(output);

    if let Err(error) = copy_result {
        if let Err(cleanup_error) = fs::remove_file(&staging) {
            eprintln!(
                "Could not clean failed publication staging file {}: {}",
                staging.display(),
                cleanup_error,
            );
        }

        return Err(error);
    }

    // Publish the finished copy without replacing an existing name.
    // Staging and destination are on the same filesystem.
    //
    // No directory synchronization is performed here. This example
    // does not promise crash-durable publication metadata.
    let publish_result = fs::hard_link(&staging, &destination).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "publishing {} -> {}: {error}",
                staging.display(),
                destination.display(),
            ),
        )
    });

    if let Err(error) = fs::remove_file(&staging) {
        eprintln!(
            "Could not remove publication staging file {}: {}",
            staging.display(),
            error,
        );
    }

    publish_result?;

    Ok(destination)
}

fn serve_downloads(
    mut connection: ReadyServer,
    downloads: &mut DownloadCatalog,
    first_request: Vec<u8>,
) -> io::Result<()> {
    let owner = connection.identity().clone();
    let mut request = first_request;

    loop {
        // Authorization and ownership are checked for every request.
        // File reading happens outside the encrypted socket phases.
        let response = match downloads.respond(&owner, &request, authorized) {
            Ok(response) => response,
            Err(error) => {
                eprintln!("Download request rejected: {error}");

                // Do not expose paths or detailed storage errors.
                connection.respond(b"E", FILE_OPERATION_BUDGET)?;
                connection.close();

                return Ok(());
            }
        };

        connection.respond(&response, FILE_OPERATION_BUDGET)?;

        // The client may close or rotate the connection here.
        // Any receive error drops this connection, not the catalog.
        request = connection.receive_request(FILE_OPERATION_BUDGET)?;
    }
}

fn publish_request(
    service: &mut FileTransferService,
    downloads: &mut DownloadCatalog,
    owner: &ClientIdentity,
    request: &[u8],
    published_directory: &Path,
) -> io::Result<PathBuf> {
    let body = request
        .strip_prefix(PUBLISH_PREFIX)
        .ok_or_else(|| invalid_input("invalid publication request"))?;

    // Sixteen ID bytes, followed by 1..=128 filename bytes.
    if !(17..=144).contains(&body.len()) {
        return Err(invalid_input("invalid publication request length"));
    }

    let mut upload_id = [0_u8; 16];
    upload_id.copy_from_slice(&body[..16]);

    let name =
        std::str::from_utf8(&body[16..]).map_err(|_| invalid_input("filename must be UTF-8"))?;

    if !valid_filename(name) {
        return Err(invalid_input("unsupported publication filename"));
    }

    let mut source = service.open_completed(owner, upload_id, authorized)?;

    let published_path = publish_copy(&mut source, published_directory, name)?;

    drop(source);

    // Register a read-only handle to the published copy.
    //
    // Registration hashes the file with a bounded buffer. The application
    // must keep registered contents immutable for their entire lifetime.
    let published_file = fs::File::open(&published_path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "opening published file {}: {error}",
                published_path.display(),
            ),
        )
    })?;

    if let Err(error) = downloads.register(owner.clone(), upload_id, name, published_file) {
        eprintln!(
            "Published file exists at {}, but download registration failed. \
             The private upload is retained. Error: {}",
            published_path.display(),
            error,
        );

        return Err(error);
    }

    // The download catalog now refers to the published copy,
    // independently of the upload registry.
    match service.discard_completed(owner, upload_id, authorized) {
        Ok(()) => {
            eprintln!(
                "Registered download and removed private upload: {}",
                published_path.display(),
            );
        }
        Err(error) => {
            eprintln!(
                "Download registered for {}, but private-upload cleanup \
                 failed: {}. Cleanup needs retry.",
                published_path.display(),
                error,
            );
        }
    }

    Ok(published_path)
}

fn serve_connection(
    mut connection: ReadyServer,
    service: &mut FileTransferService,
    downloads: &mut DownloadCatalog,
    published_directory: &Path,
) -> io::Result<()> {
    let owner = connection.identity().clone();

    if !authorized(&owner) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "example file access is not authorized",
        ));
    }

    let route = connection.receive_request(FILE_OPERATION_BUDGET)?;

    if is_download_request(&route) {
        return serve_downloads(connection, downloads, route);
    }

    if route.as_slice() == UPLOAD_ROUTE {
        connection.respond(b"OK", FILE_OPERATION_BUDGET)?;

        loop {
            connection = service.serve_one(connection, FILE_OPERATION_BUDGET, authorized)?;
        }
    }

    if route.starts_with(PUBLISH_PREFIX) {
        let result = publish_request(service, downloads, &owner, &route, published_directory);

        let response: &[u8] = match &result {
            Ok(path) => {
                println!("Published and registered: {}", path.display());
                b"OK"
            }
            Err(error) => {
                eprintln!("Publication or registration failed: {error}");
                b"ERROR"
            }
        };

        connection.respond(response, FILE_OPERATION_BUDGET)?;
        connection.close();

        return result.map(|_| ());
    }

    connection.respond(b"ERROR", FILE_OPERATION_BUDGET)?;
    connection.close();

    Err(invalid_input("unknown example connection route"))
}

fn maintenance(service: &mut FileTransferService) {
    service.poll_verifications();

    // Runs between connections, not on a background timer.
    match service.cleanup_idle(IDLE_UPLOAD_TIMEOUT, 8) {
        Ok(report) if report.attempted > 0 => {
            eprintln!(
                "Cleanup: removed {}, failed {}, released {} bytes",
                report.removed, report.failed, report.released_bytes,
            );
        }
        Ok(_) => {}
        Err(error) => {
            eprintln!("Upload cleanup failed: {error}");
        }
    }

    eprintln!(
        "Stored uploads: {}; reserved bytes: {}",
        service.upload_count(),
        service.reserved_bytes(),
    );
}

fn main() -> io::Result<()> {
    let args = arguments()?;

    let certificate = fs::read(&args.certificate)?;
    let private_key = zeroize::Zeroizing::new(fs::read(&args.private_key)?);

    let timeouts = ConnectionTimeouts::new(
        Duration::from_secs(10),
        Duration::from_secs(10),
        Duration::from_secs(10),
    )?;

    let server = Server::new(&[certificate.as_slice()], private_key.as_slice(), timeouts)?;

    drop(private_key);

    let listener = TcpListener::bind(args.address)?;

    // Example policy, not BRN protocol limits or validated capacity.
    let limits = FileTransferLimits {
        max_file_size: 10_000_000_000,
        max_reserved_bytes: 20_000_000_000,
        max_uploads: 8,
        max_uploads_per_owner: 8,
    };

    // The upload service still requires a new upload directory.
    //
    // Its parent must be trusted. On non-Unix systems, configure
    // appropriate parent ACLs before running this example.
    let mut service =
        FileTransferService::create(&args.upload_directory, limits).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "creating upload service at {}: {error}",
                    args.upload_directory.display(),
                ),
            )
        })?;

    let published_directory = publication_directory(&args.upload_directory);

    // Create once. An existing directory is accepted, but existing
    // files are not automatically registered in the download catalog.
    match create_private_directory(&published_directory) {
        Ok(()) => {}
        Err(error)
            if error.kind() == io::ErrorKind::AlreadyExists && published_directory.is_dir() => {}
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "creating publication directory {}: {error}",
                    published_directory.display(),
                ),
            ));
        }
    }

    // Application-owned published-file registry.
    //
    // Limits bound registered files and logical bytes, not all physical
    // filesystem usage. This registry is not persisted across restarts.
    let mut downloads = DownloadCatalog::new(128, 20_000_000_000)?;

    let authenticator = DemoAuthenticator;

    println!("Listening on {}", listener.local_addr()?);
    println!("Upload storage: {}", args.upload_directory.display());
    println!("Published storage: {}", published_directory.display());
    println!("Demo authentication only; do not expose this server publicly.");
    println!("Publication creates and registers a separate named copy.");
    println!("Private-upload deletion is attempted after registration.");
    println!("Download registration is in memory only.");
    println!("Published copies are not included in upload reservations.");

    loop {
        let (socket, peer) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                continue;
            }
            Err(error) => return Err(error),
        };

        eprintln!("Connection from {peer}");

        let setup = (|| {
            server
                .accept(socket)?
                .authenticate(&authenticator, SETUP_BUDGET)?
                .establish_keys(SETUP_BUDGET)
        })();

        match setup {
            Ok(connection) => {
                if let Err(error) = serve_connection(
                    connection,
                    &mut service,
                    &mut downloads,
                    &published_directory,
                ) {
                    eprintln!("Connection ended for {peer}: {error}");
                }
            }
            Err(error) => {
                eprintln!("Connection setup failed for {peer}: {error}");
            }
        }

        maintenance(&mut service);
    }
}

#[cfg(test)]
mod tests {
    use super::{publication_directory, valid_filename};
    use std::path::{Path, PathBuf};

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

    #[test]
    fn appends_publication_directory_suffix() {
        assert_eq!(
            publication_directory(Path::new("uploads")),
            PathBuf::from("uploads.published"),
        );

        assert_eq!(
            publication_directory(Path::new("uploads.example")),
            PathBuf::from("uploads.example.published"),
        );
    }
}
