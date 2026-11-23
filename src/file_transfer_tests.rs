use std::fs;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::{
    AuthenticationError, Authenticator, ClientIdentity, ConnectionTimeouts, FileTransferLimits,
    FileTransferService, FileUploadSource, FileUploadStatus, MAX_FILE_CHUNK_LEN, PendingClient,
    ReadyClient, Server,
};

const OPERATION_BUDGET: Duration = Duration::from_secs(5);
const ACCEPT_BUDGET: Duration = Duration::from_secs(10);
const VERIFICATION_BUDGET: Duration = Duration::from_secs(10);

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> io::Result<Self> {
        loop {
            let number = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("brn-file-loopback-{}-{number}", std::process::id()));

            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn new_in(root: &Path) -> io::Result<Self> {
        loop {
            let number = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = root.join(format!("brn-file-large-{}-{number}", std::process::id()));

            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn source(&self) -> PathBuf {
        self.path.join("source.bin")
    }

    fn uploads(&self) -> PathBuf {
        self.path.join("uploads")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

// Test double only. Not a production credential verifier.
struct TestAuthenticator;

impl Authenticator for TestAuthenticator {
    fn authenticate(&self, credentials: &[u8]) -> Result<ClientIdentity, AuthenticationError> {
        if credentials != b"file-transfer-loopback-test" {
            return Err(AuthenticationError::Rejected);
        }

        ClientIdentity::new("file-loopback-client").map_err(|_| AuthenticationError::Unavailable)
    }
}

fn fixture(name: &str) -> io::Result<Vec<u8>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("certs")
        .join(name);

    fs::read(&path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot read fixture {}: {error}", path.display()),
        )
    })
}

fn connection_timeouts() -> io::Result<ConnectionTimeouts> {
    ConnectionTimeouts::new(
        Duration::from_secs(5),
        Duration::from_secs(3),
        Duration::from_secs(2),
    )
}

fn accept_with_timeout(listener: &TcpListener) -> io::Result<TcpStream> {
    listener.set_nonblocking(true)?;
    let started = Instant::now();

    loop {
        if started.elapsed() >= ACCEPT_BUDGET {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "file-transfer test timed out accepting connection",
            ));
        }

        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_nonblocking(false)?;
                return Ok(socket);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn connect(
    address: SocketAddr,
    ca: &[u8],
    timeouts: ConnectionTimeouts,
) -> io::Result<ReadyClient> {
    PendingClient::connect(
        address,
        "localhost",
        &[ca],
        Duration::from_secs(2),
        timeouts,
    )?
    .authenticate(b"file-transfer-loopback-test", OPERATION_BUDGET)?
    .establish_keys(OPERATION_BUDGET)
}

fn connect_upload_case(
    address: SocketAddr,
    ca: &[u8],
    timeouts: ConnectionTimeouts,
    padded: bool,
) -> io::Result<ReadyClient> {
    if !padded {
        return connect(address, ca, timeouts);
    }

    PendingClient::connect_with_padding(
        address,
        "localhost",
        &[ca],
        Duration::from_secs(2),
        timeouts,
        crate::api::PaddingPolicy::Required,
    )?
    .authenticate(b"file-transfer-loopback-test", OPERATION_BUDGET)?
    .establish_keys(OPERATION_BUDGET)
}

fn ensure(condition: bool, message: &'static str) -> io::Result<()> {
    if !condition {
        return Err(io::Error::other(message));
    }

    Ok(())
}

fn stored_path(root: &Path, upload_id: [u8; 16]) -> PathBuf {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut name = String::with_capacity(37);

    for byte in upload_id {
        name.push(HEX[(byte >> 4) as usize] as char);
        name.push(HEX[(byte & 0x0f) as usize] as char);
    }

    name.push_str(".part");
    root.join(name)
}

fn run_upload_case(reconnect: bool) -> io::Result<()> {
    run_upload_case_with_padding(reconnect, false)
}

fn run_upload_case_with_padding(reconnect: bool, padded: bool) -> io::Result<()> {
    let directory = TestDirectory::new()?;

    let length = MAX_FILE_CHUNK_LEN
        .checked_mul(2)
        .and_then(|length| length.checked_add(17))
        .ok_or_else(|| io::Error::other("test payload size overflow"))?;

    let payload: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();

    fs::write(directory.source(), &payload)?;

    let ca = fixture("ca.cert.der")?;
    let certificate = fixture("server.cert.der")?;
    let private_key = fixture("server.key.der")?;
    let timeouts = connection_timeouts()?;

    let server = Server::new(&[certificate.as_slice()], &private_key, timeouts)?;

    let server = if padded {
        server.with_padding(crate::api::PaddingPolicy::Required)
    } else {
        server
    };

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;

    let expected_size = payload.len() as u64;

    let limits = FileTransferLimits {
        max_file_size: expected_size,
        max_reserved_bytes: expected_size,
        max_uploads: 1,
        max_uploads_per_owner: 1,
    };

    let uploads = directory.uploads();
    let mut service = FileTransferService::create(&uploads, limits)?;
    let connection_count = if reconnect { 2 } else { 1 };

    let server_thread = thread::spawn(move || -> io::Result<(usize, u64)> {
        for _ in 0..connection_count {
            let socket = accept_with_timeout(&listener)?;

            let mut connection = server
                .accept(socket)?
                .authenticate(&TestAuthenticator, OPERATION_BUDGET)?
                .establish_keys(OPERATION_BUDGET)?;

            loop {
                match service.serve_one(connection, OPERATION_BUDGET, |identity| {
                    identity.as_str() == "file-loopback-client"
                }) {
                    Ok(next) => connection = next,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::UnexpectedEof
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::ConnectionAborted
                                | io::ErrorKind::BrokenPipe
                        ) =>
                    {
                        // Tests deliberately close connections without
                        // a graceful TLS shutdown.
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
        }

        service.poll_verifications();

        Ok((service.upload_count(), service.reserved_bytes()))
    });

    // Retain the result so the server thread is joined even when a
    // client-side operation returns an error.
    let client_result = (|| -> io::Result<[u8; 16]> {
        let mut source = FileUploadSource::open(directory.source(), expected_size)?;

        let connection = connect_upload_case(address, &ca, timeouts, padded)?;

        let (mut connection, upload) = source.begin(connection, OPERATION_BUDGET)?;

        let (next, mut offset) = source.send_next(&upload, connection, 0, OPERATION_BUDGET)?;
        connection = next;

        let expected_first_chunk = if padded {
            61_406_u64
        } else {
            MAX_FILE_CHUNK_LEN as u64
        };

        ensure(
            offset == expected_first_chunk,
            "first chunk acknowledgement had an unexpected offset",
        )?;

        if reconnect {
            // Simulate an interrupted connection after an acknowledged
            // chunk. The upload service remains alive on the server.
            connection.close();

            let fresh = connect_upload_case(address, &ca, timeouts, padded)?;

            let (next, status) = upload.status(fresh, OPERATION_BUDGET)?;
            connection = next;

            match status {
                FileUploadStatus::Receiving { confirmed_offset } => {
                    ensure(
                        confirmed_offset == offset,
                        "resumed upload reported an unexpected offset",
                    )?;
                    offset = confirmed_offset;
                }
                _ => {
                    return Err(io::Error::other(
                        "resumed upload was not in Receiving state",
                    ));
                }
            }
        }

        while offset < source.size() {
            (connection, offset) =
                source.send_next(&upload, connection, offset, OPERATION_BUDGET)?;
        }

        ensure(
            offset == source.size(),
            "final acknowledged offset did not match source size",
        )?;

        let (next, mut status) = upload.finish(connection, OPERATION_BUDGET)?;
        connection = next;

        let started = Instant::now();

        loop {
            match status {
                FileUploadStatus::Complete => break,
                FileUploadStatus::Verifying => {
                    if started.elapsed() >= VERIFICATION_BUDGET {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "upload verification test timed out",
                        ));
                    }

                    thread::sleep(Duration::from_millis(2));

                    (connection, status) = upload.status(connection, OPERATION_BUDGET)?;
                }
                FileUploadStatus::Receiving { .. } => {
                    return Err(io::Error::other(
                        "upload returned to Receiving after Finish",
                    ));
                }
            }
        }

        let id = upload.upload_id();
        connection.close();

        Ok(id)
    })();

    let server_result = server_thread
        .join()
        .map_err(|_| io::Error::other("file-transfer test server panicked"))?;

    let upload_id = client_result?;
    let (count, reserved) = server_result?;

    ensure(count == 1, "server retained an unexpected upload count")?;
    ensure(
        reserved == expected_size,
        "server retained an unexpected byte reservation",
    )?;

    let actual = fs::read(stored_path(&directory.uploads(), upload_id))?;

    ensure(
        actual == payload,
        "stored file contents differ from the original",
    )?;

    Ok(())
}

#[test]
fn public_file_upload_completes_over_tls() -> io::Result<()> {
    run_upload_case(false)
}

#[test]
fn public_file_upload_resumes_over_fresh_authenticated_connection() -> io::Result<()> {
    run_upload_case(true)
}

fn finish_and_wait(
    mut connection: ReadyClient,
    upload: &crate::FileUpload,
) -> io::Result<ReadyClient> {
    let (next, mut status) = upload.finish(connection, OPERATION_BUDGET)?;
    connection = next;

    let started = Instant::now();

    loop {
        match status {
            FileUploadStatus::Complete => return Ok(connection),
            FileUploadStatus::Verifying => {
                if started.elapsed() >= VERIFICATION_BUDGET {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "upload verification test timed out",
                    ));
                }

                thread::sleep(Duration::from_millis(2));

                (connection, status) = upload.status(connection, OPERATION_BUDGET)?;
            }
            FileUploadStatus::Receiving { .. } => {
                return Err(io::Error::other(
                    "upload returned to Receiving after Finish",
                ));
            }
        }
    }
}

#[test]
fn public_file_upload_recovers_after_lost_chunk_acknowledgement() -> io::Result<()> {
    run_lost_chunk_ack_case(false)
}

#[test]
fn padded_file_upload_recovers_after_lost_chunk_acknowledgement() -> io::Result<()> {
    run_lost_chunk_ack_case(true)
}

fn run_lost_chunk_ack_case(padded: bool) -> io::Result<()> {
    use crate::file_wire::{UploadRequest, UploadResponse};

    let expected_chunk_len: usize = if padded { 61_406 } else { MAX_FILE_CHUNK_LEN };

    let directory = TestDirectory::new()?;

    let length = MAX_FILE_CHUNK_LEN
        .checked_add(17)
        .ok_or_else(|| io::Error::other("test payload size overflow"))?;

    let payload: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();

    fs::write(directory.source(), &payload)?;

    let ca = fixture("ca.cert.der")?;
    let certificate = fixture("server.cert.der")?;
    let private_key = fixture("server.key.der")?;
    let timeouts = connection_timeouts()?;

    let server = Server::new(&[certificate.as_slice()], &private_key, timeouts)?;

    let server = if padded {
        server.with_padding(crate::api::PaddingPolicy::Required)
    } else {
        server
    };

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let expected_size = payload.len() as u64;

    let mut service = FileTransferService::create(
        directory.uploads(),
        FileTransferLimits {
            max_file_size: expected_size,
            max_reserved_bytes: expected_size,
            max_uploads: 1,
            max_uploads_per_owner: 1,
        },
    )?;

    let server_thread = thread::spawn(move || -> io::Result<(usize, u64)> {
        // First authenticated connection.
        let socket = accept_with_timeout(&listener)?;

        let connection = server
            .accept(socket)?
            .authenticate(&TestAuthenticator, OPERATION_BUDGET)?
            .establish_keys(OPERATION_BUDGET)?;

        // Process Begin and return its acknowledgement normally.
        let mut connection = service.serve_one(connection, OPERATION_BUDGET, |identity| {
            identity.as_str() == "file-loopback-client"
        })?;

        // Receive the first chunk, but control response transmission
        // separately so the acknowledgement can be deliberately lost.
        let request = connection.receive_request(OPERATION_BUDGET)?;

        let id = match UploadRequest::decode(&request)? {
            UploadRequest::Chunk {
                id,
                offset: 0,
                bytes,
            } if bytes.len() == expected_chunk_len => id,
            _ => {
                return Err(io::Error::other("expected the first full upload chunk"));
            }
        };

        let owner = connection.identity().clone();

        let encoded_response = service.process_request_for_test(&owner, &request)?;

        match UploadResponse::decode(&encoded_response)? {
            UploadResponse::Progress {
                id: returned_id,
                offset,
            } if returned_id == id && offset == expected_chunk_len as u64 => {}
            _ => {
                return Err(io::Error::other(
                    "server did not confirm storage of the first chunk",
                ));
            }
        }

        // The chunk is stored and its offset committed, but respond()
        // is deliberately never called.
        drop(encoded_response);
        connection.close();

        // Resume on a fresh authenticated connection.
        let socket = accept_with_timeout(&listener)?;

        let mut connection = server
            .accept(socket)?
            .authenticate(&TestAuthenticator, OPERATION_BUDGET)?
            .establish_keys(OPERATION_BUDGET)?;

        loop {
            match service.serve_one(connection, OPERATION_BUDGET, |identity| {
                identity.as_str() == "file-loopback-client"
            }) {
                Ok(next) => connection = next,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::BrokenPipe
                    ) =>
                {
                    break;
                }
                Err(error) => return Err(error),
            }
        }

        Ok((service.upload_count(), service.reserved_bytes()))
    });

    let client_result = (|| -> io::Result<[u8; 16]> {
        let mut source = FileUploadSource::open(directory.source(), expected_size)?;

        let connection = connect_upload_case(address, &ca, timeouts, padded)?;

        let (connection, upload) = source.begin(connection, OPERATION_BUDGET)?;

        // The server stores this chunk, then closes without replying.
        match source.send_next(&upload, connection, 0, OPERATION_BUDGET) {
            Err(_) => {
                // Expected: the client cannot know whether storage
                // succeeded from this failed exchange alone.
            }
            Ok((connection, _)) => {
                connection.close();

                return Err(io::Error::other(
                    "chunk unexpectedly received an acknowledgement",
                ));
            }
        }

        let connection = connect_upload_case(address, &ca, timeouts, padded)?;

        let (mut connection, status) = upload.status(connection, OPERATION_BUDGET)?;

        let mut offset = match status {
            FileUploadStatus::Receiving { confirmed_offset } => {
                ensure(
                    confirmed_offset == expected_chunk_len as u64,
                    "lost-ack recovery returned an unexpected offset",
                )?;

                confirmed_offset
            }
            _ => {
                return Err(io::Error::other(
                    "lost-ack recovery did not report Receiving",
                ));
            }
        };

        // Continue after the already stored chunk rather than
        // appending its contents a second time.
        while offset < source.size() {
            (connection, offset) =
                source.send_next(&upload, connection, offset, OPERATION_BUDGET)?;
        }

        let connection = finish_and_wait(connection, &upload)?;
        let id = upload.upload_id();

        connection.close();

        Ok(id)
    })();

    // Join even if a client operation returned an error.
    let server_result = server_thread
        .join()
        .map_err(|_| io::Error::other("lost-ack test server panicked"))?;

    if let Err(error) = &client_result {
        eprintln!("lost-ack client failed (padded={padded}): {error:?}");
    }

    if let Err(error) = &server_result {
        eprintln!("lost-ack server failed (padded={padded}): {error:?}");
    }

    let upload_id = client_result?;
    let (count, reserved) = server_result?;

    ensure(
        count == 1,
        "lost-ack test retained an unexpected upload count",
    )?;
    ensure(
        reserved == expected_size,
        "lost-ack test retained an unexpected reservation",
    )?;

    let actual = fs::read(stored_path(&directory.uploads(), upload_id))?;

    ensure(
        actual == payload,
        "lost-ack recovery duplicated or corrupted stored bytes",
    )?;

    Ok(())
}

#[derive(Clone, Copy)]
enum CapacityRestriction {
    SendingBytes,
    ReceivingBytes,
    Lifetime,
}

fn run_rotating_upload_case(max_exchanges: u64) -> io::Result<()> {
    run_rotating_upload_case_with_capacity(max_exchanges, None)
}

fn run_rotating_upload_case_with_capacity(
    max_exchanges: u64,
    restriction: Option<CapacityRestriction>,
) -> io::Result<()> {
    run_rotating_upload_case_with_padding(max_exchanges, restriction, false)
}

fn run_rotating_upload_case_with_padding(
    max_exchanges: u64,
    restriction: Option<CapacityRestriction>,
    padded: bool,
) -> io::Result<()> {
    use std::cell::Cell;
    use std::sync::mpsc::{self, TryRecvError};

    use crate::{FileUploadConnection, FileUploadRotation};

    let directory = TestDirectory::new()?;

    // Four chunks: three full chunks and one short final chunk.
    let length = MAX_FILE_CHUNK_LEN
        .checked_mul(3)
        .and_then(|length| length.checked_add(17))
        .ok_or_else(|| io::Error::other("test payload size overflow"))?;

    let payload: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();

    fs::write(directory.source(), &payload)?;

    let expected_size = payload.len() as u64;

    let mut source = FileUploadSource::open(directory.source(), expected_size)?;

    let ca = fixture("ca.cert.der")?;
    let certificate = fixture("server.cert.der")?;
    let private_key = fixture("server.key.der")?;
    let timeouts = connection_timeouts()?;

    let server = Server::new(&[certificate.as_slice()], &private_key, timeouts)?;

    let server = if padded {
        server.with_padding(crate::api::PaddingPolicy::Required)
    } else {
        server
    };

    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;

    let address = listener.local_addr()?;

    let mut service = FileTransferService::create(
        directory.uploads(),
        FileTransferLimits {
            max_file_size: expected_size,
            max_reserved_bytes: expected_size,
            max_uploads: 1,
            max_uploads_per_owner: 1,
        },
    )?;

    let (stop_sender, stop_receiver) = mpsc::channel::<()>();

    let server_thread = thread::spawn(move || -> io::Result<(usize, usize, u64)> {
        let started = Instant::now();
        let mut accepted_connections = 0_usize;

        loop {
            match stop_receiver.try_recv() {
                Ok(()) | Err(TryRecvError::Disconnected) => break,
                Err(TryRecvError::Empty) => {}
            }

            if started.elapsed() >= Duration::from_secs(30) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "rotating upload test server timed out",
                ));
            }

            let socket = match listener.accept() {
                Ok((socket, _)) => socket,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(error) => return Err(error),
            };

            socket.set_nonblocking(false)?;

            let mut connection = server
                .accept(socket)?
                .authenticate(&TestAuthenticator, OPERATION_BUDGET)?
                .establish_keys(OPERATION_BUDGET)?;

            accepted_connections += 1;

            loop {
                match service.serve_one(connection, OPERATION_BUDGET, |identity| {
                    identity.as_str() == "file-loopback-client"
                }) {
                    Ok(next) => connection = next,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::UnexpectedEof
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::ConnectionAborted
                                | io::ErrorKind::BrokenPipe
                        ) =>
                    {
                        // Rotation and final shutdown deliberately
                        // close connections without close_notify.
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
        }

        service.poll_verifications();

        Ok((
            accepted_connections,
            service.upload_count(),
            service.reserved_bytes(),
        ))
    });

    let client_result = (|| -> io::Result<([u8; 16], usize)> {
        let connected = Cell::new(0_usize);

        let mut transfer = FileUploadConnection::new(
            || {
                let connection = connect_upload_case(address, &ca, timeouts, padded)?;

                connected.set(connected.get() + 1);
                Ok(connection)
            },
            FileUploadRotation {
                max_exchanges,
                lifetime_margin: Duration::from_secs(1),
            },
        )?;

        let upload = transfer.begin(&source, OPERATION_BUDGET)?;

        let connections_before_restriction = connected.get();

        if let Some(restriction) = restriction {
            let (send_bytes, receive_bytes, lifetime) = match restriction {
                CapacityRestriction::SendingBytes => (0, u64::MAX, None),
                CapacityRestriction::ReceivingBytes => (u64::MAX, 0, None),
                CapacityRestriction::Lifetime => {
                    // The helper configures a one-second margin.
                    // Remaining lifetime therefore cannot satisfy
                    // operation budget + margin.
                    (u64::MAX, u64::MAX, Some(OPERATION_BUDGET))
                }
            };

            transfer.restrict_current_capacity_for_test(send_bytes, receive_bytes, lifetime)?;
        }

        let mut offset = 0_u64;
        let mut sent_chunks = 0_u64;

        while offset < source.size() {
            let next_offset = transfer.send_next(&mut source, &upload, offset, OPERATION_BUDGET)?;

            if sent_chunks == 0 && restriction.is_some() {
                ensure(
                    connected.get() == connections_before_restriction + 1,
                    "capacity restriction did not trigger a fresh connection",
                )?;
            }

            ensure(
                next_offset > offset,
                "rotating upload did not advance its confirmed offset",
            )?;

            offset = next_offset;
            sent_chunks += 1;

            ensure(
                transfer.successful_exchanges() <= max_exchanges,
                "connection exceeded its configured exchange count",
            )?;
        }

        ensure(sent_chunks == 4, "test did not send four chunks")?;
        ensure(
            offset == source.size(),
            "rotating upload ended at an unexpected offset",
        )?;

        let mut status = transfer.finish(&upload, OPERATION_BUDGET)?;
        let started = Instant::now();

        loop {
            match status {
                FileUploadStatus::Complete => break,
                FileUploadStatus::Verifying => {
                    if started.elapsed() >= VERIFICATION_BUDGET {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "rotating upload verification timed out",
                        ));
                    }

                    thread::sleep(Duration::from_millis(2));

                    status = transfer.status(&upload, OPERATION_BUDGET)?;
                }
                FileUploadStatus::Receiving { .. } => {
                    return Err(io::Error::other(
                        "rotating upload returned to Receiving after Finish",
                    ));
                }
            }
        }

        ensure(
            transfer.successful_exchanges() <= max_exchanges,
            "verification polling exceeded the exchange limit",
        )?;

        // At least Begin + four chunks + Finish were exchanged.
        // Verification-status polling may add more connections.
        let minimum_exchanges = 6_u64;
        let minimum_connections = minimum_exchanges.div_ceil(max_exchanges);

        ensure(
            connected.get() as u64 >= minimum_connections,
            "upload did not rotate connections as required",
        )?;

        let upload_id = upload.upload_id();

        transfer.close();

        ensure(
            transfer.successful_exchanges() == 0,
            "closed wrapper still reported retained exchanges",
        )?;

        Ok((upload_id, connected.get()))
    })();

    // Signal and join even if a client operation returned an error.
    let _ = stop_sender.send(());

    let server_result = server_thread
        .join()
        .map_err(|_| io::Error::other("rotating upload server panicked"))?;

    let (upload_id, client_connections) = client_result?;
    let (server_connections, upload_count, reserved) = server_result?;

    ensure(
        server_connections == client_connections,
        "client/server connection counts differ",
    )?;
    ensure(
        upload_count == 1,
        "rotating upload retained an unexpected upload count",
    )?;
    ensure(
        reserved == expected_size,
        "rotating upload retained an unexpected byte reservation",
    )?;

    let actual = fs::read(stored_path(&directory.uploads(), upload_id))?;

    ensure(
        actual == payload,
        "connection rotation corrupted or duplicated file contents",
    )?;

    Ok(())
}

#[test]
fn public_file_upload_rotates_after_every_exchange() -> io::Result<()> {
    run_rotating_upload_case(1)
}

#[test]
fn public_file_upload_rotates_after_two_exchanges() -> io::Result<()> {
    run_rotating_upload_case(2)
}

#[test]
fn public_file_upload_rotates_before_sending_byte_exhaustion() -> io::Result<()> {
    run_rotating_upload_case_with_capacity(u64::MAX, Some(CapacityRestriction::SendingBytes))
}

#[test]
fn public_file_upload_rotates_before_receiving_byte_exhaustion() -> io::Result<()> {
    run_rotating_upload_case_with_capacity(u64::MAX, Some(CapacityRestriction::ReceivingBytes))
}

#[test]
fn public_file_upload_rotates_when_remaining_lifetime_is_too_short() -> io::Result<()> {
    run_rotating_upload_case_with_capacity(u64::MAX, Some(CapacityRestriction::Lifetime))
}

const LARGE_BLOCK: usize = 1024 * 1024;
const LARGE_DEFAULT_BYTES: u64 = 10_000_000_000;
const LARGE_VERIFICATION_BUDGET: Duration = Duration::from_secs(30 * 60);

fn fill_pattern(start: u64, buffer: &mut [u8]) {
    for (index, byte) in buffer.iter_mut().enumerate() {
        let position = start.wrapping_add(index as u64);
        *byte = (position.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 56) as u8;
    }
}

fn write_pattern_file(path: &Path, size: u64) -> io::Result<()> {
    use std::io::Write;

    let mut file = fs::File::create(path)?;
    let mut block = vec![0_u8; LARGE_BLOCK];
    let mut written = 0_u64;

    while written < size {
        let len = (size - written).min(LARGE_BLOCK as u64) as usize;
        fill_pattern(written, &mut block[..len]);
        file.write_all(&block[..len])?;
        written += len as u64;
    }

    file.flush()
}

fn verify_pattern_file(path: &Path, size: u64) -> io::Result<()> {
    use std::io::Read;

    let mut file = fs::File::open(path)?;
    ensure(
        file.metadata()?.len() == size,
        "stored large file has an unexpected length",
    )?;

    let mut actual = vec![0_u8; LARGE_BLOCK];
    let mut expected = vec![0_u8; LARGE_BLOCK];
    let mut checked = 0_u64;

    while checked < size {
        let len = (size - checked).min(LARGE_BLOCK as u64) as usize;
        file.read_exact(&mut actual[..len])?;
        fill_pattern(checked, &mut expected[..len]);

        ensure(
            actual[..len] == expected[..len],
            "stored large file differs from the generated pattern",
        )?;

        checked += len as u64;
    }

    Ok(())
}

#[test]
#[ignore = "large disk-backed transfer; run explicitly with --ignored"]
fn public_file_upload_large_disk_backed() -> io::Result<()> {
    use std::sync::mpsc::{self, TryRecvError};

    use crate::{FileUploadConnection, FileUploadRotation};

    let size = match std::env::var("BRN_LARGE_UPLOAD_BYTES") {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|_| io::Error::other("invalid BRN_LARGE_UPLOAD_BYTES"))?,
        Err(_) => LARGE_DEFAULT_BYTES,
    };
    ensure(size > 0, "BRN_LARGE_UPLOAD_BYTES must be nonzero")?;

    let directory = match std::env::var_os("BRN_LARGE_UPLOAD_DIR") {
        Some(root) => TestDirectory::new_in(Path::new(&root))?,
        None => TestDirectory::new_in(&std::env::temp_dir())?,
    };

    eprintln!("large upload: {size} bytes in {}", directory.path.display());

    write_pattern_file(&directory.source(), size)?;

    let ca = fixture("ca.cert.der")?;
    let certificate = fixture("server.cert.der")?;
    let private_key = fixture("server.key.der")?;
    let timeouts = connection_timeouts()?;

    let server = Server::new(&[certificate.as_slice()], &private_key, timeouts)?;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;

    let mut service = FileTransferService::create(
        directory.uploads(),
        FileTransferLimits {
            max_file_size: size,
            max_reserved_bytes: size,
            max_uploads: 1,
            max_uploads_per_owner: 1,
        },
    )?;

    crate::file_disk::reset_chunk_io_timing_for_test();
    let (stop_sender, stop_receiver) = mpsc::channel::<()>();

    let server_thread = thread::spawn(move || -> io::Result<(usize, usize, u64)> {
        let mut accepted = 0_usize;

        loop {
            match stop_receiver.try_recv() {
                Ok(()) | Err(TryRecvError::Disconnected) => break,
                Err(TryRecvError::Empty) => {}
            }

            let socket = match listener.accept() {
                Ok((socket, _)) => socket,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };

            socket.set_nonblocking(false)?;

            let mut connection = server
                .accept(socket)?
                .authenticate(&TestAuthenticator, OPERATION_BUDGET)?
                .establish_keys(OPERATION_BUDGET)?;

            accepted += 1;

            loop {
                match service.serve_one(connection, OPERATION_BUDGET, |identity| {
                    identity.as_str() == "file-loopback-client"
                }) {
                    Ok(next) => connection = next,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::UnexpectedEof
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::ConnectionAborted
                                | io::ErrorKind::BrokenPipe
                        ) =>
                    {
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
        }

        service.poll_verifications();

        Ok((accepted, service.upload_count(), service.reserved_bytes()))
    });

    let source_path = directory.source();

    let client_result = (|| -> io::Result<([u8; 16], usize)> {
        use std::cell::Cell;

        let mut source = FileUploadSource::open(source_path, size)?;
        let connected = Cell::new(0_usize);

        let max_exchanges = match std::env::var("BRN_LARGE_UPLOAD_EXCHANGES") {
            Ok(value) => value
                .parse::<u64>()
                .map_err(|_| io::Error::other("invalid BRN_LARGE_UPLOAD_EXCHANGES"))?,
            Err(std::env::VarError::NotPresent) => FileUploadRotation::default().max_exchanges,
            Err(error) => {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, error));
            }
        };

        let policy = FileUploadRotation {
            max_exchanges,
            ..FileUploadRotation::default()
        };

        let mut transfer = FileUploadConnection::new(
            || {
                let connection = connect(address, &ca, timeouts)?;

                connected.set(connected.get() + 1);
                Ok(connection)
            },
            policy,
        )?;

        let upload = transfer.begin(&source, OPERATION_BUDGET)?;

        let started = Instant::now();
        let mut last_report = started;
        let mut offset = 0_u64;
        let mut chunks = 0_u64;
        let mut chunk_exchange_time = Duration::ZERO;

        while offset < source.size() {
            let exchange_started = Instant::now();

            let next = transfer.send_next(&mut source, &upload, offset, OPERATION_BUDGET)?;

            chunk_exchange_time += exchange_started.elapsed();

            ensure(next > offset, "large upload did not advance its offset")?;
            ensure(
                next - offset <= MAX_FILE_CHUNK_LEN as u64,
                "large upload advanced by more than one chunk",
            )?;

            offset = next;
            chunks += 1;

            let now = Instant::now();

            if now.duration_since(last_report) >= Duration::from_secs(1) || offset == size {
                let elapsed = now.duration_since(started);
                let seconds = elapsed.as_secs_f64().max(f64::EPSILON);
                let mib_per_second = offset as f64 / (1024.0 * 1024.0) / seconds;
                let percent = offset as f64 / size as f64 * 100.0;

                eprintln!(
                    "large upload: {offset}/{size} bytes \
                     ({percent:.1}%), {mib_per_second:.2} MiB/s average, \
                     {chunks} chunks, {} connections, {elapsed:?}",
                    connected.get(),
                );

                last_report = now;
            }
        }

        eprintln!(
            "large upload: all {offset} bytes acknowledged; \
             requesting whole-file verification"
        );

        eprintln!(
            "large upload timing: client chunk exchanges total {:?}, \
             average {:.3} ms/chunk",
            chunk_exchange_time,
            chunk_exchange_time.as_secs_f64() * 1000.0 / chunks.max(1) as f64,
        );

        let mut status = transfer.finish(&upload, OPERATION_BUDGET)?;
        let verifying = Instant::now();

        loop {
            match status {
                FileUploadStatus::Complete => break,
                FileUploadStatus::Verifying => {
                    if verifying.elapsed() >= LARGE_VERIFICATION_BUDGET {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "large upload verification timed out",
                        ));
                    }

                    thread::sleep(Duration::from_millis(200));
                    status = transfer.status(&upload, OPERATION_BUDGET)?;
                }
                FileUploadStatus::Receiving { .. } => {
                    return Err(io::Error::other(
                        "large upload returned to Receiving after Finish",
                    ));
                }
            }
        }

        // Begin + chunks + Finish are a lower bound on exchanges.
        let minimum_connections = (chunks + 2).div_ceil(policy.max_exchanges);
        ensure(
            connected.get() as u64 >= minimum_connections,
            "large upload used fewer connections than rotation requires",
        )?;

        eprintln!(
            "large upload: complete, {chunks} chunks, {} connections, {:?}",
            connected.get(),
            started.elapsed(),
        );

        let id = upload.upload_id();
        transfer.close();

        Ok((id, connected.get()))
    })();

    let _ = stop_sender.send(());

    let server_result = server_thread
        .join()
        .map_err(|_| io::Error::other("large upload server panicked"))?;

    let (upload_id, client_connections) = client_result?;
    let (server_connections, count, reserved) = server_result?;
    let disk = crate::file_disk::chunk_io_timing_for_test();

    eprintln!(
        "large upload timing: server writes {}, total {:?}, \
         average {:.3} ms/write",
        disk.writes,
        disk.write_time,
        disk.write_time.as_secs_f64() * 1000.0 / disk.writes.max(1) as f64,
    );

    eprintln!(
        "large upload timing: server syncs {}, total {:?}, \
         average {:.3} ms/sync",
        disk.syncs,
        disk.sync_time,
        disk.sync_time.as_secs_f64() * 1000.0 / disk.syncs.max(1) as f64,
    );

    ensure(
        server_connections == client_connections,
        "client/server connection counts differ",
    )?;
    ensure(count == 1, "server retained an unexpected upload count")?;
    ensure(
        reserved == size,
        "server retained an unexpected reservation",
    )?;

    eprintln!(
        "large upload: server reported Complete; \
         independently checking stored contents"
    );

    verify_pattern_file(&stored_path(&directory.uploads(), upload_id), size)
}

// Core padding tests. Reuse this module's TLS/authentication fixtures;
// do not change the existing file-transfer tests.

fn padding_test_payloads() -> Vec<Vec<u8>> {
    let mut payloads = vec![
        Vec::new(),
        b"hello man".to_vec(),
        "Text with Unicode: café, Ελληνικά".as_bytes().to_vec(),
        vec![0, 255, 0, 17, 128, 0],
    ];

    // Four bytes of inner length metadata mean the first transition
    // occurs between original payload lengths 252 and 253.
    for length in [1usize, 251, 252, 253, 255, 256, 257, 507, 508, 509] {
        payloads.push((0..length).map(|index| (index % 256) as u8).collect());
    }

    payloads
}

fn expected_padding_test_bytes(length: usize, padded: bool) -> u64 {
    if padded {
        ((length + 4).div_ceil(256) * 256) as u64
    } else {
        length as u64
    }
}

fn run_padding_loopback_case(
    client_policy: Option<crate::api::PaddingPolicy>,
    server_policy: Option<crate::api::PaddingPolicy>,
    expected_padded: Option<bool>,
) -> io::Result<()> {
    let ca = fixture("ca.cert.der")?;
    let certificate = fixture("server.cert.der")?;
    let private_key = fixture("server.key.der")?;
    let timeouts = connection_timeouts()?;

    let server = Server::new(&[certificate.as_slice()], &private_key, timeouts)?;

    let server = match server_policy {
        Some(policy) => server.with_padding(policy),
        None => server,
    };

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;

    let server_thread = thread::spawn(move || -> io::Result<()> {
        let socket = accept_with_timeout(&listener)?;
        let pending = server.accept(socket);

        let Some(padded) = expected_padded else {
            return match pending {
                Err(_) => Ok(()),
                Ok(connection) => {
                    connection.close();
                    Err(io::Error::other(
                        "server unexpectedly accepted incompatible negotiation",
                    ))
                }
            };
        };

        let mut connection = pending?
            .authenticate(&TestAuthenticator, OPERATION_BUDGET)?
            .establish_keys(OPERATION_BUDGET)?;

        for expected in padding_test_payloads() {
            let before = connection.application_key_capacity()?;

            let received = connection.receive_request(OPERATION_BUDGET)?;

            ensure(
                received == expected,
                "server received altered application bytes",
            )?;

            connection.respond(&received, OPERATION_BUDGET)?;

            let after = connection.application_key_capacity()?;
            let consumed = expected_padding_test_bytes(expected.len(), padded);

            ensure(
                before
                    .receive_plaintext_bytes
                    .checked_sub(after.receive_plaintext_bytes)
                    == Some(consumed),
                "server receive accounting does not match selected format",
            )?;

            ensure(
                before
                    .send_plaintext_bytes
                    .checked_sub(after.send_plaintext_bytes)
                    == Some(consumed),
                "server send accounting does not match selected format",
            )?;
        }

        connection.close();
        Ok(())
    });

    // Capture the result before joining so client-side errors do not
    // return early and leave the server thread unjoined.
    let client_result = (|| -> io::Result<()> {
        let pending = match client_policy {
            None => PendingClient::connect(
                address,
                "localhost",
                &[ca.as_slice()],
                Duration::from_secs(2),
                timeouts,
            ),
            Some(policy) => PendingClient::connect_with_padding(
                address,
                "localhost",
                &[ca.as_slice()],
                Duration::from_secs(2),
                timeouts,
                policy,
            ),
        };

        let Some(padded) = expected_padded else {
            return match pending {
                Err(_) => Ok(()),
                Ok(connection) => {
                    connection.close();
                    Err(io::Error::other(
                        "client unexpectedly accepted incompatible negotiation",
                    ))
                }
            };
        };

        let mut connection = pending?
            .authenticate(b"file-transfer-loopback-test", OPERATION_BUDGET)?
            .establish_keys(OPERATION_BUDGET)?;

        for payload in padding_test_payloads() {
            let before = connection.application_key_capacity()?;

            let response = connection.request(&payload, OPERATION_BUDGET)?;

            ensure(
                response == payload,
                "client received altered application bytes",
            )?;

            let after = connection.application_key_capacity()?;
            let consumed = expected_padding_test_bytes(payload.len(), padded);

            ensure(
                before
                    .send_plaintext_bytes
                    .checked_sub(after.send_plaintext_bytes)
                    == Some(consumed),
                "client send accounting does not match selected format",
            )?;

            ensure(
                before
                    .receive_plaintext_bytes
                    .checked_sub(after.receive_plaintext_bytes)
                    == Some(consumed),
                "client receive accounting does not match selected format",
            )?;
        }

        connection.close();
        Ok(())
    })();

    let server_result = server_thread
        .join()
        .map_err(|_| io::Error::other("padding test server panicked"))?;

    // Both sides have finished before either result is propagated.
    client_result?;
    server_result
}

#[test]
fn core_padding_legacy_v1_round_trip() -> io::Result<()> {
    run_padding_loopback_case(None, None, Some(false))
}

#[test]
fn core_padding_compatible_v2_policy_matrix() -> io::Result<()> {
    use crate::api::PaddingPolicy::{Disabled, Optional, Required};

    let cases = [
        (Disabled, Disabled, false),
        (Disabled, Optional, false),
        (Optional, Disabled, false),
        (Optional, Optional, true),
        (Optional, Required, true),
        (Required, Optional, true),
        (Required, Required, true),
    ];

    for (client, server, padded) in cases {
        run_padding_loopback_case(Some(client), Some(server), Some(padded)).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("client={client:?}, server={server:?}: {error}"),
            )
        })?;
    }

    Ok(())
}

#[test]
fn core_padding_incompatible_v2_policies_rejected() -> io::Result<()> {
    use crate::api::PaddingPolicy::{Disabled, Required};

    for (client, server) in [(Required, Disabled), (Disabled, Required)] {
        run_padding_loopback_case(Some(client), Some(server), None)?;
    }

    Ok(())
}

#[test]
fn core_padding_mixed_versions_rejected() -> io::Result<()> {
    use crate::api::PaddingPolicy::{Disabled, Optional, Required};

    for policy in [Disabled, Optional, Required] {
        run_padding_loopback_case(None, Some(policy), None)?;
        run_padding_loopback_case(Some(policy), None, None)?;
    }

    Ok(())
}

#[test]
fn public_file_upload_with_required_padding_completes() -> io::Result<()> {
    run_upload_case_with_padding(false, true)
}

#[test]
fn public_file_upload_with_required_padding_resumes() -> io::Result<()> {
    run_upload_case_with_padding(true, true)
}

#[test]
fn padded_file_upload_rotates_after_every_exchange() -> io::Result<()> {
    run_rotating_upload_case_with_padding(1, None, true)
}

#[test]
fn padded_file_upload_rotates_after_two_exchanges() -> io::Result<()> {
    run_rotating_upload_case_with_padding(2, None, true)
}

#[test]
fn padded_file_upload_rotates_before_sending_byte_exhaustion() -> io::Result<()> {
    run_rotating_upload_case_with_padding(u64::MAX, Some(CapacityRestriction::SendingBytes), true)
}

#[test]
fn padded_file_upload_rotates_before_receiving_byte_exhaustion() -> io::Result<()> {
    run_rotating_upload_case_with_padding(u64::MAX, Some(CapacityRestriction::ReceivingBytes), true)
}

#[test]
fn padded_file_upload_rotates_when_remaining_lifetime_is_too_short() -> io::Result<()> {
    run_rotating_upload_case_with_padding(u64::MAX, Some(CapacityRestriction::Lifetime), true)
}

#[test]
fn upload_exchange_error_clears_counter_without_reconnecting() -> io::Result<()> {
    use std::cell::Cell;

    use crate::{FileUploadConnection, FileUploadRotation};

    for padded in [false, true] {
        let directory = TestDirectory::new()?;
        let payload = b"counter reset regression";
        fs::write(directory.source(), payload)?;

        let expected_size = payload.len() as u64;
        let mut source = FileUploadSource::open(directory.source(), expected_size)?;

        let ca = fixture("ca.cert.der")?;
        let certificate = fixture("server.cert.der")?;
        let private_key = fixture("server.key.der")?;
        let timeouts = connection_timeouts()?;

        let server = Server::new(&[certificate.as_slice()], &private_key, timeouts)?;

        let server = if padded {
            server.with_padding(crate::api::PaddingPolicy::Required)
        } else {
            server
        };

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;

        let mut service = FileTransferService::create(
            directory.uploads(),
            FileTransferLimits {
                max_file_size: expected_size,
                max_reserved_bytes: expected_size,
                max_uploads: 1,
                max_uploads_per_owner: 1,
            },
        )?;

        let server_thread = thread::spawn(move || -> io::Result<()> {
            let socket = accept_with_timeout(&listener)?;

            let mut connection = server
                .accept(socket)?
                .authenticate(&TestAuthenticator, OPERATION_BUDGET)?
                .establish_keys(OPERATION_BUDGET)?;

            loop {
                match service.serve_one(connection, OPERATION_BUDGET, |identity| {
                    identity.as_str() == "file-loopback-client"
                }) {
                    Ok(next) => connection = next,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::UnexpectedEof
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::ConnectionAborted
                                | io::ErrorKind::BrokenPipe
                        ) =>
                    {
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
            }
        });

        let client_result = (|| -> io::Result<()> {
            let connected = Cell::new(0_usize);

            let mut transfer = FileUploadConnection::new(
                || {
                    let connection = connect_upload_case(address, &ca, timeouts, padded)?;

                    connected.set(connected.get() + 1);
                    Ok(connection)
                },
                FileUploadRotation {
                    max_exchanges: u64::MAX,
                    lifetime_margin: Duration::from_secs(1),
                },
            )?;

            let result = (|| -> io::Result<()> {
                let upload = transfer.begin(&source, OPERATION_BUDGET)?;

                ensure(
                    transfer.successful_exchanges() == 1,
                    "Begin did not retain one successful exchange",
                )?;

                let mut offset = 0_u64;

                while offset < source.size() {
                    let next =
                        transfer.send_next(&mut source, &upload, offset, OPERATION_BUDGET)?;

                    ensure(next > offset, "upload did not advance")?;
                    offset = next;
                }

                ensure(
                    offset == source.size(),
                    "upload ended at an unexpected offset",
                )?;
                ensure(
                    transfer.successful_exchanges() > 0,
                    "regression requires a nonzero exchange count",
                )?;
                ensure(
                    connected.get() == 1,
                    "setup unexpectedly rotated the connection",
                )?;

                let connections_before_error = connected.get();

                let error = match transfer.send_next(&mut source, &upload, offset, OPERATION_BUDGET)
                {
                    Err(error) => error,
                    Ok(_) => {
                        return Err(io::Error::other("sending at EOF unexpectedly succeeded"));
                    }
                };

                ensure(
                    error.to_string() == "upload source is at EOF; request final verification",
                    "send_next failed for an unexpected reason",
                )?;
                ensure(
                    transfer.successful_exchanges() == 0,
                    "failed operation retained a stale exchange count",
                )?;
                ensure(
                    connected.get() == connections_before_error,
                    "failed operation unexpectedly reconnected",
                )?;

                Ok(())
            })();

            // Close even when a client assertion fails, before joining.
            transfer.close();
            result
        })();

        let server_result = server_thread
            .join()
            .map_err(|_| io::Error::other("counter regression server panicked"))?;

        client_result?;
        server_result?;
    }

    Ok(())
}
