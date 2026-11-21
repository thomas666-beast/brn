//! Bounded-chunk downloads of application-registered, immutable files.
//!
//! The application supplies file handles and authenticated identities.
//! This catalog is in memory only. Protect registered files against mutation.
//! Registration hashes files synchronously; socket deadlines do not interrupt it.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::time::Duration;

use aws_lc_rs::digest;

use crate::{ClientIdentity, ReadyClient};

const META: &[u8] = b"BRND1M";
const CHUNK: &[u8] = b"BRND1C";
const CHUNK_LEN: usize = 32 * 1024;
const MAX_NAME: usize = 128;
const ROTATE_AFTER: u64 = 128;
const CAPACITY_BYTES: u64 = 64 * 1024;

/// Metadata for one immutable downloadable object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadInfo {
    pub size: u64,
    pub sha256: [u8; 32],
    /// Display metadata, never a server or client filesystem path.
    pub original_name: String,
}

struct Entry {
    owner: ClientIdentity,
    file: File,
    info: DownloadInfo,
}

/// Application-owned, nonpersistent download catalog.
///
/// Each object remains private to its registered owner. Supply read-only
/// regular-file handles; the application must prevent subsequent mutation.
/// Limits cover registered logical bytes, not physical filesystem usage.
/// This implementation retains one file handle per registered object.
pub struct DownloadCatalog {
    entries: HashMap<[u8; 16], Entry>,
    max_files: usize,
    max_bytes: u64,
    bytes: u64,
}

impl DownloadCatalog {
    pub fn new(max_files: usize, max_bytes: u64) -> io::Result<Self> {
        if max_files == 0 {
            return Err(invalid("download catalog requires a nonzero file limit"));
        }
        Ok(Self {
            entries: HashMap::new(),
            max_files,
            max_bytes,
            bytes: 0,
        })
    }

    /// Registers an application-authorized publication under its download ID.
    /// Hashes synchronously with a fixed-size buffer. Does not publish or delete.
    /// Existing IDs are rejected, not replaced.
    pub fn register(
        &mut self,
        owner: ClientIdentity,
        id: [u8; 16],
        original_name: &str,
        mut file: File,
    ) -> io::Result<DownloadInfo> {
        if self.entries.contains_key(&id) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "download ID exists",
            ));
        }
        if self.entries.len() >= self.max_files {
            return Err(io::Error::other("download catalog file limit exceeded"));
        }
        if original_name.is_empty()
            || original_name.len() > MAX_NAME
            || original_name.chars().any(char::is_control)
        {
            return Err(invalid("invalid original filename metadata"));
        }
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > u64::MAX / 8 {
            return Err(invalid("invalid downloadable file"));
        }
        let size = metadata.len();
        let reserved = self
            .bytes
            .checked_add(size)
            .filter(|total| *total <= self.max_bytes)
            .ok_or_else(|| io::Error::other("download catalog byte limit exceeded"))?;
        file.seek(SeekFrom::Start(0))?;
        let mut context = digest::Context::new(&digest::SHA256);
        let mut buffer = [0_u8; CHUNK_LEN];
        let mut measured = 0_u64;
        loop {
            let count = match file.read(&mut buffer) {
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            if count == 0 {
                break;
            }
            measured = measured
                .checked_add(count as u64)
                .filter(|value| *value <= size)
                .ok_or_else(|| invalid_data("file changed during registration"))?;
            context.update(&buffer[..count]);
        }
        if measured != size || file.metadata()?.len() != size {
            return Err(invalid_data("file changed during registration"));
        }
        let mut sha256 = [0_u8; 32];
        sha256.copy_from_slice(context.finish().as_ref());
        let info = DownloadInfo {
            size,
            sha256,
            original_name: original_name.to_owned(),
        };
        self.entries.insert(
            id,
            Entry {
                owner,
                file,
                info: info.clone(),
            },
        );
        self.bytes = reserved;
        Ok(info)
    }

    /// Processes one decoded application request, outside encrypted I/O phases.
    /// Checks application authorization and registered ownership on every call.
    /// Errors should be sent to the peer as a generic bounded rejection.
    pub fn respond(
        &mut self,
        owner: &ClientIdentity,
        request: &[u8],
        authorize: impl FnOnce(&ClientIdentity) -> bool,
    ) -> io::Result<Vec<u8>> {
        if !authorize(owner) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "download denied",
            ));
        }
        let meta = request.starts_with(META);
        let chunk = request.starts_with(CHUNK);
        if (!meta && !chunk) || request.len() != if meta { 22 } else { 62 } {
            return Err(invalid("invalid download request"));
        }
        let mut id = [0_u8; 16];
        id.copy_from_slice(&request[6..22]);
        let entry = self
            .entries
            .get_mut(&id)
            .filter(|entry| &entry.owner == owner)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "download not found"))?;
        if entry.file.metadata()?.len() != entry.info.size {
            return Err(invalid_data("registered file length changed"));
        }
        if meta {
            let name = entry.info.original_name.as_bytes();
            let mut response = Vec::with_capacity(43 + name.len());
            response.push(b'M');
            response.extend_from_slice(&entry.info.size.to_be_bytes());
            response.extend_from_slice(&entry.info.sha256);
            response.extend_from_slice(&(name.len() as u16).to_be_bytes());
            response.extend_from_slice(name);
            return Ok(response);
        }
        if request[22..54] != entry.info.sha256 {
            return Err(invalid_data("download version mismatch"));
        }
        let mut encoded_offset = [0_u8; 8];
        encoded_offset.copy_from_slice(&request[54..62]);
        let offset = u64::from_be_bytes(encoded_offset);
        if offset >= entry.info.size {
            return Err(invalid("download offset out of range"));
        }
        let length = (entry.info.size - offset).min(CHUNK_LEN as u64) as usize;
        let mut response = vec![0_u8; 9 + length];
        response[0] = b'D';
        response[1..9].copy_from_slice(&encoded_offset);
        entry.file.seek(SeekFrom::Start(offset))?;
        entry.file.read_exact(&mut response[9..])?;
        Ok(response)
    }
}

/// Whether an application request selects the download protocol.
pub fn is_download_request(request: &[u8]) -> bool {
    request.starts_with(META) || request.starts_with(CHUNK)
}

fn metadata(
    connection: &mut ReadyClient,
    id: [u8; 16],
    budget: Duration,
) -> io::Result<DownloadInfo> {
    let mut request = META.to_vec();
    request.extend_from_slice(&id);
    let response = connection.request(&request, budget)?;
    if response.len() < 43 || response[0] != b'M' {
        return Err(invalid_data("download metadata rejected or malformed"));
    }
    let name_len = u16::from_be_bytes([response[41], response[42]]) as usize;
    if name_len == 0 || name_len > MAX_NAME || response.len() != 43 + name_len {
        return Err(invalid_data("invalid download filename metadata"));
    }
    let mut encoded_size = [0_u8; 8];
    encoded_size.copy_from_slice(&response[1..9]);
    let size = u64::from_be_bytes(encoded_size);
    if size > u64::MAX / 8 {
        return Err(invalid_data("download exceeds digest limit"));
    }
    let mut sha256 = [0_u8; 32];
    sha256.copy_from_slice(&response[9..41]);
    let original_name = std::str::from_utf8(&response[43..])
        .map_err(|_| invalid_data("download filename is not UTF-8"))?
        .to_owned();
    if original_name.chars().any(char::is_control) {
        return Err(invalid_data(
            "download filename contains control characters",
        ));
    }
    Ok(DownloadInfo {
        size,
        sha256,
        original_name,
    })
}

/// Downloads into an empty caller-provided file and verifies size and SHA-256.
///
/// The connector returns fresh authenticated keys, WITHOUT an upload routing
/// handshake. It is called initially and when rotation/capacity requires it.
/// The application chooses/provisions the destination and finalizes it only on
/// success. This helper never uses remote filename metadata as a local path.
///
/// Errors may leave partial output. No failed exchange is automatically retried.
/// This initial helper supports connection rotation during a running download,
/// not persisted checkpoints or cross-process resume.
pub fn download_to<C>(
    mut connect: C,
    id: [u8; 16],
    output: &mut File,
    max_size: u64,
    budget: Duration,
) -> io::Result<DownloadInfo>
where
    C: FnMut() -> io::Result<ReadyClient>,
{
    let required_lifetime = budget
        .checked_add(Duration::from_secs(5))
        .filter(|_| !budget.is_zero())
        .ok_or_else(|| invalid("invalid download budget"))?;
    if !output.metadata()?.is_file() || output.metadata()?.len() != 0 {
        return Err(invalid(
            "download destination must be an empty regular file",
        ));
    }
    output.seek(SeekFrom::Start(0))?;
    let mut connection = connect()?;
    ensure_capacity(&mut connection, required_lifetime)?;
    let info = metadata(&mut connection, id, budget)?;
    if info.size > max_size {
        return Err(invalid("download exceeds application size limit"));
    }
    let mut exchanges = 1_u64;
    let mut offset = 0_u64;
    let mut context = digest::Context::new(&digest::SHA256);
    while offset < info.size {
        let usable =
            exchanges < ROTATE_AFTER && ensure_capacity(&mut connection, required_lifetime).is_ok();
        if !usable {
            connection.close();
            connection = connect()?;
            ensure_capacity(&mut connection, required_lifetime)?;
            if metadata(&mut connection, id, budget)? != info {
                return Err(invalid_data("download metadata changed after reconnect"));
            }
            exchanges = 1;
        }
        let mut request = CHUNK.to_vec();
        request.extend_from_slice(&id);
        request.extend_from_slice(&info.sha256);
        request.extend_from_slice(&offset.to_be_bytes());
        let response = connection.request(&request, budget)?;
        let expected = (info.size - offset).min(CHUNK_LEN as u64) as usize;
        if response.len() != 9 + expected
            || response[0] != b'D'
            || response[1..9] != offset.to_be_bytes()
        {
            return Err(invalid_data("download chunk rejected or malformed"));
        }
        output.write_all(&response[9..])?;
        context.update(&response[9..]);
        offset += expected as u64;
        exchanges += 1;
    }
    connection.close();
    if context.finish().as_ref() != info.sha256 || output.metadata()?.len() != info.size {
        return Err(invalid_data("download size or SHA-256 mismatch"));
    }
    output.sync_all()?;
    Ok(info)
}

fn ensure_capacity(connection: &mut ReadyClient, lifetime: Duration) -> io::Result<()> {
    let capacity = connection.application_key_capacity()?;
    if capacity.send_plaintext_bytes < CAPACITY_BYTES
        || capacity.receive_plaintext_bytes < CAPACITY_BYTES
        || capacity.send_messages < 2
        || capacity.receive_messages < 2
        || capacity.remaining_lifetime <= lifetime
    {
        return Err(io::Error::other("insufficient download key capacity"));
    }
    Ok(())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture {
        directory: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            loop {
                let number = NEXT.fetch_add(1, Ordering::Relaxed);
                let directory = std::env::temp_dir()
                    .join(format!("brn-download-test-{}-{number}", std::process::id()));
                match std::fs::create_dir(&directory) {
                    Ok(()) => return Self { directory },
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("test directory: {error}"),
                }
            }
        }
        fn file(&self, bytes: &[u8]) -> File {
            let path = self.directory.join("source");
            std::fs::write(&path, bytes).unwrap();
            File::open(path).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }
    fn owner() -> ClientIdentity {
        ClientIdentity::new("test:alice").unwrap()
    }
    fn meta_request(id: [u8; 16]) -> Vec<u8> {
        let mut request = META.to_vec();
        request.extend_from_slice(&id);
        request
    }
    fn chunk_request(id: [u8; 16], hash: [u8; 32], offset: u64) -> Vec<u8> {
        let mut request = CHUNK.to_vec();
        request.extend_from_slice(&id);
        request.extend_from_slice(&hash);
        request.extend_from_slice(&offset.to_be_bytes());
        request
    }
    #[test]
    fn metadata_and_chunks_match_registered_file() {
        let fixture = Fixture::new();
        let mut catalog = DownloadCatalog::new(2, 1_000_000).unwrap();
        let bytes = vec![0x5a; CHUNK_LEN + 3];
        let id = [1; 16];
        let info = catalog
            .register(owner(), id, "james.mp4", fixture.file(&bytes))
            .unwrap();
        assert_eq!(info.size, bytes.len() as u64);
        assert_eq!(
            info.sha256.as_slice(),
            digest::digest(&digest::SHA256, &bytes).as_ref()
        );
        let response = catalog
            .respond(&owner(), &meta_request(id), |_| true)
            .unwrap();
        assert_eq!(&response[43..], b"james.mp4");
        let response = catalog
            .respond(&owner(), &chunk_request(id, info.sha256, 0), |_| true)
            .unwrap();
        assert_eq!(&response[9..], &bytes[..CHUNK_LEN]);
        let response = catalog
            .respond(
                &owner(),
                &chunk_request(id, info.sha256, CHUNK_LEN as u64),
                |_| true,
            )
            .unwrap();
        assert_eq!(&response[9..], &bytes[CHUNK_LEN..]);
    }
    #[test]
    fn authorization_and_ownership_are_required() {
        let fixture = Fixture::new();
        let mut catalog = DownloadCatalog::new(1, 100).unwrap();
        let id = [2; 16];
        catalog
            .register(owner(), id, "a", fixture.file(b"abc"))
            .unwrap();
        assert_eq!(
            catalog
                .respond(&owner(), &meta_request(id), |_| false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let other = ClientIdentity::new("test:bob").unwrap();
        assert_eq!(
            catalog
                .respond(&other, &meta_request(id), |_| true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }
    #[test]
    fn rejects_wrong_version_and_end_offset() {
        let fixture = Fixture::new();
        let mut catalog = DownloadCatalog::new(1, 100).unwrap();
        let id = [3; 16];
        let info = catalog
            .register(owner(), id, "a", fixture.file(b"abc"))
            .unwrap();
        assert!(
            catalog
                .respond(&owner(), &chunk_request(id, [0; 32], 0), |_| true)
                .is_err()
        );
        assert!(
            catalog
                .respond(&owner(), &chunk_request(id, info.sha256, 3), |_| true)
                .is_err()
        );
        assert!(catalog.respond(&owner(), b"BRND1M", |_| true).is_err());
    }
    #[test]
    fn supports_empty_files_and_enforces_registration_limits() {
        let fixture = Fixture::new();
        let mut catalog = DownloadCatalog::new(1, 0).unwrap();
        let id = [4; 16];
        let info = catalog
            .register(owner(), id, "empty", fixture.file(b""))
            .unwrap();
        assert_eq!(info.size, 0);
        assert_eq!(
            info.sha256.as_slice(),
            digest::digest(&digest::SHA256, b"").as_ref()
        );
        assert!(
            catalog
                .register(owner(), [5; 16], "another", fixture.file(b""))
                .is_err()
        );
        let mut catalog = DownloadCatalog::new(1, 2).unwrap();
        assert!(
            catalog
                .register(owner(), id, "too-big", fixture.file(b"abc"))
                .is_err()
        );
    }
}
