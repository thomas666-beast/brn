use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use aws_lc_rs::digest;

use crate::file_wire::MAX_CHUNK_LEN;

const HASH_BUFFER_LEN: usize = 64 * 1024;

// SHA-256 accepts messages shorter than 2^64 bits.
const MAX_HASH_INPUT_LEN: u64 = u64::MAX / 8;

/// Disk contents for one incomplete upload.
///
/// Not Clone or Copy. The upload manager must retain exclusive access
/// across state validation, disk writes, and metadata commits.
///
/// The file must reside in a server-controlled private directory.
/// Neither the path nor its parent directories may be client-controlled.
pub(crate) struct UploadFile {
    file: File,
    confirmed_len: u64,
    failed: bool,

    #[cfg(test)]
    fail_write_after: Option<usize>,

    #[cfg(test)]
    fail_sync: bool,
}

impl UploadFile {
    /// Creates a new read/write file without replacing an existing file.
    ///
    /// On Unix, requests owner-only permissions.
    ///
    /// This does not create parent directories, reserve quota, register
    /// upload ownership, or persist upload metadata.
    pub(crate) fn create(path: &Path) -> io::Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            options.mode(0o600);
        }

        let file = options.open(path)?;

        Ok(Self {
            file,
            confirmed_len: 0,
            failed: false,

            #[cfg(test)]
            fail_write_after: None,

            #[cfg(test)]
            fail_sync: false,
        })
    }

    /// Writes one bounded chunk and synchronizes it before confirming.
    ///
    /// Validation errors do not poison the file. Once disk work starts,
    /// any returned I/O error permanently disables this handle.
    ///
    /// A failed write can leave an unconfirmed partial tail on disk.
    /// Recovery must not infer a confirmed offset from file length.
    pub(crate) fn append_synced(&mut self, offset: u64, bytes: &[u8]) -> io::Result<u64> {
        self.ensure_usable()?;

        if bytes.is_empty() || bytes.len() > MAX_CHUNK_LEN {
            return Err(invalid_input("invalid upload chunk length"));
        }

        if offset != self.confirmed_len {
            return Err(invalid_input("upload disk offset mismatch"));
        }

        let length = u64::try_from(bytes.len())
            .map_err(|_| invalid_input("upload chunk length overflow"))?;

        let end = offset
            .checked_add(length)
            .filter(|end| *end <= MAX_HASH_INPUT_LEN)
            .ok_or_else(|| invalid_input("upload size exceeds digest limit"))?;

        let result = (|| {
            if self.file.metadata()?.len() != self.confirmed_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "upload file length changed unexpectedly",
                ));
            }

            self.file.seek(SeekFrom::Start(offset))?;
            #[cfg(test)]
            let write_started = std::time::Instant::now();

            let write_result = self.write_chunk(bytes);

            #[cfg(test)]
            record_chunk_io_for_test(false, write_started.elapsed());

            write_result?;

            #[cfg(test)]
            let sync_started = std::time::Instant::now();

            let sync_result = self.sync_chunk();

            #[cfg(test)]
            record_chunk_io_for_test(true, sync_started.elapsed());

            sync_result?;

            Ok(end)
        })();

        match result {
            Ok(end) => {
                self.confirmed_len = end;
                Ok(end)
            }
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }

    /// Reads the current file with a bounded buffer and hashes it.
    ///
    /// Returns the measured size and SHA-256 digest.
    /// The upload manager must compare these against UploadState.
    ///
    /// This is synchronous disk work. It is not interrupted by BRN
    /// socket deadlines and must not run inside an encrypted I/O phase.
    ///
    /// No other process or handle may modify the file during this work.
    pub(crate) fn measure_sha256(&mut self) -> io::Result<(u64, [u8; 32])> {
        self.ensure_usable()?;

        let result = self.measure_sha256_inner();

        if result.is_err() {
            self.failed = true;
        }

        result
    }

    fn measure_sha256_inner(&mut self) -> io::Result<(u64, [u8; 32])> {
        if self.confirmed_len > MAX_HASH_INPUT_LEN {
            return Err(invalid_input("upload size exceeds digest limit"));
        }

        if self.file.metadata()?.len() != self.confirmed_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upload file length changed unexpectedly",
            ));
        }

        // Also synchronize an empty file before final verification.
        self.file.sync_all()?;
        self.file.seek(SeekFrom::Start(0))?;

        let mut context = digest::Context::new(&digest::SHA256);
        let mut buffer = [0_u8; HASH_BUFFER_LEN];
        let mut measured = 0_u64;

        loop {
            let count = match self.file.read(&mut buffer) {
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(error) => return Err(error),
            };

            if count == 0 {
                break;
            }

            measured = measured
                .checked_add(count as u64)
                .filter(|size| *size <= self.confirmed_len)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "upload grew during verification",
                    )
                })?;

            context.update(&buffer[..count]);
        }

        if measured != self.confirmed_len || self.file.metadata()?.len() != self.confirmed_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upload file length changed during verification",
            ));
        }

        let digest = context.finish();
        let mut sha256 = [0_u8; 32];
        sha256.copy_from_slice(digest.as_ref());

        Ok((measured, sha256))
    }

    fn write_chunk(&mut self, bytes: &[u8]) -> io::Result<()> {
        #[cfg(test)]
        if let Some(length) = self.fail_write_after.take() {
            let length = length.min(bytes.len());

            self.file.write_all(&bytes[..length])?;

            return Err(io::Error::other("injected partial upload write failure"));
        }

        self.file.write_all(bytes)
    }

    fn sync_chunk(&mut self) -> io::Result<()> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_sync) {
            return Err(io::Error::other("injected upload synchronization failure"));
        }

        self.file.sync_all()
    }

    fn ensure_usable(&self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("upload file handle is disabled"));
        }

        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn confirmed_len(&self) -> u64 {
        self.confirmed_len
    }

    #[cfg(test)]
    pub(crate) fn fail_next_write_after_for_test(&mut self, length: usize) {
        self.fail_write_after = Some(length);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_sync_for_test(&mut self) {
        self.fail_sync = true;
    }
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) struct ChunkIoTiming {
    pub(crate) writes: u64,
    pub(crate) syncs: u64,
    pub(crate) write_time: std::time::Duration,
    pub(crate) sync_time: std::time::Duration,
}

#[cfg(test)]
static CHUNK_IO_TIMING: std::sync::Mutex<ChunkIoTiming> = std::sync::Mutex::new(ChunkIoTiming {
    writes: 0,
    syncs: 0,
    write_time: std::time::Duration::ZERO,
    sync_time: std::time::Duration::ZERO,
});

#[cfg(test)]
pub(crate) fn reset_chunk_io_timing_for_test() {
    let mut timing = CHUNK_IO_TIMING
        .lock()
        .unwrap_or_else(|error| error.into_inner());

    *timing = ChunkIoTiming {
        writes: 0,
        syncs: 0,
        write_time: std::time::Duration::ZERO,
        sync_time: std::time::Duration::ZERO,
    };
}

#[cfg(test)]
pub(crate) fn chunk_io_timing_for_test() -> ChunkIoTiming {
    *CHUNK_IO_TIMING
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

#[cfg(test)]
fn record_chunk_io_for_test(synchronization: bool, elapsed: std::time::Duration) {
    let mut timing = CHUNK_IO_TIMING
        .lock()
        .unwrap_or_else(|error| error.into_inner());

    if synchronization {
        timing.syncs += 1;
        timing.sync_time += elapsed;
    } else {
        timing.writes += 1;
        timing.write_time += elapsed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            loop {
                let number = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "brn-file-disk-test-{}-{number}",
                    std::process::id()
                ));

                match fs::create_dir(&path) {
                    Ok(()) => return Self { path },
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        continue;
                    }
                    Err(error) => panic!("cannot create test directory: {error}"),
                }
            }
        }

        fn file(&self) -> PathBuf {
            self.path.join("upload.part")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn expected_sha256(bytes: &[u8]) -> [u8; 32] {
        let value = digest::digest(&digest::SHA256, bytes);
        let mut output = [0; 32];
        output.copy_from_slice(value.as_ref());
        output
    }

    #[test]
    fn creates_empty_file_and_refuses_to_overwrite() {
        let directory = TestDirectory::new();
        let path = directory.file();
        let mut upload = UploadFile::create(&path).unwrap();

        assert_eq!(upload.confirmed_len(), 0);
        assert_eq!(upload.measure_sha256().unwrap(), (0, expected_sha256(b"")));

        assert!(matches!(
            UploadFile::create(&path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists
        ));
        assert_eq!(fs::read(&path).unwrap(), b"");
    }

    #[test]
    fn appends_chunks_and_hashes_actual_contents() {
        let directory = TestDirectory::new();
        let path = directory.file();
        let mut upload = UploadFile::create(&path).unwrap();

        assert_eq!(upload.append_synced(0, b"hello ").unwrap(), 6);
        assert_eq!(upload.append_synced(6, b"world").unwrap(), 11);
        assert_eq!(upload.confirmed_len(), 11);

        assert_eq!(
            upload.measure_sha256().unwrap(),
            (11, expected_sha256(b"hello world"))
        );
        assert_eq!(fs::read(&path).unwrap(), b"hello world");

        // Hashing changes the file cursor, not the next append offset.
        assert_eq!(upload.append_synced(11, b"!").unwrap(), 12);
        assert_eq!(
            upload.measure_sha256().unwrap(),
            (12, expected_sha256(b"hello world!"))
        );
    }

    #[test]
    fn rejects_invalid_chunks_without_disabling_handle() {
        let directory = TestDirectory::new();
        let mut upload = UploadFile::create(&directory.file()).unwrap();

        assert!(upload.append_synced(0, b"").is_err());
        assert!(upload.append_synced(1, b"x").is_err());

        let oversized = vec![0; MAX_CHUNK_LEN + 1];
        assert!(upload.append_synced(0, &oversized).is_err());

        assert_eq!(upload.confirmed_len(), 0);
        assert_eq!(upload.append_synced(0, b"valid").unwrap(), 5);
    }

    #[test]
    fn hashes_across_multiple_read_buffers() {
        let directory = TestDirectory::new();
        let mut upload = UploadFile::create(&directory.file()).unwrap();

        let payload = vec![0x5a; HASH_BUFFER_LEN * 2 + 17];
        let mut offset = 0;

        for chunk in payload.chunks(MAX_CHUNK_LEN) {
            offset = upload.append_synced(offset, chunk).unwrap();
        }

        assert_eq!(
            upload.measure_sha256().unwrap(),
            (payload.len() as u64, expected_sha256(&payload))
        );
    }

    #[test]
    fn unexpected_file_length_disables_future_writes() {
        let directory = TestDirectory::new();
        let path = directory.file();
        let mut upload = UploadFile::create(&path).unwrap();

        upload.append_synced(0, b"abc").unwrap();

        let mut other = OpenOptions::new().append(true).open(&path).unwrap();
        other.write_all(b"x").unwrap();
        drop(other);

        assert!(upload.append_synced(3, b"d").is_err());
        assert_eq!(upload.confirmed_len(), 3);

        // Repairing the length must not reactivate a poisoned handle.
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(3)
            .unwrap();

        assert!(upload.append_synced(3, b"d").is_err());
        assert!(upload.measure_sha256().is_err());
    }

    #[test]
    fn verification_detects_unexpected_truncation() {
        let directory = TestDirectory::new();
        let path = directory.file();
        let mut upload = UploadFile::create(&path).unwrap();

        upload.append_synced(0, b"contents").unwrap();

        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(2)
            .unwrap();

        assert!(upload.measure_sha256().is_err());
        assert!(upload.append_synced(8, b"x").is_err());
        assert_eq!(upload.confirmed_len(), 8);
    }

    #[test]
    fn partial_write_failure_keeps_old_offset_and_disables_handle() {
        let directory = TestDirectory::new();
        let path = directory.file();
        let mut upload = UploadFile::create(&path).unwrap();

        assert_eq!(upload.append_synced(0, b"abc").unwrap(), 3);

        upload.fail_write_after = Some(2);

        let error = upload.append_synced(3, b"defg").unwrap_err();

        assert_eq!(error.to_string(), "injected partial upload write failure",);

        // Two bytes reached the file, but none of this chunk was
        // confirmed.
        assert_eq!(fs::read(&path).unwrap(), b"abcde");
        assert_eq!(upload.confirmed_len(), 3);
        assert!(upload.failed);

        // Removing the unconfirmed tail must not revive the handle.
        upload.file.set_len(3).unwrap();

        assert_eq!(
            upload.append_synced(3, b"defg").unwrap_err().to_string(),
            "upload file handle is disabled",
        );
        assert!(upload.measure_sha256().is_err());

        assert_eq!(upload.confirmed_len(), 3);
        assert_eq!(fs::read(&path).unwrap(), b"abc");
    }

    #[test]
    fn synchronization_failure_keeps_old_offset_and_disables_handle() {
        let directory = TestDirectory::new();
        let path = directory.file();
        let mut upload = UploadFile::create(&path).unwrap();

        assert_eq!(upload.append_synced(0, b"abc").unwrap(), 3);

        upload.fail_sync = true;

        let error = upload.append_synced(3, b"def").unwrap_err();

        assert_eq!(error.to_string(), "injected upload synchronization failure",);

        // The complete chunk was written, but synchronization did not
        // succeed, so the confirmed offset must not advance.
        assert_eq!(fs::read(&path).unwrap(), b"abcdef");
        assert_eq!(upload.confirmed_len(), 3);
        assert!(upload.failed);

        // The injection is one-shot. Further operations must still
        // fail because the handle itself is permanently disabled.
        assert!(!upload.fail_sync);

        assert_eq!(
            upload.append_synced(3, b"def").unwrap_err().to_string(),
            "upload file handle is disabled",
        );
        assert!(upload.measure_sha256().is_err());

        assert_eq!(upload.confirmed_len(), 3);
        assert_eq!(fs::read(&path).unwrap(), b"abcdef");
    }
}
