use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use aws_lc_rs::digest;

use crate::ReadyClient;
use crate::file_upload::{FileUpload, MAX_FILE_CHUNK_LEN};

const MAX_HASH_INPUT_LEN: u64 = u64::MAX / 8;

/// Bounded local-file reader with a precomputed SHA-256 digest.
///
/// Keep the source file unchanged throughout hashing and uploading.
/// Metadata checks are best-effort change detection, not a snapshot.
///
/// Hashing and reads are synchronous filesystem operations. BRN socket
/// deadlines cannot interrupt a blocked local filesystem operation.
///
/// The source owns one reusable chunk buffer. BRN's encoding and
/// encryption layers may allocate additional bounded message buffers.
pub struct FileUploadSource {
    file: File,
    size: u64,
    sha256: [u8; 32],
    modified: Option<SystemTime>,
    buffer: Vec<u8>,
}

impl FileUploadSource {
    /// Opens and hashes a regular file.
    ///
    /// Rejects files larger than max_file_size before scanning contents.
    ///
    /// Paths must come from trusted application context. Opening a path
    /// can itself block before the regular-file check is performed.
    pub fn open(path: impl AsRef<Path>, max_file_size: u64) -> io::Result<Self> {
        Self::from_file(File::open(path)?, max_file_size)
    }

    /// Takes ownership of an already opened regular file and hashes it.
    ///
    /// Reads from the beginning regardless of the initial cursor.
    /// Do not share another writable handle to the file.
    pub fn from_file(mut file: File, max_file_size: u64) -> io::Result<Self> {
        let metadata = file.metadata()?;

        if !metadata.is_file() {
            return Err(invalid_input("upload source must be a regular file"));
        }

        let size = metadata.len();

        if size > max_file_size || size > MAX_HASH_INPUT_LEN {
            return Err(invalid_input("upload source exceeds size limit"));
        }

        if MAX_FILE_CHUNK_LEN == 0 {
            return Err(invalid_input("upload chunk capacity is zero"));
        }

        let modified = metadata.modified().ok();
        let mut buffer = vec![0_u8; MAX_FILE_CHUNK_LEN];

        file.seek(SeekFrom::Start(0))?;

        let mut context = digest::Context::new(&digest::SHA256);
        let mut measured = 0_u64;

        loop {
            let count = match file.read(&mut buffer) {
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
                .filter(|length| *length <= size)
                .ok_or_else(source_changed)?;

            context.update(&buffer[..count]);
        }

        if measured != size {
            return Err(source_changed());
        }

        check_metadata(&file.metadata()?, size, modified)?;

        let digest = context.finish();
        let mut sha256 = [0_u8; 32];
        sha256.copy_from_slice(digest.as_ref());

        file.seek(SeekFrom::Start(0))?;

        Ok(Self {
            file,
            size,
            sha256,
            modified,
            buffer,
        })
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// Begins a server upload using this source's measured metadata.
    ///
    /// On error, the connection is consumed and dropped.
    /// The source itself remains available.
    pub fn begin(
        &self,
        connection: ReadyClient,
        budget: Duration,
    ) -> io::Result<(ReadyClient, FileUpload)> {
        let started = Instant::now();
        remaining_budget(started, budget)?;

        self.check_unchanged()?;

        FileUpload::begin(
            connection,
            self.size,
            self.sha256,
            remaining_budget(started, budget)?,
        )
    }

    /// Reads at most one upload chunk at the requested byte offset.
    ///
    /// Returns an empty slice at EOF. Offsets beyond EOF are rejected.
    /// The returned slice borrows the reusable source buffer.
    ///
    /// For resumption, use a fresh server-confirmed offset.
    pub fn read_chunk(&mut self, offset: u64) -> io::Result<&[u8]> {
        self.read_chunk_limited(offset, MAX_FILE_CHUNK_LEN)
    }

    fn read_chunk_limited(&mut self, offset: u64, max_length: usize) -> io::Result<&[u8]> {
        if max_length == 0 {
            return Err(invalid_input("upload chunk capacity is zero"));
        }

        if offset > self.size {
            return Err(invalid_input("upload source offset exceeds EOF"));
        }

        self.check_unchanged()?;

        let capacity = self.buffer.len().min(max_length);

        let length = (self.size - offset).min(capacity as u64);
        let length = usize::try_from(length)
            .map_err(|_| invalid_input("upload source chunk length overflow"))?;

        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(&mut self.buffer[..length])?;

        self.check_unchanged()?;

        Ok(&self.buffer[..length])
    }

    /// Reads and sends one chunk from a server-confirmed offset.
    ///
    /// The upload checkpoint must match this source's size and digest.
    /// The checkpoint's upload ID must additionally be validated by a
    /// server status query when resuming.
    ///
    /// Returns the next confirmed offset on success.
    /// At EOF, call FileUpload::finish() instead.
    ///
    /// The budget includes local preparation and the BRN exchange.
    /// A blocked local read cannot be interrupted; budget exhaustion is
    /// checked after it returns.
    ///
    /// On any error, the connection is consumed and dropped. The server
    /// may have accepted a chunk before its acknowledgement was lost.
    pub fn send_next(
        &mut self,
        upload: &FileUpload,
        connection: ReadyClient,
        confirmed_offset: u64,
        budget: Duration,
    ) -> io::Result<(ReadyClient, u64)> {
        let started = Instant::now();
        remaining_budget(started, budget)?;

        self.check_upload(upload)?;

        let payload_limit = connection.max_request_payload_len()?;

        let chunk_limit = crate::file_wire::max_chunk_len_for_payload_limit(payload_limit)?;

        let bytes = self.read_chunk_limited(confirmed_offset, chunk_limit)?;

        if bytes.is_empty() {
            return Err(invalid_input(
                "upload source is at EOF; request final verification",
            ));
        }

        upload.send_chunk(
            connection,
            confirmed_offset,
            bytes,
            remaining_budget(started, budget)?,
        )
    }

    fn check_upload(&self, upload: &FileUpload) -> io::Result<()> {
        if upload.size() != self.size || upload.sha256() != &self.sha256 {
            return Err(invalid_input(
                "upload checkpoint does not match source metadata",
            ));
        }

        Ok(())
    }

    fn check_unchanged(&self) -> io::Result<()> {
        check_metadata(&self.file.metadata()?, self.size, self.modified)
    }
}

fn check_metadata(metadata: &Metadata, size: u64, modified: Option<SystemTime>) -> io::Result<()> {
    if !metadata.is_file() || metadata.len() != size || metadata.modified().ok() != modified {
        return Err(source_changed());
    }

    Ok(())
}

fn remaining_budget(started: Instant, budget: Duration) -> io::Result<Duration> {
    budget
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "upload source operation budget expired",
            )
        })
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn source_changed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "upload source changed")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::{self, OpenOptions};
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
                    "brn-file-source-test-{}-{number}",
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
            self.path.join("source.bin")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        let digest = digest::digest(&digest::SHA256, bytes);
        let mut output = [0; 32];
        output.copy_from_slice(digest.as_ref());
        output
    }

    #[test]
    fn hashes_regular_file_and_reads_from_explicit_offsets() {
        let directory = TestDirectory::new();
        let path = directory.file();
        fs::write(&path, b"hello world").unwrap();

        let mut source = FileUploadSource::open(&path, 100).unwrap();

        assert_eq!(source.size(), 11);
        assert_eq!(source.sha256(), &sha256(b"hello world"));

        assert_eq!(source.read_chunk(6).unwrap(), b"world");
        assert_eq!(source.read_chunk(0).unwrap(), b"hello world");
        assert!(source.read_chunk(11).unwrap().is_empty());
        assert!(source.read_chunk(12).is_err());
    }

    #[test]
    fn supports_empty_file() {
        let directory = TestDirectory::new();
        let path = directory.file();
        fs::write(&path, b"").unwrap();

        let mut source = FileUploadSource::open(&path, 0).unwrap();

        assert_eq!(source.size(), 0);
        assert_eq!(source.sha256(), &sha256(b""));
        assert!(source.read_chunk(0).unwrap().is_empty());
    }

    #[test]
    fn bounds_chunk_reads_and_handles_short_final_chunk() {
        let directory = TestDirectory::new();
        let path = directory.file();

        let bytes = vec![0x5a; MAX_FILE_CHUNK_LEN + 17];
        fs::write(&path, &bytes).unwrap();

        let mut source = FileUploadSource::open(&path, bytes.len() as u64).unwrap();

        assert_eq!(source.read_chunk(0).unwrap(), &bytes[..MAX_FILE_CHUNK_LEN]);
        assert_eq!(
            source.read_chunk(MAX_FILE_CHUNK_LEN as u64).unwrap(),
            &bytes[MAX_FILE_CHUNK_LEN..]
        );
        assert_eq!(source.sha256(), &sha256(&bytes));
    }

    #[test]
    fn rejects_file_larger_than_local_limit() {
        let directory = TestDirectory::new();
        let path = directory.file();
        fs::write(&path, b"abc").unwrap();

        assert!(matches!(
            FileUploadSource::open(&path, 2),
            Err(error) if error.kind() == io::ErrorKind::InvalidInput
        ));
    }

    #[test]
    fn detects_truncation_before_reading_next_chunk() {
        let directory = TestDirectory::new();
        let path = directory.file();
        fs::write(&path, b"contents").unwrap();

        let mut source = FileUploadSource::open(&path, 100).unwrap();

        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(2)
            .unwrap();

        assert_eq!(
            source.read_chunk(0).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn checkpoint_must_match_source_size_and_digest() {
        let directory = TestDirectory::new();
        let path = directory.file();
        fs::write(&path, b"abc").unwrap();

        let source = FileUploadSource::open(&path, 100).unwrap();

        let matching = FileUpload::from_parts([0x42; 16], source.size(), *source.sha256());
        assert!(source.check_upload(&matching).is_ok());

        let wrong_size = FileUpload::from_parts([0x42; 16], 4, *source.sha256());
        assert!(source.check_upload(&wrong_size).is_err());

        let wrong_digest = FileUpload::from_parts([0x42; 16], 3, [0; 32]);
        assert!(source.check_upload(&wrong_digest).is_err());
    }

    #[test]
    fn from_file_hashes_from_start_not_current_cursor() {
        let directory = TestDirectory::new();
        let path = directory.file();
        fs::write(&path, b"abcdef").unwrap();

        let mut file = File::open(&path).unwrap();
        file.seek(SeekFrom::Start(4)).unwrap();

        let source = FileUploadSource::from_file(file, 100).unwrap();

        assert_eq!(source.size(), 6);
        assert_eq!(source.sha256(), &sha256(b"abcdef"));
    }

    #[test]
    fn zero_operation_budget_is_rejected() {
        let error = remaining_budget(Instant::now(), Duration::ZERO).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn detects_growth_before_reading_next_chunk() {
        let directory = TestDirectory::new();
        let path = directory.file();
        fs::write(&path, b"contents").unwrap();

        let mut source = FileUploadSource::open(&path, 100).unwrap();

        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(9)
            .unwrap();

        assert_eq!(
            source.read_chunk(0).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn invalid_offset_does_not_prevent_later_valid_reads() {
        let directory = TestDirectory::new();
        let path = directory.file();
        fs::write(&path, b"abcdef").unwrap();

        let mut source = FileUploadSource::open(&path, 100).unwrap();

        assert_eq!(
            source.read_chunk(u64::MAX).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );

        assert_eq!(source.read_chunk(2).unwrap(), b"cdef");
        assert_eq!(source.read_chunk(0).unwrap(), b"abcdef");
    }

    #[test]
    fn limited_reads_preserve_offsets_and_default_read_behavior() {
        let directory = TestDirectory::new();
        let path = directory.file();

        fs::write(&path, b"abcdefghij").unwrap();

        let mut source = FileUploadSource::open(&path, 100).unwrap();

        assert_eq!(source.read_chunk_limited(0, 4).unwrap(), b"abcd");
        assert_eq!(source.read_chunk_limited(4, 4).unwrap(), b"efgh");
        assert_eq!(source.read_chunk_limited(8, 4).unwrap(), b"ij");
        assert!(source.read_chunk_limited(10, 4).unwrap().is_empty());
        assert!(source.read_chunk_limited(11, 4).is_err());
        assert!(source.read_chunk_limited(0, 0).is_err());

        assert_eq!(source.read_chunk(0).unwrap(), b"abcdefghij");
    }
}
