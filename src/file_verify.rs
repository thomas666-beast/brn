use std::io;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread;

use crate::file_disk::UploadFile;
use crate::file_wire::UploadId;

const MAX_WAITING_JOBS: usize = 1024;

/// Owns the file while verification is queued or running.
///
/// The registry must prevent chunk writes, abort, deletion, and ID
/// reuse for this upload until it processes the corresponding result.
pub(crate) struct VerificationJob {
    pub(crate) id: UploadId,
    pub(crate) file: UploadFile,
}

/// Result produced after the worker has closed the file handle.
///
/// Actual measurements must still be compared with the registry's
/// expected size and digest before marking the upload complete.
pub(crate) struct VerificationResult {
    pub(crate) id: UploadId,
    pub(crate) measured: io::Result<(u64, [u8; 32])>,
}

/// One background hashing thread with bounded input/output queues.
///
/// Job submission and result polling never wait for queue capacity.
/// Hashing and filesystem operations themselves remain blocking.
///
/// Not Clone. The registry should own this worker independently of
/// individual BRN connections.
pub(crate) struct VerificationWorker {
    jobs: SyncSender<VerificationJob>,
    results: Receiver<VerificationResult>,
}

/// Keeps queued jobs alive no longer than the result sender.
///
/// Field declaration order matters: release queued jobs before
/// exposing result-channel disconnection.
struct VerificationThread<J = VerificationJob, R = VerificationResult> {
    receiver: Receiver<J>,
    sender: SyncSender<R>,
}

impl<J, R> VerificationThread<J, R> {
    fn run_with(self, mut process: impl FnMut(J) -> R) {
        while let Ok(job) = self.receiver.recv() {
            let result = process(job);

            if self.sender.send(result).is_err() {
                break;
            }
        }
    }
}

impl VerificationThread {
    fn run(self) {
        self.run_with(|job| {
            let VerificationJob { id, mut file } = job;

            let measured = file.measure_sha256();

            // Release the active file before publishing its result.
            drop(file);

            VerificationResult { id, measured }
        });
    }
}
impl VerificationWorker {
    /// Starts one verification worker.
    ///
    /// `waiting_jobs` bounds the input queue, not the total number of
    /// jobs across the input queue, active worker, and result queue.
    ///
    /// A single worker intentionally limits simultaneous disk scans.
    pub(crate) fn new(waiting_jobs: usize) -> io::Result<Self> {
        if waiting_jobs == 0 || waiting_jobs > MAX_WAITING_JOBS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid verification queue capacity",
            ));
        }

        let (jobs, receiver) = mpsc::sync_channel::<VerificationJob>(waiting_jobs);

        let (sender, results) = mpsc::sync_channel::<VerificationResult>(waiting_jobs + 1);

        let worker = VerificationThread { receiver, sender };

        // Intentionally detached. Dropping the public endpoints does
        // not wait for a potentially blocked filesystem operation.
        //
        // Move the complete owner into run(), preserving its field
        // destruction order on normal exit and panic unwinding.
        let handle = thread::Builder::new()
            .name("brn-file-verify".to_owned())
            .spawn(move || worker.run())?;

        drop(handle);

        Ok(Self { jobs, results })
    }

    /// Attempts to enqueue a file without blocking.
    ///
    /// Both error variants return the original job, including its file:
    /// - Full: retain the file and retry later.
    /// - Disconnected: fail closed and disable verification service.
    ///
    /// The caller must not silently drop a rejected job.
    pub(crate) fn try_submit(
        &self,
        job: VerificationJob,
    ) -> Result<(), TrySendError<VerificationJob>> {
        self.jobs.try_send(job)
    }

    /// Polls one completion without blocking.
    ///
    /// Ok(None) means no result is currently available.
    /// Disconnection is reported only after buffered results drain.
    pub(crate) fn try_result(&self) -> io::Result<Option<VerificationResult>> {
        match self.results.try_recv() {
            Ok(result) => Ok(Some(result)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "file verification worker disconnected",
            )),
        }
    }
}

#[cfg(test)]
impl VerificationWorker {
    /// Creates controlled channels without starting a worker thread.
    ///
    /// Tests own the job receiver and result sender, allowing exact
    /// control over queue fullness, completion, and disconnection.
    pub(crate) fn controlled_for_test(
        capacity: usize,
    ) -> (
        Self,
        Receiver<VerificationJob>,
        SyncSender<VerificationResult>,
    ) {
        assert!(capacity > 0);

        let (jobs, job_receiver) = mpsc::sync_channel(capacity);
        let (result_sender, results) = mpsc::sync_channel(capacity);

        (Self { jobs, results }, job_receiver, result_sender)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use aws_lc_rs::digest;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            loop {
                let number = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "brn-file-verify-test-{}-{number}",
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

        fn job(&self, number: u8, bytes: &[u8]) -> VerificationJob {
            let path = self.path.join(format!("{number}.part"));
            let mut file = UploadFile::create(&path).unwrap();

            if !bytes.is_empty() {
                file.append_synced(0, bytes).unwrap();
            }

            VerificationJob {
                id: UploadId([number; 16]),
                file,
            }
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
    fn verifies_file_and_returns_matching_id() {
        let directory = TestDirectory::new();
        let worker = VerificationWorker::new(2).unwrap();

        assert!(worker.try_submit(directory.job(1, b"abc")).is_ok());

        let result = worker
            .results
            .recv_timeout(Duration::from_secs(10))
            .unwrap();

        assert_eq!(result.id, UploadId([1; 16]));
        assert_eq!(result.measured.unwrap(), (3, sha256(b"abc")));

        assert!(worker.try_result().unwrap().is_none());
    }

    #[test]
    fn verifies_empty_file() {
        let directory = TestDirectory::new();
        let worker = VerificationWorker::new(1).unwrap();

        assert!(worker.try_submit(directory.job(2, b"")).is_ok());

        let result = worker
            .results
            .recv_timeout(Duration::from_secs(10))
            .unwrap();

        assert_eq!(result.measured.unwrap(), (0, sha256(b"")));
    }

    #[test]
    fn full_queue_returns_job_without_losing_file() {
        let directory = TestDirectory::new();

        // No thread: keeping the receiver idle makes fullness
        // deterministic rather than dependent on scheduling.
        let (jobs, receiver) = mpsc::sync_channel(1);
        let (_sender, results) = mpsc::sync_channel(1);

        let worker = VerificationWorker { jobs, results };

        assert!(worker.try_submit(directory.job(3, b"first")).is_ok());

        let returned = match worker.try_submit(directory.job(4, b"second")) {
            Err(TrySendError::Full(job)) => job,
            _ => panic!("expected a full queue"),
        };

        assert_eq!(returned.id, UploadId([4; 16]));
        assert_eq!(returned.file.confirmed_len(), 6);

        drop(returned);
        drop(receiver);
    }

    #[test]
    fn disconnected_queue_returns_original_job() {
        let directory = TestDirectory::new();

        let (jobs, receiver) = mpsc::sync_channel(1);
        let (_sender, results) = mpsc::sync_channel(1);
        drop(receiver);

        let worker = VerificationWorker { jobs, results };

        let returned = match worker.try_submit(directory.job(5, b"data")) {
            Err(TrySendError::Disconnected(job)) => job,
            _ => panic!("expected a disconnected queue"),
        };

        assert_eq!(returned.id, UploadId([5; 16]));
        assert_eq!(returned.file.confirmed_len(), 4);
    }

    #[test]
    fn reports_result_channel_disconnection() {
        let (jobs, _receiver) = mpsc::sync_channel(1);
        let (sender, results) = mpsc::sync_channel(1);
        drop(sender);

        let worker = VerificationWorker { jobs, results };

        let error = match worker.try_result() {
            Err(error) => error,
            Ok(_) => panic!("expected result-channel disconnection"),
        };

        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn rejects_invalid_queue_capacities() {
        assert!(matches!(
            VerificationWorker::new(0),
            Err(error) if error.kind() == io::ErrorKind::InvalidInput
        ));

        assert!(matches!(
            VerificationWorker::new(MAX_WAITING_JOBS + 1),
            Err(error) if error.kind() == io::ErrorKind::InvalidInput
        ));
    }

    #[test]
    #[cfg(panic = "unwind")]
    fn worker_panic_releases_active_and_queued_jobs_before_disconnect() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicUsize;

        struct TrackedJob {
            dropped: Arc<AtomicUsize>,
        }

        impl Drop for TrackedJob {
            fn drop(&mut self) {
                self.dropped.fetch_add(1, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicUsize::new(0));

        let (jobs, receiver) = mpsc::sync_channel::<TrackedJob>(2);
        let (sender, results) = mpsc::sync_channel::<()>(1);

        // Queue both jobs before starting the worker. When the first
        // job is processed, the second must still be queued.
        for _ in 0..2 {
            assert!(
                jobs.send(TrackedJob {
                    dropped: Arc::clone(&dropped),
                })
                .is_ok()
            );
        }

        let worker = VerificationThread { receiver, sender };

        let handle = thread::spawn(move || {
            worker.run_with(|job| -> () {
                assert_eq!(
                    job.dropped.load(Ordering::SeqCst),
                    0,
                    "a job was released before processing began",
                );

                panic!("injected verification worker panic");
            });
        });

        // No result is sent. Disconnection must become observable only
        // after both active and queued job ownership has been released.
        assert!(matches!(
            results.recv_timeout(Duration::from_secs(10)),
            Err(mpsc::RecvTimeoutError::Disconnected),
        ));

        assert_eq!(
            dropped.load(Ordering::SeqCst),
            2,
            "result channel disconnected before all jobs were released",
        );

        assert!(
            handle.join().is_err(),
            "worker did not propagate the injected panic",
        );
    }
}
