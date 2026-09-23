use std::collections::HashSet;
use std::io::{self, BufReader, Read, Write};
use std::num::NonZeroUsize;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::vector::{
    CKKS_SCHEME, CkksBatchEncryptionInput, CkksEncryptedQueryScoreBatchInput,
    CkksEncryptedQueryScoreInput, CkksEncryptionInput, CkksError, CkksParameters,
    CkksPlaintextQueryScoreBatchInput, CkksPlaintextQueryScoreInput, CkksQueryEncryptionInput,
    CkksVectorBackend,
};

/// How long a request waits for a busy bridge worker before failing.
const WORKER_RESERVATION_WAIT: Duration = Duration::from_secs(5);
/// Poll interval while waiting for a bridge worker.
const WORKER_RESERVATION_POLL: Duration = Duration::from_millis(5);

const DEFAULT_BRIDGE_TIMEOUT: Duration = Duration::from_secs(30);
/// Per-line stdout (and total stderr) budget for a bridge worker. Sized so a batch of
/// `MAX_BRIDGE_CIPHERTEXT_BYTES` ciphertexts fits; the previous 1 MiB default truncated any
/// response carrying a full-size CKKS ciphertext and killed the worker.
const DEFAULT_MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const MIN_OPENFHE_SECURITY_LEVEL_BITS: u16 = 128;
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;
const MAX_BRIDGE_PROGRAM_SHA256_BYTES: u64 = 64 * 1024 * 1024;
const MAX_BRIDGE_CIPHERTEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_BRIDGE_CIPHERTEXT_B64_LEN: usize = MAX_BRIDGE_CIPHERTEXT_BYTES.div_ceil(3) * 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BridgeSandbox {
    ProcessHardening,
    LinuxLandlockWriteDeny,
    LinuxLandlockWriteDenyNetworkNamespace,
    /// Write-deny plus a read/execute allow-list: the system roots, the program itself and the
    /// configured read roots are the only paths the bridge can read or execute.
    LinuxLandlockStrict,
    LinuxLandlockStrictNetworkNamespace,
}

#[derive(Clone)]
pub struct CommandOpenFheBackend {
    program: PathBuf,
    args: Vec<String>,
    timeout: Duration,
    max_output_bytes: usize,
    pool_size: NonZeroUsize,
    checked_program: bool,
    expected_sha256_b64: Option<String>,
    sandbox: BridgeSandbox,
    /// Extra paths the strict Landlock sandbox lets the bridge read (Linux only).
    landlock_read_allow_roots: Vec<PathBuf>,
    sensitive_env_names: Vec<String>,
    workers: Arc<Mutex<Vec<Arc<WorkerProcess>>>>,
    /// Workers being spawned outside the `workers` lock; counted against `pool_size`.
    spawning: Arc<AtomicUsize>,
}

impl std::fmt::Debug for CommandOpenFheBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandOpenFheBackend")
            .field("program", &"[redacted]")
            .field("args_count", &self.args.len())
            .field("timeout", &self.timeout)
            .field("max_output_bytes", &self.max_output_bytes)
            .field("pool_size", &self.pool_size)
            .field("checked_program", &self.checked_program)
            .field(
                "expected_sha256_b64",
                &self.expected_sha256_b64.as_ref().map(|_| "<configured>"),
            )
            .field("sandbox", &self.sandbox)
            .field(
                "landlock_read_allow_roots_count",
                &self.landlock_read_allow_roots.len(),
            )
            .field("sensitive_env_names_count", &self.sensitive_env_names.len())
            .finish()
    }
}

impl PartialEq for CommandOpenFheBackend {
    fn eq(&self, other: &Self) -> bool {
        self.program == other.program
            && self.args == other.args
            && self.timeout == other.timeout
            && self.max_output_bytes == other.max_output_bytes
            && self.pool_size == other.pool_size
            && self.checked_program == other.checked_program
            && self.expected_sha256_b64 == other.expected_sha256_b64
            && self.sandbox == other.sandbox
            && self.landlock_read_allow_roots == other.landlock_read_allow_roots
            && self.sensitive_env_names == other.sensitive_env_names
    }
}

impl Eq for CommandOpenFheBackend {}

struct WorkerProcess {
    child: Mutex<Child>,
    stdin: Mutex<ChildStdin>,
    stdout_rx: Mutex<mpsc::Receiver<BridgeStdoutEvent>>,
    stderr_truncated: Arc<AtomicBool>,
    registered_contexts: Mutex<HashSet<String>>,
    terminated: AtomicBool,
    reserved: AtomicBool,
    reader_threads: Mutex<WorkerReaderThreads>,
}

#[derive(Default)]
struct WorkerReaderThreads {
    stdout: Option<JoinHandle<()>>,
    stderr: Option<JoinHandle<io::Result<()>>>,
}

struct WorkerReservation {
    worker_process: Arc<WorkerProcess>,
}

enum BridgeStdoutEvent {
    Response { bytes: Vec<u8>, truncated: bool },
    Eof,
    Error(io::Error),
    StderrExceeded,
}

impl WorkerProcess {
    fn try_reserve_request(&self) -> bool {
        self.reserved
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn release_request(&self) {
        self.reserved.store(false, Ordering::Release);
    }

    fn try_wait(&self) -> Result<Option<ExitStatus>, CkksError> {
        self.child
            .lock()
            .map_err(|_| CkksError::Backend("OpenFHE bridge child mutex was poisoned".to_string()))?
            .try_wait()
            .map_err(|err| {
                CkksError::Backend(format!("failed to poll OpenFHE bridge status: {err}"))
            })
    }

    fn shutdown(&self, join_readers: bool) -> Result<(), CkksError> {
        if !self.terminated.swap(true, Ordering::SeqCst) {
            let mut child = self.child.lock().map_err(|_| {
                CkksError::Backend("OpenFHE bridge child mutex was poisoned".to_string())
            })?;
            #[cfg(target_os = "linux")]
            {
                // The bridge runs in its own session (`setsid` in `pre_exec`), so its process
                // group is exactly the bridge plus whatever it forked. Kill all of it, or a
                // grandchild keeps the pipes and the last plaintext request alive.
                if let Ok(pgid) = nix::libc::pid_t::try_from(child.id()) {
                    // SAFETY: plain syscall on a pid this process created and still owns.
                    unsafe {
                        nix::libc::kill(-pgid, nix::libc::SIGKILL);
                    }
                }
            }
            let _ = child.kill();
            let _ = child.wait();
        }

        if join_readers {
            let WorkerReaderThreads {
                stdout: stdout_thread,
                stderr: stderr_thread,
            } = self.take_reader_threads()?;
            if let Some(stdout_thread) = stdout_thread {
                stdout_thread
                    .join()
                    .map_err(|_| CkksError::Backend("bridge stdout reader panicked".to_string()))?;
            }
            if let Some(stderr_thread) = stderr_thread {
                stderr_thread
                    .join()
                    .map_err(|_| CkksError::Backend("bridge stderr reader panicked".to_string()))?
                    .map_err(|err| {
                        CkksError::Backend(format!("failed to drain OpenFHE bridge stderr: {err}"))
                    })?;
            }
        } else if let Ok(mut reader_threads) = self.reader_threads.lock() {
            let _ = std::mem::take(&mut *reader_threads);
        }

        Ok(())
    }

    fn take_reader_threads(&self) -> Result<WorkerReaderThreads, CkksError> {
        let mut reader_threads = self.reader_threads.lock().map_err(|_| {
            CkksError::Backend("OpenFHE bridge reader thread mutex was poisoned".to_string())
        })?;
        Ok(std::mem::take(&mut *reader_threads))
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        // Whichever path dropped the last reference (pool reset, concurrent backend drops), the
        // bridge must not outlive its pool unkilled or unreaped.
        let _ = self.shutdown(false);
    }
}

/// Releases a reserved-but-not-yet-pushed pool slot when the spawn finishes or fails.
struct SpawnSlot(Arc<AtomicUsize>);

impl Drop for SpawnSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl WorkerReservation {
    fn reserved(worker_process: Arc<WorkerProcess>) -> Self {
        Self { worker_process }
    }

    fn worker(&self) -> &Arc<WorkerProcess> {
        &self.worker_process
    }
}

impl Drop for WorkerReservation {
    fn drop(&mut self) {
        self.worker_process.release_request();
    }
}

impl CommandOpenFheBackend {
    fn new_unchecked(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            timeout: DEFAULT_BRIDGE_TIMEOUT,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            pool_size: NonZeroUsize::MIN,
            checked_program: false,
            expected_sha256_b64: None,
            sandbox: BridgeSandbox::ProcessHardening,
            landlock_read_allow_roots: Vec::new(),
            sensitive_env_names: Vec::new(),
            workers: Arc::new(Mutex::new(Vec::new())),
            spawning: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn new_checked(program: impl Into<PathBuf>) -> Result<Self, CkksError> {
        let program = program.into();
        validate_checked_bridge_program(&program)?;
        ensure_checked_bridge_spawn_supported()?;

        let mut backend = Self::new_unchecked(program);
        backend.checked_program = true;
        Ok(backend)
    }

    pub fn new_checked_with_sha256_b64(
        program: impl Into<PathBuf>,
        expected_sha256_b64: impl AsRef<str>,
    ) -> Result<Self, CkksError> {
        let program = program.into();
        let expected_sha256_b64 = expected_sha256_b64.as_ref().to_string();
        validate_checked_bridge_program(&program)?;
        validate_bridge_program_sha256_b64(&program, &expected_sha256_b64)?;
        ensure_checked_bridge_spawn_supported()?;

        let mut backend = Self::new_unchecked(program);
        backend.checked_program = true;
        backend.expected_sha256_b64 = Some(expected_sha256_b64);
        Ok(backend)
    }

    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self.reset_worker_pool_after_policy_change();
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.reset_worker_pool_after_policy_change();
        self
    }

    pub fn with_max_output_bytes(mut self, max_output_bytes: usize) -> Self {
        self.max_output_bytes = max_output_bytes;
        self.reset_worker_pool_after_policy_change();
        self
    }

    pub fn with_pool_size(mut self, pool_size: NonZeroUsize) -> Self {
        self.pool_size = pool_size;
        self.reset_worker_pool_after_policy_change();
        self
    }

    pub fn with_linux_landlock_write_deny_sandbox(mut self) -> Self {
        self.sandbox = BridgeSandbox::LinuxLandlockWriteDeny;
        self.reset_worker_pool_after_policy_change();
        self
    }

    pub fn with_linux_landlock_write_deny_network_namespace_sandbox(mut self) -> Self {
        self.sandbox = BridgeSandbox::LinuxLandlockWriteDenyNetworkNamespace;
        self.reset_worker_pool_after_policy_change();
        self
    }

    /// Landlock write-deny plus a read/execute allow-list (Linux). The bridge can read and
    /// execute only the system roots (`/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/etc`), read
    /// `/dev/null`, `/dev/urandom` and `/dev/random`, read and execute the program itself, and
    /// read the roots configured with [`Self::with_linux_landlock_read_allow_roots`]. Storage,
    /// configuration and key material stay unreadable even if the bridge is compromised.
    pub fn with_linux_landlock_strict_sandbox(mut self) -> Self {
        self.sandbox = BridgeSandbox::LinuxLandlockStrict;
        self.reset_worker_pool_after_policy_change();
        self
    }

    /// [`Self::with_linux_landlock_strict_sandbox`] plus a private network namespace.
    pub fn with_linux_landlock_strict_network_namespace_sandbox(mut self) -> Self {
        self.sandbox = BridgeSandbox::LinuxLandlockStrictNetworkNamespace;
        self.reset_worker_pool_after_policy_change();
        self
    }

    /// Directories or files the strict Landlock sandbox additionally lets the bridge read, for
    /// example an OpenFHE data directory outside the system roots. Every root must be an
    /// absolute, normalized path other than `/`; a root that cannot be opened when a worker
    /// starts fails the spawn instead of silently narrowing the policy.
    pub fn with_linux_landlock_read_allow_roots<I, P>(mut self, roots: I) -> Result<Self, CkksError>
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        let mut validated: Vec<PathBuf> = Vec::new();
        for root in roots {
            let root = root.into();
            validate_landlock_read_allow_root(&root)?;
            if !validated.contains(&root) {
                validated.push(root);
            }
        }
        if validated.len() > MAX_LANDLOCK_READ_ALLOW_ROOTS {
            return Err(CkksError::Backend(format!(
                "at most {MAX_LANDLOCK_READ_ALLOW_ROOTS} Landlock read-allow roots are supported"
            )));
        }
        self.landlock_read_allow_roots = validated;
        self.reset_worker_pool_after_policy_change();
        Ok(self)
    }

    pub fn with_sensitive_env_names<I, S>(mut self, env_names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.sensitive_env_names = env_names
            .into_iter()
            .map(Into::into)
            .filter(|name| !name.is_empty())
            .collect();
        self.reset_worker_pool_after_policy_change();
        self
    }

    fn reset_worker_pool_after_policy_change(&mut self) {
        self.workers = Arc::new(Mutex::new(Vec::new()));
    }
}

#[cfg(target_os = "linux")]
#[allow(
    clippy::unnecessary_wraps,
    reason = "signature shared with the non-Linux variant"
)]
fn ensure_checked_bridge_spawn_supported() -> Result<(), CkksError> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_checked_bridge_spawn_supported() -> Result<(), CkksError> {
    Err(CkksError::Backend(
        "OpenFHE checked bridge spawn requires Linux fd-backed /proc/self/fd execution".to_string(),
    ))
}

fn validate_checked_bridge_program(path: &Path) -> Result<(), CkksError> {
    if !path.is_absolute() {
        return Err(CkksError::Backend(
            "OpenFHE bridge program must be an absolute path".to_string(),
        ));
    }

    let link_metadata = fs_err::symlink_metadata(path).map_err(|err| {
        CkksError::Backend(format!("failed to inspect OpenFHE bridge program: {err}"))
    })?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
        return Err(CkksError::Backend(
            "OpenFHE bridge program must be a regular non-symlink file".to_string(),
        ));
    }

    let metadata = fs_err::metadata(path).map_err(|err| {
        CkksError::Backend(format!("failed to inspect OpenFHE bridge program: {err}"))
    })?;
    if !metadata.is_file() {
        return Err(CkksError::Backend(
            "OpenFHE bridge program must be a regular file".to_string(),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        unsafe extern "C" {
            fn geteuid() -> u32;
        }

        let mode = metadata.permissions().mode();
        if mode & 0o111 == 0 || mode & 0o022 != 0 {
            return Err(CkksError::Backend(
                "OpenFHE bridge program must be executable and not group/world-writable"
                    .to_string(),
            ));
        }

        let effective_uid = unsafe { geteuid() };
        let owner = metadata.uid();
        if owner != 0 && owner != effective_uid {
            return Err(CkksError::Backend(
                "OpenFHE bridge program must be owned by root or the qdrant process user"
                    .to_string(),
            ));
        }

        let mut parent = path.parent();
        while let Some(directory) = parent {
            let directory_metadata = fs_err::symlink_metadata(directory).map_err(|err| {
                CkksError::Backend(format!(
                    "failed to inspect OpenFHE bridge parent directory: {err}"
                ))
            })?;
            if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
                return Err(CkksError::Backend(
                    "OpenFHE bridge parent path must be a regular directory".to_string(),
                ));
            }
            if directory_metadata.permissions().mode() & 0o022 != 0 {
                return Err(CkksError::Backend(
                    "OpenFHE bridge parent directory must not be group/world-writable".to_string(),
                ));
            }
            let owner = directory_metadata.uid();
            if owner != 0 && owner != effective_uid {
                return Err(CkksError::Backend(
                    "OpenFHE bridge parent directory must be owned by root or the qdrant process user".to_string(),
                ));
            }
            parent = directory.parent();
        }
    }

    Ok(())
}

fn validate_bridge_program_sha256_b64(
    path: &Path,
    expected_sha256_b64: &str,
) -> Result<(), CkksError> {
    let expected = decode_bridge_sha256_pin(path, expected_sha256_b64)?;
    let actual = hash_bridge_program_for_sha256(path)?;
    validate_bridge_sha256_digest(path, &expected, &actual)
}

fn decode_bridge_sha256_pin(_path: &Path, expected_sha256_b64: &str) -> Result<Vec<u8>, CkksError> {
    if expected_sha256_b64.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(CkksError::Backend(
            "OpenFHE bridge sha256 pin must decode to 32 bytes".to_string(),
        ));
    }
    let expected = BASE64URL_NOPAD
        .decode(expected_sha256_b64.as_bytes())
        .map_err(|_| {
            CkksError::Backend("OpenFHE bridge sha256 pin must be base64url-no-padding".to_string())
        })?;
    if expected.len() != 32 {
        return Err(CkksError::Backend(
            "OpenFHE bridge sha256 pin must decode to 32 bytes".to_string(),
        ));
    }

    Ok(expected)
}

fn validate_bridge_sha256_digest(
    _path: &Path,
    expected: &[u8],
    actual: &[u8],
) -> Result<(), CkksError> {
    if !constant_time_eq::constant_time_eq(actual, expected) {
        return Err(CkksError::Backend(
            "OpenFHE bridge sha256 pin does not match".to_string(),
        ));
    }

    Ok(())
}

struct BridgeSpawnProgram {
    path: PathBuf,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fd: Option<fs_err::File>,
    /// Shebang scripts are re-read through `/proc/self/fd/<fd>` by their interpreter after
    /// exec, so that descriptor must survive exec; binaries are executed directly and keep it
    /// close-on-exec.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    inherit_fd_after_exec: bool,
}

impl BridgeSpawnProgram {
    fn path(&self) -> &Path {
        &self.path
    }

    /// The validated program descriptor; `pre_exec` keeps it open because the exec path names it.
    #[cfg(target_os = "linux")]
    fn keep_fd(&self) -> Option<i32> {
        use std::os::fd::AsRawFd;
        self.fd.as_ref().map(|file| file.as_raw_fd())
    }

    /// The descriptor the bridge may keep after exec, if any.
    #[cfg(target_os = "linux")]
    fn inherit_fd(&self) -> Option<i32> {
        self.inherit_fd_after_exec.then(|| self.keep_fd()).flatten()
    }
}

fn bridge_spawn_program(
    program: &Path,
    checked_program: bool,
    expected_sha256_b64: Option<&str>,
) -> Result<BridgeSpawnProgram, CkksError> {
    if !checked_program {
        return Ok(BridgeSpawnProgram {
            path: program.to_path_buf(),
            fd: None,
            inherit_fd_after_exec: false,
        });
    }

    checked_bridge_spawn_program(program, expected_sha256_b64)
}

#[cfg(target_os = "linux")]
fn checked_bridge_spawn_program(
    program: &Path,
    expected_sha256_b64: Option<&str>,
) -> Result<BridgeSpawnProgram, CkksError> {
    use std::os::fd::AsRawFd;

    use fs_err::OpenOptions;
    use fs_err::os::unix::fs::OpenOptionsExt;

    validate_checked_bridge_program(program)?;

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(program)
        .map_err(|err| {
            CkksError::Backend(format!(
                "failed to open OpenFHE bridge program for checked spawn: {err}"
            ))
        })?;
    let metadata = file.metadata().map_err(|err| {
        CkksError::Backend(format!(
            "failed to inspect OpenFHE bridge program for checked spawn: {err}"
        ))
    })?;
    if !metadata.is_file() {
        return Err(CkksError::Backend(
            "OpenFHE bridge program must remain a regular file for checked spawn".to_string(),
        ));
    }
    validate_bridge_program_size(program, metadata.len())?;

    let mut prefix = [0u8; 2];
    let prefix_len = file.read(&mut prefix).map_err(|err| {
        CkksError::Backend(format!(
            "failed to read OpenFHE bridge program for checked spawn: {err}"
        ))
    })?;
    let is_shebang_script = prefix_len == 2 && prefix == *b"#!";

    if let Some(expected_sha256_b64) = expected_sha256_b64 {
        let expected = decode_bridge_sha256_pin(program, expected_sha256_b64)?;
        let actual = hash_bridge_program_reader(program, &mut file, &prefix[..prefix_len])?;
        validate_bridge_sha256_digest(program, &expected, &actual)?;
    }
    // Shebang interpreters reopen /proc/self/fd/<fd> after exec, so the script fd must be
    // inherited; production bridge binaries keep FD_CLOEXEC and do not inherit it. The flag is
    // cleared inside `pre_exec`, in the child only: clearing it here would let every other
    // process spawned in the meantime inherit the descriptor.
    Ok(BridgeSpawnProgram {
        path: PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())),
        fd: Some(file),
        inherit_fd_after_exec: is_shebang_script,
    })
}

#[cfg(not(target_os = "linux"))]
fn checked_bridge_spawn_program(
    program: &Path,
    expected_sha256_b64: Option<&str>,
) -> Result<BridgeSpawnProgram, CkksError> {
    validate_checked_bridge_program(program)?;
    if let Some(expected_sha256_b64) = expected_sha256_b64 {
        validate_bridge_program_sha256_b64(program, expected_sha256_b64)?;
    }
    Err(CkksError::Backend(
        "OpenFHE checked bridge spawn requires Linux fd-backed /proc/self/fd execution".to_string(),
    ))
}

#[cfg(unix)]
fn hash_bridge_program_for_sha256(path: &Path) -> Result<[u8; 32], CkksError> {
    use fs_err::OpenOptions;
    use fs_err::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|err| {
            CkksError::Backend(format!(
                "failed to open OpenFHE bridge program for sha256 pinning: {err}"
            ))
        })?;
    let metadata = file.metadata().map_err(|err| {
        CkksError::Backend(format!(
            "failed to inspect OpenFHE bridge program for sha256 pinning: {err}"
        ))
    })?;
    if !metadata.is_file() {
        return Err(CkksError::Backend(
            "OpenFHE bridge program must remain a regular file while hashing sha256 pin"
                .to_string(),
        ));
    }
    validate_bridge_program_size(path, metadata.len())?;

    hash_bridge_program_reader(path, &mut file, &[])
}

#[cfg(not(unix))]
fn hash_bridge_program_for_sha256(path: &Path) -> Result<[u8; 32], CkksError> {
    let mut file = fs_err::File::open(path).map_err(|err| {
        CkksError::Backend(format!(
            "failed to read OpenFHE bridge program for sha256 pinning: {err}"
        ))
    })?;
    let metadata = file.metadata().map_err(|err| {
        CkksError::Backend(format!(
            "failed to inspect OpenFHE bridge program for sha256 pinning: {err}"
        ))
    })?;
    if !metadata.is_file() {
        return Err(CkksError::Backend(
            "OpenFHE bridge program must remain a regular file while hashing sha256 pin"
                .to_string(),
        ));
    }
    validate_bridge_program_size(path, metadata.len())?;
    hash_bridge_program_reader(path, &mut file, &[])
}

fn validate_bridge_program_size(_path: &Path, size: u64) -> Result<(), CkksError> {
    if size > MAX_BRIDGE_PROGRAM_SHA256_BYTES {
        return Err(CkksError::Backend(format!(
            "OpenFHE bridge program exceeds {MAX_BRIDGE_PROGRAM_SHA256_BYTES} bytes while hashing sha256 pin",
        )));
    }
    Ok(())
}

fn hash_bridge_program_reader(
    _path: &Path,
    reader: &mut impl Read,
    initial_bytes: &[u8],
) -> Result<[u8; 32], CkksError> {
    let mut hasher = Sha256::new();
    let mut total_read = initial_bytes.len() as u64;
    if total_read > MAX_BRIDGE_PROGRAM_SHA256_BYTES {
        return Err(CkksError::Backend(format!(
            "OpenFHE bridge program exceeds {MAX_BRIDGE_PROGRAM_SHA256_BYTES} bytes while hashing sha256 pin",
        )));
    }
    hasher.update(initial_bytes);

    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(|err| {
            CkksError::Backend(format!(
                "failed to read OpenFHE bridge program for sha256 pinning: {err}"
            ))
        })?;
        if read == 0 {
            break;
        }
        total_read = total_read.checked_add(read as u64).ok_or_else(|| {
            CkksError::Backend(format!(
                "OpenFHE bridge program exceeds {MAX_BRIDGE_PROGRAM_SHA256_BYTES} bytes while hashing sha256 pin",
            ))
        })?;
        if total_read > MAX_BRIDGE_PROGRAM_SHA256_BYTES {
            return Err(CkksError::Backend(format!(
                "OpenFHE bridge program exceeds {MAX_BRIDGE_PROGRAM_SHA256_BYTES} bytes while hashing sha256 pin",
            )));
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hasher.finalize().into())
}

impl Drop for CommandOpenFheBackend {
    fn drop(&mut self) {
        if Arc::strong_count(&self.workers) != 1 {
            return;
        }
        if let Ok(mut workers) = self.workers.lock() {
            for worker in workers.drain(..) {
                let _ = worker.shutdown(false);
            }
        }
    }
}

impl CkksVectorBackend for CommandOpenFheBackend {
    fn encrypt(&self, input: CkksEncryptionInput<'_>) -> Result<Vec<u8>, CkksError> {
        let context_id = input.public_material.digest_for(input.parameters);
        let request = CommandOpenFheRequest {
            version: 1,
            operation: "encrypt",
            scheme: CKKS_SCHEME,
            collection: input.collection,
            point_id: input.point_id,
            vector_name: input.vector_name,
            context_id: context_id.clone(),
            parameters: Some(input.parameters),
            crypto_context: Some(BASE64URL_NOPAD.encode(input.public_material.crypto_context())),
            public_key: Some(BASE64URL_NOPAD.encode(input.public_material.public_key())),
            values: input.values,
        };
        let request_bytes = serialize_bridge_request(&request, "OpenFHE bridge request")?;
        let cached_request_bytes =
            serialize_bridge_request_without_public_material(&request, "OpenFHE bridge request")?;

        let expected_security_profile = expected_security_profile(input.parameters)?;
        self.send_bridge_request_with_context(
            &context_id,
            &request_bytes,
            &cached_request_bytes,
            |response_bytes| {
                decode_single_bridge_response(response_bytes, expected_security_profile)
            },
        )
    }

    fn encrypt_batch(
        &self,
        input: CkksBatchEncryptionInput<'_>,
    ) -> Result<Vec<Vec<u8>>, CkksError> {
        if input.items.is_empty() {
            return Ok(Vec::new());
        }
        if input.items.len() == 1 {
            let item = input.items[0];
            return self
                .encrypt(CkksEncryptionInput {
                    parameters: input.parameters,
                    public_material: input.public_material,
                    collection: input.collection,
                    point_id: item.point_id,
                    vector_name: input.vector_name,
                    values: item.values,
                })
                .map(|ciphertext| vec![ciphertext]);
        }

        let items: Vec<_> = input
            .items
            .iter()
            .map(|item| CommandOpenFheBatchItem {
                point_id: item.point_id,
                values: item.values,
            })
            .collect();
        let context_id = input.public_material.digest_for(input.parameters);
        let request = CommandOpenFheBatchRequest {
            version: 1,
            operation: "encrypt_batch",
            scheme: CKKS_SCHEME,
            collection: input.collection,
            vector_name: input.vector_name,
            context_id: context_id.clone(),
            parameters: Some(input.parameters),
            crypto_context: Some(BASE64URL_NOPAD.encode(input.public_material.crypto_context())),
            public_key: Some(BASE64URL_NOPAD.encode(input.public_material.public_key())),
            items,
        };
        let request_bytes = serialize_bridge_request(&request, "OpenFHE bridge batch request")?;
        let cached_request_bytes = serialize_bridge_request_without_public_material(
            &request,
            "OpenFHE bridge batch request",
        )?;

        let expected_security_profile = expected_security_profile(input.parameters)?;
        self.send_bridge_request_with_context(
            &context_id,
            &request_bytes,
            &cached_request_bytes,
            |response_bytes| {
                decode_batch_bridge_response(
                    response_bytes,
                    input.items.len(),
                    expected_security_profile,
                )
            },
        )
    }

    fn encrypt_query(&self, input: CkksQueryEncryptionInput<'_>) -> Result<Vec<u8>, CkksError> {
        let context_id = input.public_material.digest_for(input.parameters);
        let request = CommandOpenFheQueryRequest {
            version: 1,
            operation: "encrypt_query",
            scheme: CKKS_SCHEME,
            collection: input.collection,
            vector_name: input.vector_name,
            context_id: context_id.clone(),
            parameters: Some(input.parameters),
            crypto_context: Some(BASE64URL_NOPAD.encode(input.public_material.crypto_context())),
            public_key: Some(BASE64URL_NOPAD.encode(input.public_material.public_key())),
            values: input.values,
        };
        let request_bytes =
            serialize_bridge_request(&request, "OpenFHE bridge query encryption request")?;
        let cached_request_bytes = serialize_bridge_request_without_public_material(
            &request,
            "OpenFHE bridge query encryption request",
        )?;

        let expected_security_profile = expected_security_profile(input.parameters)?;
        self.send_bridge_request_with_context(
            &context_id,
            &request_bytes,
            &cached_request_bytes,
            |response_bytes| {
                decode_single_bridge_response(response_bytes, expected_security_profile)
            },
        )
    }

    fn score_plaintext_query(
        &self,
        input: CkksPlaintextQueryScoreInput<'_>,
    ) -> Result<f64, CkksError> {
        let context_id = input.public_material.digest_for(input.parameters);
        let request = CommandOpenFheScoreRequest {
            version: 1,
            operation: "score_plaintext_query",
            scheme: CKKS_SCHEME,
            collection: input.collection,
            point_id: input.point_id,
            vector_name: input.vector_name,
            distance: input.distance,
            context_id: context_id.clone(),
            parameters: Some(input.parameters),
            crypto_context: Some(BASE64URL_NOPAD.encode(input.public_material.crypto_context())),
            public_key: Some(BASE64URL_NOPAD.encode(input.public_material.public_key())),
            query_values: input.query_values,
            ciphertext: BASE64URL_NOPAD.encode(input.ciphertext),
        };
        let request_bytes = serialize_bridge_request(&request, "OpenFHE bridge score request")?;
        let cached_request_bytes = serialize_bridge_request_without_public_material(
            &request,
            "OpenFHE bridge score request",
        )?;

        let expected_security_profile = expected_security_profile(input.parameters)?;
        self.send_bridge_request_with_context(
            &context_id,
            &request_bytes,
            &cached_request_bytes,
            |response_bytes| {
                decode_score_bridge_response(response_bytes, expected_security_profile)
            },
        )
    }

    fn score_plaintext_query_batch(
        &self,
        input: CkksPlaintextQueryScoreBatchInput<'_>,
    ) -> Result<Vec<f64>, CkksError> {
        if input.items.is_empty() {
            return Ok(Vec::new());
        }
        if input.items.len() == 1 {
            let item = input.items[0];
            return self
                .score_plaintext_query(CkksPlaintextQueryScoreInput {
                    parameters: input.parameters,
                    public_material: input.public_material,
                    collection: input.collection,
                    point_id: item.point_id,
                    vector_name: input.vector_name,
                    distance: input.distance,
                    query_values: input.query_values,
                    ciphertext: item.ciphertext,
                })
                .map(|score| vec![score]);
        }

        let items = input
            .items
            .iter()
            .map(|item| CommandOpenFheScoreBatchItem {
                point_id: item.point_id,
                ciphertext: BASE64URL_NOPAD.encode(item.ciphertext),
            })
            .collect::<Vec<_>>();
        let context_id = input.public_material.digest_for(input.parameters);
        let request = CommandOpenFheScoreBatchRequest {
            version: 1,
            operation: "score_plaintext_query_batch",
            scheme: CKKS_SCHEME,
            collection: input.collection,
            vector_name: input.vector_name,
            distance: input.distance,
            context_id: context_id.clone(),
            parameters: Some(input.parameters),
            crypto_context: Some(BASE64URL_NOPAD.encode(input.public_material.crypto_context())),
            public_key: Some(BASE64URL_NOPAD.encode(input.public_material.public_key())),
            query_values: input.query_values,
            items,
        };
        let request_bytes =
            serialize_bridge_request(&request, "OpenFHE bridge score batch request")?;
        let cached_request_bytes = serialize_bridge_request_without_public_material(
            &request,
            "OpenFHE bridge score batch request",
        )?;

        let expected_security_profile = expected_security_profile(input.parameters)?;
        self.send_bridge_request_with_context(
            &context_id,
            &request_bytes,
            &cached_request_bytes,
            |response_bytes| {
                decode_score_batch_bridge_response(
                    response_bytes,
                    input.items.len(),
                    expected_security_profile,
                )
            },
        )
    }

    fn score_encrypted_query(
        &self,
        input: CkksEncryptedQueryScoreInput<'_>,
    ) -> Result<f64, CkksError> {
        let context_id = input.public_material.digest_for(input.parameters);
        let request = CommandOpenFheEncryptedScoreRequest {
            version: 1,
            operation: "score_encrypted_query",
            scheme: CKKS_SCHEME,
            collection: input.collection,
            point_id: input.point_id,
            vector_name: input.vector_name,
            distance: input.distance,
            context_id: context_id.clone(),
            parameters: Some(input.parameters),
            crypto_context: Some(BASE64URL_NOPAD.encode(input.public_material.crypto_context())),
            public_key: Some(BASE64URL_NOPAD.encode(input.public_material.public_key())),
            encrypted_query: BASE64URL_NOPAD.encode(input.encrypted_query),
            ciphertext: BASE64URL_NOPAD.encode(input.ciphertext),
        };
        let request_bytes =
            serialize_bridge_request(&request, "OpenFHE bridge encrypted-query score request")?;
        let cached_request_bytes = serialize_bridge_request_without_public_material(
            &request,
            "OpenFHE bridge encrypted-query score request",
        )?;

        let expected_security_profile = expected_security_profile(input.parameters)?;
        self.send_bridge_request_with_context(
            &context_id,
            &request_bytes,
            &cached_request_bytes,
            |response_bytes| {
                decode_score_bridge_response(response_bytes, expected_security_profile)
            },
        )
    }

    fn score_encrypted_query_batch(
        &self,
        input: CkksEncryptedQueryScoreBatchInput<'_>,
    ) -> Result<Vec<f64>, CkksError> {
        if input.items.is_empty() {
            return Ok(Vec::new());
        }
        if input.items.len() == 1 {
            let item = input.items[0];
            return self
                .score_encrypted_query(CkksEncryptedQueryScoreInput {
                    parameters: input.parameters,
                    public_material: input.public_material,
                    collection: input.collection,
                    point_id: item.point_id,
                    vector_name: input.vector_name,
                    distance: input.distance,
                    encrypted_query: input.encrypted_query,
                    ciphertext: item.ciphertext,
                })
                .map(|score| vec![score]);
        }

        let items = input
            .items
            .iter()
            .map(|item| CommandOpenFheScoreBatchItem {
                point_id: item.point_id,
                ciphertext: BASE64URL_NOPAD.encode(item.ciphertext),
            })
            .collect::<Vec<_>>();
        let context_id = input.public_material.digest_for(input.parameters);
        let request = CommandOpenFheEncryptedScoreBatchRequest {
            version: 1,
            operation: "score_encrypted_query_batch",
            scheme: CKKS_SCHEME,
            collection: input.collection,
            vector_name: input.vector_name,
            distance: input.distance,
            context_id: context_id.clone(),
            parameters: Some(input.parameters),
            crypto_context: Some(BASE64URL_NOPAD.encode(input.public_material.crypto_context())),
            public_key: Some(BASE64URL_NOPAD.encode(input.public_material.public_key())),
            encrypted_query: BASE64URL_NOPAD.encode(input.encrypted_query),
            items,
        };
        let request_bytes = serialize_bridge_request(
            &request,
            "OpenFHE bridge encrypted-query score batch request",
        )?;
        let cached_request_bytes = serialize_bridge_request_without_public_material(
            &request,
            "OpenFHE bridge encrypted-query score batch request",
        )?;

        let expected_security_profile = expected_security_profile(input.parameters)?;
        self.send_bridge_request_with_context(
            &context_id,
            &request_bytes,
            &cached_request_bytes,
            |response_bytes| {
                decode_score_batch_bridge_response(
                    response_bytes,
                    input.items.len(),
                    expected_security_profile,
                )
            },
        )
    }
}

impl CommandOpenFheBackend {
    fn send_bridge_request_with_context<T>(
        &self,
        context_id: &str,
        request_with_public_material: &[u8],
        request_with_registered_context: &[u8],
        decode_response: impl Fn(&[u8]) -> Result<T, CkksError>,
    ) -> Result<T, CkksError> {
        self.send_bridge_request_impl(
            Some(context_id),
            request_with_public_material,
            Some(request_with_registered_context),
            decode_response,
        )
    }

    fn send_bridge_request_impl<T>(
        &self,
        context_id: Option<&str>,
        request_with_public_material: &[u8],
        request_with_registered_context: Option<&[u8]>,
        decode_response: impl Fn(&[u8]) -> Result<T, CkksError>,
    ) -> Result<T, CkksError> {
        for attempt in 0..=1 {
            // `worker_process` returns only after atomically reserving a worker.
            // The reservation is held for the whole request, so stdin/stdout
            // access does not need a second worker-local request mutex.
            let worker_reservation = self.worker_process()?;
            let worker_process = Arc::clone(worker_reservation.worker());
            if worker_process.stderr_truncated.load(Ordering::Relaxed) {
                self.discard_worker(&worker_process, false)?;
                return Err(CkksError::Backend(format!(
                    "OpenFHE bridge stderr exceeded {} bytes",
                    self.max_output_bytes,
                )));
            }

            let context_registered = if let Some(context_id) = context_id {
                worker_process
                    .registered_contexts
                    .lock()
                    .map_err(|_| {
                        CkksError::Backend(
                            "OpenFHE bridge context cache mutex was poisoned".to_string(),
                        )
                    })?
                    .contains(context_id)
            } else {
                false
            };
            let selected_request = if context_registered {
                request_with_registered_context.unwrap_or(request_with_public_material)
            } else {
                request_with_public_material
            };
            let mut request_bytes = Zeroizing::new(selected_request.to_vec());
            request_bytes.push(b'\n');

            // A bridge that speaks unasked has left the protocol: its stale line would otherwise
            // be taken as the answer to this request.
            let unsolicited = worker_process
                .stdout_rx
                .lock()
                .map_err(|_| {
                    CkksError::Backend(
                        "OpenFHE bridge stdout receiver mutex was poisoned".to_string(),
                    )
                })?
                .try_recv();
            match unsolicited {
                Ok(BridgeStdoutEvent::Response { .. }) => {
                    self.discard_worker(&worker_process, false)?;
                    return Err(CkksError::Backend(
                        "OpenFHE bridge produced output without a request".to_string(),
                    ));
                }
                Ok(BridgeStdoutEvent::StderrExceeded) => {
                    self.discard_worker(&worker_process, false)?;
                    return Err(CkksError::Backend(format!(
                        "OpenFHE bridge stderr exceeded {} bytes",
                        self.max_output_bytes,
                    )));
                }
                Ok(BridgeStdoutEvent::Eof | BridgeStdoutEvent::Error(_)) => {
                    // The worker died between requests; a fresh one serves this request.
                    self.discard_worker(&worker_process, false)?;
                    if attempt == 0 {
                        continue;
                    }
                    return Err(CkksError::Backend(
                        "OpenFHE bridge exited before the request".to_string(),
                    ));
                }
                Err(_) => {}
            }

            let timeout = self.timeout;
            match write_bridge_request_with_deadline(&worker_process, request_bytes, timeout) {
                Ok(()) => {}
                Err(BridgeWriteError::Spawn(err)) => {
                    // Thread pressure on this side, not a bridge fault: keep the worker.
                    return Err(CkksError::Backend(format!(
                        "failed to start the OpenFHE bridge writer thread: {err}"
                    )));
                }
                Err(BridgeWriteError::Timeout) => {
                    // A bridge that stopped draining stdin would otherwise park this thread and
                    // its worker reservation forever once the request exceeded the pipe buffer.
                    self.discard_worker(&worker_process, false)?;
                    return Err(CkksError::Backend(format!(
                        "OpenFHE bridge did not accept the request within {} ms",
                        timeout.as_millis(),
                    )));
                }
                Err(BridgeWriteError::Io(err)) => {
                    let retry = attempt == 0
                        && matches!(
                            err.kind(),
                            io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof
                        );
                    self.discard_worker(&worker_process, false)?;
                    if retry {
                        continue;
                    }
                    return Err(CkksError::Backend(format!(
                        "failed to write OpenFHE bridge request: {err}",
                    )));
                }
            }

            let response = worker_process
                .stdout_rx
                .lock()
                .map_err(|_| {
                    CkksError::Backend(
                        "OpenFHE bridge stdout receiver mutex was poisoned".to_string(),
                    )
                })?
                .recv_timeout(timeout);
            let (response_bytes, truncated) = match response {
                Ok(BridgeStdoutEvent::Response {
                    mut bytes,
                    truncated,
                }) => {
                    if bytes.last() == Some(&b'\n') {
                        bytes.pop();
                        if bytes.last() == Some(&b'\r') {
                            bytes.pop();
                        }
                    }
                    (bytes, truncated)
                }
                Ok(BridgeStdoutEvent::Eof) => {
                    if worker_process.stderr_truncated.load(Ordering::Relaxed) {
                        self.discard_worker(&worker_process, false)?;
                        return Err(CkksError::Backend(format!(
                            "OpenFHE bridge stderr exceeded {} bytes",
                            self.max_output_bytes,
                        )));
                    }
                    let retry = attempt == 0;
                    self.discard_worker(&worker_process, false)?;
                    if retry {
                        continue;
                    }
                    return Err(CkksError::Backend(
                        "OpenFHE bridge returned an empty response".to_string(),
                    ));
                }
                Ok(BridgeStdoutEvent::Error(err)) => {
                    let retry = attempt == 0
                        && matches!(
                            err.kind(),
                            io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof
                        );
                    self.discard_worker(&worker_process, false)?;
                    if retry {
                        continue;
                    }
                    return Err(CkksError::Backend(format!(
                        "failed to read OpenFHE bridge response: {err}",
                    )));
                }
                Ok(BridgeStdoutEvent::StderrExceeded) => {
                    self.discard_worker(&worker_process, false)?;
                    return Err(CkksError::Backend(format!(
                        "OpenFHE bridge stderr exceeded {} bytes",
                        self.max_output_bytes,
                    )));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    self.discard_worker(&worker_process, false)?;
                    return Err(CkksError::Backend(format!(
                        "OpenFHE bridge timed out after {} ms",
                        timeout.as_millis(),
                    )));
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let retry = attempt == 0;
                    self.discard_worker(&worker_process, false)?;
                    if retry {
                        continue;
                    }
                    return Err(CkksError::Backend(
                        "bridge stdout reader disconnected".to_string(),
                    ));
                }
            };
            if truncated {
                self.discard_worker(&worker_process, false)?;
                return Err(CkksError::Backend(format!(
                    "OpenFHE bridge stdout exceeded {} bytes",
                    self.max_output_bytes,
                )));
            }
            if response_bytes.is_empty() {
                if worker_process.stderr_truncated.load(Ordering::Relaxed) {
                    self.discard_worker(&worker_process, false)?;
                    return Err(CkksError::Backend(format!(
                        "OpenFHE bridge stderr exceeded {} bytes",
                        self.max_output_bytes,
                    )));
                }
                let retry = attempt == 0;
                self.discard_worker(&worker_process, false)?;
                if retry {
                    continue;
                }
                return Err(CkksError::Backend(
                    "OpenFHE bridge returned an empty response".to_string(),
                ));
            }
            if worker_process.stderr_truncated.load(Ordering::Relaxed) {
                self.discard_worker(&worker_process, false)?;
                return Err(CkksError::Backend(format!(
                    "OpenFHE bridge stderr exceeded {} bytes",
                    self.max_output_bytes,
                )));
            }
            if let Some(status) = worker_process.try_wait()? {
                self.discard_worker(&worker_process, false)?;
                if !status.success() {
                    return Err(CkksError::Backend(format!(
                        "OpenFHE bridge exited with status {status}",
                    )));
                }
            }

            return match decode_response(&response_bytes) {
                Ok(response) => {
                    if let Some(context_id) = context_id
                        && !context_registered
                    {
                        worker_process
                            .registered_contexts
                            .lock()
                            .map_err(|_| {
                                CkksError::Backend(
                                    "OpenFHE bridge context cache mutex was poisoned".to_string(),
                                )
                            })?
                            .insert(context_id.to_string());
                    }
                    Ok(response)
                }
                Err(err) => {
                    self.discard_worker(&worker_process, false)?;
                    Err(err)
                }
            };
        }

        Err(CkksError::Backend(
            "OpenFHE bridge retry budget was exhausted".to_string(),
        ))
    }

    fn worker_process(&self) -> Result<WorkerReservation, CkksError> {
        // A momentarily saturated pool must not fail requests outright: sandboxed bridge kinds
        // run a single worker, so back-to-back searches would otherwise error instead of
        // queueing briefly. Wait a bounded time for a worker to free up before giving up.
        let deadline = std::time::Instant::now() + WORKER_RESERVATION_WAIT;
        loop {
            let mut workers = self.workers.lock().map_err(|_| {
                CkksError::Backend("OpenFHE bridge workers mutex was poisoned".to_string())
            })?;

            let mut worker_index = 0;
            while worker_index < workers.len() {
                let worker_process = &workers[worker_index];
                if worker_process.stderr_truncated.load(Ordering::Relaxed) {
                    let worker_process = workers.swap_remove(worker_index);
                    worker_process.shutdown(false)?;
                    continue;
                }
                if worker_process.try_wait()?.is_some() {
                    let worker_process = workers.swap_remove(worker_index);
                    worker_process.shutdown(false)?;
                    continue;
                }
                worker_index += 1;
            }

            for worker_process in workers.iter() {
                if worker_process.try_reserve_request() {
                    return Ok(WorkerReservation::reserved(Arc::clone(worker_process)));
                }
            }

            let spawning = self.spawning.load(Ordering::Acquire);
            if workers.len().saturating_add(spawning) < self.pool_size.get() {
                // Reserve a pool slot and spawn without holding the lock: hashing the bridge
                // binary and starting the process took long enough to stall every request
                // that only needed an idle worker.
                self.spawning.fetch_add(1, Ordering::AcqRel);
                drop(workers);
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(CkksError::Backend(format!(
                    "OpenFHE bridge worker pool is exhausted; all {} workers stayed busy for {:?}",
                    self.pool_size.get(),
                    WORKER_RESERVATION_WAIT,
                )));
            }
            drop(workers);
            std::thread::sleep(WORKER_RESERVATION_POLL);
        }
        let spawn_slot = SpawnSlot(Arc::clone(&self.spawning));

        let spawn_program = bridge_spawn_program(
            &self.program,
            self.checked_program,
            self.expected_sha256_b64.as_deref(),
        )?;

        let mut command = Command::new(spawn_program.path());
        command
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if self.checked_program {
            command.env_clear();
            command.current_dir("/");
            // Preserve only a fixed search path for shebangs that use
            // `/usr/bin/env`. Production bridge binaries should not depend on
            // ambient service environment.
            command.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        } else {
            for (name, _) in std::env::vars_os() {
                let name_string = name.to_string_lossy();
                if name_string == "QDRANT" || name_string.starts_with("QDRANT_") {
                    command.env_remove(name);
                }
            }
        }
        for name in &self.sensitive_env_names {
            command.env_remove(name);
        }
        #[cfg(target_os = "linux")]
        let (keep_fd, inherit_fd) = (spawn_program.keep_fd(), spawn_program.inherit_fd());
        #[cfg(not(target_os = "linux"))]
        let (keep_fd, inherit_fd) = (None, None);
        #[cfg(target_os = "linux")]
        let landlock_strict_rules = bridge_sandbox_uses_landlock_read_allow_list(self.sandbox)
            .then(|| {
                linux_landlock_strict_rules(&self.landlock_read_allow_roots, &self.program, keep_fd)
            })
            .transpose()?;
        #[cfg(not(target_os = "linux"))]
        let landlock_strict_rules: Option<LinuxLandlockStrictRules> = None;
        configure_bridge_command_sandbox(
            &mut command,
            self.checked_program,
            self.sandbox,
            keep_fd,
            inherit_fd,
            landlock_strict_rules,
        );

        let mut child = spawn_bridge_child(command)
            .map_err(|err| CkksError::Backend(format!("failed to start OpenFHE bridge: {err}")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| CkksError::Backend("failed to open bridge stdin".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| CkksError::Backend("failed to open bridge stdout".to_string()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| CkksError::Backend("failed to open bridge stderr".to_string()))?;

        // One pending line is all a well-behaved bridge ever produces. A bounded channel turns
        // any further output into back-pressure on the bridge's pipe instead of server memory.
        let (stdout_tx, stdout_rx) = mpsc::sync_channel(1);
        let stderr_tx = stdout_tx.clone();
        let max_output_bytes = self.max_output_bytes;
        let stdout_thread = thread::spawn(move || {
            let mut stdout = BufReader::new(stdout);
            loop {
                let mut bytes = Vec::new();
                let mut truncated = false;
                let mut byte = [0u8; 1];
                loop {
                    match stdout.read(&mut byte) {
                        Ok(0) => {
                            if stdout_tx.send(BridgeStdoutEvent::Eof).is_err() {
                                return;
                            }
                            return;
                        }
                        Ok(_) => {
                            if bytes.len() == max_output_bytes {
                                truncated = true;
                                break;
                            }
                            bytes.push(byte[0]);
                            if byte[0] == b'\n' {
                                break;
                            }
                        }
                        Err(err) => {
                            let _ = stdout_tx.send(BridgeStdoutEvent::Error(err));
                            return;
                        }
                    }
                }
                if stdout_tx
                    .send(BridgeStdoutEvent::Response { bytes, truncated })
                    .is_err()
                {
                    return;
                }
            }
        });

        let stderr_truncated = Arc::new(AtomicBool::new(false));
        let stderr_truncated_thread = Arc::clone(&stderr_truncated);
        let max_output_bytes = self.max_output_bytes;
        let stderr_thread = thread::spawn(move || {
            let mut stderr = stderr;
            let mut buffer = [0u8; 4096];
            let mut total = 0usize;
            loop {
                let read = stderr.read(&mut buffer)?;
                if read == 0 {
                    return Ok(());
                }
                total = total.saturating_add(read);
                if total > max_output_bytes {
                    stderr_truncated_thread.store(true, Ordering::Relaxed);
                    let _ = stderr_tx.send(BridgeStdoutEvent::StderrExceeded);
                    return Ok(());
                }
            }
        });

        let worker_process = Arc::new(WorkerProcess {
            child: Mutex::new(child),
            stdin: Mutex::new(stdin),
            stdout_rx: Mutex::new(stdout_rx),
            stderr_truncated,
            registered_contexts: Mutex::new(HashSet::new()),
            terminated: AtomicBool::new(false),
            reserved: AtomicBool::new(true),
            reader_threads: Mutex::new(WorkerReaderThreads {
                stdout: Some(stdout_thread),
                stderr: Some(stderr_thread),
            }),
        });
        let mut workers = self.workers.lock().map_err(|_| {
            CkksError::Backend("OpenFHE bridge workers mutex was poisoned".to_string())
        })?;
        workers.push(Arc::clone(&worker_process));
        // Release the spawn slot while the pool lock is still held: otherwise another caller
        // briefly counts this worker twice (pushed and still spawning) and may report the pool
        // as exhausted although a slot is free.
        drop(spawn_slot);
        drop(workers);
        Ok(WorkerReservation::reserved(worker_process))
    }

    fn discard_worker(
        &self,
        worker_process: &Arc<WorkerProcess>,
        join_readers: bool,
    ) -> Result<(), CkksError> {
        worker_process.shutdown(join_readers)?;
        let mut workers = self.workers.lock().map_err(|_| {
            CkksError::Backend("OpenFHE bridge workers mutex was poisoned".to_string())
        })?;
        if let Some(index) = workers
            .iter()
            .position(|current| Arc::ptr_eq(current, worker_process))
        {
            workers.swap_remove(index);
        }
        Ok(())
    }
}

enum BridgeWriteError {
    Timeout,
    Io(io::Error),
    /// No writer thread could be started; the worker itself is untouched.
    Spawn(io::Error),
}

/// Writes one request line to the bridge from a helper thread and waits at most `timeout` for
/// the write to complete. On timeout the caller kills the worker, which closes the pipe and
/// unblocks the helper; the request bytes stay zeroized on every path.
/// Spawns a bridge child from a thread that lives as long as the process.
///
/// The child asks for `PR_SET_PDEATHSIG`, and Linux delivers that signal when the *thread* that
/// spawned the child exits, not when the process does. Request threads come from pools that
/// recycle idle threads, so a worker spawned on one of them was killed mid-flight for every other
/// caller as soon as that thread was reaped. One dedicated spawner thread keeps the parent-death
/// signal meaning what it was meant to mean: the bridge dies with Qdrant.
fn spawn_bridge_child(command: Command) -> io::Result<Child> {
    type SpawnJob = (Command, mpsc::Sender<io::Result<Child>>);
    static SPAWNER: OnceLock<Option<Mutex<mpsc::Sender<SpawnJob>>>> = OnceLock::new();
    let spawner = SPAWNER
        .get_or_init(|| {
            let (job_tx, job_rx) = mpsc::channel::<SpawnJob>();
            thread::Builder::new()
                .name("openfhe-bridge-spawner".to_string())
                .spawn(move || {
                    for (mut command, reply) in job_rx {
                        let _ = reply.send(command.spawn());
                    }
                })
                .ok()
                .map(|_| Mutex::new(job_tx))
        })
        .as_ref()
        .ok_or_else(|| io::Error::other("failed to start the OpenFHE bridge spawner thread"))?;
    let (reply_tx, reply_rx) = mpsc::channel();
    spawner
        .lock()
        .map_err(|_| io::Error::other("OpenFHE bridge spawner mutex was poisoned"))?
        .send((command, reply_tx))
        .map_err(|_| io::Error::other("OpenFHE bridge spawner thread is gone"))?;
    reply_rx
        .recv()
        .map_err(|_| io::Error::other("OpenFHE bridge spawner thread dropped the request"))?
}

/// Parse failures never quote the offending bytes: a bridge that returns garbage could
/// otherwise place its own text, or an echo of the plaintext request, into the error.
fn bridge_response_parse_error(what: &str, err: &serde_json::Error) -> CkksError {
    let kind = match err.classify() {
        serde_json::error::Category::Io => "io",
        serde_json::error::Category::Syntax => "syntax",
        serde_json::error::Category::Data => "data",
        serde_json::error::Category::Eof => "eof",
    };
    CkksError::Backend(format!(
        "{what} ({kind} error at line {}, column {})",
        err.line(),
        err.column()
    ))
}

fn write_bridge_request_with_deadline(
    worker_process: &Arc<WorkerProcess>,
    request_bytes: Zeroizing<Vec<u8>>,
    timeout: Duration,
) -> Result<(), BridgeWriteError> {
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let writer_process = Arc::clone(worker_process);
    let spawned = thread::Builder::new()
        .name("openfhe-bridge-write".to_string())
        .spawn(move || {
            let result = match writer_process.stdin.lock() {
                Ok(mut stdin) => stdin
                    .write_all(request_bytes.as_slice())
                    .and_then(|_| stdin.flush()),
                Err(_) => Err(io::Error::other("OpenFHE bridge stdin mutex was poisoned")),
            };
            let _ = result_tx.send(result);
        });
    if let Err(err) = spawned {
        return Err(BridgeWriteError::Spawn(err));
    }
    match result_rx.recv_timeout(timeout) {
        Ok(result) => result.map_err(BridgeWriteError::Io),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(BridgeWriteError::Timeout),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(BridgeWriteError::Io(io::Error::other(
            "OpenFHE bridge writer thread exited without a result",
        ))),
    }
}

fn serialize_bridge_request<T: Serialize>(
    request: &T,
    request_name: &str,
) -> Result<Zeroizing<Vec<u8>>, CkksError> {
    serde_json::to_vec(request)
        .map(Zeroizing::new)
        .map_err(|err| CkksError::Backend(format!("failed to serialize {request_name}: {err}")))
}

trait CommandOpenFheContextRequest: Serialize + Clone {
    fn remove_public_material(&mut self);
}

fn serialize_bridge_request_without_public_material<T: CommandOpenFheContextRequest>(
    request: &T,
    request_name: &str,
) -> Result<Zeroizing<Vec<u8>>, CkksError> {
    let mut request = request.clone();
    request.remove_public_material();
    serde_json::to_vec(&request)
        .map(Zeroizing::new)
        .map_err(|err| {
            CkksError::Backend(format!(
                "failed to serialize cached-context {request_name}: {err}"
            ))
        })
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[cfg(target_os = "linux")]
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
/// Access rights Landlock accepts in a rule whose parent is a non-directory.
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_FILE_COMPATIBLE: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_TRUNCATE;
#[cfg(target_os = "linux")]
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

#[cfg(target_os = "linux")]
#[repr(C, packed)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Upper bound on configured strict-sandbox read roots; every root becomes one Landlock rule.
pub const MAX_LANDLOCK_READ_ALLOW_ROOTS: usize = 64;

/// System roots the strict sandbox lets the bridge read and execute: interpreters, shared
/// libraries, the loader cache and locale data live here. Roots a distribution lacks are skipped.
#[cfg(target_os = "linux")]
const LANDLOCK_STRICT_SYSTEM_ROOTS: [&str; 6] = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"];

/// Device files the strict sandbox lets the bridge open; `/dev/null` may also be written.
#[cfg(target_os = "linux")]
const LANDLOCK_STRICT_DEVICE_FILES: [(&str, u64); 3] = [
    (
        "/dev/null",
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
    ),
    ("/dev/urandom", LANDLOCK_ACCESS_FS_READ_FILE),
    ("/dev/random", LANDLOCK_ACCESS_FS_READ_FILE),
];

/// One `path_beneath` Landlock rule, resolved in the parent so the forked child allocates nothing.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct LinuxLandlockPathRule {
    path: std::ffi::CString,
    allowed_access: u64,
    /// Configured roots and the program must exist; system roots a distribution lacks are skipped.
    required: bool,
}

/// The strict sandbox's allow-list, prepared before the fork.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct LinuxLandlockStrictRules {
    paths: Vec<LinuxLandlockPathRule>,
    /// The already-open checked program descriptor; it is granted read and execute so the
    /// `/proc/self/fd/<fd>` exec path and the interpreter's re-read of a shebang script work.
    program_fd: Option<i32>,
}

/// Checks one strict-sandbox read root: absolute, normalized (no `.`, `..`, empty or trailing
/// segments), not `/` and free of NUL bytes. Existence is checked when a worker starts.
pub fn validate_landlock_read_allow_root(root: &Path) -> Result<(), CkksError> {
    let raw = root.as_os_str().as_encoded_bytes();
    if raw.first() != Some(&b'/') {
        return Err(CkksError::Backend(
            "Landlock read-allow roots must be absolute paths".to_string(),
        ));
    }
    if raw.contains(&0) {
        return Err(CkksError::Backend(
            "Landlock read-allow roots must not contain NUL bytes".to_string(),
        ));
    }
    if raw.len() == 1 {
        return Err(CkksError::Backend(
            "Landlock read-allow roots must not be the filesystem root".to_string(),
        ));
    }
    if raw[1..]
        .split(|byte| *byte == b'/')
        .any(|segment| segment.is_empty() || segment == b"." || segment == b"..")
    {
        return Err(CkksError::Backend(
            "Landlock read-allow roots must be normalized paths without `.`, `..`, empty or              trailing segments"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_landlock_strict_rules(
    read_allow_roots: &[PathBuf],
    program: &Path,
    program_fd: Option<i32>,
) -> Result<LinuxLandlockStrictRules, CkksError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    fn rule(
        path: &Path,
        allowed_access: u64,
        required: bool,
    ) -> Result<LinuxLandlockPathRule, CkksError> {
        let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            CkksError::Backend("Landlock rule paths must not contain NUL bytes".to_string())
        })?;
        Ok(LinuxLandlockPathRule {
            path,
            allowed_access,
            required,
        })
    }

    let read_exec =
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE;
    let mut paths = Vec::new();
    for root in LANDLOCK_STRICT_SYSTEM_ROOTS {
        paths.push(rule(Path::new(root), read_exec, false)?);
    }
    for (device, allowed_access) in LANDLOCK_STRICT_DEVICE_FILES {
        paths.push(rule(Path::new(device), allowed_access, false)?);
    }
    for root in read_allow_roots {
        validate_landlock_read_allow_root(root)?;
        paths.push(rule(
            root,
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
            true,
        )?);
    }
    if program_fd.is_none() {
        // Unchecked (test-only) programs are executed by path, so the path itself is allowed.
        paths.push(rule(
            program,
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_EXECUTE,
            true,
        )?);
    }
    Ok(LinuxLandlockStrictRules { paths, program_fd })
}

#[cfg(target_os = "linux")]
fn landlock_strict_handled_access_for_abi(abi_version: i64) -> u64 {
    landlock_write_deny_access_for_abi(abi_version)
        | LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
}

/// Adds one `path_beneath` rule; directory-only rights are dropped for non-directory parents
/// because Landlock rejects them with `EINVAL`. Runs in the forked child, so it allocates nothing.
#[cfg(target_os = "linux")]
fn landlock_add_path_rule(
    ruleset_fd: nix::libc::c_long,
    parent_fd: i32,
    allowed_access: u64,
) -> io::Result<()> {
    // SAFETY: `stat` is plain old data; `fstat` fills it for an open descriptor.
    let mut metadata: nix::libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { nix::libc::fstat(parent_fd, &mut metadata) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let allowed_access = if metadata.st_mode & nix::libc::S_IFMT == nix::libc::S_IFDIR {
        allowed_access
    } else {
        allowed_access & LANDLOCK_ACCESS_FS_FILE_COMPATIBLE
    };
    let attr = LandlockPathBeneathAttr {
        allowed_access,
        parent_fd,
    };
    // SAFETY: the attribute struct matches the kernel ABI layout and outlives the call.
    let result = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_landlock_add_rule,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &attr as *const LandlockPathBeneathAttr,
            0u32,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Installs the strict ruleset: every write access bit plus read and execute are handled, and
/// only the prepared allow-list is granted. Runs in the forked child.
#[cfg(target_os = "linux")]
fn apply_linux_landlock_strict(rules: &LinuxLandlockStrictRules) -> io::Result<()> {
    let abi_version = linux_landlock_abi_version()?;
    if abi_version < 1 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Linux Landlock ABI is unavailable",
        ));
    }

    let attr = LandlockRulesetAttr {
        handled_access_fs: landlock_strict_handled_access_for_abi(abi_version),
    };
    // SAFETY: the attribute struct matches the kernel ABI layout and outlives the call.
    let ruleset_fd = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_landlock_create_ruleset,
            &attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };
    if ruleset_fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let populate_and_restrict = || -> io::Result<()> {
        for rule in &rules.paths {
            // SAFETY: the path is a valid NUL-terminated string prepared in the parent.
            let fd = unsafe {
                nix::libc::open(rule.path.as_ptr(), nix::libc::O_PATH | nix::libc::O_CLOEXEC)
            };
            if fd < 0 {
                let err = io::Error::last_os_error();
                if !rule.required && err.raw_os_error() == Some(nix::libc::ENOENT) {
                    continue;
                }
                return Err(err);
            }
            let added = landlock_add_path_rule(ruleset_fd, fd, rule.allowed_access);
            // SAFETY: closing the descriptor opened above.
            unsafe {
                nix::libc::close(fd);
            }
            added?;
        }
        if let Some(program_fd) = rules.program_fd {
            landlock_add_path_rule(
                ruleset_fd,
                program_fd,
                LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_EXECUTE,
            )?;
        }
        // SAFETY: restricting the calling thread with the populated ruleset descriptor.
        let restricted =
            unsafe { nix::libc::syscall(nix::libc::SYS_landlock_restrict_self, ruleset_fd, 0u32) };
        if restricted != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    };
    let outcome = populate_and_restrict();
    // SAFETY: closing the ruleset descriptor created above.
    let close_result = unsafe { nix::libc::close(ruleset_fd as nix::libc::c_int) };
    outcome?;
    if close_result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_landlock_abi_version() -> io::Result<i64> {
    let version = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_landlock_create_ruleset,
            std::ptr::null::<LandlockRulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if version < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(version)
}

#[cfg(target_os = "linux")]
fn landlock_write_deny_access_for_abi(abi_version: i64) -> u64 {
    let mut access = LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;
    if abi_version >= 2 {
        access |= LANDLOCK_ACCESS_FS_REFER;
    }
    if abi_version >= 3 {
        access |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    access
}

#[cfg(target_os = "linux")]
fn apply_linux_landlock_write_deny() -> io::Result<()> {
    let abi_version = linux_landlock_abi_version()?;
    if abi_version < 1 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Linux Landlock ABI is unavailable",
        ));
    }

    let attr = LandlockRulesetAttr {
        handled_access_fs: landlock_write_deny_access_for_abi(abi_version),
    };
    let ruleset_fd = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_landlock_create_ruleset,
            &attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };
    if ruleset_fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let restrict_result =
        unsafe { nix::libc::syscall(nix::libc::SYS_landlock_restrict_self, ruleset_fd, 0u32) };
    let restrict_error = if restrict_result != 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    let close_result = unsafe { nix::libc::close(ruleset_fd as nix::libc::c_int) };
    if let Some(err) = restrict_error {
        return Err(err);
    }
    if close_result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_linux_network_namespace_egress_deny() -> io::Result<()> {
    let result = unsafe { nix::libc::unshare(nix::libc::CLONE_NEWNET) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bridge_sandbox_uses_landlock(sandbox: BridgeSandbox) -> bool {
    matches!(
        sandbox,
        BridgeSandbox::LinuxLandlockWriteDeny
            | BridgeSandbox::LinuxLandlockWriteDenyNetworkNamespace
    ) || bridge_sandbox_uses_landlock_read_allow_list(sandbox)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn bridge_sandbox_uses_landlock_read_allow_list(sandbox: BridgeSandbox) -> bool {
    matches!(
        sandbox,
        BridgeSandbox::LinuxLandlockStrict | BridgeSandbox::LinuxLandlockStrictNetworkNamespace
    )
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn bridge_sandbox_uses_network_namespace(sandbox: BridgeSandbox) -> bool {
    matches!(
        sandbox,
        BridgeSandbox::LinuxLandlockWriteDenyNetworkNamespace
            | BridgeSandbox::LinuxLandlockStrictNetworkNamespace
    )
}

/// Marks every descriptor above stdio close-on-exec except `keep`, so nothing Qdrant happens to
/// hold open (sockets, storage files, another worker's script fd) reaches the bridge. Runs in
/// the forked child, so it allocates nothing.
#[cfg(target_os = "linux")]
fn close_inherited_descriptors(keep: Option<i32>) -> io::Result<()> {
    const CLOSE_RANGE_CLOEXEC: nix::libc::c_uint = 1 << 2;
    let mark_range = |first: u32, last: u32| -> io::Result<()> {
        if first > last {
            return Ok(());
        }
        // SAFETY: `close_range` only touches this process's descriptor table.
        let result = unsafe {
            nix::libc::syscall(
                nix::libc::SYS_close_range,
                first as nix::libc::c_uint,
                last as nix::libc::c_uint,
                CLOSE_RANGE_CLOEXEC,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            // Kernels before 5.11 have no CLOSE_RANGE_CLOEXEC (or no close_range at all):
            // close the descriptors a service realistically holds instead.
            Some(nix::libc::ENOSYS) | Some(nix::libc::EINVAL) => {
                for fd in first..=last.min(4096) {
                    // SAFETY: closing a descriptor number; EBADF for unused ones is ignored.
                    unsafe {
                        nix::libc::close(fd as i32);
                    }
                }
                Ok(())
            }
            _ => Err(err),
        }
    };
    match keep {
        Some(fd) if fd >= 3 => {
            let fd = fd as u32;
            mark_range(3, fd - 1)?;
            mark_range(fd + 1, u32::MAX)
        }
        _ => mark_range(3, u32::MAX),
    }
}

#[cfg(target_os = "linux")]
fn configure_bridge_command_sandbox(
    command: &mut Command,
    checked_program: bool,
    sandbox: BridgeSandbox,
    keep_fd: Option<i32>,
    inherit_fd: Option<i32>,
    landlock_strict_rules: Option<LinuxLandlockStrictRules>,
) {
    // This is not a full sandbox, but it prevents the bridge process from
    // gaining privileges through setuid binaries or file capabilities after
    // Qdrant has already validated the executable path and ownership. It also
    // disables core dumps for the plaintext-bearing bridge process, restricts
    // default permissions for any bridge-created files, and blocks regular
    // file writes for checked production bridge binaries. Network-namespace
    // sandbox kinds additionally detach the bridge from the host network
    // namespace before exec so a bridge with no network dependency has no
    // route to external egress. The
    // parent-death signal prevents a bridge from staying alive as an orphan if
    // Qdrant exits while the bridge is handling plaintext embeddings.
    unsafe {
        command.pre_exec(move || {
            if bridge_sandbox_uses_network_namespace(sandbox) {
                apply_linux_network_namespace_egress_deny()?;
            }
            let result = nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
            let result = nix::libc::prctl(nix::libc::PR_SET_PDEATHSIG, nix::libc::SIGKILL, 0, 0, 0);
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
            // Own session and process group, so shutdown can kill the bridge together with
            // anything it forked.
            if nix::libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            close_inherited_descriptors(keep_fd)?;
            if let Some(fd) = inherit_fd {
                let flags = nix::libc::fcntl(fd, nix::libc::F_GETFD);
                if flags < 0
                    || nix::libc::fcntl(fd, nix::libc::F_SETFD, flags & !nix::libc::FD_CLOEXEC) < 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            let zero_limit = nix::libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            let result = nix::libc::setrlimit(nix::libc::RLIMIT_CORE, &zero_limit);
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
            if checked_program {
                let result = nix::libc::setrlimit(nix::libc::RLIMIT_FSIZE, &zero_limit);
                if result != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            if let Some(rules) = &landlock_strict_rules {
                apply_linux_landlock_strict(rules)?;
            } else if bridge_sandbox_uses_landlock(sandbox) {
                apply_linux_landlock_write_deny()?;
            }
            nix::libc::umask(0o077);
            Ok(())
        });
    }
}

#[cfg(not(target_os = "linux"))]
fn configure_bridge_command_sandbox(
    _command: &mut Command,
    _checked_program: bool,
    _sandbox: BridgeSandbox,
    _keep_fd: Option<i32>,
    _inherit_fd: Option<i32>,
    _landlock_strict_rules: Option<LinuxLandlockStrictRules>,
) {
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheRequest<'a> {
    version: u8,
    operation: &'static str,
    scheme: &'static str,
    collection: &'a str,
    point_id: &'a str,
    vector_name: &'a str,
    context_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<&'a CkksParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crypto_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    values: &'a [f64],
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheBatchRequest<'a> {
    version: u8,
    operation: &'static str,
    scheme: &'static str,
    collection: &'a str,
    vector_name: &'a str,
    context_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<&'a CkksParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crypto_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    items: Vec<CommandOpenFheBatchItem<'a>>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheBatchItem<'a> {
    point_id: &'a str,
    values: &'a [f64],
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheQueryRequest<'a> {
    version: u8,
    operation: &'static str,
    scheme: &'static str,
    collection: &'a str,
    vector_name: &'a str,
    context_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<&'a CkksParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crypto_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    values: &'a [f64],
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheScoreRequest<'a> {
    version: u8,
    operation: &'static str,
    scheme: &'static str,
    collection: &'a str,
    point_id: &'a str,
    vector_name: &'a str,
    distance: &'a str,
    context_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<&'a CkksParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crypto_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    query_values: &'a [f64],
    ciphertext: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheScoreBatchRequest<'a> {
    version: u8,
    operation: &'static str,
    scheme: &'static str,
    collection: &'a str,
    vector_name: &'a str,
    distance: &'a str,
    context_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<&'a CkksParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crypto_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    query_values: &'a [f64],
    items: Vec<CommandOpenFheScoreBatchItem<'a>>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheScoreBatchItem<'a> {
    point_id: &'a str,
    ciphertext: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheEncryptedScoreRequest<'a> {
    version: u8,
    operation: &'static str,
    scheme: &'static str,
    collection: &'a str,
    point_id: &'a str,
    vector_name: &'a str,
    distance: &'a str,
    context_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<&'a CkksParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crypto_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    encrypted_query: String,
    ciphertext: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheEncryptedScoreBatchRequest<'a> {
    version: u8,
    operation: &'static str,
    scheme: &'static str,
    collection: &'a str,
    vector_name: &'a str,
    distance: &'a str,
    context_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<&'a CkksParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crypto_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    encrypted_query: String,
    items: Vec<CommandOpenFheScoreBatchItem<'a>>,
}

macro_rules! impl_command_openfhe_context_request {
    ($request:ty) => {
        impl<'a> CommandOpenFheContextRequest for $request {
            fn remove_public_material(&mut self) {
                self.parameters = None;
                self.crypto_context = None;
                self.public_key = None;
            }
        }
    };
}

impl_command_openfhe_context_request!(CommandOpenFheRequest<'a>);
impl_command_openfhe_context_request!(CommandOpenFheBatchRequest<'a>);
impl_command_openfhe_context_request!(CommandOpenFheQueryRequest<'a>);
impl_command_openfhe_context_request!(CommandOpenFheScoreRequest<'a>);
impl_command_openfhe_context_request!(CommandOpenFheScoreBatchRequest<'a>);
impl_command_openfhe_context_request!(CommandOpenFheEncryptedScoreRequest<'a>);
impl_command_openfhe_context_request!(CommandOpenFheEncryptedScoreBatchRequest<'a>);

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheResponse {
    version: u8,
    #[serde(default)]
    security_profile: Option<String>,
    #[serde(default)]
    security_level_bits: Option<u16>,
    #[serde(default)]
    noise_budget_bits: Option<f64>,
    ciphertext: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheBatchResponse {
    version: u8,
    #[serde(default)]
    security_profile: Option<String>,
    #[serde(default)]
    security_level_bits: Option<u16>,
    #[serde(default)]
    noise_budget_bits: Option<f64>,
    ciphertexts: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheScoreResponse {
    version: u8,
    #[serde(default)]
    security_profile: Option<String>,
    #[serde(default)]
    security_level_bits: Option<u16>,
    #[serde(default)]
    noise_budget_bits: Option<f64>,
    score: f64,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheScoreBatchResponse {
    version: u8,
    #[serde(default)]
    security_profile: Option<String>,
    #[serde(default)]
    security_level_bits: Option<u16>,
    #[serde(default)]
    noise_budget_bits: Option<f64>,
    scores: Vec<f64>,
}

fn decode_single_bridge_response(
    response_bytes: &[u8],
    expected_security_profile: &str,
) -> Result<Vec<u8>, CkksError> {
    let response: CommandOpenFheResponse =
        serde_json::from_slice(response_bytes).map_err(|err| {
            bridge_response_parse_error("failed to parse OpenFHE bridge response", &err)
        })?;
    if response.version != 1 {
        return Err(CkksError::Backend(format!(
            "unsupported OpenFHE bridge response version {}",
            response.version,
        )));
    }
    validate_bridge_security_profile(
        response.security_profile.as_deref(),
        expected_security_profile,
    )?;
    validate_bridge_security_metadata(response.security_level_bits, response.noise_budget_bits)?;

    decode_bridge_ciphertext(&response.ciphertext, "OpenFHE bridge returned")
}

fn decode_score_bridge_response(
    response_bytes: &[u8],
    expected_security_profile: &str,
) -> Result<f64, CkksError> {
    let response: CommandOpenFheScoreResponse =
        serde_json::from_slice(response_bytes).map_err(|err| {
            bridge_response_parse_error("failed to parse OpenFHE bridge score response", &err)
        })?;
    if response.version != 1 {
        return Err(CkksError::Backend(format!(
            "unsupported OpenFHE bridge score response version {}",
            response.version,
        )));
    }
    validate_bridge_security_profile(
        response.security_profile.as_deref(),
        expected_security_profile,
    )?;
    validate_bridge_security_metadata(response.security_level_bits, response.noise_budget_bits)?;
    if !response.score.is_finite() {
        return Err(CkksError::Backend(
            "OpenFHE bridge returned non-finite score".to_string(),
        ));
    }

    Ok(response.score)
}

fn decode_score_batch_bridge_response(
    response_bytes: &[u8],
    expected: usize,
    expected_security_profile: &str,
) -> Result<Vec<f64>, CkksError> {
    let response: CommandOpenFheScoreBatchResponse = serde_json::from_slice(response_bytes)
        .map_err(|err| {
            bridge_response_parse_error("failed to parse OpenFHE bridge score batch response", &err)
        })?;
    if response.version != 1 {
        return Err(CkksError::Backend(format!(
            "unsupported OpenFHE bridge score batch response version {}",
            response.version,
        )));
    }
    validate_bridge_security_profile(
        response.security_profile.as_deref(),
        expected_security_profile,
    )?;
    validate_bridge_security_metadata(response.security_level_bits, response.noise_budget_bits)?;
    if response.scores.len() != expected {
        return Err(CkksError::Backend(format!(
            "OpenFHE bridge returned {} batch scores for {expected} encrypted vectors",
            response.scores.len(),
        )));
    }
    if response.scores.iter().any(|score| !score.is_finite()) {
        return Err(CkksError::Backend(
            "OpenFHE bridge returned non-finite batch score".to_string(),
        ));
    }

    Ok(response.scores)
}

fn decode_batch_bridge_response(
    response_bytes: &[u8],
    expected: usize,
    expected_security_profile: &str,
) -> Result<Vec<Vec<u8>>, CkksError> {
    let response: CommandOpenFheBatchResponse =
        serde_json::from_slice(response_bytes).map_err(|err| {
            bridge_response_parse_error("failed to parse OpenFHE bridge batch response", &err)
        })?;
    if response.version != 1 {
        return Err(CkksError::Backend(format!(
            "unsupported OpenFHE bridge batch response version {}",
            response.version,
        )));
    }
    validate_bridge_security_profile(
        response.security_profile.as_deref(),
        expected_security_profile,
    )?;
    validate_bridge_security_metadata(response.security_level_bits, response.noise_budget_bits)?;
    if response.ciphertexts.len() != expected {
        return Err(CkksError::Backend(format!(
            "OpenFHE bridge returned {} batch ciphertexts for {expected} input vectors",
            response.ciphertexts.len(),
        )));
    }

    response
        .ciphertexts
        .iter()
        .map(|ciphertext| decode_bridge_ciphertext(ciphertext, "OpenFHE bridge returned batch"))
        .collect()
}

fn decode_bridge_ciphertext(ciphertext_b64: &str, context: &str) -> Result<Vec<u8>, CkksError> {
    if ciphertext_b64.len() > MAX_BRIDGE_CIPHERTEXT_B64_LEN {
        return Err(CkksError::Backend(format!(
            "{context} ciphertext exceeds maximum size"
        )));
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(ciphertext_b64.as_bytes())
        .map_err(|_| CkksError::Backend(format!("{context} invalid ciphertext")))?;
    if ciphertext.is_empty() {
        return Err(CkksError::Backend(format!("{context} empty ciphertext")));
    }
    if ciphertext.len() > MAX_BRIDGE_CIPHERTEXT_BYTES {
        return Err(CkksError::Backend(format!(
            "{context} ciphertext exceeds maximum size"
        )));
    }
    Ok(ciphertext)
}

fn expected_security_profile(parameters: &CkksParameters) -> Result<&'static str, CkksError> {
    parameters.security_profile().ok_or_else(|| {
        CkksError::InvalidParameters(
            "OpenFHE bridge request parameters do not match an allowlisted security profile"
                .to_string(),
        )
    })
}

fn validate_bridge_security_profile(
    reported: Option<&str>,
    expected: &str,
) -> Result<(), CkksError> {
    let reported = reported.ok_or_else(|| {
        CkksError::Backend(format!(
            "OpenFHE bridge response is missing security profile {expected}",
        ))
    })?;

    if reported != expected {
        return Err(CkksError::Backend(format!(
            "OpenFHE bridge security profile does not match expected {expected}",
        )));
    }

    Ok(())
}

fn validate_bridge_security_metadata(
    security_level_bits: Option<u16>,
    noise_budget_bits: Option<f64>,
) -> Result<(), CkksError> {
    if let Some(security_level_bits) = security_level_bits
        && security_level_bits < MIN_OPENFHE_SECURITY_LEVEL_BITS
    {
        return Err(CkksError::Backend(format!(
            "OpenFHE bridge security level {security_level_bits} bits is below required {MIN_OPENFHE_SECURITY_LEVEL_BITS} bits",
        )));
    }

    if let Some(noise_budget_bits) = noise_budget_bits
        && (!noise_budget_bits.is_finite() || noise_budget_bits < 0.0)
    {
        return Err(CkksError::Backend(format!(
            "OpenFHE bridge returned invalid noise budget {noise_budget_bits}",
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_zeroizing_bridge_request(_: &Zeroizing<Vec<u8>>) {}

    #[test]
    fn bridge_request_serialization_uses_zeroizing_buffers() {
        let parameters = CkksParameters::default();
        let request = serialize_bridge_request(
            &CommandOpenFheQueryRequest {
                version: 1,
                operation: "encrypt_query",
                scheme: CKKS_SCHEME,
                collection: "docs",
                vector_name: "text",
                context_id: "ctx-1".to_string(),
                parameters: Some(&parameters),
                crypto_context: Some("crypto-context".to_string()),
                public_key: Some("public-key".to_string()),
                values: &[1.0, 2.0],
            },
            "test query request",
        )
        .unwrap();

        assert_zeroizing_bridge_request(&request);
        assert!(
            std::str::from_utf8(request.as_slice())
                .unwrap()
                .contains("\"values\"")
        );
    }

    #[test]
    fn bridge_response_decode_rejects_oversized_ciphertext_before_decode() {
        let expected_profile = CkksParameters::default().security_profile().unwrap();
        let oversized_ciphertext = "A".repeat(MAX_BRIDGE_CIPHERTEXT_B64_LEN + 1);

        let single_response = serde_json::json!({
            "version": 1,
            "ciphertext": oversized_ciphertext,
            "security_profile": expected_profile,
            "security_level_bits": MIN_OPENFHE_SECURITY_LEVEL_BITS,
        })
        .to_string();
        let err = decode_single_bridge_response(single_response.as_bytes(), expected_profile)
            .expect_err("oversized single ciphertext must fail before decode");
        assert!(format!("{err}").contains("ciphertext exceeds maximum size"));

        let batch_response = serde_json::json!({
            "version": 1,
            "ciphertexts": ["A".repeat(MAX_BRIDGE_CIPHERTEXT_B64_LEN + 1)],
            "security_profile": expected_profile,
            "security_level_bits": MIN_OPENFHE_SECURITY_LEVEL_BITS,
        })
        .to_string();
        let err = decode_batch_bridge_response(batch_response.as_bytes(), 1, expected_profile)
            .expect_err("oversized batch ciphertext must fail before decode");
        assert!(format!("{err}").contains("ciphertext exceeds maximum size"));
    }

    #[test]
    fn bridge_response_decode_rejects_empty_ciphertext() {
        let expected_profile = CkksParameters::default().security_profile().unwrap();
        let response = serde_json::json!({
            "version": 1,
            "ciphertext": "",
            "security_profile": expected_profile,
            "security_level_bits": MIN_OPENFHE_SECURITY_LEVEL_BITS,
        })
        .to_string();

        let err = decode_single_bridge_response(response.as_bytes(), expected_profile)
            .expect_err("empty bridge ciphertext must fail closed");
        assert!(format!("{err}").contains("empty ciphertext"));
    }

    #[test]
    fn landlock_read_allow_roots_must_be_absolute_normalized_and_not_the_filesystem_root() {
        let backend = CommandOpenFheBackend::new_unchecked("/usr/bin/true");
        for rejected in [
            "relative/dir",
            "/var/../etc",
            "/",
            "/opt/./openfhe",
            "/opt/",
            "//opt",
            "",
        ] {
            assert!(
                backend
                    .clone()
                    .with_linux_landlock_read_allow_roots([rejected])
                    .is_err(),
                "{rejected:?} must be rejected"
            );
        }
        assert!(
            backend
                .clone()
                .with_linux_landlock_read_allow_roots(
                    (0..=MAX_LANDLOCK_READ_ALLOW_ROOTS).map(|index| format!("/opt/root-{index}"))
                )
                .is_err(),
            "more than the maximum number of roots must be rejected"
        );

        let sentinel = "openfhe-read-root-sentinel";
        let backend = backend
            .with_linux_landlock_read_allow_roots([
                format!("/opt/{sentinel}"),
                format!("/opt/{sentinel}"),
                "/usr/share/openfhe".to_string(),
            ])
            .unwrap();
        assert_eq!(
            backend.landlock_read_allow_roots,
            vec![
                PathBuf::from(format!("/opt/{sentinel}")),
                PathBuf::from("/usr/share/openfhe"),
            ]
        );
        let rendered = format!("{backend:?}");
        assert!(
            rendered.contains("landlock_read_allow_roots_count: 2"),
            "{rendered}"
        );
        assert!(!rendered.contains(sentinel), "{rendered}");
    }

    #[test]
    fn landlock_strict_sandbox_kinds_are_distinct_policies() {
        let base = CommandOpenFheBackend::new_unchecked("/usr/bin/true");
        let strict = base.clone().with_linux_landlock_strict_sandbox();
        let strict_netns = base
            .clone()
            .with_linux_landlock_strict_network_namespace_sandbox();
        let write_deny = base.clone().with_linux_landlock_write_deny_sandbox();
        assert_ne!(strict, base);
        assert_ne!(strict, write_deny);
        assert_ne!(strict, strict_netns);
        assert_ne!(
            strict.clone(),
            strict
                .clone()
                .with_linux_landlock_read_allow_roots(["/opt/openfhe"])
                .unwrap(),
            "read roots are part of the sandbox policy"
        );
        assert!(format!("{strict:?}").contains("sandbox: LinuxLandlockStrict"));
        assert!(format!("{strict_netns:?}").contains("LinuxLandlockStrictNetworkNamespace"));

        for sandbox in [
            BridgeSandbox::LinuxLandlockStrict,
            BridgeSandbox::LinuxLandlockStrictNetworkNamespace,
        ] {
            assert!(bridge_sandbox_uses_landlock_read_allow_list(sandbox));
        }
        for sandbox in [
            BridgeSandbox::ProcessHardening,
            BridgeSandbox::LinuxLandlockWriteDeny,
            BridgeSandbox::LinuxLandlockWriteDenyNetworkNamespace,
        ] {
            assert!(!bridge_sandbox_uses_landlock_read_allow_list(sandbox));
        }
        assert!(bridge_sandbox_uses_network_namespace(
            BridgeSandbox::LinuxLandlockStrictNetworkNamespace
        ));
        assert!(!bridge_sandbox_uses_network_namespace(
            BridgeSandbox::LinuxLandlockStrict
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_strict_rules_cover_system_roots_devices_program_and_configured_roots() {
        let rules = linux_landlock_strict_rules(
            &[PathBuf::from("/opt/openfhe")],
            Path::new("/opt/bridge/openfhe-bridge"),
            None,
        )
        .unwrap();
        assert!(rules.program_fd.is_none());
        let paths: Vec<&str> = rules
            .paths
            .iter()
            .map(|rule| rule.path.to_str().unwrap())
            .collect();
        assert_eq!(
            paths,
            [
                "/usr",
                "/lib",
                "/lib64",
                "/bin",
                "/sbin",
                "/etc",
                "/dev/null",
                "/dev/urandom",
                "/dev/random",
                "/opt/openfhe",
                "/opt/bridge/openfhe-bridge",
            ]
        );
        let by_path = |path: &str| {
            rules
                .paths
                .iter()
                .find(|rule| rule.path.to_str().ok() == Some(path))
                .unwrap()
        };
        assert!(!by_path("/lib64").required);
        assert!(by_path("/opt/openfhe").required);
        assert_eq!(
            by_path("/opt/openfhe").allowed_access,
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
            "configured roots are readable but never executable"
        );
        assert_eq!(
            by_path("/opt/bridge/openfhe-bridge").allowed_access,
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_EXECUTE
        );
        assert_eq!(
            by_path("/dev/null").allowed_access,
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE
        );
        assert!(
            rules
                .paths
                .iter()
                .all(|rule| rule.allowed_access & LANDLOCK_ACCESS_FS_MAKE_REG == 0),
            "no rule may grant file creation"
        );

        let checked =
            linux_landlock_strict_rules(&[], Path::new("/opt/bridge/openfhe-bridge"), Some(7))
                .unwrap();
        assert_eq!(checked.program_fd, Some(7));
        assert!(
            checked
                .paths
                .iter()
                .all(|rule| rule.path.to_str().ok() != Some("/opt/bridge/openfhe-bridge")),
            "checked programs are granted through their descriptor, not their path"
        );

        let handled = landlock_strict_handled_access_for_abi(3);
        assert_eq!(
            handled
                & (LANDLOCK_ACCESS_FS_EXECUTE
                    | LANDLOCK_ACCESS_FS_READ_FILE
                    | LANDLOCK_ACCESS_FS_READ_DIR),
            LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
        );
        assert_eq!(
            handled & landlock_write_deny_access_for_abi(3),
            landlock_write_deny_access_for_abi(3)
        );
    }

    #[test]
    fn command_backend_debug_redacts_program_policy_values() {
        let sentinel = "openfhe-backend-debug-sentinel";
        let mut backend = CommandOpenFheBackend::new_unchecked(format!("/tmp/{sentinel}/bridge"))
            .with_args([format!("--token={sentinel}")])
            .with_sensitive_env_names([format!("OPENFHE_{sentinel}")]);
        backend.expected_sha256_b64 = Some(format!("sha256-{sentinel}"));
        let rendered = format!("{backend:?}");

        assert!(!rendered.contains(sentinel), "{rendered}");
        assert!(rendered.contains("program: \"[redacted]\""), "{rendered}");
        assert!(rendered.contains("args_count: 1"), "{rendered}");
        assert!(rendered.contains("expected_sha256_b64: Some"), "{rendered}");
        assert!(
            rendered.contains("sensitive_env_names_count: 1"),
            "{rendered}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unchecked_bridge_strips_qdrant_and_sensitive_env_names() {
        use std::os::unix::fs::PermissionsExt;

        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _env_guard = ENV_LOCK.lock().unwrap();

        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-openfhe-env-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let script = dir.path().join("openfhe-bridge");
        let expected_profile = CkksParameters::default().security_profile().unwrap();
        let script_body = format!(
            r#"#!/bin/sh
if [ "${{QDRANT+x}}" = x ] || \
   [ "${{QDRANT_UNCHECKED_OPENFHE_SECRET_FOR_TEST+x}}" = x ] || \
   [ "${{TENANT_OPENFHE_ENV_SECRET_FOR_TEST+x}}" = x ]; then
  printf '%s\n' 'secret env leaked to unchecked bridge' >&2
  exit 41
fi
if [ "${{OPENFHE_BRIDGE_PUBLIC_ENV_FOR_TEST}}" != "ambient-ok" ]; then
  printf '%s\n' 'public env did not reach unchecked bridge' >&2
  exit 42
fi
while IFS= read -r _line; do
  printf '%s\n' '{{"version":1,"ciphertext":"AQ","security_profile":"{expected_profile}","security_level_bits":128}}'
done
"#
        );
        fs_err::write(&script, script_body).unwrap();
        let mut dir_permissions = fs_err::metadata(dir.path()).unwrap().permissions();
        dir_permissions.set_mode(0o700);
        fs_err::set_permissions(dir.path(), dir_permissions).unwrap();
        let mut script_permissions = fs_err::metadata(&script).unwrap().permissions();
        script_permissions.set_mode(0o700);
        fs_err::set_permissions(&script, script_permissions).unwrap();

        unsafe {
            std::env::set_var("QDRANT", "qdrant-root-secret");
            std::env::set_var(
                "QDRANT_UNCHECKED_OPENFHE_SECRET_FOR_TEST",
                "qdrant-prefixed-secret",
            );
            std::env::set_var(
                "TENANT_OPENFHE_ENV_SECRET_FOR_TEST",
                "tenant-material-secret",
            );
            std::env::set_var("OPENFHE_BRIDGE_PUBLIC_ENV_FOR_TEST", "ambient-ok");
        }

        let backend = CommandOpenFheBackend::new_unchecked(&script)
            .with_timeout(Duration::from_secs(2))
            .with_sensitive_env_names(["TENANT_OPENFHE_ENV_SECRET_FOR_TEST"]);
        let parameters = CkksParameters::default();
        let public_material =
            crate::vector::CkksPublicMaterial::new(b"env-test-context", b"env-test-public-key")
                .unwrap();
        let result = backend.encrypt(CkksEncryptionInput {
            parameters: &parameters,
            public_material: &public_material,
            collection: "docs",
            point_id: "point-1",
            vector_name: "embedding",
            values: &[1.0, 2.0],
        });

        unsafe {
            std::env::remove_var("QDRANT");
            std::env::remove_var("QDRANT_UNCHECKED_OPENFHE_SECRET_FOR_TEST");
            std::env::remove_var("TENANT_OPENFHE_ENV_SECRET_FOR_TEST");
            std::env::remove_var("OPENFHE_BRIDGE_PUBLIC_ENV_FOR_TEST");
        }

        let ciphertext = result.expect("unchecked bridge should receive only allowed env values");
        assert_eq!(ciphertext, vec![1]);
    }

    #[test]
    fn cached_context_requests_strip_public_material_for_all_openfhe_operations() {
        let parameters = CkksParameters::default();
        let score_item = CommandOpenFheScoreBatchItem {
            point_id: "42",
            ciphertext: "ciphertext".to_string(),
        };
        let batch_item = CommandOpenFheBatchItem {
            point_id: "42",
            values: &[1.0, 2.0],
        };

        let mut requests = Vec::new();
        requests.push(
            serialize_bridge_request_without_public_material(
                &CommandOpenFheRequest {
                    version: 1,
                    operation: "encrypt",
                    scheme: CKKS_SCHEME,
                    collection: "docs",
                    point_id: "42",
                    vector_name: "text",
                    context_id: "ctx-1".to_string(),
                    parameters: Some(&parameters),
                    crypto_context: Some("crypto-context".to_string()),
                    public_key: Some("public-key".to_string()),
                    values: &[1.0, 2.0],
                },
                "test encrypt request",
            )
            .unwrap(),
        );
        requests.push(
            serialize_bridge_request_without_public_material(
                &CommandOpenFheBatchRequest {
                    version: 1,
                    operation: "encrypt_batch",
                    scheme: CKKS_SCHEME,
                    collection: "docs",
                    vector_name: "text",
                    context_id: "ctx-1".to_string(),
                    parameters: Some(&parameters),
                    crypto_context: Some("crypto-context".to_string()),
                    public_key: Some("public-key".to_string()),
                    items: vec![batch_item],
                },
                "test batch request",
            )
            .unwrap(),
        );
        requests.push(
            serialize_bridge_request_without_public_material(
                &CommandOpenFheQueryRequest {
                    version: 1,
                    operation: "encrypt_query",
                    scheme: CKKS_SCHEME,
                    collection: "docs",
                    vector_name: "text",
                    context_id: "ctx-1".to_string(),
                    parameters: Some(&parameters),
                    crypto_context: Some("crypto-context".to_string()),
                    public_key: Some("public-key".to_string()),
                    values: &[1.0, 2.0],
                },
                "test query request",
            )
            .unwrap(),
        );
        requests.push(
            serialize_bridge_request_without_public_material(
                &CommandOpenFheScoreRequest {
                    version: 1,
                    operation: "score_plaintext_query",
                    scheme: CKKS_SCHEME,
                    collection: "docs",
                    point_id: "42",
                    vector_name: "text",
                    distance: "cosine",
                    context_id: "ctx-1".to_string(),
                    parameters: Some(&parameters),
                    crypto_context: Some("crypto-context".to_string()),
                    public_key: Some("public-key".to_string()),
                    query_values: &[1.0, 2.0],
                    ciphertext: "ciphertext".to_string(),
                },
                "test score request",
            )
            .unwrap(),
        );
        requests.push(
            serialize_bridge_request_without_public_material(
                &CommandOpenFheScoreBatchRequest {
                    version: 1,
                    operation: "score_plaintext_query_batch",
                    scheme: CKKS_SCHEME,
                    collection: "docs",
                    vector_name: "text",
                    distance: "cosine",
                    context_id: "ctx-1".to_string(),
                    parameters: Some(&parameters),
                    crypto_context: Some("crypto-context".to_string()),
                    public_key: Some("public-key".to_string()),
                    query_values: &[1.0, 2.0],
                    items: vec![score_item.clone()],
                },
                "test score batch request",
            )
            .unwrap(),
        );
        requests.push(
            serialize_bridge_request_without_public_material(
                &CommandOpenFheEncryptedScoreRequest {
                    version: 1,
                    operation: "score_encrypted_query",
                    scheme: CKKS_SCHEME,
                    collection: "docs",
                    point_id: "42",
                    vector_name: "text",
                    distance: "cosine",
                    context_id: "ctx-1".to_string(),
                    parameters: Some(&parameters),
                    crypto_context: Some("crypto-context".to_string()),
                    public_key: Some("public-key".to_string()),
                    encrypted_query: "query-ciphertext".to_string(),
                    ciphertext: "ciphertext".to_string(),
                },
                "test encrypted score request",
            )
            .unwrap(),
        );
        requests.push(
            serialize_bridge_request_without_public_material(
                &CommandOpenFheEncryptedScoreBatchRequest {
                    version: 1,
                    operation: "score_encrypted_query_batch",
                    scheme: CKKS_SCHEME,
                    collection: "docs",
                    vector_name: "text",
                    distance: "cosine",
                    context_id: "ctx-1".to_string(),
                    parameters: Some(&parameters),
                    crypto_context: Some("crypto-context".to_string()),
                    public_key: Some("public-key".to_string()),
                    encrypted_query: "query-ciphertext".to_string(),
                    items: vec![score_item],
                },
                "test encrypted score batch request",
            )
            .unwrap(),
        );

        for request in requests {
            let request: serde_json::Value = serde_json::from_slice(&request).unwrap();
            assert_eq!(request["context_id"], "ctx-1");
            assert!(request.get("parameters").is_none());
            assert!(request.get("crypto_context").is_none());
            assert!(request.get("public_key").is_none());
        }
    }

    #[cfg(unix)]
    #[test]
    fn worker_process_reserves_idle_worker_until_reservation_drops() {
        let backend = CommandOpenFheBackend::new_unchecked("cat")
            .with_pool_size(NonZeroUsize::new(2).unwrap());

        let first = backend.worker_process().unwrap();
        let first_worker = Arc::clone(first.worker());
        let second = backend.worker_process().unwrap();
        let second_worker = Arc::clone(second.worker());

        assert!(!Arc::ptr_eq(&first_worker, &second_worker));

        drop(first);
        let third = backend.worker_process().unwrap();

        assert!(Arc::ptr_eq(third.worker(), &first_worker));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bridge_worker_survives_the_exit_of_the_thread_that_spawned_it() {
        let backend = CommandOpenFheBackend::new_unchecked("cat")
            .with_pool_size(NonZeroUsize::new(1).unwrap());
        let spawner = backend.clone();
        let worker = std::thread::spawn(move || {
            let reservation = spawner.worker_process().unwrap();
            Arc::clone(reservation.worker())
        })
        .join()
        .unwrap();
        // PR_SET_PDEATHSIG fires when the spawning *thread* exits; give the kernel a moment.
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            worker.try_wait().unwrap().is_none(),
            "bridge worker died with the thread that spawned it"
        );
        let reservation = backend.worker_process().unwrap();
        assert!(Arc::ptr_eq(reservation.worker(), &worker));
    }

    #[cfg(unix)]
    #[test]
    fn unsolicited_bridge_output_discards_the_worker_before_a_request_is_sent() {
        let backend = CommandOpenFheBackend::new_unchecked("sh")
            .with_args(["-c".to_string(), "printf 'hello\\n'; exec cat".to_string()])
            .with_pool_size(NonZeroUsize::new(1).unwrap());
        let worker = Arc::clone(backend.worker_process().unwrap().worker());
        std::thread::sleep(Duration::from_millis(300));
        let err = backend
            .send_bridge_request_impl(None, br#"{"ping":1}"#, None, |bytes| Ok(bytes.to_vec()))
            .unwrap_err();
        assert!(
            matches!(err, CkksError::Backend(ref message) if message.contains("without a request")),
            "{err:?}"
        );
        assert!(worker.terminated.load(Ordering::SeqCst));
    }

    #[cfg(unix)]
    #[test]
    fn cloned_backend_worker_process_fails_fast_when_shared_pool_is_busy() {
        let backend = CommandOpenFheBackend::new_unchecked("cat")
            .with_pool_size(NonZeroUsize::new(1).unwrap());
        let cloned = backend.clone();

        let _first = backend.worker_process().unwrap();
        match cloned.worker_process() {
            Ok(_) => {
                panic!("a busy full pool must fail fast instead of serializing on a busy worker")
            }
            Err(CkksError::Backend(message)) => {
                assert!(message.contains("worker pool is exhausted"), "{message}");
            }
            Err(err) => panic!("unexpected busy full pool error: {err:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn builder_policy_change_uses_isolated_worker_pool() {
        let backend = CommandOpenFheBackend::new_unchecked("cat")
            .with_pool_size(NonZeroUsize::new(1).unwrap());
        let first = backend.worker_process().unwrap();
        let first_worker = Arc::clone(first.worker());

        let changed = backend.clone().with_timeout(Duration::from_millis(250));
        let changed_worker = changed.worker_process().unwrap();

        assert!(
            !Arc::ptr_eq(changed_worker.worker(), &first_worker),
            "policy-changing builders must not reuse workers started with the previous policy",
        );
    }

    #[cfg(unix)]
    #[test]
    fn bridge_request_retries_once_after_worker_exits_before_response() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-openfhe-retry-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let marker = dir.path().join("first-worker-exited");
        let script = dir.path().join("openfhe-bridge");
        let expected_profile = CkksParameters::default().security_profile().unwrap();
        let script_body = format!(
            r#"#!/bin/sh
if [ ! -f "{marker}" ]; then
  : > "{marker}"
  exit 0
fi
while IFS= read -r _line; do
  printf '%s\n' '{{"version":1,"ciphertext":"AQ","security_profile":"{expected_profile}","security_level_bits":128}}'
done
"#,
            marker = marker.display(),
        );
        fs_err::write(&script, script_body).unwrap();
        let mut dir_permissions = fs_err::metadata(dir.path()).unwrap().permissions();
        dir_permissions.set_mode(0o700);
        fs_err::set_permissions(dir.path(), dir_permissions).unwrap();
        let mut script_permissions = fs_err::metadata(&script).unwrap().permissions();
        script_permissions.set_mode(0o700);
        fs_err::set_permissions(&script, script_permissions).unwrap();

        let backend = CommandOpenFheBackend::new_unchecked(&script)
            .with_timeout(Duration::from_secs(2))
            .with_pool_size(NonZeroUsize::new(1).unwrap());
        let parameters = CkksParameters::default();
        let public_material =
            crate::vector::CkksPublicMaterial::new(b"retry-test-context", b"retry-test-public-key")
                .unwrap();

        let ciphertext = backend
            .encrypt(CkksEncryptionInput {
                parameters: &parameters,
                public_material: &public_material,
                collection: "docs",
                point_id: "point-1",
                vector_name: "embedding",
                values: &[1.0, 2.0],
            })
            .expect("second bridge worker should satisfy the retried request");

        assert_eq!(ciphertext, vec![1]);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_batch_request_retries_once_after_worker_exits_before_response() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-openfhe-batch-retry-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let marker = dir.path().join("first-worker-exited");
        let script = dir.path().join("openfhe-bridge");
        let expected_profile = CkksParameters::default().security_profile().unwrap();
        let script_body = format!(
            r#"#!/bin/sh
if [ ! -f "{marker}" ]; then
  : > "{marker}"
  exit 0
fi
while IFS= read -r _line; do
  printf '%s\n' '{{"version":1,"ciphertexts":["AQ","Ag"],"security_profile":"{expected_profile}","security_level_bits":128}}'
done
"#,
            marker = marker.display(),
        );
        fs_err::write(&script, script_body).unwrap();
        let mut dir_permissions = fs_err::metadata(dir.path()).unwrap().permissions();
        dir_permissions.set_mode(0o700);
        fs_err::set_permissions(dir.path(), dir_permissions).unwrap();
        let mut script_permissions = fs_err::metadata(&script).unwrap().permissions();
        script_permissions.set_mode(0o700);
        fs_err::set_permissions(&script, script_permissions).unwrap();

        let backend = CommandOpenFheBackend::new_unchecked(&script)
            .with_timeout(Duration::from_secs(2))
            .with_pool_size(NonZeroUsize::new(1).unwrap());
        let parameters = CkksParameters::default();
        let public_material = crate::vector::CkksPublicMaterial::new(
            b"batch-retry-test-context",
            b"batch-retry-test-public-key",
        )
        .unwrap();
        let items = [
            crate::vector::CkksVectorBatchItem {
                point_id: "point-1",
                values: &[1.0, 2.0],
            },
            crate::vector::CkksVectorBatchItem {
                point_id: "point-2",
                values: &[3.0, 4.0],
            },
        ];

        let ciphertexts = backend
            .encrypt_batch(CkksBatchEncryptionInput {
                parameters: &parameters,
                public_material: &public_material,
                collection: "docs",
                vector_name: "embedding",
                items: &items,
            })
            .expect("second bridge worker should satisfy the retried batch request");

        assert_eq!(ciphertexts, vec![vec![1], vec![2]]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(
        clippy::used_underscore_binding,
        reason = "the fd is kept only for its lifetime"
    )]
    fn checked_bridge_spawn_program_uses_validated_proc_fd_path() {
        let program = std::env::current_exe().unwrap();
        let expected_sha256_b64 =
            BASE64URL_NOPAD.encode(&Sha256::digest(fs_err::read(&program).unwrap()));

        let spawn_program =
            checked_bridge_spawn_program(&program, Some(&expected_sha256_b64)).unwrap();

        assert!(spawn_program.path().starts_with("/proc/self/fd"));
        assert!(spawn_program.fd.is_some());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn checked_bridge_spawn_is_linux_only() {
        let program = std::env::current_exe().unwrap();
        let expected_sha256_b64 =
            BASE64URL_NOPAD.encode(&Sha256::digest(fs_err::read(&program).unwrap()));

        let err = CommandOpenFheBackend::new_checked_with_sha256_b64(&program, expected_sha256_b64)
            .expect_err("non-Linux checked bridge spawn must fail closed");

        assert!(
            format!("{err}").contains("requires Linux fd-backed /proc/self/fd execution"),
            "{err}"
        );
    }

    #[test]
    fn checked_bridge_sha256_pin_rejects_oversized_encoded_pin() {
        let program = std::env::current_exe().unwrap();
        let err = CommandOpenFheBackend::new_checked_with_sha256_b64(&program, "A".repeat(1024))
            .expect_err("oversized sha256 pin must fail before bridge hash validation");
        assert!(format!("{err}").contains("must decode to 32 bytes"));
    }

    #[test]
    fn checked_bridge_errors_do_not_reflect_program_path() {
        let relative_program = PathBuf::from("qdrant-sec-openfhe-path-sentinel");
        let err = CommandOpenFheBackend::new_checked(&relative_program)
            .expect_err("relative checked bridge program path must be rejected");
        let rendered = format!("{err}");
        assert!(
            !rendered.contains("qdrant-sec-openfhe-path-sentinel"),
            "{rendered}"
        );

        let program = std::env::current_exe().unwrap();
        let err = CommandOpenFheBackend::new_checked_with_sha256_b64(
            &program,
            BASE64URL_NOPAD.encode(&[0u8; 32]),
        )
        .expect_err("sha256 mismatch must be rejected");
        let rendered = format!("{err}");
        assert!(
            !rendered.contains(&program.display().to_string()),
            "{rendered}"
        );
    }

    #[test]
    fn checked_bridge_sha256_pin_rejects_oversized_program_before_hash() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-openfhe-oversized-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        #[cfg(unix)]
        {
            let mut dir_permissions = fs_err::metadata(dir.path()).unwrap().permissions();
            dir_permissions.set_mode(0o700);
            fs_err::set_permissions(dir.path(), dir_permissions).unwrap();
        }

        let program = dir.path().join("openfhe-bridge");
        let file = fs_err::File::create(&program).unwrap();
        file.set_len(MAX_BRIDGE_PROGRAM_SHA256_BYTES + 1).unwrap();
        drop(file);
        #[cfg(unix)]
        {
            let mut permissions = fs_err::metadata(&program).unwrap().permissions();
            permissions.set_mode(0o700);
            fs_err::set_permissions(&program, permissions).unwrap();
        }

        let err = CommandOpenFheBackend::new_checked_with_sha256_b64(
            &program,
            BASE64URL_NOPAD.encode(&[0u8; 32]),
        )
        .expect_err("oversized bridge program must fail before full-file hash allocation");
        assert!(format!("{err}").contains("exceeds"));
    }
}

#[cfg(test)]
#[path = "openfhe_concurrency_tests.rs"]
mod concurrency_tests;
