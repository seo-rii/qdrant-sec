use std::fmt::{self, Debug, Formatter};
use std::io::{self, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd as _, FromRawFd as _};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt as _;

use tempfile::NamedTempFile;

#[cfg(test)]
thread_local! {
    static FAIL_IMMUTABLE_JSON_AFTER_RENAME_V2: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

#[cfg(test)]
pub(super) fn set_fail_immutable_json_after_rename_v2(enabled: bool) {
    FAIL_IMMUTABLE_JSON_AFTER_RENAME_V2.set(enabled);
}

fn fail_immutable_json_after_rename_v2() -> Result<(), PrivateOramMutationJournalError> {
    #[cfg(test)]
    if FAIL_IMMUTABLE_JSON_AFTER_RENAME_V2.get() {
        return Err(PrivateOramMutationJournalError::Indeterminate);
    }
    Ok(())
}

use super::*;
use crate::content_manager::private_oram_mutation_state_v2::{
    DecodedPrivateOramMutationStateUntrusted, PrivateOramMutationJournalPhaseV2,
    PrivateOramMutationJournalStateV2, PrivateOramMutationOwnerJournalEvidenceV2,
    PrivateOramMutationOwnerTerminalBatchV2, PrivateOramMutationPointStageEvidenceV2,
    canonical_private_oram_mutation_state_history_v2, decode_untrusted_private_oram_mutation_state,
    initial_private_oram_mutation_state_v2, next_private_oram_mutation_state_v2,
    private_oram_point_stage_evidence_v2_from_durable_token, record_digest_at_phase_v2,
    validate_private_oram_mutation_state_v2_structure,
};

mod owner_recovery_capsule;
#[cfg(test)]
pub(crate) use owner_recovery_capsule::private_oram_owner_recovery_capsule_install_receipt_for_test;
pub use owner_recovery_capsule::{
    PrivateOramOwnerRecoveryCapsuleInstallReceiptV2, PrivateOramOwnerRecoveryCapsulePackageV2,
    PrivateOramOwnerRecoveryCapsuleStoreV2,
    decode_private_oram_owner_recovery_capsule_install_receipt_v2,
    decode_private_oram_owner_recovery_capsule_package_v2,
    encode_private_oram_owner_recovery_capsule_install_receipt_v2,
    encode_private_oram_owner_recovery_capsule_package_v2,
    validate_private_oram_owner_recovery_capsule_install_receipt_v2,
};

const STATE_RECORDS_DIR: &str = "state_records";
const STATE_RECORD_FILE_SUFFIX: &str = ".json";
const FORMAT_FILE: &str = "format.json";
const V2_JOURNAL_FORMAT_VERSION: u16 = 2;
const MAX_FORMAT_BYTES: u64 = 1 << 12;
const MAX_V2_STATE_RECORDS: usize = 7;
const MAX_V2_HISTORY_BYTES: u64 = 256 * 1024 * 1024;

#[cfg(target_os = "linux")]
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
#[cfg(target_os = "linux")]
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
#[cfg(target_os = "linux")]
const RESOLVE_BENEATH: u64 = 0x08;
#[cfg(target_os = "linux")]
const RENAME_NOREPLACE_V2: u32 = 1;

#[cfg(target_os = "linux")]
#[repr(C)]
struct PrivateOramOpenHowV2 {
    flags: u64,
    mode: u64,
    resolve: u64,
}

struct PrivateOramPinnedDirectoryV2 {
    file: std::fs::File,
}

impl Debug for PrivateOramPinnedDirectoryV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramPinnedDirectoryV2")
            .field("file", &"[redacted]")
            .finish()
    }
}

struct PrivateOramPinnedFileV2 {
    file: std::fs::File,
    name: std::ffi::OsString,
    max_bytes: u64,
    bytes: Vec<u8>,
}

impl Debug for PrivateOramPinnedFileV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramPinnedFileV2")
            .field("file", &"[redacted]")
            .field("name", &"[redacted]")
            .field("max_bytes", &self.max_bytes)
            .field("bytes", &"[redacted]")
            .finish()
    }
}

impl PrivateOramPinnedFileV2 {
    #[cfg(target_os = "linux")]
    fn open_at(
        parent: &std::fs::File,
        name: &std::ffi::OsStr,
        max_bytes: u64,
    ) -> Result<Self, PrivateOramMutationJournalError> {
        let checked_name = checked_private_oram_entry_name_v2(name)?;
        let how = PrivateOramOpenHowV2 {
            flags: u64::try_from(
                nix::libc::O_RDONLY | nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW,
            )
            .map_err(|_| PrivateOramMutationJournalError::Unsupported)?,
            mode: 0,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
        };
        // SAFETY: `checked_name` is a single-component C string, `how` has the Linux open_how
        // ABI, and the returned descriptor is owned immediately on success.
        let descriptor = unsafe {
            nix::libc::syscall(
                nix::libc::SYS_openat2,
                parent.as_raw_fd(),
                checked_name.as_ptr(),
                &how,
                std::mem::size_of::<PrivateOramOpenHowV2>(),
            )
        };
        if descriptor < 0 {
            let error = io::Error::last_os_error();
            return Err(match error.raw_os_error() {
                Some(nix::libc::ENOSYS | nix::libc::EINVAL | nix::libc::E2BIG) => {
                    PrivateOramMutationJournalError::Unsupported
                }
                Some(nix::libc::ENOENT) => PrivateOramMutationJournalError::Io(error),
                _ => PrivateOramMutationJournalError::Corrupt,
            });
        }
        let descriptor =
            i32::try_from(descriptor).map_err(|_| PrivateOramMutationJournalError::Unsupported)?;
        // SAFETY: the successful syscall returned one owned file descriptor.
        let file = unsafe { std::fs::File::from_raw_fd(descriptor) };
        validate_private_file_metadata(
            &file
                .metadata()
                .map_err(PrivateOramMutationJournalError::Io)?,
            max_bytes,
        )?;
        let bytes = read_private_oram_pinned_file_v2(&file, max_bytes)?;
        validate_private_file_metadata(
            &file
                .metadata()
                .map_err(PrivateOramMutationJournalError::Io)?,
            max_bytes,
        )?;
        Ok(Self {
            file,
            name: name.to_owned(),
            max_bytes,
            bytes,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn open_at(
        _parent: &std::fs::File,
        _name: &std::ffi::OsStr,
        _max_bytes: u64,
    ) -> Result<Self, PrivateOramMutationJournalError> {
        Err(PrivateOramMutationJournalError::Unsupported)
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn deserialize<T: DeserializeOwned>(&self) -> Result<T, PrivateOramMutationJournalError> {
        serde_json::from_slice(&self.bytes).map_err(|_| PrivateOramMutationJournalError::Corrupt)
    }

    fn validate_binding_and_contents(
        &self,
        parent: &std::fs::File,
    ) -> Result<(), PrivateOramMutationJournalError> {
        let current_metadata = self
            .file
            .metadata()
            .map_err(PrivateOramMutationJournalError::Io)?;
        validate_private_file_metadata(&current_metadata, self.max_bytes)?;
        if read_private_oram_pinned_file_v2(&self.file, self.max_bytes)? != self.bytes {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        let reopened = Self::open_at(parent, &self.name, self.max_bytes)?;
        let reopened_metadata = reopened
            .file
            .metadata()
            .map_err(PrivateOramMutationJournalError::Io)?;
        ensure_same_file(&current_metadata, &reopened_metadata)?;
        if reopened.bytes != self.bytes {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        Ok(())
    }
}

struct PrivateOramJsonCandidateV2 {
    named: NamedTempFile,
    pinned: PrivateOramPinnedFileV2,
}

impl Debug for PrivateOramJsonCandidateV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramJsonCandidateV2")
            .field("named", &"[redacted]")
            .field("pinned", &self.pinned)
            .finish()
    }
}

impl PrivateOramJsonCandidateV2 {
    #[allow(
        clippy::disallowed_methods,
        reason = "the temporary file is created below a retained directory descriptor"
    )]
    fn new<T: Serialize>(
        temp: &PrivateOramPinnedDirectoryV2,
        value: &T,
        max_bytes: u64,
    ) -> Result<Self, PrivateOramMutationJournalError> {
        let bytes = serde_json::to_vec(value)
            .map_err(|error| PrivateOramMutationJournalError::Io(io::Error::other(error)))?;
        if u64::try_from(bytes.len()).map_err(|_| PrivateOramMutationJournalError::Corrupt)?
            > max_bytes
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        let mut named = NamedTempFile::new_in(temp.pinned_path()?)
            .map_err(PrivateOramMutationJournalError::Io)?;
        named
            .write_all(&bytes)
            .map_err(PrivateOramMutationJournalError::Io)?;
        named.flush().map_err(PrivateOramMutationJournalError::Io)?;
        named
            .as_file()
            .sync_all()
            .map_err(PrivateOramMutationJournalError::Io)?;
        validate_private_file_metadata(
            &named
                .as_file()
                .metadata()
                .map_err(PrivateOramMutationJournalError::Io)?,
            max_bytes,
        )?;
        let name = private_oram_temp_file_name_v2(&named)?;
        let pinned = PrivateOramPinnedFileV2::open_at(&temp.file, &name, max_bytes)?;
        ensure_same_file(
            &named
                .as_file()
                .metadata()
                .map_err(PrivateOramMutationJournalError::Io)?,
            &pinned
                .file
                .metadata()
                .map_err(PrivateOramMutationJournalError::Io)?,
        )?;
        if pinned.bytes() != bytes {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        Ok(Self { named, pinned })
    }

    fn name(&self) -> &std::ffi::OsStr {
        &self.pinned.name
    }

    fn validate_source(
        &self,
        temp: &PrivateOramPinnedDirectoryV2,
    ) -> Result<(), PrivateOramMutationJournalError> {
        self.pinned.validate_binding_and_contents(&temp.file)?;
        ensure_same_file(
            &self
                .named
                .as_file()
                .metadata()
                .map_err(PrivateOramMutationJournalError::Io)?,
            &self
                .pinned
                .file
                .metadata()
                .map_err(PrivateOramMutationJournalError::Io)?,
        )
    }

    fn validate_installed(
        &self,
        destination_parent: &PrivateOramPinnedDirectoryV2,
        destination_name: &std::ffi::OsStr,
        max_bytes: u64,
    ) -> Result<PrivateOramPinnedFileV2, PrivateOramMutationJournalError> {
        let installed = PrivateOramPinnedFileV2::open_at(
            &destination_parent.file,
            destination_name,
            max_bytes,
        )?;
        ensure_same_file(
            &self
                .pinned
                .file
                .metadata()
                .map_err(PrivateOramMutationJournalError::Io)?,
            &installed
                .file
                .metadata()
                .map_err(PrivateOramMutationJournalError::Io)?,
        )?;
        if installed.bytes() != self.pinned.bytes() {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        installed.validate_binding_and_contents(&destination_parent.file)?;
        Ok(installed)
    }

    fn keep_after_publish(self) -> Result<(), PrivateOramMutationJournalError> {
        self.named
            .keep()
            .map(|_| ())
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)
    }
}

#[cfg(target_os = "linux")]
fn read_private_oram_pinned_file_v2(
    file: &std::fs::File,
    max_bytes: u64,
) -> Result<Vec<u8>, PrivateOramMutationJournalError> {
    use std::os::unix::fs::FileExt as _;

    let initial_length = file
        .metadata()
        .map_err(PrivateOramMutationJournalError::Io)?
        .len()
        .min(max_bytes);
    let capacity =
        usize::try_from(initial_length).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    let mut buffer = [0_u8; 64 * 1024];
    let mut offset = 0_u64;
    loop {
        let read = match file.read_at(&mut buffer, offset) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(PrivateOramMutationJournalError::Io(error)),
        };
        if read == 0 {
            break;
        }
        offset = offset
            .checked_add(u64::try_from(read).map_err(|_| PrivateOramMutationJournalError::Corrupt)?)
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        if offset > max_bytes {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(bytes)
}

#[cfg(not(target_os = "linux"))]
fn read_private_oram_pinned_file_v2(
    _file: &std::fs::File,
    _max_bytes: u64,
) -> Result<Vec<u8>, PrivateOramMutationJournalError> {
    Err(PrivateOramMutationJournalError::Unsupported)
}

impl PrivateOramPinnedDirectoryV2 {
    #[cfg(target_os = "linux")]
    fn open_at(
        parent: &std::fs::File,
        name: &std::ffi::OsStr,
    ) -> Result<Self, PrivateOramMutationJournalError> {
        let name = checked_private_oram_entry_name_v2(name)?;
        let how = PrivateOramOpenHowV2 {
            flags: u64::try_from(
                nix::libc::O_RDONLY
                    | nix::libc::O_CLOEXEC
                    | nix::libc::O_NOFOLLOW
                    | nix::libc::O_DIRECTORY,
            )
            .map_err(|_| PrivateOramMutationJournalError::Unsupported)?,
            mode: 0,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
        };
        // SAFETY: `name` is a single-component C string, `how` has the Linux open_how ABI,
        // and the returned descriptor is owned immediately on success.
        let descriptor = unsafe {
            nix::libc::syscall(
                nix::libc::SYS_openat2,
                parent.as_raw_fd(),
                name.as_ptr(),
                &how,
                std::mem::size_of::<PrivateOramOpenHowV2>(),
            )
        };
        if descriptor < 0 {
            let error = io::Error::last_os_error();
            return Err(match error.raw_os_error() {
                Some(nix::libc::ENOSYS | nix::libc::EINVAL | nix::libc::E2BIG) => {
                    PrivateOramMutationJournalError::Unsupported
                }
                Some(nix::libc::ENOENT) => PrivateOramMutationJournalError::Io(error),
                _ => PrivateOramMutationJournalError::Corrupt,
            });
        }
        let descriptor =
            i32::try_from(descriptor).map_err(|_| PrivateOramMutationJournalError::Unsupported)?;
        // SAFETY: the successful syscall returned one owned file descriptor.
        let file = unsafe { std::fs::File::from_raw_fd(descriptor) };
        validate_private_directory_metadata(
            &file
                .metadata()
                .map_err(PrivateOramMutationJournalError::Io)?,
        )?;
        Ok(Self { file })
    }

    #[cfg(not(target_os = "linux"))]
    fn open_at(
        _parent: &std::fs::File,
        _name: &std::ffi::OsStr,
    ) -> Result<Self, PrivateOramMutationJournalError> {
        Err(PrivateOramMutationJournalError::Unsupported)
    }

    fn pinned_path(&self) -> Result<std::path::PathBuf, PrivateOramMutationJournalError> {
        #[cfg(target_os = "linux")]
        {
            Ok(std::path::PathBuf::from("/proc/self/fd").join(self.file.as_raw_fd().to_string()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(PrivateOramMutationJournalError::Unsupported)
        }
    }

    fn sync(&self) -> Result<(), PrivateOramMutationJournalError> {
        self.file
            .sync_all()
            .map_err(PrivateOramMutationJournalError::Io)
    }

    fn validate_binding(
        &self,
        parent: &std::fs::File,
        name: &std::ffi::OsStr,
    ) -> Result<(), PrivateOramMutationJournalError> {
        let reopened = Self::open_at(parent, name)?;
        let expected = self
            .file
            .metadata()
            .map_err(PrivateOramMutationJournalError::Io)?;
        let actual = reopened
            .file
            .metadata()
            .map_err(PrivateOramMutationJournalError::Io)?;
        ensure_same_directory(&expected, &actual)
    }
}

fn checked_private_oram_entry_name_v2(
    name: &std::ffi::OsStr,
) -> Result<std::ffi::CString, PrivateOramMutationJournalError> {
    let bytes = name.as_encoded_bytes();
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
        || bytes.contains(&0)
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    std::ffi::CString::new(bytes).map_err(|_| PrivateOramMutationJournalError::Corrupt)
}

#[cfg(target_os = "linux")]
fn rename_private_oram_entry_at_v2(
    source_parent: &std::fs::File,
    source_name: &std::ffi::OsStr,
    destination_parent: &std::fs::File,
    destination_name: &std::ffi::OsStr,
    no_replace: bool,
) -> Result<(), PrivateOramMutationJournalError> {
    let source_name = checked_private_oram_entry_name_v2(source_name)?;
    let destination_name = checked_private_oram_entry_name_v2(destination_name)?;
    let flags = if no_replace { RENAME_NOREPLACE_V2 } else { 0 };
    // SAFETY: both names are single-component C strings, both descriptors remain open for the
    // syscall, and `flags` contains only the supported renameat2 bit used by this module.
    let result = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_renameat2,
            source_parent.as_raw_fd(),
            source_name.as_ptr(),
            destination_parent.as_raw_fd(),
            destination_name.as_ptr(),
            flags,
        )
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        return Err(match error.raw_os_error() {
            Some(nix::libc::ENOSYS | nix::libc::EINVAL) => {
                PrivateOramMutationJournalError::Unsupported
            }
            _ => PrivateOramMutationJournalError::Io(error),
        });
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn rename_private_oram_entry_at_v2(
    _source_parent: &std::fs::File,
    _source_name: &std::ffi::OsStr,
    _destination_parent: &std::fs::File,
    _destination_name: &std::ffi::OsStr,
    _no_replace: bool,
) -> Result<(), PrivateOramMutationJournalError> {
    Err(PrivateOramMutationJournalError::Unsupported)
}

#[cfg(target_os = "linux")]
fn create_private_oram_directory_at_v2(
    parent: &PrivateOramPinnedDirectoryV2,
    name: &std::ffi::OsStr,
) -> Result<PrivateOramPinnedDirectoryV2, PrivateOramMutationJournalError> {
    let name = checked_private_oram_entry_name_v2(name)?;
    // SAFETY: `name` is a single-component C string and `parent` remains open for the syscall.
    let result = unsafe { nix::libc::mkdirat(parent.file.as_raw_fd(), name.as_ptr(), 0o700) };
    if result < 0 {
        return Err(PrivateOramMutationJournalError::Io(
            io::Error::last_os_error(),
        ));
    }
    let directory = PrivateOramPinnedDirectoryV2::open_at(
        &parent.file,
        std::ffi::OsStr::from_bytes(name.as_bytes()),
    )?;
    parent
        .sync()
        .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
    directory.validate_binding(&parent.file, std::ffi::OsStr::from_bytes(name.as_bytes()))?;
    Ok(directory)
}

#[cfg(not(target_os = "linux"))]
fn create_private_oram_directory_at_v2(
    _parent: &PrivateOramPinnedDirectoryV2,
    _name: &std::ffi::OsStr,
) -> Result<PrivateOramPinnedDirectoryV2, PrivateOramMutationJournalError> {
    Err(PrivateOramMutationJournalError::Unsupported)
}

#[cfg(target_os = "linux")]
fn write_new_private_oram_json_at_v2<T: Serialize>(
    parent: &PrivateOramPinnedDirectoryV2,
    name: &std::ffi::OsStr,
    value: &T,
    max_bytes: u64,
) -> Result<PrivateOramPinnedFileV2, PrivateOramMutationJournalError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| PrivateOramMutationJournalError::Io(io::Error::other(error)))?;
    if u64::try_from(bytes.len()).map_err(|_| PrivateOramMutationJournalError::Corrupt)? > max_bytes
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let checked_name = checked_private_oram_entry_name_v2(name)?;
    let how = PrivateOramOpenHowV2 {
        flags: u64::try_from(
            nix::libc::O_WRONLY
                | nix::libc::O_CLOEXEC
                | nix::libc::O_NOFOLLOW
                | nix::libc::O_CREAT
                | nix::libc::O_EXCL,
        )
        .map_err(|_| PrivateOramMutationJournalError::Unsupported)?,
        mode: 0o600,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: `checked_name` is a single-component C string, `how` has the Linux open_how ABI,
    // and the returned descriptor is owned immediately on success.
    let descriptor = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_openat2,
            parent.file.as_raw_fd(),
            checked_name.as_ptr(),
            &how,
            std::mem::size_of::<PrivateOramOpenHowV2>(),
        )
    };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        return Err(match error.raw_os_error() {
            Some(nix::libc::ENOSYS | nix::libc::EINVAL | nix::libc::E2BIG) => {
                PrivateOramMutationJournalError::Unsupported
            }
            _ => PrivateOramMutationJournalError::Io(error),
        });
    }
    let descriptor =
        i32::try_from(descriptor).map_err(|_| PrivateOramMutationJournalError::Unsupported)?;
    // SAFETY: the successful syscall returned one owned file descriptor.
    let mut file = unsafe { std::fs::File::from_raw_fd(descriptor) };
    file.write_all(&bytes)
        .map_err(PrivateOramMutationJournalError::Io)?;
    file.flush().map_err(PrivateOramMutationJournalError::Io)?;
    validate_private_file_metadata(
        &file
            .metadata()
            .map_err(PrivateOramMutationJournalError::Io)?,
        max_bytes,
    )?;
    file.sync_all()
        .map_err(PrivateOramMutationJournalError::Io)?;
    let pinned = PrivateOramPinnedFileV2::open_at(&parent.file, name, max_bytes)?;
    ensure_same_file(
        &file
            .metadata()
            .map_err(PrivateOramMutationJournalError::Io)?,
        &pinned
            .file
            .metadata()
            .map_err(PrivateOramMutationJournalError::Io)?,
    )?;
    if pinned.bytes() != bytes {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    pinned.validate_binding_and_contents(&parent.file)?;
    Ok(pinned)
}

#[cfg(not(target_os = "linux"))]
fn write_new_private_oram_json_at_v2<T: Serialize>(
    _parent: &PrivateOramPinnedDirectoryV2,
    _name: &std::ffi::OsStr,
    _value: &T,
    _max_bytes: u64,
) -> Result<PrivateOramPinnedFileV2, PrivateOramMutationJournalError> {
    Err(PrivateOramMutationJournalError::Unsupported)
}

fn private_oram_temp_file_name_v2(
    candidate: &NamedTempFile,
) -> Result<std::ffi::OsString, PrivateOramMutationJournalError> {
    let name = candidate
        .path()
        .file_name()
        .ok_or(PrivateOramMutationJournalError::Corrupt)?;
    #[cfg(target_os = "linux")]
    checked_private_oram_entry_name_v2(name)?;
    Ok(name.to_owned())
}

struct PrivateOramPinnedActiveNamespaceV2<'lock> {
    root: &'lock std::fs::File,
    namespace_name: std::ffi::OsString,
    root_temp: PrivateOramPinnedDirectoryV2,
    active: PrivateOramPinnedDirectoryV2,
    active_temp: PrivateOramPinnedDirectoryV2,
    records: Option<PrivateOramPinnedDirectoryV2>,
}

impl Debug for PrivateOramPinnedActiveNamespaceV2<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramPinnedActiveNamespaceV2")
            .field("root", &"[redacted]")
            .field("root_temp", &self.root_temp)
            .field("active", &self.active)
            .field("active_temp", &self.active_temp)
            .field("records", &self.records)
            .finish()
    }
}

impl<'lock> PrivateOramPinnedActiveNamespaceV2<'lock> {
    fn open(
        lock: &'lock PrivateOramMutationJournalLock,
    ) -> Result<Self, PrivateOramMutationJournalError> {
        Self::open_named(lock, std::ffi::OsStr::new(ACTIVE_DIR))
    }

    fn open_named(
        lock: &'lock PrivateOramMutationJournalLock,
        namespace_name: &std::ffi::OsStr,
    ) -> Result<Self, PrivateOramMutationJournalError> {
        checked_private_oram_entry_name_v2(namespace_name)?;
        lock.validate_root_identity()?;
        let root = lock.root.directory.file();
        let root_temp =
            PrivateOramPinnedDirectoryV2::open_at(root, std::ffi::OsStr::new(TEMP_DIR))?;
        let active = PrivateOramPinnedDirectoryV2::open_at(root, namespace_name)?;
        let active_temp = PrivateOramPinnedDirectoryV2::open_at(
            &active.file,
            std::ffi::OsStr::new(ACTIVE_TEMP_DIR),
        )?;
        let records = optional_private_oram_directory_at_v2(
            &active.file,
            std::ffi::OsStr::new(STATE_RECORDS_DIR),
        )?;
        let namespace = Self {
            root,
            namespace_name: namespace_name.to_owned(),
            root_temp,
            active,
            active_temp,
            records,
        };
        namespace.validate_bindings(lock)?;
        Ok(namespace)
    }

    fn validate_bindings(
        &self,
        lock: &PrivateOramMutationJournalLock,
    ) -> Result<(), PrivateOramMutationJournalError> {
        self.root_temp
            .validate_binding(self.root, std::ffi::OsStr::new(TEMP_DIR))?;
        self.active
            .validate_binding(self.root, &self.namespace_name)?;
        self.active_temp
            .validate_binding(&self.active.file, std::ffi::OsStr::new(ACTIVE_TEMP_DIR))?;
        match &self.records {
            Some(records) => records
                .validate_binding(&self.active.file, std::ffi::OsStr::new(STATE_RECORDS_DIR))?,
            None => {
                if private_oram_directory_exists_at_v2(
                    &self.active.file,
                    std::ffi::OsStr::new(STATE_RECORDS_DIR),
                )? {
                    return Err(PrivateOramMutationJournalError::Corrupt);
                }
            }
        }
        lock.validate_root_identity()
    }

    fn records(&self) -> Result<&PrivateOramPinnedDirectoryV2, PrivateOramMutationJournalError> {
        self.records
            .as_ref()
            .ok_or(PrivateOramMutationJournalError::Corrupt)
    }
}

fn optional_private_oram_directory_at_v2(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
) -> Result<Option<PrivateOramPinnedDirectoryV2>, PrivateOramMutationJournalError> {
    match PrivateOramPinnedDirectoryV2::open_at(parent, name) {
        Ok(directory) => Ok(Some(directory)),
        Err(PrivateOramMutationJournalError::Io(error))
            if error.kind() == io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn private_oram_directory_exists_at_v2(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
) -> Result<bool, PrivateOramMutationJournalError> {
    Ok(optional_private_oram_directory_at_v2(parent, name)?.is_some())
}

fn optional_private_oram_file_at_v2(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
    max_bytes: u64,
) -> Result<Option<PrivateOramPinnedFileV2>, PrivateOramMutationJournalError> {
    match PrivateOramPinnedFileV2::open_at(parent, name, max_bytes) {
        Ok(file) => Ok(Some(file)),
        Err(PrivateOramMutationJournalError::Io(error))
            if error.kind() == io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PrivateOramMutationJournalFormatV2 {
    state_version: u16,
    descriptor_digest: String,
}

#[derive(Clone, PartialEq, Eq)]
pub(in crate::content_manager) struct PrivateOramMutationJournalStructuralSnapshotV2 {
    pub(super) descriptor: PrivateOramMutationJournalDescriptorV1,
    immutable_manifest: PrivateOramImmutableManifestBundleV2,
    pub(super) state: PrivateOramMutationJournalStateV2,
    pending_next: Option<PrivateOramMutationJournalStateV2>,
}

impl Debug for PrivateOramMutationJournalStructuralSnapshotV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationJournalStructuralSnapshotV2")
            .field("descriptor", &self.descriptor)
            .field("immutable_manifest", &"[redacted]")
            .field("state", &self.state)
            .field("has_pending_next", &self.pending_next.is_some())
            .finish()
    }
}

impl PrivateOramMutationJournalStructuralSnapshotV2 {
    pub(in crate::content_manager) fn validated_descriptor(
        &self,
    ) -> &PrivateOramMutationJournalDescriptorV1 {
        &self.descriptor
    }

    pub(in crate::content_manager) fn effective_state(&self) -> &PrivateOramMutationJournalStateV2 {
        self.pending_next.as_ref().unwrap_or(&self.state)
    }

    pub(in crate::content_manager) fn immutable_manifest(
        &self,
    ) -> &PrivateOramImmutableManifestBundleV2 {
        &self.immutable_manifest
    }

    #[cfg(test)]
    pub(super) fn with_effective_state_for_test(
        &self,
        state: PrivateOramMutationJournalStateV2,
    ) -> Result<Self, PrivateOramMutationJournalError> {
        validate_private_oram_mutation_state_v2_structure(&self.descriptor, &state)?;
        Ok(Self {
            descriptor: self.descriptor.clone(),
            immutable_manifest: self.immutable_manifest.clone(),
            state,
            pending_next: None,
        })
    }

    #[cfg(test)]
    pub(super) fn pending_next_for_test(&self) -> Option<&PrivateOramMutationJournalStateV2> {
        self.pending_next.as_ref()
    }
}

impl PrivateOramMutationJournal {
    /// Calculates the exact parent descriptor and sequence-1 record without publishing them.
    /// Only inert owner pre-staging may consume the returned binding.
    pub fn plan_admitted_parent_v2(
        &self,
        coordinator_peer_id: PeerId,
        owner_peer_ids: &[PeerId],
        immutable_manifest: &PrivateOramImmutableManifestBundleV2,
        validated: &PrivateOramValidatedOwnerPrepareV1,
        admission: &PrivateOramMutationAdmissionPlanV2,
    ) -> Result<PrivateOramMutationPlannedParentV2, PrivateOramMutationJournalError> {
        if coordinator_peer_id != admission.lease.owner_peer_id
            || validated.mutation_digest() != admission.mutation_digest
            || validated.mutation_bundle() != &admission.mutation_bundle
        {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "admission_plan",
            ));
        }
        let descriptor = self.build_descriptor(
            coordinator_peer_id,
            owner_peer_ids,
            admission.mutation_bundle.clone(),
            admission.lease.clone(),
            admission.expected_old_state.clone(),
        )?;
        self.validate_immutable_manifest_for_descriptor(immutable_manifest, &descriptor)?;
        let state = initial_private_oram_mutation_state_v2(&descriptor)?;
        let lease_acquired_record_digest = record_digest_at_phase_v2(
            &descriptor,
            &state,
            PrivateOramMutationJournalPhaseV2::LeaseAcquired,
        )?;
        Ok(PrivateOramMutationPlannedParentV2 {
            descriptor_digest: descriptor.descriptor_digest,
            lease_acquired_record_digest,
            preparing_lease: descriptor.preparing_lease,
            owner_requirements: descriptor.owner_requirements,
        })
    }

    pub fn begin_admitted_v2(
        &self,
        coordinator_peer_id: PeerId,
        owner_peer_ids: &[PeerId],
        immutable_manifest: PrivateOramImmutableManifestBundleV2,
        validated: &PrivateOramValidatedOwnerPrepareV1,
        admission: &PrivateOramMutationAdmissionPlanV2,
    ) -> Result<PrivateOramMutationParentLeaseAcquiredV2, PrivateOramMutationJournalError> {
        let planned = self.plan_admitted_parent_v2(
            coordinator_peer_id,
            owner_peer_ids,
            &immutable_manifest,
            validated,
            admission,
        )?;
        let snapshot = self.begin_v2(
            coordinator_peer_id,
            owner_peer_ids,
            immutable_manifest,
            validated.mutation_bundle().clone(),
            admission.lease.clone(),
            admission.expected_old_state.clone(),
        )?;
        if snapshot.descriptor.mutation_digest != admission.mutation_digest
            || snapshot.descriptor.preparing_lease != admission.lease
            || snapshot.descriptor.expected_consensus_old_state != admission.expected_old_state
            || snapshot.descriptor.descriptor_digest != planned.descriptor_digest
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let lease_acquired_record_digest = record_digest_at_phase_v2(
            &snapshot.descriptor,
            snapshot.effective_state(),
            PrivateOramMutationJournalPhaseV2::LeaseAcquired,
        )?;
        if lease_acquired_record_digest != planned.lease_acquired_record_digest {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        Ok(PrivateOramMutationParentLeaseAcquiredV2 {
            descriptor_digest: snapshot.descriptor.descriptor_digest.clone(),
            lease_acquired_record_digest,
            preparing_lease: snapshot.descriptor.preparing_lease.clone(),
            owner_requirements: snapshot.descriptor.owner_requirements.clone(),
        })
    }

    pub(super) fn begin_v2(
        &self,
        coordinator_peer_id: PeerId,
        owner_peer_ids: &[PeerId],
        immutable_manifest: PrivateOramImmutableManifestBundleV2,
        mutation_bundle: PrivateOramAppendMutationBundleV1,
        preparing_lease: PrivateOramMutationLease,
        expected_consensus_old_state: PrivateOramConsensusCollectionStateV2,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let descriptor = self.build_descriptor(
            coordinator_peer_id,
            owner_peer_ids,
            mutation_bundle,
            preparing_lease,
            expected_consensus_old_state,
        )?;
        self.validate_immutable_manifest_for_descriptor(&immutable_manifest, &descriptor)?;
        self.ensure_root_layout()?;
        let lock = self.acquire_lock()?;
        let root = lock.root.directory.file();
        let root_temp =
            PrivateOramPinnedDirectoryV2::open_at(root, std::ffi::OsStr::new(TEMP_DIR))?;
        root_temp.validate_binding(root, std::ffi::OsStr::new(TEMP_DIR))?;
        if private_oram_directory_exists_at_v2(root, std::ffi::OsStr::new(ACTIVE_DIR))? {
            let current = self.load_v2_locked(&lock)?;
            if current.descriptor == descriptor && current.immutable_manifest == immutable_manifest
            {
                let namespace = PrivateOramPinnedActiveNamespaceV2::open(&lock)?;
                namespace
                    .active
                    .sync()
                    .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
                sync_private_oram_root_publish_v2(root, &root_temp)?;
                namespace.validate_bindings(&lock)?;
                lock.validate_root_identity()?;
                return Ok(current);
            }
            return Err(PrivateOramMutationJournalError::ConcurrentMutation);
        }

        let state = initial_private_oram_mutation_state_v2(&descriptor)?;
        let format = PrivateOramMutationJournalFormatV2 {
            state_version: V2_JOURNAL_FORMAT_VERSION,
            descriptor_digest: descriptor.descriptor_digest.clone(),
        };
        let staging = tempfile::Builder::new()
            .prefix("begin-v2-")
            .tempdir_in(root_temp.pinned_path()?)
            .map_err(PrivateOramMutationJournalError::Io)?;
        set_private_directory_permissions(staging.path())?;
        let staging_name = staging
            .path()
            .file_name()
            .ok_or(PrivateOramMutationJournalError::Corrupt)?
            .to_owned();
        #[cfg(target_os = "linux")]
        checked_private_oram_entry_name_v2(&staging_name)?;
        let staging_directory =
            PrivateOramPinnedDirectoryV2::open_at(&root_temp.file, &staging_name)?;
        ensure_same_directory(
            &fs::symlink_metadata(staging.path()).map_err(PrivateOramMutationJournalError::Io)?,
            &staging_directory
                .file
                .metadata()
                .map_err(PrivateOramMutationJournalError::Io)?,
        )?;
        let active_temp = create_private_oram_directory_at_v2(
            &staging_directory,
            std::ffi::OsStr::new(ACTIVE_TEMP_DIR),
        )?;
        let records = create_private_oram_directory_at_v2(
            &staging_directory,
            std::ffi::OsStr::new(STATE_RECORDS_DIR),
        )?;
        let descriptor_file = write_new_private_oram_json_at_v2(
            &staging_directory,
            std::ffi::OsStr::new(DESCRIPTOR_FILE),
            &descriptor,
            MAX_DESCRIPTOR_BYTES,
        )?;
        let immutable_manifest_file = write_new_private_oram_json_at_v2(
            &staging_directory,
            std::ffi::OsStr::new(IMMUTABLE_MANIFEST_FILE),
            &immutable_manifest,
            MAX_IMMUTABLE_MANIFEST_BYTES,
        )?;
        let format_file = write_new_private_oram_json_at_v2(
            &staging_directory,
            std::ffi::OsStr::new(FORMAT_FILE),
            &format,
            MAX_FORMAT_BYTES,
        )?;
        let state_file = write_new_private_oram_json_at_v2(
            &staging_directory,
            std::ffi::OsStr::new(STATE_FILE),
            &state,
            MAX_STATE_BYTES,
        )?;
        let initial_record_name = state_record_file_name(state.sequence)?;
        let initial_record_file = write_new_private_oram_json_at_v2(
            &records,
            std::ffi::OsStr::new(&initial_record_name),
            &state,
            MAX_STATE_BYTES,
        )?;
        records
            .sync()
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        active_temp
            .sync()
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        staging_directory
            .sync()
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        descriptor_file.validate_binding_and_contents(&staging_directory.file)?;
        immutable_manifest_file.validate_binding_and_contents(&staging_directory.file)?;
        format_file.validate_binding_and_contents(&staging_directory.file)?;
        state_file.validate_binding_and_contents(&staging_directory.file)?;
        initial_record_file.validate_binding_and_contents(&records.file)?;
        staging_directory.validate_binding(&root_temp.file, &staging_name)?;
        root_temp.validate_binding(root, std::ffi::OsStr::new(TEMP_DIR))?;

        let publish_result = rename_private_oram_entry_at_v2(
            &root_temp.file,
            &staging_name,
            root,
            std::ffi::OsStr::new(ACTIVE_DIR),
            true,
        );
        let installed_active =
            optional_private_oram_directory_at_v2(root, std::ffi::OsStr::new(ACTIVE_DIR))?;
        let published_ours = installed_active.as_ref().is_some_and(|installed| {
            let staging_metadata = staging_directory.file.metadata();
            let installed_metadata = installed.file.metadata();
            matches!(
                (staging_metadata, installed_metadata),
                (Ok(staging_metadata), Ok(installed_metadata))
                    if ensure_same_directory(&staging_metadata, &installed_metadata).is_ok()
            )
        });
        match publish_result {
            Ok(()) if !published_ours => {
                return Err(PrivateOramMutationJournalError::Indeterminate);
            }
            Ok(()) => {}
            Err(error) => {
                if published_ours {
                    // `renameat2` may be reported as interrupted after the directory became visible.
                } else if installed_active.is_some() {
                    let current = self.load_v2_locked(&lock)?;
                    if current.descriptor == descriptor
                        && current.immutable_manifest == immutable_manifest
                        && current.state == state
                        && current.pending_next.is_none()
                    {
                        sync_private_oram_root_publish_v2(root, &root_temp)?;
                        lock.validate_root_identity()?;
                        return Ok(current);
                    }
                } else {
                    return Err(match error {
                        PrivateOramMutationJournalError::Unsupported => error,
                        PrivateOramMutationJournalError::Io(ref error)
                            if error.kind() == io::ErrorKind::AlreadyExists =>
                        {
                            PrivateOramMutationJournalError::ConcurrentMutation
                        }
                        _ => PrivateOramMutationJournalError::Indeterminate,
                    });
                }
            }
        }
        let _published_path = staging.keep();
        sync_private_oram_root_publish_v2(root, &root_temp)?;
        let loaded = self.load_v2_locked(&lock)?;
        lock.validate_root_identity()?;
        Ok(loaded)
    }

    pub(super) fn load_v2(
        &self,
    ) -> Result<
        Option<PrivateOramMutationJournalStructuralSnapshotV2>,
        PrivateOramMutationJournalError,
    > {
        if !path_entry_exists(&self.root)? {
            return Ok(None);
        }
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.temp_path())?;
        let lock = self.acquire_lock()?;
        if !private_oram_directory_exists_at_v2(
            lock.root.directory.file(),
            std::ffi::OsStr::new(ACTIVE_DIR),
        )? {
            lock.validate_root_identity()?;
            return Ok(None);
        }
        let snapshot = self.load_v2_locked(&lock)?;
        lock.validate_root_identity()?;
        Ok(Some(snapshot))
    }

    /// Loads inert restart material from the canonical parent journal.
    ///
    /// The returned bundles cannot authorize a child transition. Recovery reopens this journal
    /// under its exclusive lock and requires exact equality before minting live authority.
    pub fn load_recovery_material_v2(
        &self,
    ) -> Result<PrivateOramMutationRecoveryMaterialV2, PrivateOramMutationJournalError> {
        let snapshot = self
            .load_v2()?
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        if snapshot.state.phase.sequence()
            < PrivateOramMutationJournalPhaseV2::DecisionDurable.sequence()
            || snapshot.state.decision.is_none()
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        Ok(PrivateOramMutationRecoveryMaterialV2 {
            immutable_manifest: snapshot.immutable_manifest,
            mutation_bundle: snapshot.descriptor.mutation_bundle,
        })
    }

    /// Recovers one remote owner's paired child stores under live V2 parent authority.
    ///
    /// `request.collection_name` is bound by the caller's authenticated collection resolver. All
    /// cryptographic and durable locators are revalidated here under the pinned parent lock.
    pub fn recover_remote_owner_pair_v2(
        &self,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
        request: &PrivateOramPeerRecoveryRequestV2,
        material: &PrivateOramMutationRecoveryMaterialV2,
        resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    ) -> Result<PrivateOramPeerRecoveryTerminalV2, PrivateOramMutationJournalError> {
        validate_private_oram_peer_recovery_request_v2_shape(request)
            .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
        self.validate_owner_recovery_resources_v1(&resources)?;
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.temp_path())?;

        let parent_lock = self.acquire_lock()?;
        let snapshot = self.load_v2_locked(&parent_lock)?;
        if snapshot.state.phase.sequence()
            < PrivateOramMutationJournalPhaseV2::DecisionDurable.sequence()
            || snapshot.immutable_manifest != material.immutable_manifest
            || snapshot.descriptor.mutation_bundle != material.mutation_bundle
            || resources.immutable_manifest != &snapshot.immutable_manifest
            || resources.mutation_bundle != &snapshot.descriptor.mutation_bundle
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }

        let (active_lease, disposition, decision) =
            validated_reconcile_decision_for_v2_snapshot(&snapshot, reconcile_snapshot)?;
        if snapshot.state.decision.as_ref() != Some(&decision) {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let mutation = &snapshot.descriptor.mutation_bundle.mutation;
        let manifest = &snapshot.immutable_manifest.manifest;
        let hnsw_index = manifest
            .indexes
            .first()
            .filter(|index| index.kind() == PrivateOramIndexKindV2::Hnsw)
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        if request.collection_id != mutation.collection_id
            || request.mutation_id != mutation.mutation_id
            || request.parent_descriptor_digest != snapshot.descriptor.descriptor_digest
            || request.decision_record_digest != decision.authority_record_digest()
            || request.coordinator_peer_id != snapshot.descriptor.coordinator_peer_id
            || request.owner_signing_key_id != manifest.owner_signing_key_id
            || request.vector_name != hnsw_index.index_name
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }

        let expected_parent = snapshot.clone();
        let authority = build_owner_recovery_authority_v2(
            &snapshot.descriptor,
            &snapshot.state,
            &active_lease,
            disposition,
            request.owner_peer_id,
        )?;
        let live = PrivateOramLiveOwnerRecoveryAuthorityV1::new(
            authority,
            &parent_lock,
            &self.owner_recovery_parent_bridge,
            &self.owner_recovery_parent_verifier,
        );
        let outcome = live
            .recover_pair_v1(resources)
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        drop(live);

        let revalidated_parent = self
            .load_v2_locked(&parent_lock)
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        if revalidated_parent != expected_parent {
            return Err(PrivateOramMutationJournalError::Indeterminate);
        }
        parent_lock
            .validate_root_identity()
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        private_oram_peer_recovery_terminal_from_outcome_v2(request, &outcome)
    }

    pub fn mark_owners_prepared_from_durable_v2(
        &self,
        parent: &PrivateOramMutationParentLeaseAcquiredV2,
        owner_projections: Vec<PrivateOramMutationPreparedOwnerProjectionV2>,
    ) -> Result<PrivateOramMutationOwnersPreparedV2, PrivateOramMutationJournalError> {
        if owner_projections.is_empty()
            || owner_projections.iter().any(|projection| {
                projection.parent_descriptor_digest != parent.descriptor_digest
                    || projection.parent_lease_acquired_record_digest
                        != parent.lease_acquired_record_digest
                    || !is_sha256_digest(&projection.owner_journal_descriptor_digest)
            })
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let mut owner_journals = owner_projections
            .iter()
            .map(|projection| PrivateOramMutationOwnerJournalEvidenceV2 {
                owner_peer_id: projection.owner_peer_id,
                journal_descriptor_digest: projection.owner_journal_descriptor_digest.clone(),
            })
            .collect::<Vec<_>>();
        owner_journals.sort_by_key(|owner| owner.owner_peer_id);
        if owner_journals
            .windows(2)
            .any(|pair| pair[0].owner_peer_id >= pair[1].owner_peer_id)
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let mut owner_prepares = owner_projections
            .into_iter()
            .flat_map(|projection| projection.indexes)
            .collect::<Vec<_>>();
        owner_prepares.sort_by(prepare_evidence_order);
        let snapshot =
            self.mark_owner_prepare_evidence_v2(parent, owner_journals, owner_prepares)?;
        let owners_prepared_record_digest = record_digest_at_phase_v2(
            &snapshot.descriptor,
            snapshot.effective_state(),
            PrivateOramMutationJournalPhaseV2::OwnersPrepared,
        )?;
        Ok(PrivateOramMutationOwnersPreparedV2 {
            descriptor_digest: snapshot.descriptor.descriptor_digest,
            owners_prepared_record_digest,
        })
    }

    fn mark_owner_prepare_evidence_v2(
        &self,
        parent: &PrivateOramMutationParentLeaseAcquiredV2,
        owner_journals: Vec<PrivateOramMutationOwnerJournalEvidenceV2>,
        owner_prepares: Vec<PrivateOramMutationOwnerPrepareEvidenceV1>,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let expected_owner_journals = owner_journals.clone();
        let expected_owner_prepares = owner_prepares.clone();
        let expected_descriptor_digest = parent.descriptor_digest.clone();
        let expected_lease_acquired_record_digest = parent.lease_acquired_record_digest.clone();
        self.transition_v2(
            PrivateOramMutationJournalPhaseV2::OwnersPrepared,
            move |descriptor, state| {
                if descriptor.descriptor_digest != expected_descriptor_digest
                    || record_digest_at_phase_v2(
                        descriptor,
                        state,
                        PrivateOramMutationJournalPhaseV2::LeaseAcquired,
                    )? != expected_lease_acquired_record_digest
                {
                    return Err(PrivateOramMutationJournalError::InvalidTransition);
                }
                validate_owner_prepares(descriptor, &expected_owner_prepares)?;
                (state.owner_journals == expected_owner_journals
                    && state.owner_prepares == expected_owner_prepares)
                    .then_some(())
                    .ok_or(PrivateOramMutationJournalError::InvalidTransition)
            },
            move |descriptor, current, next| {
                if descriptor.descriptor_digest != parent.descriptor_digest
                    || current.record_digest != parent.lease_acquired_record_digest
                {
                    return Err(PrivateOramMutationJournalError::InvalidTransition);
                }
                validate_owner_prepares(descriptor, &owner_prepares)?;
                next.owner_journals = owner_journals;
                next.owner_prepares = owner_prepares;
                Ok(())
            },
        )
    }

    #[cfg(test)]
    pub(super) fn mark_owners_prepared_v2(
        &self,
        owner_prepares: Vec<PrivateOramMutationOwnerPrepareEvidenceV1>,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let snapshot = self
            .load_v2()?
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        let parent = PrivateOramMutationParentLeaseAcquiredV2 {
            descriptor_digest: snapshot.descriptor.descriptor_digest.clone(),
            lease_acquired_record_digest: record_digest_at_phase_v2(
                &snapshot.descriptor,
                snapshot.effective_state(),
                PrivateOramMutationJournalPhaseV2::LeaseAcquired,
            )?,
            preparing_lease: snapshot.descriptor.preparing_lease.clone(),
            owner_requirements: snapshot.descriptor.owner_requirements.clone(),
        };
        let mut owner_journals = owner_prepares
            .iter()
            .map(|prepared| (prepared.peer_id, prepared.prepared_journal_digest.clone()))
            .collect::<std::collections::BTreeMap<_, _>>()
            .into_iter()
            .map(|(owner_peer_id, journal_descriptor_digest)| {
                PrivateOramMutationOwnerJournalEvidenceV2 {
                    owner_peer_id,
                    journal_descriptor_digest,
                }
            })
            .collect::<Vec<_>>();
        owner_journals.sort_by_key(|owner| owner.owner_peer_id);
        self.mark_owner_prepare_evidence_v2(&parent, owner_journals, owner_prepares)
    }

    #[cfg(test)]
    pub(super) fn mark_owners_prepared_with_owner_journals_v2(
        &self,
        owner_journals: Vec<PrivateOramMutationOwnerJournalEvidenceV2>,
        owner_prepares: Vec<PrivateOramMutationOwnerPrepareEvidenceV1>,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let snapshot = self
            .load_v2()?
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        let parent = PrivateOramMutationParentLeaseAcquiredV2 {
            descriptor_digest: snapshot.descriptor.descriptor_digest.clone(),
            lease_acquired_record_digest: record_digest_at_phase_v2(
                &snapshot.descriptor,
                snapshot.effective_state(),
                PrivateOramMutationJournalPhaseV2::LeaseAcquired,
            )?,
            preparing_lease: snapshot.descriptor.preparing_lease.clone(),
            owner_requirements: snapshot.descriptor.owner_requirements.clone(),
        };
        self.mark_owner_prepare_evidence_v2(&parent, owner_journals, owner_prepares)
    }

    pub(super) fn validated_point_stage_parent_v2(
        &self,
    ) -> Result<PrivateOramValidatedPointStageParentV1, PrivateOramMutationJournalError> {
        let snapshot = self
            .load_v2()?
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        let (phase, owners_prepared_record_digest, expected_child_descriptor_digest) =
            match (&snapshot.state.phase, snapshot.state.point_stage.as_ref()) {
                (PrivateOramMutationJournalPhaseV2::OwnersPrepared, None) => (
                    PrivateOramValidatedPointStageParentPhaseV1::OwnersPrepared,
                    snapshot.state.record_digest.clone(),
                    None,
                ),
                (
                    PrivateOramMutationJournalPhaseV2::PointStageDurable,
                    Some(PrivateOramMutationPointStageEvidenceV2::PrivateOramPointStaging {
                        child_descriptor_digest,
                        parent_owners_prepared_record_digest,
                        ..
                    }),
                ) => (
                    PrivateOramValidatedPointStageParentPhaseV1::PointStageDurable,
                    parent_owners_prepared_record_digest.clone(),
                    Some(child_descriptor_digest.clone()),
                ),
                (
                    PrivateOramMutationJournalPhaseV2::PointStageDurable,
                    Some(PrivateOramMutationPointStageEvidenceV2::NoServerPointRecord {
                        parent_owners_prepared_record_digest,
                    }),
                ) => (
                    PrivateOramValidatedPointStageParentPhaseV1::PointStageDurable,
                    parent_owners_prepared_record_digest.clone(),
                    None,
                ),
                _ => return Err(PrivateOramMutationJournalError::InvalidTransition),
            };
        Ok(PrivateOramValidatedPointStageParentV1 {
            descriptor: snapshot.descriptor,
            owners_prepared_record_digest,
            phase,
            expected_child_descriptor_digest,
        })
    }

    pub fn stage_point_from_prepared_v2(
        &self,
        owners_prepared: &PrivateOramMutationOwnersPreparedV2,
        canonical_frame_bytes: Option<&[u8]>,
    ) -> Result<PrivateOramMutationPointStageDurableV2, PrivateOramMutationJournalError> {
        let snapshot = self
            .load_v2()?
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        if snapshot.descriptor.descriptor_digest != owners_prepared.descriptor_digest
            || record_digest_at_phase_v2(
                &snapshot.descriptor,
                snapshot.effective_state(),
                PrivateOramMutationJournalPhaseV2::OwnersPrepared,
            )? != owners_prepared.owners_prepared_record_digest
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let parent = self.validated_point_stage_parent_v2()?;
        let durable_point_stage = match snapshot
            .descriptor
            .mutation_bundle
            .mutation
            .point_operation_kind
        {
            PrivateOramPointOperationKindV1::VisiblePointRecord => {
                let frame = canonical_frame_bytes.ok_or(
                    PrivateOramMutationJournalError::InvalidInput("staged_insert_frame"),
                )?;
                let collection_path = self
                    .root
                    .parent()
                    .ok_or(PrivateOramMutationJournalError::Corrupt)?;
                let store = PrivateOramPointStagingStore::new(collection_path);
                let (_, durable) = store.prepare(frame, &parent)?;
                self.mark_private_point_stage_durable_v2(&durable)?;
                Some(durable)
            }
            PrivateOramPointOperationKindV1::NoServerPointRecord => {
                if canonical_frame_bytes.is_some() {
                    return Err(PrivateOramMutationJournalError::InvalidInput(
                        "staged_insert_frame",
                    ));
                }
                self.mark_no_server_point_stage_durable_v2(&parent)?;
                None
            }
        };
        let committed = self
            .load_v2()?
            .ok_or(PrivateOramMutationJournalError::Indeterminate)?;
        if committed.descriptor.descriptor_digest != owners_prepared.descriptor_digest {
            return Err(PrivateOramMutationJournalError::Indeterminate);
        }
        let point_stage_record_digest = record_digest_at_phase_v2(
            &committed.descriptor,
            committed.effective_state(),
            PrivateOramMutationJournalPhaseV2::PointStageDurable,
        )?;
        Ok(PrivateOramMutationPointStageDurableV2 {
            descriptor_digest: committed.descriptor.descriptor_digest,
            point_stage_record_digest,
            durable_point_stage,
        })
    }

    pub(super) fn mark_private_point_stage_durable_v2(
        &self,
        durable_stage: &PrivateOramDurablePointStageTokenV1,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let evidence = private_oram_point_stage_evidence_v2_from_durable_token(durable_stage);
        self.mark_point_stage_durable_v2(
            durable_stage.parent_descriptor_digest(),
            durable_stage.parent_owners_prepared_record_digest(),
            evidence,
        )
    }

    pub(super) fn mark_no_server_point_stage_durable_v2(
        &self,
        parent: &PrivateOramValidatedPointStageParentV1,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        self.mark_point_stage_durable_v2(
            &parent.descriptor.descriptor_digest,
            &parent.owners_prepared_record_digest,
            PrivateOramMutationPointStageEvidenceV2::NoServerPointRecord {
                parent_owners_prepared_record_digest: parent.owners_prepared_record_digest.clone(),
            },
        )
    }

    /// Reconstructs exactly one next recovery action from durable state and Raft-confirmed
    /// authority. V2 production activation is intentionally limited to the no-server-point path.
    #[doc(hidden)]
    pub fn open_private_oram_mutation_resume_v2(
        &self,
        authority: LinearizablePrivateOramMutationReconcileSnapshotV2,
        collection_name: &str,
    ) -> Result<PrivateOramMutationResumeV2, PrivateOramMutationJournalError> {
        if collection_name.is_empty() {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "collection_name",
            ));
        }
        let authority = PrivateOramMutationResumeAuthorityV2::from_linearizable(authority);
        if authority.applied_index == 0 {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let snapshot = self
            .load_v2()?
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        if snapshot.state.phase.sequence()
            < PrivateOramMutationJournalPhaseV2::PointStageDurable.sequence()
            || snapshot.immutable_manifest.manifest.result_privacy
                != ResultPrivacyMode::PrivatePayloadOramRequired
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_live_point_stage_v2(&snapshot.descriptor, snapshot.effective_state(), None)?;
        let (_, _, evidence) =
            validated_reconcile_decision_for_v2_snapshot(&snapshot, &authority.reconcile)?;
        let parent_watermark = authority
            .reconcile
            .parent_watermark()
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
        let journal_sequence = snapshot.state.phase.sequence();
        if parent_watermark.sequence() > journal_sequence {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        if parent_watermark.sequence() < journal_sequence {
            let next_sequence = parent_watermark
                .sequence()
                .checked_add(1)
                .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
            let expectation = derive_private_oram_mutation_parent_watermark_at_sequence_v2(
                &snapshot,
                next_sequence,
            )?;
            validate_private_oram_mutation_parent_watermark_v2_cas_transition(
                parent_watermark,
                expectation.watermark(),
                &expectation,
            )?;
            return Ok(PrivateOramMutationResumeV2::NeedParentProgress(
                PrivateOramMutationNeedParentProgressV2 {
                    proposal: PrivateOramMutationParentProgressProposalV2 {
                        key: PrivateOramMutationKey {
                            collection_id: snapshot
                                .descriptor
                                .mutation_bundle
                                .mutation
                                .collection_id
                                .clone(),
                        },
                        expectation,
                    },
                },
            ));
        }
        match snapshot.state.phase {
            PrivateOramMutationJournalPhaseV2::PointStageDurable => Ok(
                PrivateOramMutationResumeV2::NeedDecision(PrivateOramMutationNeedDecisionV2 {
                    authority,
                    decision: validated_mutation_decision_from_v2_snapshot(&snapshot, evidence)?,
                }),
            ),
            PrivateOramMutationJournalPhaseV2::DecisionDurable => {
                let decision = validated_decision_durable_from_v2_snapshot(&snapshot, evidence)?;
                let requests =
                    remote_owner_recovery_requests_v2(&snapshot, collection_name, &decision)?;
                Ok(PrivateOramMutationResumeV2::NeedRemoteTerminals(
                    PrivateOramMutationNeedRemoteTerminalsV2 { decision, requests },
                ))
            }
            PrivateOramMutationJournalPhaseV2::RemotesTerminal => {
                Ok(PrivateOramMutationResumeV2::NeedLocalTerminal(
                    PrivateOramMutationNeedLocalTerminalV2 {
                        authority,
                        remotes: validated_remotes_terminal_from_v2_snapshot(&snapshot, evidence)?,
                    },
                ))
            }
            PrivateOramMutationJournalPhaseV2::LocalTerminal => {
                Ok(PrivateOramMutationResumeV2::NeedPointResolution(
                    PrivateOramMutationNeedPointResolutionV2 {
                        authority,
                        local: validated_local_terminal_from_v2_snapshot(&snapshot)?,
                    },
                ))
            }
            PrivateOramMutationJournalPhaseV2::PointResolved => {
                Ok(PrivateOramMutationResumeV2::Complete(
                    PrivateOramMutationTerminalCompleteV2 { authority },
                ))
            }
            PrivateOramMutationJournalPhaseV2::LeaseAcquired
            | PrivateOramMutationJournalPhaseV2::OwnersPrepared => {
                Err(PrivateOramMutationJournalError::InvalidTransition)
            }
        }
    }

    #[doc(hidden)]
    pub fn resume_private_oram_decision_v2(
        &self,
        permit: PrivateOramMutationNeedDecisionV2,
    ) -> Result<(), PrivateOramMutationJournalError> {
        let PrivateOramMutationNeedDecisionV2 {
            authority,
            decision,
        } = permit;
        if authority.applied_index == 0 {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        self.mark_decision_durable_v2(&decision).map(|_| ())
    }

    #[doc(hidden)]
    pub fn resume_private_oram_remote_terminals_v2(
        &self,
        plan: PrivateOramMutationNeedRemoteTerminalsV2,
        authority: LinearizablePrivateOramMutationReconcileSnapshotV2,
        responses: &[PrivateOramAuthenticatedOwnerRecoveryResponse],
    ) -> Result<(), PrivateOramMutationJournalError> {
        let authority = PrivateOramMutationResumeAuthorityV2::from_linearizable(authority);
        if authority.applied_index == 0 {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let snapshot = self
            .load_v2()?
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        let (_, _, evidence) =
            validated_reconcile_decision_for_v2_snapshot(&snapshot, &authority.reconcile)?;
        validate_decision_durable_token_v2(
            &snapshot.descriptor,
            snapshot.effective_state(),
            &plan.decision,
        )?;
        if plan.decision.evidence != evidence {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        self.mark_authenticated_remote_terminals_v2(&plan.decision, responses)
            .map(|_| ())
    }

    #[doc(hidden)]
    pub fn resume_private_oram_local_terminal_v2(
        &self,
        permit: PrivateOramMutationNeedLocalTerminalV2,
        authenticated_local_owner_peer_id: PeerId,
        resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    ) -> Result<(), PrivateOramMutationJournalError> {
        let PrivateOramMutationNeedLocalTerminalV2 { authority, remotes } = permit;
        if authority.applied_index == 0 {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        self.recover_local_owner_and_mark_terminal_v2(
            &remotes,
            &authority.reconcile,
            authenticated_local_owner_peer_id,
            resources,
        )
        .map(|_| ())
    }

    #[doc(hidden)]
    pub fn resume_private_oram_no_server_point_resolution_v2(
        &self,
        permit: PrivateOramMutationNeedPointResolutionV2,
    ) -> Result<(), PrivateOramMutationJournalError> {
        let PrivateOramMutationNeedPointResolutionV2 { authority, local } = permit;
        if authority.applied_index == 0 {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        self.mark_no_server_point_resolved_v2(&local).map(|_| ())
    }

    #[doc(hidden)]
    pub fn open_private_oram_mutation_cleanup_v2(
        &self,
        terminal: PrivateOramMutationTerminalCompleteV2,
    ) -> Result<PrivateOramMutationCleanupV2, PrivateOramMutationJournalError> {
        let PrivateOramMutationTerminalCompleteV2 { authority } = terminal;
        if authority.applied_index == 0 {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let snapshot = self
            .load_v2()?
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        let expectation = cleanup_expectation_from_terminal_v2(&snapshot, &authority.reconcile)?;
        let key = PrivateOramMutationKey {
            collection_id: snapshot
                .descriptor
                .mutation_bundle
                .mutation
                .collection_id
                .clone(),
        };
        let lifecycle = authority
            .reconcile
            .cleanup_lifecycle()
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
        match lifecycle.expectation_status(&expectation)? {
            PrivateOramMutationCleanupExpectationStatusV2::NeedsWitness => {
                Ok(PrivateOramMutationCleanupV2::NeedCleanupWitness(
                    PrivateOramMutationNeedCleanupWitnessV2 {
                        proposal: PrivateOramMutationCleanupWitnessProposalV2 { key, expectation },
                    },
                ))
            }
            PrivateOramMutationCleanupExpectationStatusV2::WitnessDurable { witness_digest } => {
                Ok(PrivateOramMutationCleanupV2::NeedLocalCleanup(
                    PrivateOramMutationNeedLocalCleanupV2 {
                        collection_id: snapshot
                            .descriptor
                            .mutation_bundle
                            .mutation
                            .collection_id
                            .clone(),
                        mutation_id: snapshot
                            .descriptor
                            .mutation_bundle
                            .mutation
                            .mutation_id
                            .clone(),
                        owner_peer_id: snapshot.descriptor.coordinator_peer_id,
                        descriptor_digest: snapshot.descriptor.descriptor_digest.clone(),
                        terminal_record_digest: snapshot.state.record_digest.clone(),
                        generation: authority.reconcile.lease_slot().generation,
                        witness_digest,
                        cleanup_evidence_digest: expectation.evidence_digest().to_string(),
                    },
                ))
            }
            PrivateOramMutationCleanupExpectationStatusV2::ClearPending {
                witness_digest,
                clear_attempt_id_digest,
            } => {
                let complete = self.load_local_cleanup_complete_v2()?;
                if complete.generation != authority.reconcile.lease_slot().generation
                    || complete.descriptor_digest != snapshot.descriptor.descriptor_digest
                    || complete.terminal_record_digest != snapshot.state.record_digest
                    || complete.witness_digest != witness_digest
                    || complete.cleanup_evidence_digest != expectation.evidence_digest()
                    || complete.clear_attempt_id_digest != clear_attempt_id_digest
                {
                    return Err(PrivateOramMutationJournalError::InvalidTransition);
                }
                Ok(PrivateOramMutationCleanupV2::NeedClear(
                    PrivateOramMutationNeedClearV2 {
                        key,
                        generation: authority.reconcile.lease_slot().generation,
                        expected_clear_attempt_id_digest: clear_attempt_id_digest,
                    },
                ))
            }
            PrivateOramMutationCleanupExpectationStatusV2::ClearedPendingAcknowledgement {
                ..
            }
            | PrivateOramMutationCleanupExpectationStatusV2::Acknowledged { .. } => {
                Err(PrivateOramMutationJournalError::InvalidTransition)
            }
        }
    }

    #[doc(hidden)]
    pub fn complete_private_oram_mutation_local_cleanup_v2(
        &self,
        permit: PrivateOramMutationNeedLocalCleanupV2,
    ) -> Result<PrivateOramMutationClearPendingProposalV2, PrivateOramMutationJournalError> {
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.temp_path())?;
        let lock = self.acquire_lock()?;
        let snapshot = self.load_v2_locked(&lock)?;
        if snapshot.pending_next.is_some()
            || snapshot.state.phase != PrivateOramMutationJournalPhaseV2::PointResolved
            || snapshot.descriptor.descriptor_digest != permit.descriptor_digest
            || snapshot.state.record_digest != permit.terminal_record_digest
            || snapshot.descriptor.preparing_lease.generation != permit.generation
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let mut complete = PrivateOramMutationLocalCleanupCompleteV2 {
            version: LOCAL_CLEANUP_COMPLETE_VERSION_V2,
            generation: permit.generation,
            descriptor_digest: permit.descriptor_digest,
            terminal_record_digest: permit.terminal_record_digest,
            witness_digest: permit.witness_digest,
            cleanup_evidence_digest: permit.cleanup_evidence_digest,
            clear_attempt_id_digest: String::new(),
        };
        complete.clear_attempt_id_digest = local_cleanup_complete_digest_v2(&complete)?;
        validate_local_cleanup_complete_v2(&complete)?;
        let namespace = PrivateOramPinnedActiveNamespaceV2::open(&lock)?;
        namespace.validate_bindings(&lock)?;
        let installed = publish_immutable_private_oram_json_v2(
            &namespace,
            &namespace.active,
            std::ffi::OsStr::new(LOCAL_CLEANUP_COMPLETE_FILE_V2),
            &complete,
            MAX_LOCAL_CLEANUP_COMPLETE_BYTES_V2,
        )?;
        let installed_complete: PrivateOramMutationLocalCleanupCompleteV2 =
            installed.deserialize()?;
        validate_local_cleanup_complete_v2(&installed_complete)?;
        if installed_complete != complete {
            return Err(PrivateOramMutationJournalError::ConcurrentMutation);
        }
        namespace.validate_bindings(&lock)?;
        lock.validate_root_identity()?;
        Ok(PrivateOramMutationClearPendingProposalV2 {
            key: PrivateOramMutationKey {
                collection_id: snapshot.descriptor.mutation_bundle.mutation.collection_id,
            },
            generation: complete.generation,
            witness_digest: complete.witness_digest,
            clear_attempt_id_digest: complete.clear_attempt_id_digest,
        })
    }

    fn load_local_cleanup_complete_v2(
        &self,
    ) -> Result<PrivateOramMutationLocalCleanupCompleteV2, PrivateOramMutationJournalError> {
        let complete = read_json_private(
            &self.active_path().join(LOCAL_CLEANUP_COMPLETE_FILE_V2),
            MAX_LOCAL_CLEANUP_COMPLETE_BYTES_V2,
        )?;
        validate_local_cleanup_complete_v2(&complete)?;
        Ok(complete)
    }

    #[doc(hidden)]
    pub fn archive_private_oram_mutation_after_clear_v2(
        &self,
        permit: PrivateOramMutationClearedPendingArchivePermitV2,
    ) -> Result<(), PrivateOramMutationJournalError> {
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.temp_path())?;
        let lock = self.acquire_lock()?;
        let archive_name = format!(
            "{TERMINAL_ARCHIVE_NAME_PREFIX_V2}{:020}",
            permit.generation()
        );
        let archive_name = std::ffi::OsStr::new(&archive_name);
        checked_private_oram_entry_name_v2(archive_name)?;
        let root = lock.root.directory.file();
        let active_exists =
            private_oram_directory_exists_at_v2(root, std::ffi::OsStr::new(ACTIVE_DIR))?;
        let archive_exists = private_oram_directory_exists_at_v2(root, archive_name)?;
        if active_exists && archive_exists {
            return Err(PrivateOramMutationJournalError::ConcurrentMutation);
        }
        let moved_source = if active_exists {
            let active = self.load_v2_locked(&lock)?;
            validate_terminal_archive_source_v2(&active, &permit)?;
            let namespace = PrivateOramPinnedActiveNamespaceV2::open(&lock)?;
            let complete = load_local_cleanup_complete_from_namespace_v2(&namespace)?;
            validate_local_cleanup_against_archive_permit_v2(&complete, &permit)?;
            namespace.validate_bindings(&lock)?;
            rename_private_oram_entry_at_v2(
                root,
                std::ffi::OsStr::new(ACTIVE_DIR),
                root,
                archive_name,
                true,
            )
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
            // ACTIVE_DIR and the generation archive are direct children of this exact retained
            // root descriptor, so this one directory fsync covers both removal and installation.
            root.sync_all()
                .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
            Some(namespace)
        } else if !archive_exists {
            return Err(PrivateOramMutationJournalError::Corrupt);
        } else {
            None
        };

        let namespace = PrivateOramPinnedActiveNamespaceV2::open_named(&lock, archive_name)?;
        if let Some(source) = moved_source.as_ref() {
            ensure_same_directory(
                &source
                    .active
                    .file
                    .metadata()
                    .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?,
                &namespace
                    .active
                    .file
                    .metadata()
                    .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?,
            )
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
            if private_oram_directory_exists_at_v2(root, std::ffi::OsStr::new(ACTIVE_DIR))? {
                return Err(PrivateOramMutationJournalError::Indeterminate);
            }
            validate_private_directory_metadata(
                &source
                    .active
                    .file
                    .metadata()
                    .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?,
            )
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        }
        let archived = self.load_v2_from_namespace(&namespace)?;
        validate_terminal_archive_source_v2(&archived, &permit)?;
        let complete = load_local_cleanup_complete_from_namespace_v2(&namespace)?;
        validate_local_cleanup_against_archive_permit_v2(&complete, &permit)?;
        let mut archive = PrivateOramMutationTerminalArchiveV2 {
            version: TERMINAL_ARCHIVE_VERSION_V2,
            generation: permit.generation(),
            descriptor_digest: permit.descriptor_digest().to_string(),
            terminal_record_digest: permit.terminal_record_digest().to_string(),
            witness_digest: permit.witness_digest().to_string(),
            cleanup_evidence_digest: permit.cleanup_evidence_digest().to_string(),
            clear_attempt_id_digest: permit.clear_attempt_id_digest().to_string(),
            clear_receipt_digest: permit.clear_receipt_digest().to_string(),
            tombstone_digest: permit.archive_binding_digest().to_string(),
            archive_digest: String::new(),
        };
        archive.archive_digest = terminal_archive_digest_v2(&archive)?;
        validate_terminal_archive_v2(&archive)?;
        let installed = publish_immutable_private_oram_json_v2(
            &namespace,
            &namespace.active,
            std::ffi::OsStr::new(TERMINAL_ARCHIVE_FILE_V2),
            &archive,
            MAX_TERMINAL_ARCHIVE_BYTES_V2,
        )?;
        let installed_archive: PrivateOramMutationTerminalArchiveV2 = installed.deserialize()?;
        validate_terminal_archive_v2(&installed_archive)?;
        if installed_archive != archive {
            return Err(PrivateOramMutationJournalError::ConcurrentMutation);
        }
        namespace.validate_bindings(&lock)?;
        lock.validate_root_identity()
    }

    pub(super) fn validated_decision_for_v2_state(
        &self,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
        durable_point_stage: Option<&PrivateOramDurablePointStageTokenV1>,
    ) -> Result<PrivateOramValidatedMutationDecisionV2, PrivateOramMutationJournalError> {
        let snapshot = self
            .load_v2()?
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        if snapshot.state.phase.sequence()
            < PrivateOramMutationJournalPhaseV2::PointStageDurable.sequence()
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_live_point_stage_v2(
            &snapshot.descriptor,
            snapshot.effective_state(),
            durable_point_stage,
        )?;
        let (_, _, evidence) =
            validated_reconcile_decision_for_v2_snapshot(&snapshot, reconcile_snapshot)?;
        let effective = snapshot.effective_state();
        Ok(PrivateOramValidatedMutationDecisionV2 {
            evidence,
            expected_descriptor_digest: snapshot.descriptor.descriptor_digest.clone(),
            expected_predecessor_record_digest: record_digest_at_phase_v2(
                &snapshot.descriptor,
                effective,
                PrivateOramMutationJournalPhaseV2::PointStageDurable,
            )?,
        })
    }

    pub(super) fn mark_decision_durable_v2(
        &self,
        decision: &PrivateOramValidatedMutationDecisionV2,
    ) -> Result<
        (
            PrivateOramMutationJournalStructuralSnapshotV2,
            PrivateOramValidatedDecisionDurableV2,
        ),
        PrivateOramMutationJournalError,
    > {
        let expected = decision.evidence.clone();
        let expected_descriptor_digest = decision.expected_descriptor_digest.clone();
        let expected_predecessor_record_digest =
            decision.expected_predecessor_record_digest.clone();
        let snapshot = self.transition_v2(
            PrivateOramMutationJournalPhaseV2::DecisionDurable,
            move |descriptor, state| {
                (descriptor.descriptor_digest == expected_descriptor_digest
                    && record_digest_at_phase_v2(
                        descriptor,
                        state,
                        PrivateOramMutationJournalPhaseV2::PointStageDurable,
                    )? == expected_predecessor_record_digest
                    && state.decision.as_ref() == Some(&expected))
                .then_some(())
                .ok_or(PrivateOramMutationJournalError::InvalidTransition)
            },
            |descriptor, current, next| {
                if descriptor.descriptor_digest != decision.expected_descriptor_digest
                    || current.record_digest != decision.expected_predecessor_record_digest
                {
                    return Err(PrivateOramMutationJournalError::InvalidTransition);
                }
                next.decision = Some(decision.evidence.clone());
                Ok(())
            },
        )?;
        let decision_record_digest = record_digest_at_phase_v2(
            &snapshot.descriptor,
            &snapshot.state,
            PrivateOramMutationJournalPhaseV2::DecisionDurable,
        )?;
        Ok((
            snapshot,
            PrivateOramValidatedDecisionDurableV2 {
                evidence: decision.evidence.clone(),
                expected_descriptor_digest: decision.expected_descriptor_digest.clone(),
                decision_record_digest,
            },
        ))
    }

    pub(super) fn mark_authenticated_remote_terminals_v2(
        &self,
        decision: &PrivateOramValidatedDecisionDurableV2,
        responses: &[PrivateOramAuthenticatedOwnerRecoveryResponse],
    ) -> Result<
        (
            PrivateOramMutationJournalStructuralSnapshotV2,
            PrivateOramValidatedRemotesTerminalV2,
        ),
        PrivateOramMutationJournalError,
    > {
        let claims = responses
            .iter()
            .map(PrivateOramAuthenticatedOwnerTerminalClaimV2::try_from_authenticated_response)
            .collect::<Result<Vec<_>, _>>()?;
        self.mark_remote_terminal_claims_v2(decision, &claims)
    }

    #[cfg(test)]
    pub(super) fn mark_remote_terminal_claims_v2_for_test(
        &self,
        decision: &PrivateOramValidatedDecisionDurableV2,
        outcomes: &[PrivateOramAuthenticatedOwnerTerminalClaimV2],
    ) -> Result<
        (
            PrivateOramMutationJournalStructuralSnapshotV2,
            PrivateOramValidatedRemotesTerminalV2,
        ),
        PrivateOramMutationJournalError,
    > {
        self.mark_remote_terminal_claims_v2(decision, outcomes)
    }

    fn mark_remote_terminal_claims_v2(
        &self,
        decision: &PrivateOramValidatedDecisionDurableV2,
        outcomes: &[PrivateOramAuthenticatedOwnerTerminalClaimV2],
    ) -> Result<
        (
            PrivateOramMutationJournalStructuralSnapshotV2,
            PrivateOramValidatedRemotesTerminalV2,
        ),
        PrivateOramMutationJournalError,
    > {
        let mut owners = outcomes
            .iter()
            .map(|outcome| {
                let expected_digest = private_oram_owner_terminal_evidence_v2_digest(
                    &decision.expected_descriptor_digest,
                    outcome.kind,
                    &outcome.evidence,
                )?;
                if outcome.evidence.terminal_evidence_digest != expected_digest {
                    return Err(PrivateOramMutationJournalError::InvalidTransition);
                }
                Ok((outcome.kind, outcome.evidence.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        owners.sort_unstable_by_key(|(_, evidence)| evidence.owner_peer_id);
        if owners
            .windows(2)
            .any(|pair| pair[0].1.owner_peer_id == pair[1].1.owner_peer_id)
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let kind = match decision.evidence.kind() {
            ValidatedPrivateOramMutationDecisionKindV2::ExactNew => {
                PrivateOramMutationOwnerTerminalKindV2::FinalizedNew
            }
            ValidatedPrivateOramMutationDecisionKindV2::ExactOldAbort => {
                PrivateOramMutationOwnerTerminalKindV2::AbortedOld
            }
        };
        if owners.iter().any(|(owner_kind, _)| *owner_kind != kind) {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let batch = PrivateOramMutationOwnerTerminalBatchV2 {
            kind,
            owners: owners.into_iter().map(|(_, evidence)| evidence).collect(),
        };
        let snapshot = self.mark_owner_terminal_batch_v2(
            None,
            PrivateOramMutationJournalPhaseV2::RemotesTerminal,
            &decision.evidence,
            &decision.expected_descriptor_digest,
            &decision.decision_record_digest,
            batch,
        )?;
        let remotes_terminal_record_digest = record_digest_at_phase_v2(
            &snapshot.descriptor,
            &snapshot.state,
            PrivateOramMutationJournalPhaseV2::RemotesTerminal,
        )?;
        Ok((
            snapshot,
            PrivateOramValidatedRemotesTerminalV2 {
                evidence: decision.evidence.clone(),
                expected_descriptor_digest: decision.expected_descriptor_digest.clone(),
                remotes_terminal_record_digest,
            },
        ))
    }

    #[cfg(test)]
    pub(super) fn mark_remotes_terminal_v2(
        &self,
        decision: &PrivateOramValidatedDecisionDurableV2,
        outcomes: &[PrivateOramValidatedOwnerRecoveryOutcomeV1],
    ) -> Result<
        (
            PrivateOramMutationJournalStructuralSnapshotV2,
            PrivateOramValidatedRemotesTerminalV2,
        ),
        PrivateOramMutationJournalError,
    > {
        let snapshot = self.mark_owner_terminals_v2(
            None,
            PrivateOramMutationJournalPhaseV2::RemotesTerminal,
            &decision.evidence,
            &decision.expected_descriptor_digest,
            &decision.decision_record_digest,
            outcomes,
        )?;
        let remotes_terminal_record_digest = record_digest_at_phase_v2(
            &snapshot.descriptor,
            &snapshot.state,
            PrivateOramMutationJournalPhaseV2::RemotesTerminal,
        )?;
        Ok((
            snapshot,
            PrivateOramValidatedRemotesTerminalV2 {
                evidence: decision.evidence.clone(),
                expected_descriptor_digest: decision.expected_descriptor_digest.clone(),
                remotes_terminal_record_digest,
            },
        ))
    }

    #[cfg(test)]
    pub(super) fn mark_local_terminal_v2(
        &self,
        remotes: &PrivateOramValidatedRemotesTerminalV2,
        outcome: &PrivateOramValidatedOwnerRecoveryOutcomeV1,
    ) -> Result<
        (
            PrivateOramMutationJournalStructuralSnapshotV2,
            PrivateOramValidatedLocalTerminalV2,
        ),
        PrivateOramMutationJournalError,
    > {
        self.mark_local_terminal_v2_with_lock(None, remotes, outcome)
    }

    fn mark_local_terminal_v2_with_lock(
        &self,
        lock: Option<&PrivateOramMutationJournalLock>,
        remotes: &PrivateOramValidatedRemotesTerminalV2,
        outcome: &PrivateOramValidatedOwnerRecoveryOutcomeV1,
    ) -> Result<
        (
            PrivateOramMutationJournalStructuralSnapshotV2,
            PrivateOramValidatedLocalTerminalV2,
        ),
        PrivateOramMutationJournalError,
    > {
        let snapshot = self.mark_owner_terminals_v2(
            lock,
            PrivateOramMutationJournalPhaseV2::LocalTerminal,
            &remotes.evidence,
            &remotes.expected_descriptor_digest,
            &remotes.remotes_terminal_record_digest,
            std::slice::from_ref(outcome),
        )?;
        let local_terminal_record_digest = record_digest_at_phase_v2(
            &snapshot.descriptor,
            &snapshot.state,
            PrivateOramMutationJournalPhaseV2::LocalTerminal,
        )?;
        Ok((
            snapshot,
            PrivateOramValidatedLocalTerminalV2 {
                evidence: remotes.evidence.clone(),
                expected_descriptor_digest: remotes.expected_descriptor_digest.clone(),
                local_terminal_record_digest,
            },
        ))
    }

    pub(super) fn recover_local_owner_and_mark_terminal_v2(
        &self,
        remotes: &PrivateOramValidatedRemotesTerminalV2,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
        authenticated_local_owner_peer_id: PeerId,
        resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    ) -> Result<
        (
            PrivateOramMutationJournalStructuralSnapshotV2,
            PrivateOramValidatedLocalTerminalV2,
        ),
        PrivateOramMutationJournalError,
    > {
        self.recover_local_owner_and_mark_terminal_v2_with(
            remotes,
            reconcile_snapshot,
            authenticated_local_owner_peer_id,
            resources,
            |parent_lock, outcome| {
                self.mark_local_terminal_v2_with_lock(Some(parent_lock), remotes, outcome)
            },
        )
    }

    fn recover_local_owner_and_mark_terminal_v2_with(
        &self,
        remotes: &PrivateOramValidatedRemotesTerminalV2,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
        authenticated_local_owner_peer_id: PeerId,
        resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
        publish_local_terminal: impl FnOnce(
            &PrivateOramMutationJournalLock,
            &PrivateOramValidatedOwnerRecoveryOutcomeV1,
        ) -> Result<
            (
                PrivateOramMutationJournalStructuralSnapshotV2,
                PrivateOramValidatedLocalTerminalV2,
            ),
            PrivateOramMutationJournalError,
        >,
    ) -> Result<
        (
            PrivateOramMutationJournalStructuralSnapshotV2,
            PrivateOramValidatedLocalTerminalV2,
        ),
        PrivateOramMutationJournalError,
    > {
        self.validate_owner_recovery_resources_v1(&resources)?;
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.temp_path())?;
        let parent_lock = self.acquire_lock()?;
        let snapshot = self.load_v2_locked(&parent_lock)?;
        if snapshot.state.phase.sequence()
            < PrivateOramMutationJournalPhaseV2::RemotesTerminal.sequence()
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_remotes_terminal_token_v2(&snapshot.descriptor, &snapshot.state, remotes)?;
        if authenticated_local_owner_peer_id != snapshot.descriptor.coordinator_peer_id {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let (active_lease, disposition, decision) =
            validated_reconcile_decision_for_v2_snapshot(&snapshot, reconcile_snapshot)?;
        if decision != remotes.evidence {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let authority = build_owner_recovery_authority_v2(
            &snapshot.descriptor,
            snapshot.effective_state(),
            &active_lease,
            disposition,
            authenticated_local_owner_peer_id,
        )?;
        let live = PrivateOramLiveOwnerRecoveryAuthorityV1::new(
            authority,
            &parent_lock,
            &self.owner_recovery_parent_bridge,
            &self.owner_recovery_parent_verifier,
        );
        let resolved = live
            .recover_pair_then_v1(resources, |outcome| {
                publish_local_terminal(&parent_lock, &outcome)
            })
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        drop(live);
        let resolved = resolved.map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        let loaded = self
            .load_v2_locked(&parent_lock)
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        if loaded != resolved.0 {
            return Err(PrivateOramMutationJournalError::Indeterminate);
        }
        validate_local_terminal_token_v2(&loaded.descriptor, loaded.effective_state(), &resolved.1)
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        parent_lock
            .validate_root_identity()
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        Ok(resolved)
    }

    #[cfg(test)]
    pub(super) fn recover_local_owner_with_parent_terminal_failure_v2(
        &self,
        remotes: &PrivateOramValidatedRemotesTerminalV2,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
        authenticated_local_owner_peer_id: PeerId,
        resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    ) -> Result<
        (
            PrivateOramMutationJournalStructuralSnapshotV2,
            PrivateOramValidatedLocalTerminalV2,
        ),
        PrivateOramMutationJournalError,
    > {
        self.recover_local_owner_and_mark_terminal_v2_with(
            remotes,
            reconcile_snapshot,
            authenticated_local_owner_peer_id,
            resources,
            |_, _| Err(PrivateOramMutationJournalError::InvalidTransition),
        )
    }

    #[cfg(test)]
    pub(super) fn recover_local_owner_with_post_parent_terminal_failure_v2(
        &self,
        remotes: &PrivateOramValidatedRemotesTerminalV2,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
        authenticated_local_owner_peer_id: PeerId,
        resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    ) -> Result<
        (
            PrivateOramMutationJournalStructuralSnapshotV2,
            PrivateOramValidatedLocalTerminalV2,
        ),
        PrivateOramMutationJournalError,
    > {
        self.recover_local_owner_and_mark_terminal_v2_with(
            remotes,
            reconcile_snapshot,
            authenticated_local_owner_peer_id,
            resources,
            |parent_lock, outcome| {
                self.mark_local_terminal_v2_with_lock(Some(parent_lock), remotes, outcome)?;
                Err(PrivateOramMutationJournalError::InvalidTransition)
            },
        )
    }

    #[cfg(test)]
    pub(super) fn mark_private_point_resolved_v2(
        &self,
        local: &PrivateOramValidatedLocalTerminalV2,
        point_store: &PrivateOramPointStagingStore,
        outcome: PrivateOramPointResolutionOutcomeV2,
        receipt: PrivateOramPointResolutionReceiptV2,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let collection_path = self
            .root
            .parent()
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        if !point_store.belongs_to_collection(collection_path) {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.temp_path())?;
        let parent_lock = self.acquire_lock()?;
        let snapshot = self.load_v2_locked(&parent_lock)?;
        validate_local_terminal_token_v2(&snapshot.descriptor, snapshot.effective_state(), local)?;
        let evidence = match outcome {
            PrivateOramPointResolutionOutcomeV2::PublishedExactNew => {
                RawPrivateOramMutationPointResolutionEvidenceV2::PublishedExactNew { receipt }
            }
            PrivateOramPointResolutionOutcomeV2::AbortedExactOld => {
                RawPrivateOramMutationPointResolutionEvidenceV2::AbortedExactOld { receipt }
            }
        };
        validate_point_resolution_candidate_v2(
            &snapshot.descriptor,
            snapshot.effective_state(),
            &evidence,
        )?;
        if snapshot.effective_state().phase == PrivateOramMutationJournalPhaseV2::PointResolved {
            return self.mark_point_resolved_from_evidence_v2(Some(&parent_lock), local, &evidence);
        }
        let point_parent = validated_point_stage_parent_for_terminal_v2(
            &snapshot.descriptor,
            snapshot.effective_state(),
        )?;
        let resolved = point_store.with_consumed_live_stage(&point_parent, |live| {
            validate_live_point_stage_v2(
                &snapshot.descriptor,
                snapshot.effective_state(),
                Some(live.durable()),
            )?;
            if live.frame().point.vectors.is_empty() {
                validate_point_resolution_candidate_v2(
                    &snapshot.descriptor,
                    snapshot.effective_state(),
                    &evidence,
                )?;
                self.mark_point_resolved_from_evidence_v2(Some(&parent_lock), local, &evidence)
            } else {
                Err(PrivateOramMutationJournalError::InvalidTransition)
            }
        })??;
        parent_lock
            .validate_root_identity()
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        Ok(resolved)
    }

    pub(super) fn mark_no_server_point_resolved_v2(
        &self,
        local: &PrivateOramValidatedLocalTerminalV2,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let evidence = RawPrivateOramMutationPointResolutionEvidenceV2::NoServerPointRecord {
            decision_kind: local.evidence.kind(),
            parent_local_terminal_record_digest: local.local_terminal_record_digest.clone(),
        };
        self.mark_point_resolved_from_evidence_v2(None, local, &evidence)
    }

    fn mark_point_resolved_from_evidence_v2(
        &self,
        lock: Option<&PrivateOramMutationJournalLock>,
        local: &PrivateOramValidatedLocalTerminalV2,
        evidence: &RawPrivateOramMutationPointResolutionEvidenceV2,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let expected_evidence = evidence.clone();
        let expected_decision = local.evidence.clone();
        let verify_descriptor_digest = local.expected_descriptor_digest.clone();
        let verify_local_record_digest = local.local_terminal_record_digest.clone();
        let update_descriptor_digest = local.expected_descriptor_digest.clone();
        let update_local_record_digest = local.local_terminal_record_digest.clone();
        let verify_existing =
            move |descriptor: &PrivateOramMutationJournalDescriptorV1,
                  state: &PrivateOramMutationJournalStateV2| {
                (descriptor.descriptor_digest == verify_descriptor_digest
                    && record_digest_at_phase_v2(
                        descriptor,
                        state,
                        PrivateOramMutationJournalPhaseV2::LocalTerminal,
                    )? == verify_local_record_digest
                    && state.decision.as_ref() == Some(&expected_decision)
                    && state.point_resolution.as_ref() == Some(&expected_evidence))
                .then_some(())
                .ok_or(PrivateOramMutationJournalError::InvalidTransition)
            };
        let update = move |descriptor: &PrivateOramMutationJournalDescriptorV1,
                           current: &PrivateOramMutationJournalStateV2,
                           next: &mut PrivateOramMutationJournalStateV2| {
            if descriptor.descriptor_digest != update_descriptor_digest
                || current.record_digest != update_local_record_digest
                || current.decision.as_ref() != Some(&local.evidence)
            {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            next.point_resolution = Some(evidence.clone());
            Ok(())
        };
        if let Some(lock) = lock {
            self.transition_v2_locked(
                lock,
                PrivateOramMutationJournalPhaseV2::PointResolved,
                verify_existing,
                update,
            )
        } else {
            self.transition_v2(
                PrivateOramMutationJournalPhaseV2::PointResolved,
                verify_existing,
                update,
            )
        }
    }

    #[cfg(test)]
    pub(super) fn validated_local_terminal_for_current_v2(
        &self,
    ) -> Result<PrivateOramValidatedLocalTerminalV2, PrivateOramMutationJournalError> {
        let snapshot = self
            .load_v2()?
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        validated_local_terminal_from_v2_snapshot(&snapshot)
    }

    fn mark_owner_terminals_v2(
        &self,
        lock: Option<&PrivateOramMutationJournalLock>,
        phase: PrivateOramMutationJournalPhaseV2,
        decision: &RawPrivateOramMutationDecisionEvidenceV2,
        expected_descriptor_digest: &str,
        expected_predecessor_record_digest: &str,
        outcomes: &[PrivateOramValidatedOwnerRecoveryOutcomeV1],
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let mut owners = outcomes
            .iter()
            .map(validated_owner_terminal_evidence_v2)
            .collect::<Result<Vec<_>, _>>()?;
        owners.sort_unstable_by_key(|(_, evidence)| evidence.owner_peer_id);
        let kind = match decision.kind() {
            ValidatedPrivateOramMutationDecisionKindV2::ExactNew => {
                PrivateOramMutationOwnerTerminalKindV2::FinalizedNew
            }
            ValidatedPrivateOramMutationDecisionKindV2::ExactOldAbort => {
                PrivateOramMutationOwnerTerminalKindV2::AbortedOld
            }
        };
        if owners.iter().any(|(owner_kind, _)| *owner_kind != kind) {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let batch = PrivateOramMutationOwnerTerminalBatchV2 {
            kind,
            owners: owners.into_iter().map(|(_, evidence)| evidence).collect(),
        };
        self.mark_owner_terminal_batch_v2(
            lock,
            phase,
            decision,
            expected_descriptor_digest,
            expected_predecessor_record_digest,
            batch,
        )
    }

    fn mark_owner_terminal_batch_v2(
        &self,
        lock: Option<&PrivateOramMutationJournalLock>,
        phase: PrivateOramMutationJournalPhaseV2,
        decision: &RawPrivateOramMutationDecisionEvidenceV2,
        expected_descriptor_digest: &str,
        expected_predecessor_record_digest: &str,
        batch: PrivateOramMutationOwnerTerminalBatchV2,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let expected = batch.clone();
        let expected_decision = decision.clone();
        let verify_descriptor_digest = expected_descriptor_digest.to_string();
        let verify_predecessor_record_digest = expected_predecessor_record_digest.to_string();
        let update_descriptor_digest = expected_descriptor_digest.to_string();
        let update_predecessor_record_digest = expected_predecessor_record_digest.to_string();
        let predecessor_phase = match phase {
            PrivateOramMutationJournalPhaseV2::RemotesTerminal => {
                PrivateOramMutationJournalPhaseV2::DecisionDurable
            }
            PrivateOramMutationJournalPhaseV2::LocalTerminal => {
                PrivateOramMutationJournalPhaseV2::RemotesTerminal
            }
            _ => return Err(PrivateOramMutationJournalError::InvalidTransition),
        };
        let verify_existing =
            move |descriptor: &PrivateOramMutationJournalDescriptorV1,
                  state: &PrivateOramMutationJournalStateV2| {
                let existing = match phase {
                    PrivateOramMutationJournalPhaseV2::RemotesTerminal => {
                        state.remote_terminals.as_ref()
                    }
                    PrivateOramMutationJournalPhaseV2::LocalTerminal => {
                        state.local_terminals.as_ref()
                    }
                    _ => return Err(PrivateOramMutationJournalError::InvalidTransition),
                };
                (descriptor.descriptor_digest == verify_descriptor_digest
                    && record_digest_at_phase_v2(descriptor, state, predecessor_phase)?
                        == verify_predecessor_record_digest
                    && state.decision.as_ref() == Some(&expected_decision)
                    && existing == Some(&expected))
                .then_some(())
                .ok_or(PrivateOramMutationJournalError::InvalidTransition)
            };
        let update = move |descriptor: &PrivateOramMutationJournalDescriptorV1,
                           current: &PrivateOramMutationJournalStateV2,
                           next: &mut PrivateOramMutationJournalStateV2| {
            if descriptor.descriptor_digest != update_descriptor_digest
                || current.record_digest != update_predecessor_record_digest
                || current.decision.as_ref() != Some(decision)
            {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            match phase {
                PrivateOramMutationJournalPhaseV2::RemotesTerminal => {
                    next.remote_terminals = Some(batch);
                }
                PrivateOramMutationJournalPhaseV2::LocalTerminal => {
                    next.local_terminals = Some(batch);
                }
                _ => return Err(PrivateOramMutationJournalError::InvalidTransition),
            }
            Ok(())
        };
        if let Some(lock) = lock {
            self.transition_v2_locked(lock, phase, verify_existing, update)
        } else {
            self.transition_v2(phase, verify_existing, update)
        }
    }

    fn mark_point_stage_durable_v2(
        &self,
        expected_descriptor_digest: &str,
        expected_owners_prepared_record_digest: &str,
        evidence: PrivateOramMutationPointStageEvidenceV2,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let expected_evidence = evidence.clone();
        self.transition_v2(
            PrivateOramMutationJournalPhaseV2::PointStageDurable,
            move |descriptor, state| {
                if descriptor.descriptor_digest != expected_descriptor_digest
                    || state.point_stage.as_ref() != Some(&expected_evidence)
                {
                    return Err(PrivateOramMutationJournalError::InvalidTransition);
                }
                Ok(())
            },
            move |descriptor, current, next| {
                if descriptor.descriptor_digest != expected_descriptor_digest
                    || current.record_digest != expected_owners_prepared_record_digest
                {
                    return Err(PrivateOramMutationJournalError::InvalidTransition);
                }
                next.point_stage = Some(evidence);
                Ok(())
            },
        )
    }

    fn transition_v2<Verify, Update>(
        &self,
        phase: PrivateOramMutationJournalPhaseV2,
        verify_existing: Verify,
        update: Update,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    where
        Verify: FnOnce(
            &PrivateOramMutationJournalDescriptorV1,
            &PrivateOramMutationJournalStateV2,
        ) -> Result<(), PrivateOramMutationJournalError>,
        Update: FnOnce(
            &PrivateOramMutationJournalDescriptorV1,
            &PrivateOramMutationJournalStateV2,
            &mut PrivateOramMutationJournalStateV2,
        ) -> Result<(), PrivateOramMutationJournalError>,
    {
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.temp_path())?;
        let lock = self.acquire_lock()?;
        self.transition_v2_locked(&lock, phase, verify_existing, update)
    }

    fn transition_v2_locked<Verify, Update>(
        &self,
        lock: &PrivateOramMutationJournalLock,
        phase: PrivateOramMutationJournalPhaseV2,
        verify_existing: Verify,
        update: Update,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    where
        Verify: FnOnce(
            &PrivateOramMutationJournalDescriptorV1,
            &PrivateOramMutationJournalStateV2,
        ) -> Result<(), PrivateOramMutationJournalError>,
        Update: FnOnce(
            &PrivateOramMutationJournalDescriptorV1,
            &PrivateOramMutationJournalStateV2,
            &mut PrivateOramMutationJournalStateV2,
        ) -> Result<(), PrivateOramMutationJournalError>,
    {
        lock.validate_root_identity()?;
        let namespace = PrivateOramPinnedActiveNamespaceV2::open(lock)?;
        let current_result = self.load_v2_from_namespace(&namespace);
        namespace.validate_bindings(lock)?;
        let current = current_result?;
        if current.state.phase.sequence() >= phase.sequence() {
            verify_existing(&current.descriptor, &current.state)?;
            namespace
                .active
                .sync()
                .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
            namespace
                .validate_bindings(lock)
                .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
            return Ok(current);
        }
        if current.state.phase.sequence() + 1 != phase.sequence() {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let next = next_private_oram_mutation_state_v2(
            &current.descriptor,
            &current.state,
            phase,
            |next| update(&current.descriptor, &current.state, next),
        )?;
        if current
            .pending_next
            .as_ref()
            .is_some_and(|pending| pending != &next)
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        // A visible pending record may come from an attempt whose directory fsync failed.
        // Re-running the exact publisher re-establishes record durability before the pointer moves.
        namespace.validate_bindings(lock)?;
        publish_immutable_state_record_v2(&namespace, &next)?;
        namespace
            .validate_bindings(lock)
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        publish_state_pointer_v2(&namespace, &next)?;
        namespace
            .validate_bindings(lock)
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        let loaded = self
            .load_v2_from_namespace(&namespace)
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        if loaded.state != next || loaded.pending_next.is_some() {
            return Err(PrivateOramMutationJournalError::Indeterminate);
        }
        namespace
            .validate_bindings(lock)
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        Ok(loaded)
    }

    fn load_v2_locked(
        &self,
        lock: &PrivateOramMutationJournalLock,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let namespace = PrivateOramPinnedActiveNamespaceV2::open(lock)?;
        let result = self.load_v2_from_namespace(&namespace);
        namespace.validate_bindings(lock)?;
        result
    }

    fn load_v2_from_namespace(
        &self,
        namespace: &PrivateOramPinnedActiveNamespaceV2<'_>,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let descriptor_file = required_v2_artifact(PrivateOramPinnedFileV2::open_at(
            &namespace.active.file,
            std::ffi::OsStr::new(DESCRIPTOR_FILE),
            MAX_DESCRIPTOR_BYTES,
        ))?;
        let descriptor: PrivateOramMutationJournalDescriptorV1 = descriptor_file.deserialize()?;
        validate_descriptor(&descriptor, self.signature_verification())?;
        let state_file = required_v2_artifact(PrivateOramPinnedFileV2::open_at(
            &namespace.active.file,
            std::ffi::OsStr::new(STATE_FILE),
            MAX_STATE_BYTES,
        ))?;
        let state =
            match decode_untrusted_private_oram_mutation_state(&descriptor, state_file.bytes())? {
                DecodedPrivateOramMutationStateUntrusted::V1(_) => {
                    let format = optional_private_oram_file_at_v2(
                        &namespace.active.file,
                        std::ffi::OsStr::new(FORMAT_FILE),
                        MAX_FORMAT_BYTES,
                    )?;
                    descriptor_file.validate_binding_and_contents(&namespace.active.file)?;
                    state_file.validate_binding_and_contents(&namespace.active.file)?;
                    if format.is_some() || namespace.records.is_some() {
                        return Err(PrivateOramMutationJournalError::Corrupt);
                    }
                    return Err(PrivateOramMutationJournalError::LegacyV1State);
                }
                DecodedPrivateOramMutationStateUntrusted::UntrustedV2(state) => *state,
            };
        let immutable_manifest_file = required_v2_artifact(PrivateOramPinnedFileV2::open_at(
            &namespace.active.file,
            std::ffi::OsStr::new(IMMUTABLE_MANIFEST_FILE),
            MAX_IMMUTABLE_MANIFEST_BYTES,
        ))?;
        let immutable_manifest: PrivateOramImmutableManifestBundleV2 =
            immutable_manifest_file.deserialize()?;
        self.validate_immutable_manifest_for_descriptor(&immutable_manifest, &descriptor)
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
        let format_file = required_v2_artifact(PrivateOramPinnedFileV2::open_at(
            &namespace.active.file,
            std::ffi::OsStr::new(FORMAT_FILE),
            MAX_FORMAT_BYTES,
        ))?;
        let format: PrivateOramMutationJournalFormatV2 = format_file.deserialize()?;
        if format.state_version != V2_JOURNAL_FORMAT_VERSION
            || format.descriptor_digest != descriptor.descriptor_digest
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        let history =
            required_v2_artifact(load_state_history_v2(namespace.records()?, &descriptor))?;
        let records = &history.states;
        let current_index = usize::try_from(
            state
                .sequence
                .checked_sub(1)
                .ok_or(PrivateOramMutationJournalError::Corrupt)?,
        )
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
        if records.get(current_index) != Some(&state)
            || !(records.len() == current_index + 1 || records.len() == current_index + 2)
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        let pending_next =
            (records.len() == current_index + 2).then(|| records[current_index + 1].clone());
        history.validate(namespace.records()?)?;
        descriptor_file.validate_binding_and_contents(&namespace.active.file)?;
        state_file.validate_binding_and_contents(&namespace.active.file)?;
        immutable_manifest_file.validate_binding_and_contents(&namespace.active.file)?;
        format_file.validate_binding_and_contents(&namespace.active.file)?;
        Ok(PrivateOramMutationJournalStructuralSnapshotV2 {
            descriptor,
            immutable_manifest,
            state,
            pending_next,
        })
    }
}

fn required_v2_artifact<T>(
    result: Result<T, PrivateOramMutationJournalError>,
) -> Result<T, PrivateOramMutationJournalError> {
    match result {
        Err(PrivateOramMutationJournalError::Io(error))
            if error.kind() == io::ErrorKind::NotFound =>
        {
            Err(PrivateOramMutationJournalError::Corrupt)
        }
        other => other,
    }
}

fn cleanup_expectation_from_terminal_v2(
    snapshot: &PrivateOramMutationJournalStructuralSnapshotV2,
    reconcile: &PrivateOramMutationReconcileSnapshotV1,
) -> Result<PrivateOramMutationCleanupExpectationV2, PrivateOramMutationJournalError> {
    if snapshot.pending_next.is_some()
        || snapshot.state.phase != PrivateOramMutationJournalPhaseV2::PointResolved
        || snapshot.state.sequence != PrivateOramMutationJournalPhaseV2::PointResolved.sequence()
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let (terminal_lease, _, decision) =
        validated_reconcile_decision_for_v2_snapshot(snapshot, reconcile)?;
    if snapshot.state.decision.as_ref() != Some(&decision)
        || reconcile.lease_slot().active.as_ref() != Some(&terminal_lease)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let terminal_watermark = derive_private_oram_mutation_parent_watermark_at_sequence_v2(
        snapshot,
        PrivateOramMutationJournalPhaseV2::PointResolved.sequence(),
    )?
    .watermark()
    .clone();
    if reconcile.parent_watermark() != Some(&terminal_watermark) {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let outcome = match decision.kind() {
        ValidatedPrivateOramMutationDecisionKindV2::ExactNew => {
            PrivateOramMutationClearOutcome::FinalizedOrReconciledAfterConsensusCommit
        }
        ValidatedPrivateOramMutationDecisionKindV2::ExactOldAbort => {
            PrivateOramMutationClearOutcome::AbortedBeforeConsensusCommit
        }
    };
    let terminal_consensus_state_digest =
        canonical_private_oram_consensus_state_record_digest(reconcile.consensus_state())
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    derive_private_oram_mutation_cleanup_expectation_v2(
        terminal_watermark,
        terminal_lease,
        outcome,
        terminal_consensus_state_digest,
        reconcile.consensus_state().state_sequence,
        owner_cleanup_evidence_digest_v2(snapshot)?,
        point_cleanup_evidence_digest_v2(snapshot)?,
    )
}

fn owner_cleanup_evidence_digest_v2(
    snapshot: &PrivateOramMutationJournalStructuralSnapshotV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(OWNER_CLEANUP_EVIDENCE_DIGEST_DOMAIN_V2);
    hash_digest(&mut hasher, &snapshot.descriptor.descriptor_digest)?;
    hash_digest(&mut hasher, &snapshot.state.record_digest)?;
    for (batch_tag, batch) in [
        (1_u8, snapshot.state.remote_terminals.as_ref()),
        (2_u8, snapshot.state.local_terminals.as_ref()),
    ] {
        let batch = batch.ok_or(PrivateOramMutationJournalError::Corrupt)?;
        hasher.update([batch_tag]);
        hasher.update([match batch.kind {
            PrivateOramMutationOwnerTerminalKindV2::FinalizedNew => 1,
            PrivateOramMutationOwnerTerminalKindV2::AbortedOld => 2,
        }]);
        hasher.update((batch.owners.len() as u64).to_be_bytes());
        for owner in &batch.owners {
            hasher.update(owner.owner_peer_id.to_be_bytes());
            hash_digest(&mut hasher, &owner.terminal_evidence_digest)?;
        }
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn point_cleanup_evidence_digest_v2(
    snapshot: &PrivateOramMutationJournalStructuralSnapshotV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let Some(RawPrivateOramMutationPointResolutionEvidenceV2::NoServerPointRecord {
        decision_kind,
        parent_local_terminal_record_digest,
    }) = snapshot.state.point_resolution.as_ref()
    else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    let mut hasher = Sha256::new();
    hasher.update(POINT_CLEANUP_EVIDENCE_DIGEST_DOMAIN_V2);
    hash_digest(&mut hasher, &snapshot.descriptor.descriptor_digest)?;
    hash_digest(&mut hasher, &snapshot.state.record_digest)?;
    hasher.update([match decision_kind {
        ValidatedPrivateOramMutationDecisionKindV2::ExactNew => 1,
        ValidatedPrivateOramMutationDecisionKindV2::ExactOldAbort => 2,
    }]);
    hash_digest(&mut hasher, parent_local_terminal_record_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn local_cleanup_complete_digest_v2(
    complete: &PrivateOramMutationLocalCleanupCompleteV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(LOCAL_CLEANUP_COMPLETE_DIGEST_DOMAIN_V2);
    hasher.update(complete.version.to_be_bytes());
    hasher.update(complete.generation.to_be_bytes());
    for digest in [
        &complete.descriptor_digest,
        &complete.terminal_record_digest,
        &complete.witness_digest,
        &complete.cleanup_evidence_digest,
    ] {
        hash_digest(&mut hasher, digest)?;
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn validate_local_cleanup_complete_v2(
    complete: &PrivateOramMutationLocalCleanupCompleteV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if complete.version != LOCAL_CLEANUP_COMPLETE_VERSION_V2
        || complete.generation == 0
        || !is_sha256_digest(&complete.descriptor_digest)
        || !is_sha256_digest(&complete.terminal_record_digest)
        || !is_sha256_digest(&complete.witness_digest)
        || !is_sha256_digest(&complete.cleanup_evidence_digest)
        || !is_sha256_digest(&complete.clear_attempt_id_digest)
        || complete.clear_attempt_id_digest != local_cleanup_complete_digest_v2(complete)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn load_local_cleanup_complete_from_namespace_v2(
    namespace: &PrivateOramPinnedActiveNamespaceV2<'_>,
) -> Result<PrivateOramMutationLocalCleanupCompleteV2, PrivateOramMutationJournalError> {
    let file = required_v2_artifact(PrivateOramPinnedFileV2::open_at(
        &namespace.active.file,
        std::ffi::OsStr::new(LOCAL_CLEANUP_COMPLETE_FILE_V2),
        MAX_LOCAL_CLEANUP_COMPLETE_BYTES_V2,
    ))?;
    let complete = file.deserialize()?;
    validate_local_cleanup_complete_v2(&complete)?;
    file.validate_binding_and_contents(&namespace.active.file)?;
    Ok(complete)
}

fn validate_terminal_archive_source_v2(
    snapshot: &PrivateOramMutationJournalStructuralSnapshotV2,
    permit: &PrivateOramMutationClearedPendingArchivePermitV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if snapshot.pending_next.is_some()
        || snapshot.state.phase != PrivateOramMutationJournalPhaseV2::PointResolved
        || snapshot.descriptor.coordinator_peer_id != permit.owner_peer_id()
        || snapshot.descriptor.preparing_lease.generation != permit.generation()
        || snapshot.descriptor.mutation_bundle.mutation.collection_id != permit.collection_id()
        || snapshot.descriptor.descriptor_digest != permit.descriptor_digest()
        || snapshot.state.record_digest != permit.terminal_record_digest()
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn validate_local_cleanup_against_archive_permit_v2(
    complete: &PrivateOramMutationLocalCleanupCompleteV2,
    permit: &PrivateOramMutationClearedPendingArchivePermitV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if complete.generation != permit.generation()
        || complete.descriptor_digest != permit.descriptor_digest()
        || complete.terminal_record_digest != permit.terminal_record_digest()
        || complete.witness_digest != permit.witness_digest()
        || complete.cleanup_evidence_digest != permit.cleanup_evidence_digest()
        || complete.clear_attempt_id_digest != permit.clear_attempt_id_digest()
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn terminal_archive_digest_v2(
    archive: &PrivateOramMutationTerminalArchiveV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(TERMINAL_ARCHIVE_DIGEST_DOMAIN_V2);
    hasher.update(archive.version.to_be_bytes());
    hasher.update(archive.generation.to_be_bytes());
    for digest in [
        &archive.descriptor_digest,
        &archive.terminal_record_digest,
        &archive.witness_digest,
        &archive.cleanup_evidence_digest,
        &archive.clear_attempt_id_digest,
        &archive.clear_receipt_digest,
        &archive.tombstone_digest,
    ] {
        hash_digest(&mut hasher, digest)?;
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn validate_terminal_archive_v2(
    archive: &PrivateOramMutationTerminalArchiveV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if archive.version != TERMINAL_ARCHIVE_VERSION_V2
        || archive.generation == 0
        || [
            &archive.descriptor_digest,
            &archive.terminal_record_digest,
            &archive.witness_digest,
            &archive.cleanup_evidence_digest,
            &archive.clear_attempt_id_digest,
            &archive.clear_receipt_digest,
            &archive.tombstone_digest,
            &archive.archive_digest,
        ]
        .into_iter()
        .any(|digest| !is_sha256_digest(digest))
        || archive.archive_digest != terminal_archive_digest_v2(archive)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validated_owner_terminal_evidence_v2(
    outcome: &PrivateOramValidatedOwnerRecoveryOutcomeV1,
) -> Result<
    (
        PrivateOramMutationOwnerTerminalKindV2,
        PrivateOramMutationOwnerTerminalEvidenceV2,
    ),
    PrivateOramMutationJournalError,
> {
    let (kind, terminal) = match outcome {
        PrivateOramValidatedOwnerRecoveryOutcomeV1::Finalized { terminal, .. } => (
            PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
            terminal,
        ),
        PrivateOramValidatedOwnerRecoveryOutcomeV1::AbortedOld { terminal } => {
            (PrivateOramMutationOwnerTerminalKindV2::AbortedOld, terminal)
        }
        PrivateOramValidatedOwnerRecoveryOutcomeV1::ObservedOld => {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
    };
    let mut evidence = PrivateOramMutationOwnerTerminalEvidenceV2 {
        owner_peer_id: terminal.owner_peer_id(),
        journal_descriptor_digest: terminal.journal_descriptor_digest().to_string(),
        prepared_state_digest: terminal.prepared_state_digest().to_string(),
        terminal_record_digest: terminal.terminal_record_digest().to_string(),
        parent_descriptor_digest: terminal.parent_descriptor_digest().to_string(),
        decision_authority_record_digest: terminal.consensus_authority_record_digest().to_string(),
        reconciliation_authority_digest: terminal.reconciliation_authority_digest().to_string(),
        indexes: terminal
            .indexes()
            .iter()
            .map(|index| PrivateOramMutationOwnerTerminalIndexEvidenceV2 {
                kind: index.kind(),
                index_name: index.index_name().to_string(),
                prepared_journal_digest: index.prepared_journal_digest().to_string(),
                terminal_state_digest: index.terminal_state_digest().to_string(),
            })
            .collect(),
        terminal_evidence_digest: String::new(),
    };
    evidence.terminal_evidence_digest = private_oram_owner_terminal_evidence_v2_digest(
        &evidence.parent_descriptor_digest,
        kind,
        &evidence,
    )?;
    Ok((kind, evidence))
}

pub(super) fn private_oram_peer_recovery_terminal_from_outcome_v2(
    request: &PrivateOramPeerRecoveryRequestV2,
    outcome: &PrivateOramValidatedOwnerRecoveryOutcomeV1,
) -> Result<PrivateOramPeerRecoveryTerminalV2, PrivateOramMutationJournalError> {
    let (kind, evidence) = validated_owner_terminal_evidence_v2(outcome)?;
    let mut terminal = PrivateOramPeerRecoveryTerminalV2 {
        protocol_version: request.protocol_version,
        challenge_nonce: request.challenge_nonce.clone(),
        owner_peer_id: evidence.owner_peer_id,
        terminal_kind: match kind {
            PrivateOramMutationOwnerTerminalKindV2::FinalizedNew => {
                PrivateOramPeerRecoveryTerminalKindV2::FinalizedNew
            }
            PrivateOramMutationOwnerTerminalKindV2::AbortedOld => {
                PrivateOramPeerRecoveryTerminalKindV2::AbortedOld
            }
        },
        journal_descriptor_digest: evidence.journal_descriptor_digest,
        prepared_state_digest: evidence.prepared_state_digest,
        terminal_record_digest: evidence.terminal_record_digest,
        parent_descriptor_digest: evidence.parent_descriptor_digest,
        decision_authority_record_digest: evidence.decision_authority_record_digest,
        reconciliation_authority_digest: evidence.reconciliation_authority_digest,
        indexes: evidence
            .indexes
            .into_iter()
            .map(|index| PrivateOramPeerRecoveryTerminalIndexV2 {
                kind: index.kind,
                index_name: index.index_name,
                prepared_journal_digest: index.prepared_journal_digest,
                terminal_state_digest: index.terminal_state_digest,
            })
            .collect(),
        terminal_evidence_digest: String::new(),
    };
    terminal.terminal_evidence_digest =
        try_private_oram_peer_recovery_terminal_evidence_digest_v2(request, &terminal)
            .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
    Ok(terminal)
}

fn validate_live_point_stage_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV2,
    durable_point_stage: Option<&PrivateOramDurablePointStageTokenV1>,
) -> Result<(), PrivateOramMutationJournalError> {
    match (&state.point_stage, durable_point_stage) {
        (
            Some(PrivateOramMutationPointStageEvidenceV2::PrivateOramPointStaging { .. }),
            Some(durable),
        ) if durable.parent_descriptor_digest() == descriptor.descriptor_digest
            && state.point_stage.as_ref()
                == Some(&private_oram_point_stage_evidence_v2_from_durable_token(
                    durable,
                )) =>
        {
            Ok(())
        }
        (Some(PrivateOramMutationPointStageEvidenceV2::NoServerPointRecord { .. }), None) => Ok(()),
        _ => Err(PrivateOramMutationJournalError::InvalidTransition),
    }
}

fn validated_reconcile_decision_for_v2_snapshot(
    snapshot: &PrivateOramMutationJournalStructuralSnapshotV2,
    reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
) -> Result<
    (
        PrivateOramMutationLease,
        PrivateOramMutationReconcileDispositionV1,
        RawPrivateOramMutationDecisionEvidenceV2,
    ),
    PrivateOramMutationJournalError,
> {
    let result = validated_reconcile_decision_for_v2_state(
        &snapshot.descriptor,
        &snapshot.state,
        reconcile_snapshot,
    )?;
    for state in snapshot.pending_next.iter() {
        if state.phase.sequence() >= PrivateOramMutationJournalPhaseV2::DecisionDurable.sequence()
            && state.decision.as_ref() != Some(&result.2)
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
    }
    Ok(result)
}

pub(super) fn validated_reconcile_decision_for_v2_state(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV2,
    reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
) -> Result<
    (
        PrivateOramMutationLease,
        PrivateOramMutationReconcileDispositionV1,
        RawPrivateOramMutationDecisionEvidenceV2,
    ),
    PrivateOramMutationJournalError,
> {
    if state.phase.sequence() < PrivateOramMutationJournalPhaseV2::PointStageDurable.sequence() {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let active_lease = validate_reconcile_lease_slot(descriptor, reconcile_snapshot.lease_slot())?;
    let disposition =
        if reconcile_snapshot.consensus_state() == &descriptor.expected_consensus_old_state {
            match &active_lease.phase {
                PrivateOramMutationLeasePhase::AbortDecided => {
                    PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided
                }
                PrivateOramMutationLeasePhase::Preparing
                | PrivateOramMutationLeasePhase::ConsensusCommitted { .. } => {
                    return Err(PrivateOramMutationJournalError::InvalidTransition);
                }
            }
        } else if reconcile_snapshot.consensus_state() == &expected_consensus_new_state(descriptor)?
            && matches!(
                &active_lease.phase,
                PrivateOramMutationLeasePhase::ConsensusCommitted { .. }
            )
        {
            PrivateOramMutationReconcileDispositionV1::ExactNew
        } else {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        };
    let evidence =
        build_validated_mutation_decision_evidence_v2(descriptor, &active_lease, disposition)?;
    if state.phase.sequence() >= PrivateOramMutationJournalPhaseV2::DecisionDurable.sequence()
        && state.decision.as_ref() != Some(&evidence)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok((active_lease, disposition, evidence))
}

fn validated_mutation_decision_from_v2_snapshot(
    snapshot: &PrivateOramMutationJournalStructuralSnapshotV2,
    evidence: RawPrivateOramMutationDecisionEvidenceV2,
) -> Result<PrivateOramValidatedMutationDecisionV2, PrivateOramMutationJournalError> {
    // The permit is built from the durable pointer state: a crash between publishing the
    // DecisionDurable record and moving the pointer leaves that record as `pending_next`, and
    // resuming must re-run the exact publisher rather than refuse forever. A pending record may
    // only be the DecisionDurable successor carrying this very evidence.
    let state = &snapshot.state;
    if state.phase != PrivateOramMutationJournalPhaseV2::PointStageDurable
        || state.decision.is_some()
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    if snapshot.pending_next.as_ref().is_some_and(|pending| {
        pending.phase != PrivateOramMutationJournalPhaseV2::DecisionDurable
            || pending.decision.as_ref() != Some(&evidence)
    }) {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(PrivateOramValidatedMutationDecisionV2 {
        evidence,
        expected_descriptor_digest: snapshot.descriptor.descriptor_digest.clone(),
        expected_predecessor_record_digest: record_digest_at_phase_v2(
            &snapshot.descriptor,
            state,
            PrivateOramMutationJournalPhaseV2::PointStageDurable,
        )?,
    })
}

fn validated_decision_durable_from_v2_snapshot(
    snapshot: &PrivateOramMutationJournalStructuralSnapshotV2,
    evidence: RawPrivateOramMutationDecisionEvidenceV2,
) -> Result<PrivateOramValidatedDecisionDurableV2, PrivateOramMutationJournalError> {
    let state = snapshot.effective_state();
    if state.phase.sequence() < PrivateOramMutationJournalPhaseV2::DecisionDurable.sequence()
        || state.decision.as_ref() != Some(&evidence)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(PrivateOramValidatedDecisionDurableV2 {
        evidence,
        expected_descriptor_digest: snapshot.descriptor.descriptor_digest.clone(),
        decision_record_digest: record_digest_at_phase_v2(
            &snapshot.descriptor,
            state,
            PrivateOramMutationJournalPhaseV2::DecisionDurable,
        )?,
    })
}

fn validate_decision_durable_token_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV2,
    decision: &PrivateOramValidatedDecisionDurableV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if state.phase.sequence() < PrivateOramMutationJournalPhaseV2::DecisionDurable.sequence()
        || descriptor.descriptor_digest != decision.expected_descriptor_digest
        || state.decision.as_ref() != Some(&decision.evidence)
        || record_digest_at_phase_v2(
            descriptor,
            state,
            PrivateOramMutationJournalPhaseV2::DecisionDurable,
        )? != decision.decision_record_digest
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn validated_remotes_terminal_from_v2_snapshot(
    snapshot: &PrivateOramMutationJournalStructuralSnapshotV2,
    evidence: RawPrivateOramMutationDecisionEvidenceV2,
) -> Result<PrivateOramValidatedRemotesTerminalV2, PrivateOramMutationJournalError> {
    let state = snapshot.effective_state();
    let remotes = PrivateOramValidatedRemotesTerminalV2 {
        evidence,
        expected_descriptor_digest: snapshot.descriptor.descriptor_digest.clone(),
        remotes_terminal_record_digest: record_digest_at_phase_v2(
            &snapshot.descriptor,
            state,
            PrivateOramMutationJournalPhaseV2::RemotesTerminal,
        )?,
    };
    validate_remotes_terminal_token_v2(&snapshot.descriptor, state, &remotes)?;
    Ok(remotes)
}

fn remote_owner_recovery_requests_v2(
    snapshot: &PrivateOramMutationJournalStructuralSnapshotV2,
    collection_name: &str,
    decision: &PrivateOramValidatedDecisionDurableV2,
) -> Result<Vec<PrivateOramPeerRecoveryRequestV2>, PrivateOramMutationJournalError> {
    validate_decision_durable_token_v2(&snapshot.descriptor, snapshot.effective_state(), decision)?;
    let manifest = &snapshot.immutable_manifest.manifest;
    if manifest.result_privacy != ResultPrivacyMode::PrivatePayloadOramRequired
        || !manifest
            .indexes
            .iter()
            .any(|index| index.kind() == PrivateOramIndexKindV2::Result)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let vector_name = manifest
        .indexes
        .iter()
        .find(|index| index.kind() == PrivateOramIndexKindV2::Hnsw)
        .map(|index| index.index_name.clone())
        .ok_or(PrivateOramMutationJournalError::Corrupt)?;
    let coordinator_peer_id = snapshot.descriptor.coordinator_peer_id;
    let owners = snapshot
        .descriptor
        .owner_requirements
        .iter()
        .map(|requirement| requirement.peer_id)
        .collect::<BTreeSet<_>>();
    if !owners.contains(&coordinator_peer_id) {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let mutation = &snapshot.descriptor.mutation_bundle.mutation;
    owners
        .into_iter()
        .filter(|owner_peer_id| *owner_peer_id != coordinator_peer_id)
        .map(|owner_peer_id| {
            let request = PrivateOramPeerRecoveryRequestV2 {
                protocol_version: PRIVATE_ORAM_PEER_RECOVERY_PROTOCOL_VERSION,
                // The authenticated channel replaces this placeholder immediately before send.
                challenge_nonce: BASE64URL_NOPAD.encode(&[0; 16]),
                collection_name: collection_name.to_string(),
                collection_id: mutation.collection_id.clone(),
                mutation_id: mutation.mutation_id.clone(),
                parent_descriptor_digest: snapshot.descriptor.descriptor_digest.clone(),
                decision_record_digest: decision.evidence.authority_record_digest().to_string(),
                coordinator_peer_id,
                owner_peer_id,
                vector_name: vector_name.clone(),
                owner_signing_key_id: manifest.owner_signing_key_id.clone(),
            };
            validate_private_oram_peer_recovery_request_v2_shape(&request)
                .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
            Ok(request)
        })
        .collect()
}

fn validate_remotes_terminal_token_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV2,
    remotes: &PrivateOramValidatedRemotesTerminalV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if state.phase.sequence() < PrivateOramMutationJournalPhaseV2::RemotesTerminal.sequence()
        || descriptor.descriptor_digest != remotes.expected_descriptor_digest
        || state.decision.as_ref() != Some(&remotes.evidence)
        || record_digest_at_phase_v2(
            descriptor,
            state,
            PrivateOramMutationJournalPhaseV2::RemotesTerminal,
        )? != remotes.remotes_terminal_record_digest
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn validated_local_terminal_from_v2_snapshot(
    snapshot: &PrivateOramMutationJournalStructuralSnapshotV2,
) -> Result<PrivateOramValidatedLocalTerminalV2, PrivateOramMutationJournalError> {
    let state = snapshot.effective_state();
    if state.phase.sequence() < PrivateOramMutationJournalPhaseV2::LocalTerminal.sequence() {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(PrivateOramValidatedLocalTerminalV2 {
        evidence: state
            .decision
            .clone()
            .ok_or(PrivateOramMutationJournalError::Corrupt)?,
        expected_descriptor_digest: snapshot.descriptor.descriptor_digest.clone(),
        local_terminal_record_digest: record_digest_at_phase_v2(
            &snapshot.descriptor,
            state,
            PrivateOramMutationJournalPhaseV2::LocalTerminal,
        )?,
    })
}

fn validate_local_terminal_token_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV2,
    local: &PrivateOramValidatedLocalTerminalV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if state.phase.sequence() < PrivateOramMutationJournalPhaseV2::LocalTerminal.sequence()
        || descriptor.descriptor_digest != local.expected_descriptor_digest
        || state.decision.as_ref() != Some(&local.evidence)
        || record_digest_at_phase_v2(
            descriptor,
            state,
            PrivateOramMutationJournalPhaseV2::LocalTerminal,
        )? != local.local_terminal_record_digest
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn validated_point_stage_parent_for_terminal_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV2,
) -> Result<PrivateOramValidatedPointStageParentV1, PrivateOramMutationJournalError> {
    if state.phase.sequence() < PrivateOramMutationJournalPhaseV2::LocalTerminal.sequence() {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let PrivateOramMutationPointStageEvidenceV2::PrivateOramPointStaging {
        child_descriptor_digest,
        parent_owners_prepared_record_digest,
        ..
    } = state
        .point_stage
        .as_ref()
        .ok_or(PrivateOramMutationJournalError::Corrupt)?
    else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    Ok(PrivateOramValidatedPointStageParentV1 {
        descriptor: descriptor.clone(),
        owners_prepared_record_digest: parent_owners_prepared_record_digest.clone(),
        phase: PrivateOramValidatedPointStageParentPhaseV1::PointStageDurable,
        expected_child_descriptor_digest: Some(child_descriptor_digest.clone()),
    })
}

fn validate_point_resolution_candidate_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV2,
    evidence: &RawPrivateOramMutationPointResolutionEvidenceV2,
) -> Result<(), PrivateOramMutationJournalError> {
    match state.phase {
        PrivateOramMutationJournalPhaseV2::LocalTerminal => {
            next_private_oram_mutation_state_v2(
                descriptor,
                state,
                PrivateOramMutationJournalPhaseV2::PointResolved,
                |next| {
                    next.point_resolution = Some(evidence.clone());
                    Ok(())
                },
            )?;
            Ok(())
        }
        PrivateOramMutationJournalPhaseV2::PointResolved
            if state.point_resolution.as_ref() == Some(evidence) =>
        {
            Ok(())
        }
        _ => Err(PrivateOramMutationJournalError::InvalidTransition),
    }
}

struct PrivateOramLoadedStateHistoryV2 {
    states: Vec<PrivateOramMutationJournalStateV2>,
    files: Vec<PrivateOramPinnedFileV2>,
    entry_names: Vec<std::ffi::OsString>,
}

impl PrivateOramLoadedStateHistoryV2 {
    fn validate(
        &self,
        records: &PrivateOramPinnedDirectoryV2,
    ) -> Result<(), PrivateOramMutationJournalError> {
        if private_oram_state_record_names_v2(records)? != self.entry_names {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        for file in &self.files {
            file.validate_binding_and_contents(&records.file)?;
        }
        Ok(())
    }
}

fn private_oram_state_record_names_v2(
    records: &PrivateOramPinnedDirectoryV2,
) -> Result<Vec<std::ffi::OsString>, PrivateOramMutationJournalError> {
    let records_path = records.pinned_path()?;
    let mut entry_names = fs::read_dir(&records_path)
        .map_err(PrivateOramMutationJournalError::Io)?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .map_err(PrivateOramMutationJournalError::Io)
        })
        .take(MAX_V2_STATE_RECORDS + 1)
        .collect::<Result<Vec<_>, _>>()?;
    if entry_names.is_empty() || entry_names.len() > MAX_V2_STATE_RECORDS {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    entry_names.sort_unstable();
    Ok(entry_names)
}

fn load_state_history_v2(
    records: &PrivateOramPinnedDirectoryV2,
    descriptor: &PrivateOramMutationJournalDescriptorV1,
) -> Result<PrivateOramLoadedStateHistoryV2, PrivateOramMutationJournalError> {
    let entry_names = private_oram_state_record_names_v2(records)?;
    let mut states = Vec::with_capacity(entry_names.len());
    let mut files = Vec::with_capacity(entry_names.len());
    let mut history_bytes = 0_u64;
    for (index, entry_name) in entry_names.iter().enumerate() {
        let sequence =
            u64::try_from(index + 1).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
        let expected_file_name = state_record_file_name(sequence)?;
        if entry_name.to_str() != Some(expected_file_name.as_str()) {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        let file = PrivateOramPinnedFileV2::open_at(&records.file, entry_name, MAX_STATE_BYTES)?;
        history_bytes = history_bytes
            .checked_add(
                u64::try_from(file.bytes().len())
                    .map_err(|_| PrivateOramMutationJournalError::Corrupt)?,
            )
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        if history_bytes > MAX_V2_HISTORY_BYTES {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        let state: PrivateOramMutationJournalStateV2 = file.deserialize()?;
        if state.sequence != sequence {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        validate_private_oram_mutation_state_v2_structure(descriptor, &state)
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
        states.push(state);
        files.push(file);
    }
    let final_state = states
        .last()
        .ok_or(PrivateOramMutationJournalError::Corrupt)?;
    if canonical_private_oram_mutation_state_history_v2(descriptor, final_state)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
        != states
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(PrivateOramLoadedStateHistoryV2 {
        states,
        files,
        entry_names,
    })
}

fn publish_immutable_state_record_v2(
    namespace: &PrivateOramPinnedActiveNamespaceV2<'_>,
    state: &PrivateOramMutationJournalStateV2,
) -> Result<(), PrivateOramMutationJournalError> {
    let records = namespace.records()?;
    let destination_name = state_record_file_name(state.sequence)?;
    if let Some(existing_file) = optional_private_oram_file_at_v2(
        &records.file,
        std::ffi::OsStr::new(&destination_name),
        MAX_STATE_BYTES,
    )? {
        let existing: PrivateOramMutationJournalStateV2 = existing_file.deserialize()?;
        if existing != *state {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        existing_file.validate_binding_and_contents(&records.file)?;
        records.sync()?;
        return Ok(());
    }

    let candidate =
        PrivateOramJsonCandidateV2::new(&namespace.active_temp, state, MAX_STATE_BYTES)?;
    candidate.validate_source(&namespace.active_temp)?;
    if let Err(error) = rename_private_oram_entry_at_v2(
        &namespace.active_temp.file,
        candidate.name(),
        &records.file,
        std::ffi::OsStr::new(&destination_name),
        true,
    ) {
        let installed = optional_private_oram_file_at_v2(
            &records.file,
            std::ffi::OsStr::new(&destination_name),
            MAX_STATE_BYTES,
        )?;
        if let Some(installed) = installed {
            let existing: PrivateOramMutationJournalStateV2 = installed.deserialize()?;
            if existing != *state {
                return Err(PrivateOramMutationJournalError::Corrupt);
            }
            installed.validate_binding_and_contents(&records.file)?;
            sync_private_oram_publish_directories_v2(records, &namespace.active_temp)?;
            return Ok(());
        }
        return Err(error);
    }
    let installed = candidate
        .validate_installed(
            records,
            std::ffi::OsStr::new(&destination_name),
            MAX_STATE_BYTES,
        )
        .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
    let installed_state: PrivateOramMutationJournalStateV2 = installed
        .deserialize()
        .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
    if installed_state != *state {
        return Err(PrivateOramMutationJournalError::Indeterminate);
    }
    sync_private_oram_publish_directories_v2(records, &namespace.active_temp)?;
    installed
        .validate_binding_and_contents(&records.file)
        .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
    candidate.keep_after_publish()
}

fn publish_immutable_private_oram_json_v2<T>(
    namespace: &PrivateOramPinnedActiveNamespaceV2<'_>,
    destination: &PrivateOramPinnedDirectoryV2,
    destination_name: &std::ffi::OsStr,
    value: &T,
    max_bytes: u64,
) -> Result<PrivateOramPinnedFileV2, PrivateOramMutationJournalError>
where
    T: Serialize + DeserializeOwned + PartialEq,
{
    if let Some(existing_file) =
        optional_private_oram_file_at_v2(&destination.file, destination_name, max_bytes)?
    {
        let existing: T = existing_file.deserialize()?;
        if existing != *value {
            return Err(PrivateOramMutationJournalError::ConcurrentMutation);
        }
        existing_file.validate_binding_and_contents(&destination.file)?;
        sync_private_oram_publish_directories_v2(destination, &namespace.active_temp)?;
        return Ok(existing_file);
    }

    let candidate = PrivateOramJsonCandidateV2::new(&namespace.active_temp, value, max_bytes)?;
    candidate.validate_source(&namespace.active_temp)?;
    if let Err(error) = rename_private_oram_entry_at_v2(
        &namespace.active_temp.file,
        candidate.name(),
        &destination.file,
        destination_name,
        true,
    ) {
        let installed =
            optional_private_oram_file_at_v2(&destination.file, destination_name, max_bytes)?;
        if let Some(installed) = installed {
            let existing: T = installed.deserialize()?;
            if existing != *value {
                return Err(PrivateOramMutationJournalError::ConcurrentMutation);
            }
            installed.validate_binding_and_contents(&destination.file)?;
            sync_private_oram_publish_directories_v2(destination, &namespace.active_temp)?;
            return Ok(installed);
        }
        return Err(error);
    }

    let installed = candidate
        .validate_installed(destination, destination_name, max_bytes)
        .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
    let installed_value: T = installed
        .deserialize()
        .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
    if installed_value != *value {
        return Err(PrivateOramMutationJournalError::Indeterminate);
    }
    fail_immutable_json_after_rename_v2()?;
    sync_private_oram_publish_directories_v2(destination, &namespace.active_temp)?;
    installed
        .validate_binding_and_contents(&destination.file)
        .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
    candidate.keep_after_publish()?;
    Ok(installed)
}

fn publish_state_pointer_v2(
    namespace: &PrivateOramPinnedActiveNamespaceV2<'_>,
    state: &PrivateOramMutationJournalStateV2,
) -> Result<(), PrivateOramMutationJournalError> {
    let previous = required_v2_artifact(PrivateOramPinnedFileV2::open_at(
        &namespace.active.file,
        std::ffi::OsStr::new(STATE_FILE),
        MAX_STATE_BYTES,
    ))?;
    let candidate =
        PrivateOramJsonCandidateV2::new(&namespace.active_temp, state, MAX_STATE_BYTES)?;
    previous.validate_binding_and_contents(&namespace.active.file)?;
    candidate.validate_source(&namespace.active_temp)?;
    if let Err(error) = rename_private_oram_entry_at_v2(
        &namespace.active_temp.file,
        candidate.name(),
        &namespace.active.file,
        std::ffi::OsStr::new(STATE_FILE),
        false,
    ) {
        let current = required_v2_artifact(PrivateOramPinnedFileV2::open_at(
            &namespace.active.file,
            std::ffi::OsStr::new(STATE_FILE),
            MAX_STATE_BYTES,
        ))?;
        if current.bytes() == candidate.pinned.bytes() {
            current.validate_binding_and_contents(&namespace.active.file)?;
            sync_private_oram_publish_directories_v2(&namespace.active, &namespace.active_temp)?;
            return if ensure_same_file(
                &candidate
                    .pinned
                    .file
                    .metadata()
                    .map_err(PrivateOramMutationJournalError::Io)?,
                &current
                    .file
                    .metadata()
                    .map_err(PrivateOramMutationJournalError::Io)?,
            )
            .is_ok()
            {
                candidate.keep_after_publish()
            } else {
                Ok(())
            };
        }
        if current.bytes() == previous.bytes()
            && previous
                .validate_binding_and_contents(&namespace.active.file)
                .is_ok()
        {
            return Err(error);
        }
        return Err(PrivateOramMutationJournalError::Indeterminate);
    }
    let installed = candidate
        .validate_installed(
            &namespace.active,
            std::ffi::OsStr::new(STATE_FILE),
            MAX_STATE_BYTES,
        )
        .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
    let installed_state: PrivateOramMutationJournalStateV2 = installed
        .deserialize()
        .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
    if installed_state != *state {
        return Err(PrivateOramMutationJournalError::Indeterminate);
    }
    sync_private_oram_publish_directories_v2(&namespace.active, &namespace.active_temp)?;
    installed
        .validate_binding_and_contents(&namespace.active.file)
        .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
    candidate.keep_after_publish()
}

fn sync_private_oram_publish_directories_v2(
    destination: &PrivateOramPinnedDirectoryV2,
    source: &PrivateOramPinnedDirectoryV2,
) -> Result<(), PrivateOramMutationJournalError> {
    for _ in 0..PARENT_SYNC_ATTEMPTS {
        if destination.sync().is_ok() && source.sync().is_ok() {
            return Ok(());
        }
    }
    Err(PrivateOramMutationJournalError::Indeterminate)
}

fn sync_private_oram_root_publish_v2(
    root: &std::fs::File,
    root_temp: &PrivateOramPinnedDirectoryV2,
) -> Result<(), PrivateOramMutationJournalError> {
    for _ in 0..PARENT_SYNC_ATTEMPTS {
        if root.sync_all().is_ok() && root_temp.sync().is_ok() {
            return Ok(());
        }
    }
    Err(PrivateOramMutationJournalError::Indeterminate)
}

fn state_record_file_name(sequence: u64) -> Result<String, PrivateOramMutationJournalError> {
    if !(1..=MAX_V2_STATE_RECORDS as u64).contains(&sequence) {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(format!("{sequence:020}{STATE_RECORD_FILE_SUFFIX}"))
}

#[cfg(all(test, target_os = "linux"))]
mod fd_relative_tests {
    use super::*;

    #[test]
    fn v2_fd_relative_namespace_rejects_rebinding_symlinks_and_traversal() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("root");
        create_private_directory(&root_path).unwrap();
        let active_path = root_path.join(ACTIVE_DIR);
        create_private_directory(&active_path).unwrap();
        let root = std::fs::File::open(&root_path).unwrap();
        let pinned =
            PrivateOramPinnedDirectoryV2::open_at(&root, std::ffi::OsStr::new(ACTIVE_DIR)).unwrap();

        let detached_path = root_path.join("detached");
        fs::rename(&active_path, &detached_path).unwrap();
        create_private_directory(&active_path).unwrap();
        let detached_metadata = fs::symlink_metadata(&detached_path).unwrap();
        let pinned_metadata = pinned.file.metadata().unwrap();
        ensure_same_directory(&detached_metadata, &pinned_metadata).unwrap();
        assert!(matches!(
            pinned.validate_binding(&root, std::ffi::OsStr::new(ACTIVE_DIR)),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));

        let symlink_name = std::ffi::OsStr::new("active-link");
        std::os::unix::fs::symlink(&active_path, root_path.join(symlink_name)).unwrap();
        assert!(matches!(
            PrivateOramPinnedDirectoryV2::open_at(&root, symlink_name),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
        assert!(matches!(
            checked_private_oram_entry_name_v2(std::ffi::OsStr::new("../active")),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }
}
