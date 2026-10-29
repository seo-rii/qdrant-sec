use std::io;
use std::path::Path;

use fs_err::{File, OpenOptions};

/// Commits filesystem caches for the given directory.
///
/// On Linux, it commits the entire filesystem containing the directory.
pub fn bulk_sync_dir(dir: &Path) -> io::Result<()> {
    // Matches all platforms that have `nix::unistd::syncfs` function.
    // https://github.com/nix-rust/nix/blob/v0.30.1/src/unistd.rs#L1679
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "hurd"))]
    // If the directory contains a lot of small files, calling `syncfs` once
    // could be faster than calling `fsync` on each file individually.
    // See https://man7.org/linux/man-pages/man2/syncfs.2.html
    match nix::unistd::syncfs(File::open(dir)?) {
        Ok(()) => return Ok(()),
        // Don't return an error as it could be caused by issues outside our
        // control. Just log a warning.
        Err(e) => log::warn!("syncfs failed for {}: {e}", dir.display()),
    }

    // Fallback
    sync_dir_with_fsync(dir)
}

/// Calls `fsync` recursively.
fn sync_dir_with_fsync(dir: &Path) -> io::Result<()> {
    for entry in fs_err::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_dir_with_fsync(&entry.path())?;
        } else {
            // Windows FlushFileBuffers requires a handle opened for writing.
            OpenOptions::new()
                .read(true)
                .write(cfg!(windows))
                .open(entry.path())?
                .sync_all()?;
        }
    }
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recursive_file_sync_preserves_nested_file_contents() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("nested");
        fs_err::create_dir(&nested).unwrap();
        let files = [
            (root.path().join("root.bin"), b"root data".as_slice()),
            (nested.join("child.bin"), b"nested data".as_slice()),
        ];
        for (path, bytes) in &files {
            fs_err::write(path, bytes).unwrap();
        }

        // Exercise the fallback even on platforms where bulk_sync_dir uses syncfs.
        sync_dir_with_fsync(root.path()).unwrap();

        for (path, bytes) in files {
            assert_eq!(fs_err::read(path).unwrap(), bytes);
        }
    }
}
