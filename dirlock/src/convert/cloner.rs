/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{Result, anyhow, bail};
use nix::sys::signal;
use nix::unistd::Pid;
use std::{
    ffi::{CStr, OsStr},
    fs::File,
    io::BufRead,
    io::BufReader,
    os::fd::AsRawFd,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::Child,
    process::ChildStdout,
    process::Command,
    process::ExitStatus,
    process::Stdio,
    sync::Arc,
    sync::Condvar,
    sync::Mutex,
    sync::atomic::AtomicBool,
    sync::atomic::AtomicI32,
    sync::atomic::Ordering::Relaxed,
};

use crate::config::Config;
use crate::util;

/// A background process that clones a directory with all its contents
pub struct DirectoryCloner {
    state: Arc<ClonerState>,
}

struct ClonerState {
    child_pid: Mutex<Option<Pid>>,
    progress: AtomicI32,
    finished: AtomicBool,
    cancelled: AtomicBool,
    exit_status: Mutex<Option<Result<ExitStatus>>>,
    condvar: Condvar,
}

impl DirectoryCloner {
    /// Create a new [`DirectoryCloner`] to copy of `src` as `dst`.
    /// If `dst` exists, its contents will be replaced. Use with caution.
    /// This returns immediately, the copy happens in the background.
    /// The source directory is checked for encrypted subdirectories
    /// and cross-filesystem mounts before starting the copy.
    ///
    /// If `verify_content` is `true`, files are compared by content
    /// rather than by mtime+size. Use when `dst` is already a partial
    /// clone of `src` but the original contents might have changed.
    pub fn start(src: impl AsRef<Path>, dst: impl AsRef<Path>,
                 verify_content: bool) -> Result<Self> {
        // Canonicalize src and check if it's the root directory
        let src = src.as_ref().canonicalize()?;
        if src.parent().is_none() {
            bail!("The source path cannot be the root directory");
        }

        // Create the destination directory and canonicalize it
        util::create_dir_if_needed(dst.as_ref())?;
        let dst = dst.as_ref().canonicalize()?;
        let dst_fd = std::fs::File::open(&dst)?;

        let state = Arc::new(ClonerState {
            child_pid : Mutex::new(None),
            progress : AtomicI32::new(0),
            finished : AtomicBool::new(false),
            cancelled : AtomicBool::new(false),
            exit_status : Mutex::new(None),
            condvar : Condvar::new(),
        });

        // Spawn the thread that does the actual work.
        let state2 = state.clone();
        std::thread::spawn(move || {
            // An error here means that rsync didn't even start,
            // so save it and set state.finished = true.
            let status = Self::run(&state2, src, dst, dst_fd, verify_content);
            *state2.exit_status.lock().unwrap() = Some(status);
            state2.finished.store(true, Relaxed);
            state2.condvar.notify_all();
        });

        Ok(Self { state })
    }

    /// Validate the directories, then launch rsync and monitor it.
    /// Called from the background thread.
    fn run(state: &ClonerState, src: PathBuf, dst: PathBuf, dst_fd: File,
           verify_content: bool) -> Result<ExitStatus> {
        // Validate the source directory and check free space on the destination
        let entries = Self::validate_dirs(state, &src, &dst)?;

        let mut dst = dst.into_os_string();
        dst.push(std::path::MAIN_SEPARATOR_STR);

        // What we do here in practice is ( cd $src ; rsync -aAXH ./ $dst/ )
        let mut child = Command::new("rsync")
            // This preserves ACLs (A), extended attributes (X) and hard links (H)
            // We also use -x to stop at filesystem boundaries
            .args(["-aAXHx", "--delete"])
            // We measure the progress by counting the entries that
            // rsync reports (-ii: include changed and unchanged files).
            // With %b rsync prints the line *after* transferring the file:
            // https://github.com/RsyncProject/rsync/blob/v3.4.4/rsync.1.md?plain=1#L3207
            .args(["-ii", "--out-format=%i%b"])
            .args(verify_content.then_some("--checksum"))
            .args([OsStr::new("./"), &dst])
            .current_dir(&src)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| anyhow!("Failed to run rsync: {e}"))?;

        let Some(stdout) = child.stdout.take() else {
            _ = child.kill();
            bail!("Failed to run rsync");
        };

        let pid = Pid::from_raw(child.id() as i32);
        *state.child_pid.lock().unwrap() = Some(pid);

        // If the operation was cancelled before child_pid was set,
        // make sure that rsync is killed.
        // parse_rsync_ouput() will take care of the error code.
        if state.cancelled.load(Relaxed) {
            _ = signal::kill(pid, Some(signal::SIGTERM));
        }

        Self::parse_rsync_ouput(child, stdout, state, dst_fd, entries)
    }

    /// Check that all subdirectories in `src` are on the same filesystem and
    /// not encrypted, and that `dst` has enough free space and inodes.
    /// Returns the number of entries in `src`.
    fn validate_dirs(state: &ClonerState, src: &Path, dst: &Path) -> Result<u64> {
        let free = util::free_space(dst)?;

        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(src.as_os_str().as_bytes());
        buf.push(0);
        let src_stx = util::Statx::from_path(CStr::from_bytes_with_nul(&buf)?)?;
        // It's not enough that `dst` can hold the contents of `src`, it
        // must also leave enough free space and inodes for the rest of
        // the system, so start counting from there.
        let mut total_bytes = Config::fs_min_free_bytes();
        let mut total_inodes = Config::fs_min_free_inodes();
        let mut entries: u64 = 0;
        for iter in walkdir::WalkDir::new(src).follow_links(false) {
            if state.cancelled.load(Relaxed) {
                bail!("operation cancelled");
            }
            let entry = iter?;
            let ft = entry.file_type();
            entries += 1;

            if ft.is_file() {
                total_bytes += entry.metadata()?.len();
                if total_bytes > free.bytes {
                    bail!("Not enough free space");
                }
            }
            if let Some(free_inodes) = free.inodes {
                total_inodes += 1;
                if total_inodes > free_inodes {
                    bail!("Not enough free inodes");
                }
            }

            if ! ft.is_dir() {
                continue;
            }
            buf.clear();
            buf.extend_from_slice(entry.path().as_os_str().as_bytes());
            buf.push(0);
            let stx = util::Statx::from_path(CStr::from_bytes_with_nul(&buf)?)?;
            if ! stx.same_dev(&src_stx) {
                bail!("{} has contents in different filesystems", src.display());
            }
            if stx.is_encrypted() {
                bail!("{} has encrypted content", src.display());
            }
        }
        Ok(entries)
    }

    /// Parse the output of the rsync command and wait until it's done.
    fn parse_rsync_ouput(mut child: Child, stdout: ChildStdout,
                         state: &ClonerState, syncfd: File,
                         total: u64) -> Result<ExitStatus> {
        let mut reader = BufReader::new(stdout);
        let mut line = Vec::new();
        let mut count: u64 = 0;
        state.progress.store(0, Relaxed);
        let read_status = loop {
            line.clear();
            // rsync prints one line per entry that it processes
            match reader.read_until(b'\n', &mut line) {
                Err(e) => break Err(e), // Error reading from child process
                Ok(0) => { // EOF
                    // Sync the filesystem before finishing
                    let result = nix::unistd::syncfs(syncfd.as_raw_fd())
                        .map_err(std::io::Error::from);
                    break result;
                },
                Ok(_) => (),
            }

            // '*' in the first column is for messages (e.g. "*deleting")
            if line.first() == Some(&b'*') {
                continue;
            }

            // 'total' is calculated before running rsync so it's not
            // necessarily accurate. Clamp the result to 99: 100 is
            // only set on a successful exit (see below).
            count += 1;
            if total > 0 {
                let progress = (100 * count / total).min(99);
                state.progress.store(progress as i32, Relaxed);
            }
        };

        let child_status = child.wait();
        match (child_status, read_status) {
            (Err(e), _     ) => Err(e.into()),
            (_     , Err(e)) => Err(e.into()),
            (Ok(s),  Ok(())) => {
                // If rsync succeeded then we are done.
                if s.success() {
                    state.progress.store(100, Relaxed);
                }
                Ok(s)
            }
        }
    }

    /// Return the current progress percentage
    pub fn progress(&self) -> i32 {
        self.state.progress.load(Relaxed)
    }

    /// Check is the copy is finished
    pub fn is_finished(&self) -> bool {
        self.state.finished.load(Relaxed)
    }

    /// Cancel the copy operation, killing the child rsync process
    pub fn cancel(&self) -> Result<()> {
        // If swap() returns true -> already cancelled, nothing to do
        if self.state.cancelled.swap(true, Relaxed) {
            return Ok(());
        }
        if ! self.is_finished() {
            if let Some(pid) = *self.state.child_pid.lock().unwrap() {
                match signal::kill(pid, Some(signal::SIGTERM)) {
                    Err(nix::errno::Errno::ESRCH) => (), // already exited
                    x => x?,
                }
            }
        }
        Ok(())
    }

    /// Wait until the copy is finished
    pub fn wait(&self) -> Result<()> {
        let mut exit_status = self.state.exit_status.lock().unwrap();
        while exit_status.is_none() {
            exit_status = self.state.condvar.wait(exit_status).unwrap();
        }
        if self.state.cancelled.load(Relaxed) {
            bail!("operation cancelled");
        }
        let status = exit_status.as_ref().unwrap();
        match status.as_ref().map(|e| e.code()) {
            Ok(Some(0)) => (),
            Ok(Some(n)) => bail!("rsync exited with code {n}"),
            Ok(None) => bail!("rsync killed by signal"),
            Err(e) => bail!("{e}"),
        }
        Ok(())
    }
}

impl Drop for DirectoryCloner {
    /// Make sure that the child process is killed on drop
    fn drop(&mut self) {
        let _ = self.cancel();
    }
}
