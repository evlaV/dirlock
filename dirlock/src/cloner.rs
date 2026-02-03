/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{Result, anyhow, bail};
use nix::sys::signal;
use nix::unistd::Pid;
use std::{
    ffi::OsStr,
    fs::File,
    io::BufRead,
    io::BufReader,
    os::fd::AsRawFd,
    path::Path,
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

use crate::util;

/// A background process that clones a directory with all its contents
pub struct DirectoryCloner {
    child_pid: Pid,
    state: Arc<ClonerState>,
}

struct ClonerState {
    progress: AtomicI32,
    finished: AtomicBool,
    exit_status: Mutex<Option<std::io::Result<ExitStatus>>>,
    condvar: Condvar,
}

impl DirectoryCloner {
    /// Create a new [`DirectoryCloner`] to copy of `src` as `dst`.
    /// If `dst` exists, its contents will be replaced. Use with caution.
    /// This returns immediately, the copy happens in the background.
    pub fn start(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> Result<Self> {
        // Canonicalize src and check if it's the root directory
        let src = src.as_ref().canonicalize()?;
        if src.parent().is_none() {
            bail!("The source path cannot be the root directory");
        }
        // Create the destination directory and canonicalize it
        util::create_dir_if_needed(dst.as_ref())?;
        let dst_fd = std::fs::File::open(&dst)?;
        let mut dst = dst.as_ref().canonicalize()?.into_os_string();
        dst.push(std::path::MAIN_SEPARATOR_STR);

        // What we do here in practice is ( cd $src ; rsync -aAXH ./ $dst/ )
        let mut child = Command::new("rsync")
            // This preserves ACLs (A), extended attributes (X) and hard links (H)
            .args(["-aAXH", "--info=progress2", "--no-inc-recursive", "--delete"])
            .args([OsStr::new("./"), &dst])
            .current_dir(&src)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| anyhow!("Failed to run rsync: {e}"))?;

        let Some(stdout) = child.stdout.take() else {
            _ = child.kill();
            bail!("Failed to run rsync");
        };

        let child_pid = Pid::from_raw(child.id() as i32);

        // Parse the rsync output to get the progress status
        let progress = AtomicI32::new(0);
        let finished = AtomicBool::new(false);
        let exit_status = Mutex::new(None);
        let condvar = Condvar::new();
        let state = Arc::new(ClonerState { progress, finished, exit_status, condvar });
        let state2 = state.clone();
        std::thread::spawn(move || {
            Self::parse_rsync_ouput(child, stdout, state2, dst_fd)
        });

        Ok(Self { child_pid, state })
    }

    /// Parse the output of the rsync command and wait until it's done.
    /// This runs on its own separate thread.
    fn parse_rsync_ouput(mut child: Child, stdout: ChildStdout,
                         state: Arc<ClonerState>, syncfd: File) {
        const REGEX : &str = r" *[0-9,]+ *([0-9]{1,3})% .* to-chk=([0-9]+)/";
        let re = regex::bytes::Regex::new(REGEX).unwrap();
        let mut reader = BufReader::new(stdout);
        let mut line = Vec::new();
        let mut to_chk = i32::MAX;
        state.progress.store(0, Relaxed);
        let read_status = loop {
            line.clear();
            // rsync with --info=progress2 separates lines with '\r'
            match reader.read_until(b'\r', &mut line) {
                Err(e) => break Err(e), // Error reading from child process
                Ok(0) => { // EOF
                    // Sync the filesystem before finishing
                    _ = nix::unistd::syncfs(syncfd.as_raw_fd());
                    if to_chk == 0 {
                        // set progress to 100 if rsync doesn't do it
                        state.progress.store(100, Relaxed);
                    }
                    break Ok(());
                },
                Ok(_) => (),
            }

            // Parse each line to get the progress percentage and the
            // number of files left (&[u8] -> &str -> i32)
            if let Some(capture) = re.captures(&line) {
                let cur_progress = state.progress.load(Relaxed);
                let new_progress = std::str::from_utf8(&capture[1]).ok()
                    .and_then(|s| str::parse(s).ok())
                    .unwrap_or(cur_progress);
                if new_progress > cur_progress {
                    state.progress.store(new_progress, Relaxed);
                }

                let new_to_chk = std::str::from_utf8(&capture[2]).ok()
                    .and_then(|s| str::parse(s).ok())
                    .unwrap_or(to_chk);
                to_chk = std::cmp::min(to_chk, new_to_chk);
            }
        };

        let child_status = child.wait();
        let mut exit_status = state.exit_status.lock().unwrap();
        *exit_status = match (child_status, read_status) {
            (Err(e), _     ) => Some(Err(e)),
            (_     , Err(e)) => Some(Err(e)),
            (Ok(s),  Ok(())) => Some(Ok(s)),
        };
        state.finished.store(true, Relaxed);
        state.condvar.notify_all();
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
        if ! self.is_finished() {
            signal::kill(self.child_pid, Some(signal::SIGTERM))?;
        }
        Ok(())
    }

    /// Wait until the copy is finished
    pub fn wait(&self) -> Result<()> {
        let mut exit_status = self.state.exit_status.lock().unwrap();
        while exit_status.is_none() {
            exit_status = self.state.condvar.wait(exit_status).unwrap();
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
