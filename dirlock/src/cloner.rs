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
    process::Stdio,
    sync::Arc,
    sync::atomic::AtomicI32,
    sync::atomic::Ordering::Relaxed,
    thread::JoinHandle,
};

/// A background process that clones a directory with all its contents
pub struct DirectoryCloner {
    child: Child,
    progress: Arc<AtomicI32>,
    thread: Option<JoinHandle<()>>,
}

impl DirectoryCloner {
    /// Create a new [`DirectoryCloner`] to copy of `src` as `dst`.
    /// This returns immediately, the copy happens in the background.
    pub fn start(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> Result<Self> {
        // Canonicalize src and check if it's the root directory
        let src = src.as_ref().canonicalize()?;
        if src.parent().is_none() {
            bail!("The source path cannot be the root directory");
        }
        // Create the destination directory and canonicalize it
        std::fs::create_dir(&dst)?;
        let dst_fd = std::fs::File::open(&dst)?;
        let mut dst = dst.as_ref().canonicalize()?.into_os_string();
        dst.push(std::path::MAIN_SEPARATOR_STR);

        // What we do here in practice is ( cd $src ; rsync -aAXH ./ $dst/ )
        let mut child = Command::new("rsync")
            // This preserves ACLs (A), extended attributes (X) and hard links (H)
            .args(["-aAXH", "--info=progress2", "--no-inc-recursive"])
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

        // Parse the rsync output to get the progress status
        let progress = Arc::new(AtomicI32::new(0));
        let progress2 = progress.clone();
        let thread = Some(std::thread::spawn(move || {
            Self::parse_rsync_ouput(stdout, progress2, dst_fd)
        }));

        Ok(Self { child, progress, thread })
    }

    fn parse_rsync_ouput(stdout: ChildStdout, progress: Arc<AtomicI32>,
                         syncfd: File) {
        const REGEX : &str = r" *[0-9,]+ *([0-9]{1,3})% .* to-chk=([0-9]+)/";
        let re = regex::bytes::Regex::new(REGEX).unwrap();
        let mut reader = BufReader::new(stdout);
        let mut line = Vec::new();
        let mut to_chk = i32::MAX;
        progress.store(0, Relaxed);
        loop {
            line.clear();
            // rsync with --info=progress2 separates lines with '\r'
            match reader.read_until(b'\r', &mut line) {
                Err(_) => break, // Error reading from child process
                Ok(0) => { // EOF
                    // Sync the filesystem before finishing
                    _ = nix::unistd::syncfs(syncfd.as_raw_fd());
                    if to_chk == 0 {
                        // set progress to 100 if rsync doesn't do it
                        progress.store(100, Relaxed);
                    }
                    break;
                },
                Ok(_) => (),
            }

            // Parse each line to get the progress percentage and the
            // number of files left (&[u8] -> &str -> i32)
            if let Some(capture) = re.captures(&line) {
                let cur_progress = progress.load(Relaxed);
                let new_progress = std::str::from_utf8(&capture[1]).ok()
                    .and_then(|s| str::parse(s).ok())
                    .unwrap_or(cur_progress);
                if new_progress > cur_progress {
                    progress.store(new_progress, Relaxed);
                }

                let new_to_chk = std::str::from_utf8(&capture[2]).ok()
                    .and_then(|s| str::parse(s).ok())
                    .unwrap_or(to_chk);
                to_chk = std::cmp::min(to_chk, new_to_chk);
            }
        }
    }

    /// Return the current progress percentage
    pub fn progress(&self) -> i32 {
        self.progress.load(Relaxed)
    }

    /// Check is the copy is finished
    pub fn is_finished(&self) -> bool {
        match &self.thread {
            Some(t) => t.is_finished(),
            None => true,
        }
    }

    /// Stop the copy operation, killing the child rsync process
    pub fn stop(&mut self) -> Result<()> {
        // Kill the child if it's still running
        if self.child.try_wait().transpose().is_none() {
            let child_pid = Pid::from_raw(self.child.id() as i32);
            signal::kill(child_pid, Some(signal::SIGTERM))?;
        }
        // Wait for the thread
        if let Some(t) = self.thread.take() {
            _ = t.join();
        }
        Ok(())
    }

    /// Wait until the copy is finished
    pub fn wait(mut self) -> Result<()> {
        if let Some(t) = self.thread.take() {
            if t.join().is_err() {
                eprintln!("Thread panicked");
            }
        }
        // Normallly the child process should have finished before the thread.
        // If it's still alive, something went wrong, so kill it.
        self.stop()?;
        match self.child.wait()?.code() {
            Some(0) => (),
            Some(n) => bail!("rsync exited with code {n}"),
            None => bail!("rsync killed by signal"),
        }
        Ok(())
    }
}

impl Drop for DirectoryCloner {
    /// Make sure that the child process is killed on drop
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
