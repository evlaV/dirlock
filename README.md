# dirlock

`dirlock` is a tool for managing encrypted directories using the Linux
kernel's fscrypt API.

The following basic commands are provided:

- `encrypt`: enables encryption on a directory. After this, everything
  written to that directory will be encrypted.
- `unlock`: unlocks an encrypted directory, allowing access to its
  contents.
- `lock`: locks an encrypted directory.
- `change-pass`: changes the password used to unlock a directory.
- `status`: displays information about a directory.

If a user's home directory is locked using this tool it can be
automatically unlocked at login time. A PAM module (`pam_dirlock.so`)
is provided for that purpose.

**IMPORTANT**: This tool is currently under development. Its commands
and the on-disk format of its data files are subject to change. For
convenience, two additional commands (`export-master-key` and
`import-master-key`) are provided in the meantime to backup and
restore the raw encryption keys.

### Author

Alberto Garcia - berto@igalia.com

### License

`dirlock` is published under the 3-Clause BSD license.
