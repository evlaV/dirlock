# dirlock

`dirlock` is a tool for managing encrypted directories using the Linux
kernel's fscrypt API. Therefore it encrypts individual directories and
not complete filesystem or block devices. If a directory is encrypted
then all its contents (including subdirectories) are encrypted as
well.

### Basic concepts: protectors and policies

This tool is heavily inspired by Joe Richey's [fscrypt
utility](https://github.com/google/fscrypt) and uses the same basic
design of protectors and policies.

- A directory is encrypted using an **encryption policy**, which
  contains the _raw encryption key_ passed to the kernel among other
  parameters.
- Policies are stored safely on disk using a **protector**, which
  encrypts the policy key using one of several available mechanisms,
  currently a password or a TPM module.
- A policy can be be protected by any number of protectors, and a
  protector can be used in any number of policies.
- A protector can be modified at any time (for example by changing its
  password) without affecting the policies that it protects.

### How to use dirlock

The `dirlock` command-line tool provides the following basic subcommands:

- `encrypt`: enables encryption on a directory. After this, everything
  written to that directory will be encrypted.
- `unlock`: unlocks an encrypted directory, allowing access to its
  contents.
- `lock`: locks an encrypted directory.
- `change-password`: changes the password used to unlock a directory
  (that is, the protector's password).
- `status`: displays information about a directory or the whole system.

Since the kernel's fscrypt API requires that a directory is empty when
enabling encryption, the only way to encrypt a directory that contains
data is to copy that data to an empty encrypted directory and then
replace the original one. The `encrypt` subcommand can automate that
process for you but bear in mind that the old unencrypted data can
potentially be read by accesing the raw block device directly.

In addition to the basic subcommands listed above there are advanced
ones to create and manage protector and policies directly. Run
`dirlock policy help` and `dirlock protector help` for more
information.

**IMPORTANT**: This tool is currently under development. Its commands
and the on-disk format of its data files are subject to change. For
convenience, two additional commands (`export-master-key` and
`import-master-key`) are provided in the meantime to backup and
restore the raw encryption keys.

### Protecting a user's home directory and using PAM

If a user's home directory is locked using this tool it can
automatically be unlocked at login time. A PAM module
(`pam_dirlock.so`) is provided for that purpose.

This module will handle any home directory encrypted with `dirlock`
and will return `user_unknown` otherwise. Here is how typical PAM
entries would look like:

```
auth     [success=3 user_unknown=ignore default=die] pam_dirlock.so
password [success=3 user_unknown=ignore default=die] pam_dirlock.so
```

`pam_dirlock.so` uses the password of the protector(s) to authenticate
the user so any other password entry (in `/etc/shadow` or whatever) is
not used and can be disabled.

If the PAM module is configured correctly users can change their own
passwords with the traditional Unix `passwd` command.

### Author

Alberto Garcia - berto@igalia.com

### License

`dirlock` is published under the 3-Clause BSD license.
