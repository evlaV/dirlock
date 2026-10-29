This repository contains helper tools to use dirlock on SteamOS, in
particular to handle the conversion of an unencrypted home directory
into an encrypted one.

These are very simple and basic tools, and are only meant for end
users to simplify the initial steps while dirlock is still under
development.

These are the contents:

- `dirlock-convert-home`: a simple wizard to manage the conversion of
  the user's home directory into an encrypted directory. It can also
  be used to manage recovery keys. There are two scripts:
  `dirlock-convert-home-gui` is the GUI, and `dirlock-convert-home`
  implements the functionality using the Dirlock D-Bus API. These are
  privileged operations and are protected by the policy in the
  `com.valvesoftware.dirlock.policy` file.

- `dirlock-session-progress`: a small daemon that shows the progress
  of a conversion inside a Plasma session using the KDE JobView API.
  This is started by `dirlock-convert-home-gui` but keeps running
  after that GUI is closed.

- `sddm-theme`: this is just a wrapper around the Breeze theme that
  shows a progress indicator on the login screen to track the status
  of a conversion while the user is logged out. This is necessary
  because the conversion cannot be completed while the user's session
  is still active. This theme is only used temporarily while a
  conversion is ongoing, otherwise SDDM uses Breeze as usual.

- `dirlock-sddm-tracker`: a daemon that is started automatically when
  a conversion job is detected, tracks it and provides progress
  information to `dirlock-session-progress` and the SDDM theme.

- `old-setup-scripts`: old helper scripts to enable dirlock and
  encrypt the user's home directory. They are meant to be run as root
  from an SSH session. Superseded by `dirlock-convert-home`, although
  the functionality to _decrypt_ a home directory is not implemented
  elsewhere yet.

- `tpm2-dict-setup.c`: a small tool to configure the TPM dictionary
  attack mechanism, used by `dirlock-convert-home`.
