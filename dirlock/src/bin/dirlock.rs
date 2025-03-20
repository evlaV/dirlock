/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{bail, ensure, Result};
use argh::FromArgs;
use std::io::{self, Write};
use std::path::PathBuf;
use dirlock::{
    DirStatus,
    fscrypt,
    protector::{
        ProtectorType,
    },
    util,
};
use zeroize::Zeroizing;

#[derive(FromArgs)]
/// Disk encryption tool.
struct Args {
    #[argh(subcommand)]
    command: Command,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Command {
    Status(StatusArgs),
    Encrypt(EncryptArgs),
    Lock(LockArgs),
    Unlock(UnlockArgs),
    ChangePass(ChangePassArgs),
    AddProtector(AddProtectorArgs),
    RemoveProtector(RemoveProtectorArgs),
    SystemInfo(SystemInfoArgs),
    ExportMasterKey(ExportMasterKeyArgs),
    ImportMasterKey(ImportMasterKeyArgs),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "lock")]
/// Lock an encrypted directory
struct LockArgs {
    /// lock the directory no matter who unlocked it
    #[argh(switch, long = "all-users")]
    all_users: bool,
    /// directory
    #[argh(positional)]
    dir: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "unlock")]
/// Unlock an encrypted directory
struct UnlockArgs {
    /// ID of the protector used to unlock this directory
    #[argh(option)]
    protector: Option<String>,
    /// directory
    #[argh(positional)]
    dir: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "change-password")]
/// Change the encryption password of a directory
struct ChangePassArgs {
    /// ID of the protector whose password is to be changed
    #[argh(option)]
    protector: Option<String>,
    /// directory
    #[argh(positional)]
    dir: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "add-protector")]
/// Adds a new protector to a directory
struct AddProtectorArgs {
    /// type of the protector to add (default: 'password')
    #[argh(option)]
    type_: Option<String>,
    /// directory
    #[argh(positional)]
    dir: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "remove-protector")]
/// Remove a protector from a directory
struct RemoveProtectorArgs {
    /// ID of the protector to remove
    #[argh(option)]
    protector: Option<String>,
    /// directory
    #[argh(positional)]
    dir: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "encrypt")]
/// Encrypt a directory
struct EncryptArgs {
    /// force encrypting a directory with data
    #[argh(switch, long = "force")]
    force: bool,
    /// directory
    #[argh(positional)]
    dir: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "system-info")]
/// Show information about the system
struct SystemInfoArgs {
}

#[derive(FromArgs)]
#[argh(subcommand, name = "export-master-key")]
/// Export the master encryption key of a directory
struct ExportMasterKeyArgs {
    /// directory
    #[argh(positional)]
    dir: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "import-master-key")]
/// Import a master encryption key
struct ImportMasterKeyArgs { }

#[derive(FromArgs)]
#[argh(subcommand, name = "status")]
/// Get the encryption status of a directory
struct StatusArgs {
    /// verbose output (list protectors and encryption parameters)
    #[argh(switch, short = 'v', long = "verbose")]
    verbose: bool,
    /// directory
    #[argh(positional)]
    dir: PathBuf,
}

fn cmd_lock(args: &LockArgs) -> Result<()> {
    let encrypted_dir = match dirlock::open_dir(&args.dir)? {
        DirStatus::Encrypted(d) if d.key_status == fscrypt::KeyStatus::Absent =>
            bail!("The directory {} is already locked", args.dir.display()),
        DirStatus::Encrypted(d) => d,
        x => bail!("{}", x),
    };

    let user = if args.all_users {
        fscrypt::RemoveKeyUsers::AllUsers
    } else {
        fscrypt::RemoveKeyUsers::CurrentUser
    };
    let flags = encrypted_dir.lock(user)?;

    if flags.contains(fscrypt::RemovalStatusFlags::FilesBusy) {
        println!("Key removed, but some files are still busy");
    };

    if flags.contains(fscrypt::RemovalStatusFlags::OtherUsers) {
        println!("Only this user's claim was removed");
    };

    Ok(())
}

fn cmd_unlock(args: &UnlockArgs) -> Result<()> {
    let encrypted_dir = match dirlock::open_dir(&args.dir)? {
        DirStatus::Encrypted(d) if d.key_status == fscrypt::KeyStatus::Present =>
            bail!("The directory {} is already unlocked", args.dir.display()),
        DirStatus::Encrypted(d) => d,
        x => bail!("{}", x),
    };

    let protector_id = match &args.protector {
        Some(id_str) => Some(encrypted_dir.get_protector_id_by_str(id_str)?),
        None => None
    };

    eprint!("Enter encryption password: ");
    let pass = Zeroizing::new(rpassword::read_password()?);

    if ! encrypted_dir.unlock(pass.as_bytes(), protector_id.as_ref())? {
        bail!("Unable to unlock directory {}: wrong password", args.dir.display())
    }

    Ok(())
}

fn cmd_change_pass(args: &ChangePassArgs) -> Result<()> {
    let mut encrypted_dir = match dirlock::open_dir(&args.dir)? {
        DirStatus::Encrypted(d) => d,
        x => bail!("{}", x),
    };

    let protector_id = match &args.protector {
        Some(id_str) => Some(encrypted_dir.get_protector_id_by_str(id_str)?),
        None => None
    };

    eprint!("Enter the current password: ");
    let pass = Zeroizing::new(rpassword::read_password()?);

    if ! encrypted_dir.check_pass(pass.as_bytes(), protector_id.as_ref()) {
        bail!("Password not valid for directory {}", args.dir.display())
    }

    eprint!("Enter the new password: ");
    let npass1 = Zeroizing::new(rpassword::read_password()?);
    eprint!("Repeat the new password: ");
    let npass2 = Zeroizing::new(rpassword::read_password()?);
    ensure!(npass1 == npass2, "Passwords don't match");

    if ! encrypted_dir.change_password(pass.as_bytes(), npass1.as_bytes(), protector_id.as_ref())? {
        bail!("Unable to change the password for directory {}", args.dir.display())
    }

    Ok(())
}

fn cmd_add_protector(args: &AddProtectorArgs) -> Result<()> {
    let encrypted_dir = match dirlock::open_dir(&args.dir)? {
        DirStatus::Encrypted(d) => d,
        x => bail!("{}", x),
    };

    let protector_type = if let Some(s) = &args.type_ {
        ProtectorType::try_from(s.as_str())?
    } else {
        ProtectorType::Password
    };

    eprint!("Enter the current password: ");
    let pass = Zeroizing::new(rpassword::read_password()?);

    if ! encrypted_dir.check_pass(pass.as_bytes(), None) {
        bail!("Password not valid for directory {}", args.dir.display())
    }

    eprint!("Enter password for the new protector: ");
    let npass1 = Zeroizing::new(rpassword::read_password()?);
    eprint!("Repeat the password: ");
    let npass2 = Zeroizing::new(rpassword::read_password()?);
    ensure!(npass1 == npass2, "Passwords don't match");

    if encrypted_dir.check_pass(npass1.as_bytes(), None) {
        bail!("There is already a protector with that password");
    }

    if let Some(protid) = encrypted_dir.add_protector(protector_type, pass.as_bytes(), npass1.as_bytes())? {
        println!("Added protector {protid} to directory {}", args.dir.display());
    } else {
        // FIXME: this should not happen because we checked earlier
        // that the password is correct.
        bail!("Unexpected error adding protector to directory {}", args.dir.display())
    }

    Ok(())
}

fn cmd_remove_protector(args: &RemoveProtectorArgs) -> Result<()> {
    let encrypted_dir = match dirlock::open_dir(&args.dir)? {
        DirStatus::Encrypted(d) => d,
        x => bail!("{}", x),
    };

    if encrypted_dir.protectors.len() == 1 {
        bail!("Only one protector left in that directory, refusing to remove it");
    }

    let protector_id = match &args.protector {
        Some(id_str) => encrypted_dir.get_protector_id_by_str(id_str)?,
        None => {
            eprint!("Enter the password of the protector that you want to remove: ");
            let pass = Zeroizing::new(rpassword::read_password()?);
            encrypted_dir.get_protector_id_by_pass(pass.as_bytes())?
        }
    };

    if encrypted_dir.remove_protector(&protector_id)? {
        println!("Removed protector {protector_id}");
    } else {
        bail!("Protector {protector_id} not found in directory {}", args.dir.display());
    }

    Ok(())
}

fn cmd_encrypt(args: &EncryptArgs) -> Result<()> {
    match dirlock::open_dir(&args.dir)? {
        DirStatus::Unencrypted => (),
        x => bail!("{}", x),
    };

    let empty_dir = util::dir_is_empty(&args.dir)?;

    if args.force && !empty_dir {
        println!("You are about to encrypt a directory that contains data.\n\
                  This feature is *experimental*. Make sure that you are not\n\
                  accessing the files while they are being encrypted in order\n\
                  to avoid unexpected behaviors. If this is a home directory\n\
                  the user should be ideally logged out.\n");
        print!("Do you want to continue? [y/N] ");
        io::stdout().flush().unwrap();
        let mut s = String::new();
        let _ = io::stdin().read_line(&mut s)?;
        if s.trim() != "y" {
            return Ok(());
        }
        dirlock::convert::check_can_convert_dir(&args.dir)?;
    } else if !empty_dir {
        bail!("The directory is not empty. Use --force to override");
    }

    eprint!("Enter encryption password: ");
    let pass1 = Zeroizing::new(rpassword::read_password()?);
    eprint!("Repeat encryption password: ");
    let pass2 = Zeroizing::new(rpassword::read_password()?);
    ensure!(pass1 == pass2, "Passwords don't match");

    let keyid = if args.force && !empty_dir {
        println!("\nEncrypting the contents of {}, this can take a while", args.dir.display());
        let k = dirlock::convert::convert_dir(&args.dir, pass1.as_bytes())?;
        println!("\nThe directory is now encrypted. If this was a home directory\n\
                  and you plan to log in using PAM you need to use the encryption\n\
                  password from now on. The old password in /etc/shadow is no longer\n\
                  used and you can disable it with usermod -p '*' USERNAME\n");
        k
    } else {
        dirlock::encrypt_dir(&args.dir, pass1.as_bytes())?
    };
    println!("Directory encrypted with key id {}", keyid);

    Ok(())
}

fn cmd_system_info(_args: &SystemInfoArgs) -> Result<()> {
    let tpm_status = dirlock::protector::tpm2::get_status()?;

    println!("TPM information\n\
              ---------------\n\
              {tpm_status}");

    Ok(())
}

fn cmd_export_master_key(args: &ExportMasterKeyArgs) -> Result<()> {
    use base64::prelude::*;
    let encrypted_dir = match dirlock::open_dir(&args.dir)? {
        DirStatus::Encrypted(d) => d,
        x => bail!("{x}"),
    };

    eprintln!("This will print to stdout the master key with ID {}", encrypted_dir.policy.keyid);
    eprintln!("- This is the encryption key for directory {}", args.dir.display());
    eprintln!("- This feature is only available while this tool is under development");
    eprintln!("- The printed key is *raw and unprotected*, you are reponsible for keeping it safe");
    eprintln!();
    eprint!("Enter the current encryption password: ");
    let pass = Zeroizing::new(rpassword::read_password()?);

    let Some(k) = encrypted_dir.get_master_key(pass.as_bytes(), None) else {
        bail!("Unable to unlock master key for directory {}", args.dir.display());
    };

    println!("{}", BASE64_STANDARD.encode(k.secret()));
    Ok(())
}

fn cmd_import_master_key() -> Result<()> {
    use base64::prelude::*;

    let mut key = String::new();
    eprintln!("This will import a previously exported master encryption key");
    eprintln!("- This feature is only available while this tool is under development");
    eprintln!("- You cannot import a key that has already been imported");
    eprintln!("- You will be asked to enter a password to protect the key");
    eprintln!("- After importing it you can use the key normally to unlock encrypted directories");
    eprintln!();
    eprint!("Enter master key: ");
    io::stdin().read_line(&mut key)?;

    let mut master_key = fscrypt::PolicyKey::default();
    match BASE64_STANDARD.decode_slice(key.trim(), master_key.secret_mut()) {
        Err(e) => bail!("Unable to decode key: {e}"),
        Ok(x) if x != 64 => bail!("Wrong key size"),
        Ok(_) => (),
    }

    eprint!("Enter password to protect this key: ");
    let pass1 = Zeroizing::new(rpassword::read_password()?);
    eprint!("Repeat the password: ");
    let pass2 = Zeroizing::new(rpassword::read_password()?);
    ensure!(pass1 == pass2, "Passwords don't match");

    let keyid = master_key.get_id();
    dirlock::import_policy_key(master_key, pass1.as_bytes())?;
    println!("{keyid}");
    Ok(())
}

fn cmd_status(args: &StatusArgs) -> Result<()> {
    use fscrypt::KeyStatus::*;

    let encrypted_dir = match dirlock::open_dir(&args.dir)? {
        DirStatus::Encrypted(d) => d,
        x => {
            println!("{x}");
            return Ok(());
        }
    };

    let locked = match encrypted_dir.key_status {
        Absent => "locked",
        Present => "unlocked",
        IncompletelyRemoved => "partially locked",
    };
    println!("Encrypted, {locked}, key id {}", encrypted_dir.policy.keyid);

    if ! args.verbose {
        return Ok(());
    }

    println!("Contents: {}",  encrypted_dir.policy.contents_mode);
    println!("Filenames: {}", encrypted_dir.policy.filenames_mode);
    println!("Padding: {}",   encrypted_dir.policy.flags.pad);

    if encrypted_dir.policy.flags.flags.is_empty() {
        println!("Flags: None");
    } else {
        println!("Flags: {}", encrypted_dir.policy.flags.flags);
    }

    for p in encrypted_dir.protectors {
        println!("Protector: {}, type {}", &p.protector_id, p.protector.get_type());
    }

    Ok(())
}

fn main() -> Result<()> {
    use Command::*;

    let args: Args = argh::from_env();

    dirlock::init();

    match &args.command {
        Lock(args) => cmd_lock(args),
        Unlock(args) => cmd_unlock(args),
        ChangePass(args) => cmd_change_pass(args),
        AddProtector(args) => cmd_add_protector(args),
        RemoveProtector(args) => cmd_remove_protector(args),
        Encrypt(args) => cmd_encrypt(args),
        SystemInfo(args) => cmd_system_info(args),
        ExportMasterKey(args) => cmd_export_master_key(args),
        ImportMasterKey(_) => cmd_import_master_key(),
        Status(args) => cmd_status(args),
    }
}
