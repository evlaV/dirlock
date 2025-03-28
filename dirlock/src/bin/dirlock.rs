/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{bail, Result};
use argh::FromArgs;
use std::io::{self, Write};
use std::path::PathBuf;
use dirlock::{
    DirStatus,
    fscrypt,
    protector::{
        opts::{ProtectorOpts, ProtectorOptsBuilder},
    },
    util::{
        ReadPassword,
        dir_is_empty,
        read_password,
    },
};

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
    Protector(ProtectorArgs),
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
    /// TPM2 device (default: auto)
    #[argh(option)]
    tpm2_device: Option<PathBuf>,
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
    /// encrypt the directory using an existing protector
    #[argh(option)]
    protector: Option<String>,
    /// force encrypting a directory with data
    #[argh(switch, long = "force")]
    force: bool,
    /// directory
    #[argh(positional)]
    dir: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "protector")]
/// Commands to manage protectors
struct ProtectorArgs {
    /// foo bar
    #[argh(subcommand)]
    command: ProtectorCommand,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum ProtectorCommand {
    Create(ProtectorCreateArgs),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "create")]
/// Create a new protector
struct ProtectorCreateArgs {
    /// type of the protector to add
    #[argh(option)]
    type_: String,
    /// TPM2 device (default: auto)
    #[argh(option)]
    tpm2_device: Option<PathBuf>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "system-info")]
/// Show information about the system
struct SystemInfoArgs {
    /// TPM2 device (default: auto)
    #[argh(option)]
    tpm2_device: Option<PathBuf>,
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

    let pass = read_password("Enter encryption password", ReadPassword::Once)?;

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

    let pass = read_password("Enter the current password", ReadPassword::Once)?;
    if ! encrypted_dir.check_pass(pass.as_bytes(), protector_id.as_ref()) {
        bail!("Password not valid for directory {}", args.dir.display())
    }

    let npass = read_password("Enter the new password", ReadPassword::Twice)?;
    if ! encrypted_dir.change_password(pass.as_bytes(), npass.as_bytes(), protector_id.as_ref())? {
        bail!("Unable to change the password for directory {}", args.dir.display())
    }

    Ok(())
}

fn cmd_add_protector(args: &AddProtectorArgs) -> Result<()> {
    let encrypted_dir = match dirlock::open_dir(&args.dir)? {
        DirStatus::Encrypted(d) => d,
        x => bail!("{}", x),
    };

    let mut optsbuilder = ProtectorOptsBuilder::new();
    if let Some(t) = &args.type_ {
        optsbuilder = optsbuilder.with_type(t);
    }
    if let Some(d) = &args.tpm2_device {
        optsbuilder = optsbuilder.with_tpm2_device(d);
    }
    let protector_opts = optsbuilder.build()?;

    let pass = read_password("Enter the current password", ReadPassword::Once)?;
    let Some(policy_key) = encrypted_dir.get_master_key(pass.as_bytes(), None) else {
        bail!("Password not valid for directory {}", args.dir.display())
    };

    let npass = read_password("Enter password for the new protector", ReadPassword::Twice)?;
    if encrypted_dir.check_pass(npass.as_bytes(), None) {
        bail!("There is already a protector with that password");
    }
    let protector_key = dirlock::create_protector(protector_opts, npass.as_bytes())?;
    dirlock::wrap_and_save_policy_key(protector_key, policy_key)
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
            let pass = read_password("Enter the password of the protector that you want to remove", ReadPassword::Once)?;
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

    let empty_dir = dir_is_empty(&args.dir)?;

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

    let protector_key = if let Some(id_str) = &args.protector {
        let protector = dirlock::get_protector_by_str(id_str)?;
        let pass = read_password("Enter the password of the protector", ReadPassword::Once)?;
        let Some(protector_key) = protector.unwrap_key(pass.as_bytes()) else {
            bail!("Invalid password");
        };
        protector_key
    } else {
        let pass = read_password("Enter encryption password", ReadPassword::Twice)?;
        dirlock::create_protector(ProtectorOpts::Password, pass.as_bytes())?
    };

    let keyid = if args.force && !empty_dir {
        println!("\nEncrypting the contents of {}, this can take a while", args.dir.display());
        let k = dirlock::convert::convert_dir(&args.dir, protector_key)?;
        println!("\nThe directory is now encrypted. If this was a home directory\n\
                  and you plan to log in using PAM you need to use the encryption\n\
                  password from now on. The old password in /etc/shadow is no longer\n\
                  used and you can disable it with usermod -p '*' USERNAME\n");
        k
    } else {
        dirlock::encrypt_dir(&args.dir, protector_key)?
    };
    println!("Directory encrypted with new policy id {}", keyid);

    Ok(())
}

fn cmd_create_protector(args: &ProtectorCreateArgs) -> Result<()> {
    let mut optsbuilder = ProtectorOptsBuilder::new()
        .with_type(&args.type_);

    if let Some(d) = &args.tpm2_device {
        optsbuilder = optsbuilder.with_tpm2_device(d);
    }

    let opts = optsbuilder.build()?;
    let pass = read_password("Enter password for the new protector", ReadPassword::Twice)?;
    let protector_key = dirlock::create_protector(opts, pass.as_bytes())?;

    println!("Created protector {}", protector_key.get_id());

    Ok(())
}

fn cmd_system_info(args: &SystemInfoArgs) -> Result<()> {
    let mut optsbuilder = ProtectorOptsBuilder::new()
        .with_type("tpm2");

    if let Some(d) = &args.tpm2_device {
        optsbuilder = optsbuilder.with_tpm2_device(d);
    }

    let ProtectorOpts::Tpm2(opts) = optsbuilder.build()? else {
        unreachable!(); // We only build tpm2 opts here
    };

    let tpm_status = dirlock::protector::tpm2::get_status(opts)
        .map(|s| s.to_string())
        .unwrap_or_else(|_| String::from("TPM not found"));

    println!("Protector          Type");
    println!("-----------------------");
    for id in dirlock::keystore::protector_ids()? {
        if let Some(prot) = dirlock::keystore::load_protector(&id)? {
            println!("{id}   {}", prot.name());
        }
    }

    println!("\nPolicy                              Protectors");
    println!("----------------------------------------------");
    for id in dirlock::keystore::policy_key_ids()? {
        let prots = dirlock::keystore::load_policy_map(&id)?
            .keys()
            .map(|prot_id| prot_id.to_string())
            .collect::<Vec<String>>()
            .join(", ");
        println!("{id}    {prots}");
    }

    println!("\nTPM information\n\
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
    let pass = read_password("Enter the current encryption password", ReadPassword::Once)?;

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
    let keyid = master_key.get_id();

    if ! dirlock::keystore::get_protectors_for_policy(&keyid)?.is_empty() {
        bail!("This key has already been imported");
    }

    let pass = read_password("Enter password to protect this key", ReadPassword::Twice)?;
    let protector_key = dirlock::create_protector(ProtectorOpts::Password, pass.as_bytes())?;
    dirlock::wrap_and_save_policy_key(protector_key, master_key)?;
    println!("Imported key for policy {keyid}");
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
        println!("Protector: {}, type {}", &p.protector_id, p.protector.name());
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
        Protector(args) => match &args.command {
            ProtectorCommand::Create(args) => cmd_create_protector(args),
        },
        SystemInfo(args) => cmd_system_info(args),
        ExportMasterKey(args) => cmd_export_master_key(args),
        ImportMasterKey(_) => cmd_import_master_key(),
        Status(args) => cmd_status(args),
    }
}
