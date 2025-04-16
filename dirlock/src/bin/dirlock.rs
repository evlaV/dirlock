/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{bail, Result};
use argh::FromArgs;
use std::io::{self, Write};
use std::num::NonZeroU32;
use std::path::PathBuf;
use dirlock::{
    DirStatus,
    fscrypt::{
        PolicyKeyId,
        self,
    },
    keystore,
    protector::{
        Protector,
        ProtectorId,
        ProtectorType,
        opts::{PasswordOpts, ProtectorOpts, ProtectorOptsBuilder},
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
    Policy(PolicyArgs),
    Protector(ProtectorArgs),
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
    protector: Option<ProtectorId>,
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
    protector: Option<ProtectorId>,
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
    protector: Option<ProtectorId>,
    /// force encrypting a directory with data
    #[argh(switch, long = "force")]
    force: bool,
    /// directory
    #[argh(positional)]
    dir: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "policy")]
/// Commands to manage encryption policies
struct PolicyArgs {
    #[argh(subcommand)]
    command: PolicyCommand,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum PolicyCommand {
    List(PolicyListArgs),
    Create(PolicyCreateArgs),
    Remove(PolicyRemoveArgs),
    AddProtector(PolicyAddProtectorArgs),
    RemoveProtector(PolicyRemoveProtectorArgs),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "list")]
/// List available encryption policies
struct PolicyListArgs { }

#[derive(FromArgs)]
#[argh(subcommand, name = "create")]
/// Create a new encryption policy
struct PolicyCreateArgs {
    /// ID of the protector to use for the new policy
    #[argh(option)]
    protector: Option<ProtectorId>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "remove")]
/// Permanently remove an encryption policy
struct PolicyRemoveArgs {
    /// ID of the policy to remove
    #[argh(option)]
    policy: Option<PolicyKeyId>,
    /// remove a policy without asking for confirmation
    #[argh(switch, long = "force")]
    force: bool,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "add-protector")]
/// Add a protector to an existing encryption policy
struct PolicyAddProtectorArgs {
    /// ID of the policy to modify
    #[argh(option)]
    policy: Option<PolicyKeyId>,
    /// ID of the protector to add
    #[argh(option)]
    protector: Option<ProtectorId>,
    /// ID of the protector used to unlock the policy
    #[argh(option)]
    unlock_with: Option<ProtectorId>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "remove-protector")]
/// Remove a protector from an encryption policy
struct PolicyRemoveProtectorArgs {
    /// ID of the policy to modify
    #[argh(option)]
    policy: Option<PolicyKeyId>,
    /// ID of the protector to remove
    #[argh(option)]
    protector: Option<ProtectorId>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "protector")]
/// Commands to manage protectors
struct ProtectorArgs {
    #[argh(subcommand)]
    command: ProtectorCommand,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum ProtectorCommand {
    List(ProtectorListArgs),
    Create(ProtectorCreateArgs),
    Remove(ProtectorRemoveArgs),
    VerifyPass(ProtectorVerifyPassArgs),
    ChangePass(ProtectorChangePassArgs),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "list")]
/// List available protectors
struct ProtectorListArgs { }

#[derive(FromArgs)]
#[argh(subcommand, name = "create")]
/// Create a new protector
struct ProtectorCreateArgs {
    /// protector type
    #[argh(option)]
    type_: ProtectorType,
    /// protector name (default: none)
    #[argh(option)]
    name: Option<String>,
    /// TPM2 device (default: auto)
    #[argh(option)]
    tpm2_device: Option<PathBuf>,
    /// iterations for the key derivation function (default: auto)
    #[argh(option)]
    kdf_iter: Option<NonZeroU32>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "remove")]
/// Remove a protector
struct ProtectorRemoveArgs {
    /// ID of the protector to remove
    #[argh(option)]
    protector: Option<ProtectorId>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "verify-password")]
/// Verify a protector's password
struct ProtectorVerifyPassArgs {
    /// ID of the protector to verify
    #[argh(option)]
    protector: Option<ProtectorId>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "change-password")]
/// Change a protector's password
struct ProtectorChangePassArgs {
    /// ID of the protector
    #[argh(option)]
    protector: Option<ProtectorId>,
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
/// Show the status of the system or a directory
struct StatusArgs {
    /// TPM2 device (default: auto)
    #[argh(option)]
    tpm2_device: Option<PathBuf>,
    /// directory (default: show global status)
    #[argh(positional)]
    dir: Option<PathBuf>,
}

#[cfg(feature = "tpm2")]
fn display_tpm_lockout_counter(protector: &Protector) -> Result<()> {
    use dirlock::protector::{ProtectorType, opts::Tpm2Opts};
    if protector.get_type() == ProtectorType::Tpm2 {
        let status = dirlock::protector::tpm2::get_status(Tpm2Opts::default())?;
        println!("This is a TPM2 protector. Failed authentication counter: {} / {}",
                 status.lockout_counter, status.max_auth_fail);
        if status.in_lockout {
            bail!("The TPM is locked, you must wait up to {} seconds before trying again",
                  status.lockout_interval);
        }
    }
    Ok(())
}

#[cfg(feature = "tpm2")]
fn display_tpm_information(tpm2_device: &Option<PathBuf>) -> Result<()> {
    let ProtectorOpts::Tpm2(opts) = ProtectorOptsBuilder::new()
        .with_type(Some(ProtectorType::Tpm2))
        .with_tpm2_device(tpm2_device.clone())
        .build()?
    else {
        unreachable!(); // We only build tpm2 opts here
    };

    let Ok(status) = dirlock::protector::tpm2::get_status(opts) else {
        println!("TPM not found");
        return Ok(());
    };

    println!("TPM information\n\
              ---------------\n\
              Device: {}\n\
              Manufacturer: {}\n\
              Locked: {} (failed auth attempts: {} / {})\n\
              Lockout counter decreased every {} seconds",
              status.path,
              status.manufacturer,
              if status.in_lockout { "yes" } else { "no" },
              status.lockout_counter,
              status.max_auth_fail,
              status.lockout_interval);

    Ok(())
}

#[cfg(not(feature = "tpm2"))]
fn display_tpm_lockout_counter(_protector: &Protector) -> Result<()> {
    Ok(())
}

#[cfg(not(feature = "tpm2"))]
fn display_tpm_information(_tpm2_device: &Option<PathBuf>) -> Result<()> {
    println!("TPM support not enabled");
    Ok(())
}

fn do_display_protector_list(list: Vec<&Protector>) {
    println!("{:16}    {:8}    Name", "Protector", "Type");
    println!("--------------------------------------");
    for prot in list {
        println!("{:16}    {:8}    {}", prot.id,
                 prot.get_type().to_string(),
                 prot.get_name().unwrap_or("(none)"));
    }
}

fn display_protector_list() -> Result<()> {
    let mut list = vec![];
    for id in keystore::protector_ids()? {
        if let Some(prot) = keystore::load_protector(id)? {
            list.push(prot);
        }
    }
    do_display_protector_list(list.iter().collect());
    Ok(())
}

fn display_protectors_from_dir(dir: &dirlock::EncryptedDir) {
    let list = dir.protectors.iter().map(|p| &p.protector).collect();
    do_display_protector_list(list);
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

    if let Some(id) = &args.protector {
        let _ = encrypted_dir.get_protector_by_id(id)?;
    }

    let pass = read_password("Enter encryption password", ReadPassword::Once)?;

    if ! encrypted_dir.unlock(pass.as_bytes(), args.protector.as_ref())? {
        bail!("Unable to unlock directory {}: wrong password", args.dir.display())
    }

    Ok(())
}

fn cmd_change_pass(args: &ChangePassArgs) -> Result<()> {
    let encrypted_dir = match dirlock::open_dir(&args.dir)? {
        DirStatus::Encrypted(d) => d,
        x => bail!("{}", x),
    };

    let protector = match &args.protector {
        Some(id) => encrypted_dir.get_protector_by_id(id)?,
        None => {
            if encrypted_dir.protectors.len() == 1 {
                &encrypted_dir.protectors[0].protector
            } else {
                println!("This directory has multiple protectors, you must select one.");
                display_protectors_from_dir(&encrypted_dir);
                bail!("Protector not specified");
            }
        },
    };

    do_change_verify_protector_password(Some(protector.id), false)
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

    let protector_key = if let Some(id) = args.protector {
        let protector = dirlock::get_protector_by_id(id)?;
        display_tpm_lockout_counter(&protector)?;
        let pass = read_password("Enter the password of the protector", ReadPassword::Once)?;
        let Some(protector_key) = protector.unwrap_key(pass.as_bytes()) else {
            bail!("Invalid password");
        };
        protector_key
    } else {
        let opts = ProtectorOpts::Password(PasswordOpts::default());
        let pass = read_password("Enter encryption password", ReadPassword::Twice)?;
        dirlock::create_protector(opts, pass.as_bytes())?
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

fn cmd_list_policies() -> Result<()> {
    println!("Policy                              Protectors");
    println!("----------------------------------------------------");
    for id in keystore::policy_key_ids()? {
        let prots = keystore::load_policy_map(&id)?
            .keys()
            .map(|prot_id| prot_id.to_string())
            .collect::<Vec<String>>()
            .join(", ");
        println!("{id}    {prots}");
    }
    Ok(())
}

fn cmd_create_policy(args: &PolicyCreateArgs) -> Result<()> {
    let Some(id) = args.protector else {
        println!("You must specify the ID of the protector.");
        return display_protector_list()
    };
    let protector = dirlock::get_protector_by_id(id)?;
    let pass = read_password("Enter password for the protector", ReadPassword::Once)?;
    let Some(protector_key) = protector.unwrap_key(pass.as_bytes()) else {
        bail!("Invalid password for protector {id}");
    };
    let policy_key = fscrypt::PolicyKey::new_random();
    let policy_id = policy_key.get_id();
    dirlock::wrap_and_save_policy_key(protector_key, policy_key)?;
    println!("Created encryption policy {policy_id}");
    Ok(())
}

fn cmd_remove_policy(args: &PolicyRemoveArgs) -> Result<()> {
    let Some(id) = &args.policy else {
        println!("You must specify the ID of the policy.");
        return cmd_list_policies();
    };
    if keystore::load_policy_map(id)?.is_empty() {
        bail!("Encryption policy {id} not found");
    }
    if ! args.force {
        print!("You are about to delete all data from the encryption\n\
                policy {id}\n\
                \n\
                This operation is irreversible, and unless you have a backup\n\
                of the policy and all its associated data you will no longer\n\
                be able to unlock any directory encrypted with it.\n\
                \n\
                Are you sure that you want to proceed? (yes / NO) ");
        loop {
            io::stdout().flush()?;
            let mut s = String::new();
            io::stdin().read_line(&mut s)?;
            match s.trim_end() {
                "yes" => break,
                "y" => eprint!("Please type 'yes' if you want to proceed: "),
                _ => {
                    println!("Operation cancelled");
                    return Ok(());
                }
            }
        }
    }
    keystore::remove_policy(id)?;
    println!("Encryption policy {id} removed successfully");
    Ok(())
}

fn cmd_policy_add_protector(args: &PolicyAddProtectorArgs) -> Result<()> {
    let Some(policy_id) = &args.policy else {
        bail!("You must specify the ID of the encryption policy.");
    };
    let protector = if let Some(id) = &args.protector {
        dirlock::get_protector_by_id(*id)?
    } else {
        bail!("You must specify the ID of the protector to add.");
    };

    let policy_map = keystore::load_policy_map(policy_id)?;
    if policy_map.is_empty() {
        bail!("Policy {policy_id} not found");
    }
    if policy_map.contains_key(&protector.id) {
        bail!("Policy {policy_id} is already protected with protector {}", protector.id);
    }

    let unlock_with = if let Some(id) = args.unlock_with {
        dirlock::get_protector_by_id(id)?
    } else if policy_map.len() == 1 {
        let id = policy_map.keys().next().unwrap();
        dirlock::get_protector_by_id(*id)?
    } else {
        bail!("You must specify the ID of the protector to unlock this policy.");
    };
    let Some(wrapped_policy_key) = policy_map.get(&unlock_with.id) else {
        bail!("Policy {policy_id} cannot be unlocked with protector {}", unlock_with.id);
    };

    let pass = read_password("Enter the password of the protector to add", ReadPassword::Once)?;
    let Some(protector_key) = protector.unwrap_key(pass.as_bytes()) else {
        bail!("Invalid password");
    };

    let pass = read_password("Enter the password of the existing protector", ReadPassword::Once)?;
    let Some(policy_key) = unlock_with.unwrap_policy_key(wrapped_policy_key, pass.as_bytes()) else {
        bail!("Invalid password");
    };

    dirlock::wrap_and_save_policy_key(protector_key, policy_key)?;
    println!("Protector {} added to policy {policy_id}", unlock_with.id);

    Ok(())
}

fn cmd_policy_remove_protector(args: &PolicyRemoveProtectorArgs) -> Result<()> {
    let Some(policy_id) = &args.policy else {
        bail!("You must specify the ID of the encryption policy.");
    };
    let protector = if let Some(id) = args.protector {
        dirlock::get_protector_by_id(id)?
    } else {
        bail!("You must specify the ID of the protector to remove.");
    };

    let policy_map = keystore::load_policy_map(policy_id)?;
    if policy_map.is_empty() {
        bail!("Policy {policy_id} not found");
    }
    if ! policy_map.contains_key(&protector.id) {
        bail!("Protector {} is not used in this policy", protector.id);
    }
    if policy_map.len() == 1 {
        bail!("Cannot remove the last protector. Use the 'policy remove' command instead.");
    }

    keystore::remove_protector_from_policy(policy_id, &protector.id)?;
    println!("Protector {} remove from policy {policy_id}", protector.id);

    Ok(())
}

fn cmd_create_protector(args: &ProtectorCreateArgs) -> Result<()> {
    let opts = ProtectorOptsBuilder::new()
        .with_type(Some(args.type_))
        .with_tpm2_device(args.tpm2_device.clone())
        .with_kdf_iter(args.kdf_iter)
        .with_name(args.name.clone())
        .build()?;

    let pass = read_password("Enter password for the new protector", ReadPassword::Twice)?;
    let protector_key = dirlock::create_protector(opts, pass.as_bytes())?;

    println!("Created protector {}", protector_key.get_id());

    Ok(())
}

fn cmd_remove_protector(args: &ProtectorRemoveArgs) -> Result<()> {
    let Some(id) = args.protector else {
        println!("You must specify the ID of the protector.");
        return display_protector_list()
    };
    let id_str = id.to_string();
    let protector = dirlock::get_protector_by_id(id)?;
    if keystore::remove_protector_if_unused(&protector.id)? {
        println!("Protector {id_str} removed");
    } else {
        eprintln!("Cannot remove protector {id_str}, used by the following policies:");
        for policy_id in keystore::policy_key_ids()? {
            if keystore::load_policy_map(&policy_id)?.contains_key(&protector.id) {
                println!("{policy_id}");
            }
        }
    }

    Ok(())
}

fn do_change_verify_protector_password(protector_id: Option<ProtectorId>, verify_only: bool) -> Result<()> {
    let Some(id) = protector_id else {
        println!("You must specify the ID of the protector.");
        return display_protector_list()
    };
    let mut protector = dirlock::get_protector_by_id(id)?;
    display_tpm_lockout_counter(&protector)?;
    let pass = read_password("Enter the current password", ReadPassword::Once)?;
    let Some(protector_key) = protector.unwrap_key(pass.as_bytes()) else {
        bail!("Invalid password");
    };
    if ! verify_only {
        let npass = read_password("Enter the new password", ReadPassword::Twice)?;
        if pass == npass {
            bail!("The old and new passwords are identical");
        }
        dirlock::wrap_and_save_protector_key(&mut protector, protector_key, npass.as_bytes())?;
    }
    Ok(())
}

fn cmd_verify_protector(args: &ProtectorVerifyPassArgs) -> Result<()> {
    do_change_verify_protector_password(args.protector, true)
}

fn cmd_change_protector_pass(args: &ProtectorChangePassArgs) -> Result<()> {
    do_change_verify_protector_password(args.protector, false)
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

    if ! keystore::get_protectors_for_policy(&keyid)?.is_empty() {
        bail!("This key has already been imported");
    }

    let opts = ProtectorOpts::Password(PasswordOpts::default());
    let pass = read_password("Enter password to protect this key", ReadPassword::Twice)?;
    let protector_key = dirlock::create_protector(opts, pass.as_bytes())?;
    dirlock::wrap_and_save_policy_key(protector_key, master_key)?;
    println!("Imported key for policy {keyid}");
    Ok(())
}

fn cmd_status(args: &StatusArgs) -> Result<()> {
    use fscrypt::KeyStatus::*;

    let Some(dir) = &args.dir else {
        display_protector_list()?;

        println!();
        cmd_list_policies()?;

        println!();
        display_tpm_information(&args.tpm2_device)?;

        return Ok(());
    };

    let encrypted_dir = match dirlock::open_dir(dir)? {
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
    println!("Encrypted, {locked}, policy {}", encrypted_dir.policy.keyid);

    println!("Contents: {}",  encrypted_dir.policy.contents_mode);
    println!("Filenames: {}", encrypted_dir.policy.filenames_mode);
    println!("Padding: {}",   encrypted_dir.policy.flags.pad);

    if encrypted_dir.policy.flags.flags.is_empty() {
        println!("Flags: None");
    } else {
        println!("Flags: {}", encrypted_dir.policy.flags.flags);
    }

    for p in encrypted_dir.protectors {
        print!("Protector: {}, type {}", &p.protector.id, p.protector.get_type());
        if let Some(name) = p.protector.get_name() {
            print!(", name: {name}");
        }
        println!();
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
        Encrypt(args) => cmd_encrypt(args),
        Policy(args) => match &args.command {
            PolicyCommand::List(_) => cmd_list_policies(),
            PolicyCommand::Create(args) => cmd_create_policy(args),
            PolicyCommand::Remove(args) => cmd_remove_policy(args),
            PolicyCommand::AddProtector(args) => cmd_policy_add_protector(args),
            PolicyCommand::RemoveProtector(args) => cmd_policy_remove_protector(args),
        }
        Protector(args) => match &args.command {
            ProtectorCommand::List(_) => display_protector_list(),
            ProtectorCommand::Create(args) => cmd_create_protector(args),
            ProtectorCommand::Remove(args) => cmd_remove_protector(args),
            ProtectorCommand::VerifyPass(args) => cmd_verify_protector(args),
            ProtectorCommand::ChangePass(args) => cmd_change_protector_pass(args),
        },
        ExportMasterKey(args) => cmd_export_master_key(args),
        ImportMasterKey(_) => cmd_import_master_key(),
        Status(args) => cmd_status(args),
    }
}
