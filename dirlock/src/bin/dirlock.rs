/*
 * Copyright © 2025-2026 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{bail, Result};
use argh::FromArgs;
use get_sys_info::Platform;
use std::io::{self, ErrorKind, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use dirlock::{
    CreateOpts,
    DirStatus,
    EncryptedDir,
    Keystore,
    LockState,
    recovery::RecoveryKey,
    fscrypt::{
        PolicyKeyId,
        self,
    },
    keystore,
    policy::PolicyKey,
    protector::{
        Protector,
        ProtectorId,
        ProtectorKey,
        ProtectorType,
        opts::{
            PROTECTOR_NAME_MAX_LEN,
            ProtectorOptsBuilder,
        },
    },
    util::{
        dir_is_empty,
        fs_supports_encryption,
        read_password_for_protector,
        read_new_password_for_protector,
        read_recovery_key,
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
    Convert(ConvertArgs),
    Lock(LockArgs),
    Unlock(UnlockArgs),
    ChangePass(ChangePassArgs),
    Recovery(RecoveryArgs),
    Admin(AdminArgs),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "admin")]
/// Advanced administrative commands
struct AdminArgs {
    #[argh(subcommand)]
    command: AdminCommand,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum AdminCommand {
    Policy(PolicyArgs),
    Protector(ProtectorArgs),
    Tpm2Test(Tpm2TestArgs),
    ExportMasterKey(ExportMasterKeyArgs),
    ImportMasterKey(ImportMasterKeyArgs),
    FscryptEnabled(FscryptEnabledArgs),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "lock")]
/// Lock an encrypted directory
struct LockArgs {
    /// lock the directory no matter who unlocked it
    #[argh(switch)]
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
    /// unlock using a recovery key
    #[argh(switch)]
    recovery: bool,
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
/// Encrypt an empty directory
struct EncryptArgs {
    /// create a new protector of this type (default: password)
    #[argh(option)]
    protector_type: Option<ProtectorType>,
    /// name of the new protector (default: name of the directory)
    #[argh(option)]
    protector_name: Option<String>,
    /// encrypt the directory using an existing protector
    #[argh(option)]
    protector: Option<ProtectorId>,
    /// owner of the protector and policy (default: current user)
    #[argh(option)]
    user: Option<String>,
    /// directory
    #[argh(positional)]
    dir: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "convert")]
/// Encrypt a directory that already contains data
struct ConvertArgs {
    /// create a new protector of this type (default: password)
    #[argh(option)]
    protector_type: Option<ProtectorType>,
    /// name of the new protector (default: name of the directory)
    #[argh(option)]
    protector_name: Option<String>,
    /// encrypt the directory using an existing protector
    #[argh(option)]
    protector: Option<ProtectorId>,
    /// owner of the protector and policy (default: current user)
    #[argh(option)]
    user: Option<String>,
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
    Status(PolicyStatusArgs),
    Purge(PolicyPurgeArgs),
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
    #[argh(positional)]
    policy: Option<PolicyKeyId>,
    /// don't ask for confirmation
    #[argh(switch)]
    force: bool,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "status")]
/// Show if an encryption key is present in memory
struct PolicyStatusArgs {
    /// ID of the policy to display (default: all known to dirlock)
    #[argh(option)]
    policy: Option<PolicyKeyId>,
    /// mount point of the filesystem to be checked
    #[argh(positional)]
    mntpoint: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "purge")]
/// Purge an encryption key from memory (locking all files)
struct PolicyPurgeArgs {
    /// ID of the policy to purge (default: all known to dirlock)
    #[argh(option)]
    policy: Option<PolicyKeyId>,
    /// mount point of the filesystem to purge
    #[argh(positional)]
    mntpoint: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "add-protector")]
/// Add a protector to an existing encryption policy
struct PolicyAddProtectorArgs {
    /// ID of the policy to modify
    #[argh(option)]
    policy: PolicyKeyId,
    /// ID of the protector to add
    #[argh(option)]
    protector: ProtectorId,
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
    policy: PolicyKeyId,
    /// ID of the protector to remove
    #[argh(option)]
    protector: ProtectorId,
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
    /// protector name
    #[argh(option)]
    name: String,
    /// iterations for the key derivation function (default: auto)
    #[argh(option)]
    kdf_iter: Option<NonZeroU32>,
    /// whether to require a PIN / password (default: true)
    #[argh(option)]
    use_pin: Option<bool>,
    /// owner of the protector (default: current user)
    #[argh(option)]
    user: Option<String>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "remove")]
/// Remove a protector
struct ProtectorRemoveArgs {
    /// ID of the protector to remove
    #[argh(positional)]
    protector: Option<ProtectorId>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "verify-password")]
/// Verify a protector's password
struct ProtectorVerifyPassArgs {
    /// ID of the protector to verify
    #[argh(positional)]
    protector: Option<ProtectorId>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "change-password")]
/// Change a protector's password
struct ProtectorChangePassArgs {
    /// ID of the protector
    #[argh(positional)]
    protector: Option<ProtectorId>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "recovery")]
/// Commands to manage recovery keys
struct RecoveryArgs {
    #[argh(subcommand)]
    command: RecoveryCommand,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum RecoveryCommand {
    Add(RecoveryAddArgs),
    Remove(RecoveryRemoveArgs),
    Restore(RecoveryRestoreArgs),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "add")]
/// Add a recovery key to a directory
struct RecoveryAddArgs {
    /// ID of the protector used to unlock the directory
    #[argh(option)]
    protector: Option<ProtectorId>,
    /// directory
    #[argh(positional)]
    dir: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "remove")]
/// Remove a recovery key from a directory
struct RecoveryRemoveArgs {
    /// directory
    #[argh(positional)]
    dir: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "restore")]
/// Restore access to a directory using its recovery key
struct RecoveryRestoreArgs {
    /// create a new protector of this type (default: password)
    #[argh(option)]
    protector_type: Option<ProtectorType>,
    /// name of the new protector (default: name of the directory)
    #[argh(option)]
    protector_name: Option<String>,
    /// restore using an existing protector
    #[argh(option)]
    protector: Option<ProtectorId>,
    /// owner of the protector and policy (default: current user)
    #[argh(option)]
    user: Option<String>,
    /// directory
    #[argh(positional)]
    dir: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "tpm2-test")]
/// Test if a TPM2 is available and is usable
struct Tpm2TestArgs { }

#[derive(FromArgs)]
#[argh(subcommand, name = "export-master-key")]
/// Export the master encryption key of a directory
struct ExportMasterKeyArgs {
    /// ID of the protector used to unlock the directory
    #[argh(option)]
    protector: Option<ProtectorId>,
    /// directory
    #[argh(positional)]
    dir: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "import-master-key")]
/// Import a master encryption key
struct ImportMasterKeyArgs { }

#[derive(FromArgs)]
#[argh(subcommand, name = "fscrypt-enabled")]
/// Check if fscrypt is supported on a filesystem
struct FscryptEnabledArgs {
    /// directory
    #[argh(positional)]
    dir: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "status")]
/// Show the status of the system or a directory
struct StatusArgs {
    /// brief output
    #[argh(switch, short = 'b')]
    brief: bool,
    /// directory (default: show global status)
    #[argh(positional)]
    dir: Option<PathBuf>,
}

#[cfg(feature = "tpm2")]
fn display_tpm_information() -> Result<()> {
    let Ok(status) = dirlock::protector::tpm2::get_status(None) else {
        println!("TPM not found");
        return Ok(());
    };

    println!("TPM information\n\
              ---------------\n\
              TCTI: {}\n\
              Manufacturer: {}\n\
              Locked: {} (failed auth attempts: {} / {})\n\
              Lockout counter decreased every {} seconds",
              status.tcti,
              status.manufacturer,
              if status.in_lockout { "yes" } else { "no" },
              status.lockout_counter,
              status.max_auth_fail,
              status.lockout_interval);

    Ok(())
}

#[cfg(not(feature = "tpm2"))]
fn display_tpm_information() -> Result<()> {
    println!("TPM support not enabled");
    Ok(())
}

fn display_protector_list() -> Result<()> {
    println!("{:16}    {:8}    Name", "Protector", "Type");
    println!("--------------------------------------");
    let ks = keystore();
    for id in ks.protector_ids()? {
        match ks.load_protector(id) {
            Ok(prot) => {
                println!("{:16}    {:8}    {}", prot.id,
                         prot.get_type().to_string(),
                         prot.get_name());
            },
            Err(e) => {
                println!("{:16}    [error: {}]", id, e.kind());
            }
        }
    }
    Ok(())
}

fn display_protectors_from_dir(dir: &EncryptedDir) {
    println!("{:16}    {:8}    Name", "Protector", "Type");
    println!("--------------------------------------");
    for i in &dir.protectors {
        println!("{:16}    {:8}    {}", i.protector.id,
                 i.protector.get_type().to_string(),
                 i.protector.get_name());
    }
    for i in &dir.unusable {
        println!("{:16}    [error: {}]", i.id, i.err.kind());
    }
}

fn get_dir_protector<'a>(dir: &'a EncryptedDir, prot: &Option<ProtectorId>) -> Result<&'a Protector> {
    match prot {
        Some(id) => dir.get_protector_by_id(id),
        None => {
            if dir.protectors.len() == 1 {
                Ok(&dir.protectors[0].protector)
            } else {
                println!("This directory has multiple protectors, you must select one.");
                display_protectors_from_dir(dir);
                bail!("Protector not specified");
            }
        },
    }
}

fn cmd_lock(args: &LockArgs, ks: &Keystore) -> Result<()> {
    let encrypted_dir = EncryptedDir::open(&args.dir, ks, LockState::Unlocked)?;

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

fn cmd_unlock(args: &UnlockArgs, ks: &Keystore) -> Result<()> {
    if args.recovery && args.protector.is_some() {
        bail!("Cannot use --protector and --recovery at the same time");
    }

    let encrypted_dir = EncryptedDir::open(&args.dir, ks, LockState::Locked)?;

    // If the user selected a protector then use it, otherwise try all of them
    let prots = if let Some(id) = &args.protector {
        vec![encrypted_dir.get_protector_by_id(id)?]
    } else {
        encrypted_dir.protectors.iter().map(|p| &p.protector).collect()
    };

    // Try with a recovery key if the user requested it (or if there are no protectors)
    if args.recovery || prots.is_empty() {
        if encrypted_dir.recovery.is_none() {
            bail!("The directory does not have a recovery key");
        }
        let pass = read_recovery_key()?;
        if encrypted_dir.unlock_with_recovery_key(pass.as_bytes()).unwrap_or(false) {
            return Ok(());
        } else {
            bail!("Unable to unlock directory");
        }
    }

    for p in &prots {
        if let Err(e) = p.get_prompt() {
            println!("Cannot use protector {}: {e}", p.id);
            continue;
        }
        if prots.len() > 1 {
            println!("Trying to unlock directory with protector {} (\"{}\")", p.id, p.get_name());
        }
        let pass = read_password_for_protector(p)?;

        if encrypted_dir.unlock(pass.as_bytes(), &p.id)? {
            return Ok(());
        }
        println!("Authentication failed");
    }

    bail!("Unable to unlock directory");
}

fn cmd_change_pass(args: &ChangePassArgs) -> Result<()> {
    let encrypted_dir = EncryptedDir::open(&args.dir, keystore(), LockState::Any)?;

    let protector = get_dir_protector(&encrypted_dir, &args.protector)?;
    do_change_verify_protector_password(Some(protector.id), false)
}

/// Get an existing protector or create a new one for encrypting a directory.
///
/// Returns `(protector, protector_key, protector_is_new)`.
fn get_or_create_protector(
    id: Option<ProtectorId>,
    type_: Option<ProtectorType>,
    name: Option<&str>,
    user: Option<&str>,
    dir: &Path,
    ks: &Keystore,
) -> Result<(Protector, ProtectorKey, bool)> {
    if id.is_some() && (name.is_some() || type_.is_some()) {
        bail!("Cannot set protector options for an existing protector");
    }

    if let Some(id) = id {
        if user.is_some() {
            bail!("Cannot set the user to an existing protector");
        }
        let protector = ks.load_protector(id)?;
        let pass = read_password_for_protector(&protector)?;
        let Some(protector_key) = protector.unwrap_key(pass.as_bytes())? else {
            bail!("Invalid {}", protector.get_type().credential_name());
        };
        Ok((protector, protector_key, false))
    } else {
        let name = name.map(str::to_owned).unwrap_or_else(|| {
            let mut n = format!("Protector for {}", dir.display());
            if n.len() > PROTECTOR_NAME_MAX_LEN {
                n.truncate(PROTECTOR_NAME_MAX_LEN - 4);
                n.push_str(" ...");
            }
            n
        });

        let opts = ProtectorOptsBuilder::new()
            .with_type(type_)
            .with_name(name)
            .with_user(user.map(str::to_owned))
            .build()?;
        let pass = read_new_password_for_protector(opts.get_type())?;
        let (protector, protector_key) =
            dirlock::create_protector(opts, pass.as_bytes(), CreateOpts::CreateAndSave, ks)?;
        Ok((protector, protector_key, true))
    }
}

fn cmd_encrypt(args: &EncryptArgs, ks: &Keystore) -> Result<()> {
    dirlock::ensure_unencrypted(&args.dir, ks)?;

    if ! dir_is_empty(&args.dir)? {
        bail!("The directory is not empty. Use 'convert' to encrypt a directory with data");
    }

    let (protector, protector_key, protector_is_new) = get_or_create_protector(
        args.protector, args.protector_type, args.protector_name.as_deref(), args.user.as_deref(),
        &args.dir, ks,
    )?;

    let protector_id = protector.id;
    let keyid = dirlock::encrypt_dir(&args.dir, &protector, protector_key, ks)
        .inspect_err(|_| {
            if protector_is_new {
                let _ = ks.remove_protector_if_unused(&protector_id);
            }
        })?;
    println!("Directory encrypted with new policy id {}", keyid);

    Ok(())
}

fn cmd_convert(args: &ConvertArgs) -> Result<()> {
    use dirlock::convert::*;

    let ks = keystore();
    dirlock::ensure_unencrypted(&args.dir, ks)?;

    if dir_is_empty(&args.dir)? {
        bail!("The directory is empty. Use the 'encrypt' command instead");
    }

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

    match conversion_status(&args.dir)? {
        ConversionStatus::None => (),
        ConversionStatus::Ongoing(_) => bail!("This directory is already being encrypted"),
        ConversionStatus::Interrupted(_) => {
            println!("Will resume encryption of partially encrypted directory");
        },
    }

    check_can_convert_dir(&args.dir, args.protector.as_ref(), ks)?;

    let (protector, protector_key, protector_is_new) = get_or_create_protector(
        args.protector, args.protector_type, args.protector_name.as_deref(), args.user.as_deref(),
        &args.dir, ks,
    )?;

    let protector_id = protector.id;
    println!("\nEncrypting the contents of {}, this can take a while", args.dir.display());
    let keyid = convert_dir(&args.dir, &protector, protector_key, ks)
        .inspect_err(|_| {
            if protector_is_new {
                let _ = ks.remove_protector_if_unused(&protector_id);
            }
        })?;
    println!("\nThe directory is now encrypted. If this was a home directory\n\
              and you plan to log in using PAM you need to use the encryption\n\
              password from now on. The old password in /etc/shadow is no longer\n\
              used and you can disable it with usermod -p '*' USERNAME\n");
    println!("Directory encrypted with new policy id {}", keyid);

    Ok(())
}

fn cmd_list_policies() -> Result<()> {
    let ks = keystore();
    let policies : Vec<_> = ks.policy_key_ids()?;

    println!("Policy                              Protectors");
    println!("----------------------------------------------------");
    for id in &policies {
        match ks.load_policy_data(id) {
            Ok(p) => {
                let prots = p.keys.keys()
                    .map(|prot_id| prot_id.to_string())
                    .collect::<Vec<String>>()
                    .join(", ");
                println!("{id}    {prots}");
            }
            Err(e) => {
                println!("{id}    [error: {}]", e.kind());
            }
        }
    }

    // List of mounted filesystems that support fscrypt
    let fs : Vec<_> = {
        let mut mounts = get_sys_info::System::new().mounts()?;
        // Use only one mount by source device in order to avoid
        // duplicate entries due to bind mounts.
        mounts.sort_by(|a, b| a.fs_mounted_from.cmp(&b.fs_mounted_from));
        mounts.dedup_by(|a, b| a.fs_mounted_from == b.fs_mounted_from);

        mounts.into_iter()
            .filter_map(|m| fs_supports_encryption(&m.fs_type).then_some(m.fs_mounted_on))
        .collect()
    };

    // Check what policies are unlocked in each filesystem
    let mut unlocked_policies = false;
    for id in &policies {
        let unlocked = fs.iter()
            .filter(|path| {
                fscrypt::get_key_status(Path::new(path), id)
                    .map(|(s, _)| s == fscrypt::KeyStatus::Present)
                    .unwrap_or(false)
            });
        for mnt in unlocked {
            if ! unlocked_policies {
                println!("\nUnlocked policies                   Mount point");
                println!("-----------------------------------------------");
                unlocked_policies = true;
            }
            println!("{id}    {mnt}");
        }
    }
    Ok(())
}

fn cmd_create_policy(args: &PolicyCreateArgs) -> Result<()> {
    let Some(id) = args.protector else {
        println!("You must specify the ID of the protector.");
        return display_protector_list()
    };
    let ks = keystore();
    let protector = ks.load_protector(id)?;
    let pass = read_password_for_protector(&protector)?;
    let Some(protector_key) = protector.unwrap_key(pass.as_bytes())? else {
        bail!("Invalid {} for protector {id}", protector.get_type().credential_name());
    };
    let (policy, _) = dirlock::create_policy_data(&protector, &protector_key, ks)?;
    println!("Created encryption policy {}", policy.id);
    Ok(())
}

fn cmd_remove_policy(args: &PolicyRemoveArgs) -> Result<()> {
    let Some(id) = &args.policy else {
        println!("You must specify the ID of the policy.");
        return cmd_list_policies();
    };
    let ks = keystore();
    let _ = ks.load_policy_data(id)?;
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
    ks.remove_policy(id)?;
    println!("Encryption policy {id} removed successfully");
    Ok(())
}

fn cmd_policy_status(args: &PolicyStatusArgs) -> Result<()> {
    let policies = match &args.policy {
        Some(policy) => vec![policy.clone()],
        None => keystore().policy_key_ids()?,
    };
    if policies.is_empty() {
        return Ok(());
    }
    println!("Policy                              Status");
    println!("------------------------------------------");
    for id in &policies {
        match fscrypt::get_key_status(&args.mntpoint, id) {
            Ok((status, _)) => println!("{id}    {status}"),
            Err(e) => println!("{id}    error ({e})"),
        }
    }
    Ok(())
}

fn cmd_policy_purge(args: &PolicyPurgeArgs) -> Result<()> {
    let policies = match &args.policy {
        Some(policy) => vec![policy.clone()],
        None => keystore().policy_key_ids()?,
    };
    if policies.is_empty() {
        return Ok(());
    }
    println!("Policy                              Action");
    println!("------------------------------------------");
    for id in &policies {
        use fscrypt::{KeyStatus::*, RemoveKeyUsers, RemovalStatusFlags};
        match fscrypt::get_key_status(&args.mntpoint, id) {
            Ok((Present, _)) | Ok((IncompletelyRemoved, _)) => {
                match fscrypt::remove_key(&args.mntpoint, id, RemoveKeyUsers::CurrentUser) {
                    Ok(flags) if flags.contains(RemovalStatusFlags::FilesBusy) => {
                        println!("{id}    partially removed (still in use)");
                    },
                    Ok(_) => {
                        println!("{id}    removed");
                    },
                    Err(e) => {
                        println!("{id}    none (error: {e})");
                    },
                }
            },
            Ok((Absent, _)) => {
                println!("{id}    none (key not present)");
            },
            Err(e) => {
                println!("{id}    none (error: {e})");
            },
        }
    }
    Ok(())
}

fn cmd_policy_add_protector(args: &PolicyAddProtectorArgs) -> Result<()> {
    let ks = keystore();
    let policy_id = &args.policy;
    let protector = ks.load_protector(args.protector)?;

    let unlock_with = if let Some(id) = args.unlock_with {
        ks.load_protector(id)?
    } else {
        let policy = ks.load_policy_data(policy_id)?;
        if policy.keys.len() == 1 {
            let id = *policy.keys.keys().next().unwrap();
            ks.load_protector(id)?
        } else {
            bail!("You must specify the ID of the protector to unlock this policy.");
        }
    };

    println!("Unlocking new protector {} (\"{}\")", protector.id, protector.get_name());
    let pass = read_password_for_protector(&protector)?;
    let Some(protector_key) = protector.unwrap_key(pass.as_bytes())? else {
        bail!("Invalid {}", protector.get_type().credential_name());
    };

    println!("Unlocking existing protector {} (\"{}\")", unlock_with.id, unlock_with.get_name());
    let pass = read_password_for_protector(&unlock_with)?;
    dirlock::add_protector_to_policy(policy_id, &protector_key, &unlock_with, pass.as_bytes(), ks)?;
    println!("Protector {} added to policy {policy_id}", protector.id);

    Ok(())
}

fn cmd_policy_remove_protector(args: &PolicyRemoveProtectorArgs) -> Result<()> {
    dirlock::remove_protector_from_policy(&args.policy, &args.protector, keystore())?;
    println!("Protector {} removed from policy {}", &args.protector, &args.policy);
    Ok(())
}

fn cmd_create_protector(args: &ProtectorCreateArgs) -> Result<()> {
    let opts = ProtectorOptsBuilder::new()
        .with_type(Some(args.type_))
        .with_kdf_iter(args.kdf_iter)
        .with_use_pin(args.use_pin)
        .with_name(args.name.clone())
        .with_user(args.user.clone())
        .build()?;

    let pass = read_new_password_for_protector(opts.get_type())?;
    let ks = keystore();
    let (protector, _) = dirlock::create_protector(opts, pass.as_bytes(), CreateOpts::CreateAndSave, ks)?;

    println!("Created protector {}", protector.id);

    Ok(())
}

fn cmd_remove_protector(args: &ProtectorRemoveArgs) -> Result<()> {
    let Some(id) = args.protector else {
        println!("You must specify the ID of the protector.");
        return display_protector_list()
    };
    let id_str = id.to_string();
    let ks = keystore();
    let protector = ks.load_protector(id)?;
    if ks.remove_protector_if_unused(&protector.id)? {
        println!("Protector {id_str} removed");
    } else {
        eprintln!("Cannot remove protector {id_str}, used by the following policies:");
        for policy_id in ks.policy_key_ids()? {
            if ks.load_policy_data(&policy_id)?.keys.contains_key(&protector.id) {
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
    let ks = keystore();
    let mut protector = ks.load_protector(id)?;
    let pass = read_password_for_protector(&protector)?;
    let Some(protector_key) = protector.unwrap_key(pass.as_bytes())? else {
        bail!("Invalid {}", protector.get_type().credential_name());
    };
    if ! verify_only {
        let npass = read_new_password_for_protector(protector.get_type())?;
        if pass == npass {
            bail!("The old and new passwords are identical");
        }
        dirlock::wrap_and_save_protector_key(&mut protector, protector_key, npass.as_bytes(), ks)?;
    }
    Ok(())
}

fn cmd_verify_protector(args: &ProtectorVerifyPassArgs) -> Result<()> {
    do_change_verify_protector_password(args.protector, true)
}

fn cmd_change_protector_pass(args: &ProtectorChangePassArgs) -> Result<()> {
    do_change_verify_protector_password(args.protector, false)
}

fn cmd_recovery_add(args: &RecoveryAddArgs) -> Result<()> {
    let mut encrypted_dir = EncryptedDir::open(&args.dir, keystore(), LockState::Any)?;

    if encrypted_dir.recovery.is_some() {
        bail!("This directory already has a recovery key");
    }

    let prot = if let Some(id) = args.protector {
        encrypted_dir.get_protector_by_id(&id)?
    } else if encrypted_dir.protectors.len() == 1 {
        &encrypted_dir.protectors[0].protector
    } else {
        bail!("You must specify the ID of the protector");
    };

    let pass = read_password_for_protector(prot)?;
    let Some(protkey) = prot.unwrap_key(pass.as_bytes())? else {
        bail!("Failed to unlock protector {}: wrong key", prot.id);
    };

    let recovery = encrypted_dir.add_recovery_key(&protkey)?;
    println!("Recovery key added: {recovery}");

    Ok(())
}

fn cmd_recovery_remove(args: &RecoveryRemoveArgs) -> Result<()> {
    let mut encrypted_dir = EncryptedDir::open(&args.dir, keystore(), LockState::Any)?;
    encrypted_dir.remove_recovery_key()
}

fn cmd_recovery_restore(args: &RecoveryRestoreArgs) -> Result<()> {
    let ks = keystore();
    let encrypted_dir = EncryptedDir::open(&args.dir, ks, LockState::Any)?;

    if let Some(protid) = &args.protector {
        if encrypted_dir.get_protector_by_id(protid).is_ok() {
            bail!("This directory is already protected with that protector");
        }
    }

    let Some(recovery) = &encrypted_dir.recovery else {
        bail!("This directory does not have a recovery key");
    };

    let pass = read_recovery_key()?;
    let Ok(recovery_key) = RecoveryKey::from_ascii_bytes(pass.as_bytes()) else {
        bail!("Invalid recovery key");
    };

    let Some(master_key) = recovery.unwrap_key(recovery_key.protector_key()) else {
        bail!("Wrong recovery key");
    };

    let (protector, protector_key, _) = get_or_create_protector(
        args.protector, args.protector_type, args.protector_name.as_deref(),
        args.user.as_deref(), &args.dir, ks,
    )?;

    dirlock::protect_policy_key(&protector, &protector_key, master_key, ks)?;
    println!("The directory can now be unlocked with protector {}", protector.id);
    Ok(())
}

fn cmd_export_master_key(args: &ExportMasterKeyArgs) -> Result<()> {
    use base64::prelude::*;
    let encrypted_dir = EncryptedDir::open(&args.dir, keystore(), LockState::Any)?;

    let protector = get_dir_protector(&encrypted_dir, &args.protector)?;

    eprintln!("This will print to stdout the master key with ID {}", encrypted_dir.policy.keyid);
    eprintln!("- This is the encryption key for directory {}", args.dir.display());
    eprintln!("- This feature is only available while this tool is under development");
    eprintln!("- The printed key is *raw and unprotected*, you are reponsible for keeping it safe");
    eprintln!();
    let pass = read_password_for_protector(protector)?;

    let Some(k) = encrypted_dir.get_master_key(pass.as_bytes(), &protector.id)? else {
        bail!("Authentication failed");
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

    let mut master_key = PolicyKey::default();
    match BASE64_STANDARD.decode_slice(key.trim(), master_key.secret_mut()) {
        Err(e) => bail!("Unable to decode key: {e}"),
        Ok(x) if x != 64 => bail!("Wrong key size"),
        Ok(_) => (),
    }
    let keyid = master_key.get_id();

    // Stop if there is already a protector available for this key
    // (unless the protector file is missing).
    let ks = keystore();
    let (protectors, unusable) = ks.get_protectors_for_policy(&keyid)?;
    if ! protectors.is_empty() ||
        unusable.iter().any(|p| p.err.kind() != ErrorKind::NotFound) {
        bail!("This key has already been imported (policy {keyid})");
    }

    let opts = ProtectorOptsBuilder::new()
        .with_name(String::from("Restored key"))
        .with_type(Some(ProtectorType::Password))
        .build()?;
    let pass = read_new_password_for_protector(opts.get_type())?;
    let (protector, protector_key) = dirlock::create_protector(opts, pass.as_bytes(), CreateOpts::CreateAndSave, ks)?;
    dirlock::protect_policy_key(&protector, &protector_key, master_key, ks)?;
    println!("Imported key for policy {keyid}");
    Ok(())
}

#[cfg(not(feature = "tpm2"))]
fn cmd_tpm2_test() -> Result<()> {
    bail!("TPM support is disabled");
}

#[cfg(feature = "tpm2")]
fn cmd_tpm2_test() -> Result<()> {
    use dirlock::policy::WrappedPolicyKey;

    match dirlock::protector::tpm2::get_status(None) {
        Ok(s) if s.in_lockout => bail!("TPM in lockout mode"),
        Ok(_) => (),
        Err(_) => bail!("No TPM found"),
    }

    let policy_key = PolicyKey::new_random();
    let raw_key = *policy_key.secret();
    let pass = "test";

    let opts = ProtectorOptsBuilder::new()
        .with_name(String::from(pass))
        .with_type(Some(ProtectorType::Tpm2))
        .build()?;
    let (protector, protector_key) =
        dirlock::create_protector(opts, pass.as_bytes(), CreateOpts::CreateOnly, keystore())?;
    let wrapped = WrappedPolicyKey::new(policy_key, &protector_key);
    match protector.unwrap_policy_key(&wrapped, pass.as_bytes()) {
        Ok(Some(k)) if *k.secret() == raw_key => (),
        _ => bail!("Failed decrypting data with the TPM"),
    }

    Ok(())
}

fn cmd_fscrypt_enabled(args: &FscryptEnabledArgs) -> Result<()> {
    let id = PolicyKeyId::default();
    fscrypt::get_key_status(&args.dir, &id)?;
    println!("enabled");
    Ok(())
}

fn cmd_status(args: &StatusArgs) -> Result<()> {
    let Some(dir) = &args.dir else {
        if args.brief {
            bail!("The --brief option can only be used on a directory");
        }

        display_protector_list()?;

        println!();
        cmd_list_policies()?;

        println!();
        display_tpm_information()?;

        return Ok(());
    };

    let ks = keystore();
    let dir_status = dirlock::open_dir(dir, ks)?;
    if args.brief {
        println!("{}", dir_status.name());
        return Ok(());
    }

    let DirStatus::Encrypted(encrypted_dir) = &dir_status else {
        println!("{}", dir_status.error_msg());
        return Ok(());
    };

    let locked = dir_status.name(); // locked, unlocked, partially-locked
    println!("Encrypted, {locked}, policy {}", encrypted_dir.policy.keyid);
    println!("Contents: {}",  encrypted_dir.policy.contents_mode);
    println!("Filenames: {}", encrypted_dir.policy.filenames_mode);
    println!("Padding: {}",   encrypted_dir.policy.flags.pad);

    if encrypted_dir.policy.flags.flags.is_empty() {
        println!("Flags: None");
    } else {
        println!("Flags: {}", encrypted_dir.policy.flags.flags);
    }

    println!("Recovery: {}", if encrypted_dir.recovery.is_some() { "yes" } else { "no" });
    display_protectors_from_dir(encrypted_dir);
    Ok(())
}

fn main() -> Result<()> {
    use Command::*;

    let args: Args = argh::from_env();

    dirlock::init()?;

    match &args.command {
        Lock(args) => cmd_lock(args, keystore()),
        Unlock(args) => cmd_unlock(args, keystore()),
        ChangePass(args) => cmd_change_pass(args),
        Encrypt(args) => cmd_encrypt(args, keystore()),
        Convert(args) => cmd_convert(args),
        Recovery(args) => match &args.command {
            RecoveryCommand::Add(args) => cmd_recovery_add(args),
            RecoveryCommand::Remove(args) => cmd_recovery_remove(args),
            RecoveryCommand::Restore(args) => cmd_recovery_restore(args),
        },
        Status(args) => cmd_status(args),
        Admin(args) => match &args.command {
            AdminCommand::Policy(args) => match &args.command {
                PolicyCommand::List(_) => cmd_list_policies(),
                PolicyCommand::Create(args) => cmd_create_policy(args),
                PolicyCommand::Remove(args) => cmd_remove_policy(args),
                PolicyCommand::Status(args) => cmd_policy_status(args),
                PolicyCommand::Purge(args) => cmd_policy_purge(args),
                PolicyCommand::AddProtector(args) => cmd_policy_add_protector(args),
                PolicyCommand::RemoveProtector(args) => cmd_policy_remove_protector(args),
            },
            AdminCommand::Protector(args) => match &args.command {
                ProtectorCommand::List(_) => display_protector_list(),
                ProtectorCommand::Create(args) => cmd_create_protector(args),
                ProtectorCommand::Remove(args) => cmd_remove_protector(args),
                ProtectorCommand::VerifyPass(args) => cmd_verify_protector(args),
                ProtectorCommand::ChangePass(args) => cmd_change_protector_pass(args),
            },
            AdminCommand::Tpm2Test(_) => cmd_tpm2_test(),
            AdminCommand::ExportMasterKey(args) => cmd_export_master_key(args),
            AdminCommand::ImportMasterKey(_) => cmd_import_master_key(),
            AdminCommand::FscryptEnabled(args) => cmd_fscrypt_enabled(args),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dirlock::util::push_test_password;
    use fscrypt::{RemoveKeyUsers, RemovalStatusFlags};
    use tempdir::TempDir;

    // Filesystem where to run the tests. It must support fscrypt.
    // Set to 'skip' to skip these tests.
    const MNTPOINT_ENV_VAR: &str = "DIRLOCK_TEST_FS";

    fn get_mntpoint() -> Result<Option<PathBuf>> {
        match std::env::var(MNTPOINT_ENV_VAR) {
            Ok(x) if x == "skip" => Ok(None),
            Ok(x) => Ok(Some(PathBuf::from(x))),
            _ => bail!("Environment variable '{MNTPOINT_ENV_VAR}' not set"),
        }
    }

    fn test_encrypt_args(dir: &Path) -> EncryptArgs {
        EncryptArgs {
            protector_type: None,
            protector_name: Some("test".into()),
            protector: None,
            user: None,
            dir: dir.into(),
        }
    }

    #[test]
    fn test_encrypt() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        // Encrypt the directory
        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        push_test_password("1234");
        cmd_encrypt(&test_encrypt_args(dir.path()), &ks)?;

        // encrypt leaves the directory unlocked, so lock it
        let encrypted_dir = EncryptedDir::open(dir.path(), &ks, LockState::Unlocked)?;
        let status = encrypted_dir.lock(RemoveKeyUsers::CurrentUser)?;
        assert!(!status.contains(RemovalStatusFlags::FilesBusy));
        assert!(!status.contains(RemovalStatusFlags::OtherUsers));

        Ok(())
    }

    #[test]
    fn test_lock_unlock() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        let password = "1234";

        // Encrypt the directory
        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        push_test_password(password);
        cmd_encrypt(&test_encrypt_args(dir.path()), &ks)?;

        // Lock it and verify that it's locked
        let lock_args = LockArgs { dir: dir.path().into(), all_users: false };
        cmd_lock(&lock_args, &ks)?;
        EncryptedDir::open(dir.path(), &ks, LockState::Locked)?;

        // Unlock it and verify that it's unlocked
        push_test_password(password);
        let unlock_args = UnlockArgs { dir: dir.path().into(), protector: None, recovery: false };
        cmd_unlock(&unlock_args, &ks)?;
        EncryptedDir::open(dir.path(), &ks, LockState::Unlocked)?;

        // Lock it again
        cmd_lock(&lock_args, &ks)?;

        Ok(())
    }
}
