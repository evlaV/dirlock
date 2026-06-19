/*
 * Copyright © 2025-2026 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{bail, Result};
use argh::FromArgs;
use std::io::{self, ErrorKind, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use dirlock::{
    CreateOpts,
    DirStatus,
    EncryptedDir,
    Host,
    KeyStatus,
    Keystore,
    LockState,
    PolicyKeyId,
    PolicyProtectors,
    RemovalStatusFlags,
    RemoveKeyUsers,
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
    recovery::RecoveryKey,
    util::{
        dir_is_empty,
        get_unique_mounts,
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
    Cleanup(CleanupArgs),
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
    /// don't ask for confirmation
    #[argh(switch)]
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
    Verify(RecoveryVerifyArgs),
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
#[argh(subcommand, name = "verify")]
/// Verify a recovery key
struct RecoveryVerifyArgs {
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
#[argh(subcommand, name = "cleanup")]
/// Remove stale directory conversion entries
struct CleanupArgs {
    /// path within the filesystem to clean up (default: all mounted filesystems)
    #[argh(positional)]
    dir: Option<PathBuf>,
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

/// When running tests, default to 1 KDF iteration in order to make
/// them faster.
fn get_kdf_iter(val: Option<NonZeroU32>) -> Option<NonZeroU32> {
    if cfg!(test) && val.is_none() {
        NonZeroU32::new(1)
    } else {
        val
    }
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

fn display_protector_list(ks: &Keystore) -> Result<()> {
    println!("{:16}    {:8}    Name", "Protector", "Type");
    println!("--------------------------------------");
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

fn display_protectors(prots: &PolicyProtectors) {
    println!("{:16}    {:8}    Name", "Protector", "Type");
    println!("--------------------------------------");
    for i in &prots.usable {
        println!("{:16}    {:8}    {}", i.protector.id,
                 i.protector.get_type().to_string(),
                 i.protector.get_name());
    }
    for i in &prots.unusable {
        println!("{:16}    [error: {}]", i.id, i.err.kind());
    }
}

/// Select one of the usable protectors from a list of [`PolicyProtectors`].
/// If `prot` is unset and there is only one protector, that one will be selected.
/// Otherwise the user must specify the id of the protector to select.
fn select_protector_for_policy<'a>(prots: &'a PolicyProtectors, prot: &Option<ProtectorId>) -> Result<&'a Protector> {
    match prot {
        Some(id) => prots.get_protector(id),
        None => {
            if prots.usable.len() == 1 {
                Ok(&prots.usable[0].protector)
            } else {
                println!("This policy has multiple protectors, you must select one:");
                display_protectors(prots);
                bail!("Protector not specified");
            }
        },
    }
}

fn get_dir_protector<'a>(dir: &'a EncryptedDir, prot: &Option<ProtectorId>) -> Result<&'a Protector> {
    select_protector_for_policy(&dir.protectors, prot)
}

fn cmd_lock(args: &LockArgs, ks: &Keystore) -> Result<()> {
    let encrypted_dir = EncryptedDir::open(&args.dir, ks, LockState::Unlocked)?;

    let user = if args.all_users {
        RemoveKeyUsers::AllUsers
    } else {
        RemoveKeyUsers::CurrentUser
    };
    let flags = encrypted_dir.lock(user)?;

    if flags.contains(RemovalStatusFlags::FilesBusy) {
        println!("Key removed, but some files are still busy");
    };

    if flags.contains(RemovalStatusFlags::OtherUsers) {
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
        encrypted_dir.protectors.usable.iter().map(|p| &p.protector).collect()
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
        if let Err(e) = p.get_prompt(Host::Local) {
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

fn cmd_change_pass(args: &ChangePassArgs, ks: &Keystore) -> Result<()> {
    let encrypted_dir = EncryptedDir::open(&args.dir, ks, LockState::Any)?;

    let protector = get_dir_protector(&encrypted_dir, &args.protector)?;
    do_change_verify_protector_password(Some(protector.id), false, ks)
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
            .with_kdf_iter(get_kdf_iter(None))
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

fn cmd_convert(args: &ConvertArgs, ks: &Keystore) -> Result<()> {
    use dirlock::convert::*;

    dirlock::ensure_unencrypted(&args.dir, ks)?;

    if dir_is_empty(&args.dir)? {
        bail!("The directory is empty. Use the 'encrypt' command instead");
    }

    if ! args.force {
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
    }

    let (protector, protector_key, protector_is_new) = match conversion_status(&args.dir)? {
        ConversionStatus::None => {
            get_or_create_protector(
                args.protector, args.protector_type, args.protector_name.as_deref(),
                args.user.as_deref(), &args.dir, ks,
            )?
        },
        ConversionStatus::Ongoing(_) => bail!("This directory is already being encrypted"),
        ConversionStatus::Interrupted(id) => {
            println!("Will resume encryption of partially encrypted directory.");
            if args.protector_type.is_some() || args.protector_name.is_some() || args.user.is_some() {
                bail!("Cannot set protector options when resuming an interrupted conversion");
            }
            let prots = ks.get_protectors_for_policy(&id)?;
            let protid = select_protector_for_policy(&prots, &args.protector)?.id;
            let protector = prots.into_protector(&protid)?;
            let pass = read_password_for_protector(&protector)?;
            let Some(protector_key) = protector.unwrap_key(pass.as_bytes())? else {
                bail!("Invalid {}", protector.get_type().credential_name());
            };
            (protector, protector_key, false)
        },
    };

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

fn cmd_list_policies(ks: &Keystore) -> Result<()> {
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
    let fs : Vec<_> = get_unique_mounts()?
        .into_iter()
        .map(|m| m.fs_mounted_on)
        .collect();

    // Check what policies are unlocked in each filesystem
    let mut unlocked_policies = false;
    for id in &policies {
        let unlocked = fs.iter()
            .filter(|path| {
                dirlock::get_key_status(Path::new(path), id)
                    .map(|(s, _)| s == KeyStatus::Present)
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

fn cmd_create_policy(args: &PolicyCreateArgs, ks: &Keystore) -> Result<()> {
    let Some(id) = args.protector else {
        println!("You must specify the ID of the protector.");
        return display_protector_list(ks)
    };
    let protector = ks.load_protector(id)?;
    let pass = read_password_for_protector(&protector)?;
    let Some(protector_key) = protector.unwrap_key(pass.as_bytes())? else {
        bail!("Invalid {} for protector {id}", protector.get_type().credential_name());
    };
    let (policy, _) = dirlock::create_policy_data(&protector, &protector_key, ks)?;
    println!("Created encryption policy {}", policy.id);
    Ok(())
}

fn cmd_remove_policy(args: &PolicyRemoveArgs, ks: &Keystore) -> Result<()> {
    let Some(id) = &args.policy else {
        println!("You must specify the ID of the policy.");
        return cmd_list_policies(ks);
    };
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

fn cmd_policy_status(args: &PolicyStatusArgs, ks: &Keystore) -> Result<()> {
    let policies = match &args.policy {
        Some(policy) => vec![policy.clone()],
        None => ks.policy_key_ids()?,
    };
    if policies.is_empty() {
        return Ok(());
    }
    println!("Policy                              Status");
    println!("------------------------------------------");
    for id in &policies {
        match dirlock::get_key_status(&args.mntpoint, id) {
            Ok((status, _)) => println!("{id}    {status}"),
            Err(e) => println!("{id}    error ({e})"),
        }
    }
    Ok(())
}

fn cmd_policy_purge(args: &PolicyPurgeArgs, ks: &Keystore) -> Result<()> {
    if let Err(e) = args.mntpoint.metadata() {
        bail!("Cannot open {}: {e}", args.mntpoint.display());
    }
    let policies = match &args.policy {
        Some(policy) => vec![policy.clone()],
        None => ks.policy_key_ids()?,
    };
    if policies.is_empty() {
        return Ok(());
    }
    println!("Policy                              Action");
    println!("------------------------------------------");
    for id in &policies {
        use KeyStatus::*;
        match dirlock::get_key_status(&args.mntpoint, id) {
            Ok((Present, _)) | Ok((IncompletelyRemoved, _)) => {
                match dirlock::remove_key(&args.mntpoint, id, RemoveKeyUsers::CurrentUser) {
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

fn cmd_policy_add_protector(args: &PolicyAddProtectorArgs, ks: &Keystore) -> Result<()> {
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

fn cmd_policy_remove_protector(args: &PolicyRemoveProtectorArgs, ks: &Keystore) -> Result<()> {
    dirlock::remove_protector_from_policy(&args.policy, &args.protector, ks)?;
    println!("Protector {} removed from policy {}", &args.protector, &args.policy);
    Ok(())
}

fn cmd_create_protector(args: &ProtectorCreateArgs, ks: &Keystore) -> Result<()> {
    let opts = ProtectorOptsBuilder::new()
        .with_type(Some(args.type_))
        .with_kdf_iter(get_kdf_iter(args.kdf_iter))
        .with_use_pin(args.use_pin)
        .with_name(args.name.clone())
        .with_user(args.user.clone())
        .build()?;

    let pass = read_new_password_for_protector(opts.get_type())?;
    let (protector, _) = dirlock::create_protector(opts, pass.as_bytes(), CreateOpts::CreateAndSave, ks)?;

    println!("Created protector {}", protector.id);

    Ok(())
}

fn cmd_remove_protector(args: &ProtectorRemoveArgs, ks: &Keystore) -> Result<()> {
    let Some(id) = args.protector else {
        println!("You must specify the ID of the protector.");
        return display_protector_list(ks)
    };
    let id_str = id.to_string();
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

fn do_change_verify_protector_password(protector_id: Option<ProtectorId>, verify_only: bool, ks: &Keystore) -> Result<()> {
    let Some(id) = protector_id else {
        println!("You must specify the ID of the protector.");
        return display_protector_list(ks)
    };
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

fn cmd_verify_protector(args: &ProtectorVerifyPassArgs, ks: &Keystore) -> Result<()> {
    do_change_verify_protector_password(args.protector, true, ks)
}

fn cmd_change_protector_pass(args: &ProtectorChangePassArgs, ks: &Keystore) -> Result<()> {
    do_change_verify_protector_password(args.protector, false, ks)
}

fn cmd_recovery_add(args: &RecoveryAddArgs, ks: &Keystore) -> Result<()> {
    let mut encrypted_dir = EncryptedDir::open(&args.dir, ks, LockState::Any)?;

    if encrypted_dir.recovery.is_some() {
        bail!("This directory already has a recovery key");
    }

    let prot = get_dir_protector(&encrypted_dir, &args.protector)?;
    let pass = read_password_for_protector(prot)?;
    let Some(protkey) = prot.unwrap_key(pass.as_bytes())? else {
        bail!("Failed to unlock protector {}: wrong key", prot.id);
    };

    let recovery = encrypted_dir.add_recovery_key(&protkey)?;
    println!("Recovery key added: {recovery}");

    Ok(())
}

fn cmd_recovery_remove(args: &RecoveryRemoveArgs, ks: &Keystore) -> Result<()> {
    let mut encrypted_dir = EncryptedDir::open(&args.dir, ks, LockState::Any)?;
    encrypted_dir.remove_recovery_key()
}

fn cmd_recovery_restore(args: &RecoveryRestoreArgs, ks: &Keystore) -> Result<()> {
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

fn cmd_recovery_verify(args: &RecoveryVerifyArgs, ks: &Keystore) -> Result<()> {
    let encrypted_dir = EncryptedDir::open(&args.dir, ks, LockState::Any)?;
    let pass = read_recovery_key()?;
    if !encrypted_dir.verify_recovery_key(pass.as_bytes())? {
        bail!("Wrong recovery key");
    }
    Ok(())
}

fn cmd_export_master_key(args: &ExportMasterKeyArgs, ks: &Keystore) -> Result<()> {
    use base64::prelude::*;
    let encrypted_dir = EncryptedDir::open(&args.dir, ks, LockState::Any)?;

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

fn cmd_import_master_key(ks: &Keystore) -> Result<()> {
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
    let protectors = ks.get_protectors_for_policy(&keyid)?;
    if ! protectors.usable.is_empty() ||
        protectors.unusable.iter().any(|p| p.err.kind() != ErrorKind::NotFound) {
        bail!("This key has already been imported (policy {keyid})");
    }

    let opts = ProtectorOptsBuilder::new()
        .with_name(String::from("Restored key"))
        .with_type(Some(ProtectorType::Password))
        .with_kdf_iter(get_kdf_iter(None))
        .build()?;
    let pass = read_new_password_for_protector(opts.get_type())?;
    let (protector, protector_key) = dirlock::create_protector(opts, pass.as_bytes(), CreateOpts::CreateAndSave, ks)?;
    dirlock::protect_policy_key(&protector, &protector_key, master_key, ks)?;
    println!("Imported key for policy {keyid}");
    Ok(())
}

#[cfg(not(feature = "tpm2"))]
fn cmd_tpm2_test(_ks: &Keystore) -> Result<()> {
    bail!("TPM support is disabled");
}

#[cfg(feature = "tpm2")]
fn cmd_tpm2_test(ks: &Keystore) -> Result<()> {
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
        .with_kdf_iter(get_kdf_iter(None))
        .build()?;
    let (protector, protector_key) =
        dirlock::create_protector(opts, pass.as_bytes(), CreateOpts::CreateOnly, ks)?;
    let wrapped = WrappedPolicyKey::new(policy_key, &protector_key);
    match protector.unwrap_policy_key(&wrapped, pass.as_bytes()) {
        Ok(Some(k)) if *k.secret() == raw_key => (),
        _ => bail!("Failed decrypting data with the TPM"),
    }

    Ok(())
}

fn cmd_fscrypt_enabled(args: &FscryptEnabledArgs) -> Result<()> {
    let id = PolicyKeyId::default();
    dirlock::get_key_status(&args.dir, &id)?;
    println!("enabled");
    Ok(())
}

fn cmd_cleanup(args: &CleanupArgs) -> Result<()> {
    let n = match &args.dir {
        Some(dir) => dirlock::convert::cleanup(dir)?,
        None => dirlock::convert::cleanup_all()?,
    };
    if n > 0 {
        println!("Removed {n} stale conversion entr{}", if n == 1 { "y" } else { "ies" });
    }
    Ok(())
}

fn cmd_status(args: &StatusArgs, ks: &Keystore) -> Result<()> {
    let Some(dir) = &args.dir else {
        if args.brief {
            bail!("The --brief option can only be used on a directory");
        }

        display_protector_list(ks)?;

        println!();
        cmd_list_policies(ks)?;

        println!();
        display_tpm_information()?;

        return Ok(());
    };

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
    match 2u32.checked_pow(encrypted_dir.policy.log2_data_unit_size as u32) {
        Some(1) => println!("Data unit: fs block size"),
        // The kernel says this should be within [2^9, fs block size],
        // we just report the raw values.
        Some(x) => println!("Data unit: {x} bytes"),
        None =>    println!("Data unit: 2^{} bytes",
                            encrypted_dir.policy.log2_data_unit_size),
    }

    if encrypted_dir.policy.flags.flags.is_empty() {
        println!("Flags: None");
    } else {
        println!("Flags: {}", encrypted_dir.policy.flags.flags);
    }

    println!("Recovery: {}", if encrypted_dir.recovery.is_some() { "yes" } else { "no" });
    display_protectors(&encrypted_dir.protectors);
    Ok(())
}

fn main() -> Result<()> {
    use Command::*;

    let args: Args = argh::from_env();

    dirlock::init()?;

    let ks = Keystore::default();

    match &args.command {
        Lock(args) => cmd_lock(args, &ks),
        Unlock(args) => cmd_unlock(args, &ks),
        ChangePass(args) => cmd_change_pass(args, &ks),
        Encrypt(args) => cmd_encrypt(args, &ks),
        Convert(args) => cmd_convert(args, &ks),
        Recovery(args) => match &args.command {
            RecoveryCommand::Add(args) => cmd_recovery_add(args, &ks),
            RecoveryCommand::Remove(args) => cmd_recovery_remove(args, &ks),
            RecoveryCommand::Restore(args) => cmd_recovery_restore(args, &ks),
            RecoveryCommand::Verify(args) => cmd_recovery_verify(args, &ks),
        },
        Status(args) => cmd_status(args, &ks),
        Admin(args) => match &args.command {
            AdminCommand::Policy(args) => match &args.command {
                PolicyCommand::List(_) => cmd_list_policies(&ks),
                PolicyCommand::Create(args) => cmd_create_policy(args, &ks),
                PolicyCommand::Remove(args) => cmd_remove_policy(args, &ks),
                PolicyCommand::Status(args) => cmd_policy_status(args, &ks),
                PolicyCommand::Purge(args) => cmd_policy_purge(args, &ks),
                PolicyCommand::AddProtector(args) => cmd_policy_add_protector(args, &ks),
                PolicyCommand::RemoveProtector(args) => cmd_policy_remove_protector(args, &ks),
            },
            AdminCommand::Protector(args) => match &args.command {
                ProtectorCommand::List(_) => display_protector_list(&ks),
                ProtectorCommand::Create(args) => cmd_create_protector(args, &ks),
                ProtectorCommand::Remove(args) => cmd_remove_protector(args, &ks),
                ProtectorCommand::VerifyPass(args) => cmd_verify_protector(args, &ks),
                ProtectorCommand::ChangePass(args) => cmd_change_protector_pass(args, &ks),
            },
            AdminCommand::Tpm2Test(_) => cmd_tpm2_test(&ks),
            AdminCommand::ExportMasterKey(args) => cmd_export_master_key(args, &ks),
            AdminCommand::ImportMasterKey(_) => cmd_import_master_key(&ks),
            AdminCommand::FscryptEnabled(args) => cmd_fscrypt_enabled(args),
            AdminCommand::Cleanup(args) => cmd_cleanup(args),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dirlock::util::push_test_password;
    use dirlock::{RemoveKeyUsers, RemovalStatusFlags};
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

    fn create_test_protector(ks: &Keystore, name: &str, password: &str) -> Result<ProtectorId> {
        let old_protlist = ks.protector_ids()?;
        push_test_password(password);
        cmd_create_protector(&ProtectorCreateArgs {
            type_: ProtectorType::Password,
            name: name.into(),
            kdf_iter: NonZeroU32::new(1),
            use_pin: None,
            user: None,
        }, ks)?;
        let new_protlist = ks.protector_ids()?;
        // Find the new protector
        let newprot = new_protlist.into_iter()
            .find(|id| !old_protlist.contains(id))
            .unwrap();
        Ok(newprot)
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
    fn test_encrypt_existing_protector() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        // Create an empty directory
        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        // Create two protectors
        let pass1 = "1234";
        let pass2 = "5678";
        let prot1_id = create_test_protector(&ks, "prot1", pass1)?;
        let prot2_id = create_test_protector(&ks, "prot2", pass2)?;

        // Encrypt a directory using the first protector
        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        push_test_password(pass1);
        cmd_encrypt(&EncryptArgs {
            protector: Some(prot1_id),
            protector_type: None,
            protector_name: None,
            user: None,
            dir: dir.path().into(),
        }, &ks)?;

        // Add the second protector to the policy
        let policy_id = ks.policy_key_ids()?[0].clone();
        push_test_password(pass2);
        push_test_password(pass1);
        cmd_policy_add_protector(&PolicyAddProtectorArgs {
            policy: policy_id,
            protector: prot2_id,
            unlock_with: Some(prot1_id),
        }, &ks)?;

        // Verify that the directory has both protectors
        let encrypted_dir = EncryptedDir::open(dir.path(), &ks, LockState::Unlocked)?;
        assert_eq!(encrypted_dir.protectors.usable.len(), 2);

        // Lock the directory
        let lock_args = LockArgs { dir: dir.path().into(), all_users: false };
        cmd_lock(&lock_args, &ks)?;

        // Unlock with each protector
        push_test_password(pass1);
        cmd_unlock(&UnlockArgs {
            dir: dir.path().into(),
            protector: Some(prot1_id),
            recovery: false
        }, &ks)?;
        cmd_lock(&lock_args, &ks)?;

        push_test_password(pass2);
        cmd_unlock(&UnlockArgs {
            dir: dir.path().into(),
            protector: Some(prot2_id),
            recovery: false
        }, &ks)?;
        cmd_lock(&lock_args, &ks)?;

        Ok(())
    }

    #[test]
    fn test_encrypt_non_empty() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        // Create a directory and put a file inside
        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        std::fs::write(dir.path().join("file.txt"), "hello")?;

        // Try to encrypt it: it should fail
        push_test_password("1234");
        let err = cmd_encrypt(&test_encrypt_args(dir.path()), &ks).unwrap_err();
        assert!(err.to_string().contains("not empty"), "unexpected error: {err}");

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

    #[test]
    fn test_change_pass() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        let old_password = "1234";
        let new_password = "5678";

        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        let lock_args = LockArgs { dir: dir.path().into(), all_users: false };
        let unlock_args = UnlockArgs { dir: dir.path().into(), protector: None, recovery: false };

        // Encrypt the directory and lock it
        push_test_password(old_password);
        cmd_encrypt(&test_encrypt_args(dir.path()), &ks)?;
        cmd_lock(&lock_args, &ks)?;

        // Change the password
        push_test_password(old_password);
        push_test_password(new_password);
        cmd_change_pass(&ChangePassArgs { protector: None, dir: dir.path().into() }, &ks)?;

        // Unlock with the new password
        push_test_password(new_password);
        cmd_unlock(&unlock_args, &ks)?;
        EncryptedDir::open(dir.path(), &ks, LockState::Unlocked)?;

        cmd_lock(&lock_args, &ks)?;

        // Unlocking with the old password should fail
        push_test_password(old_password);
        assert!(cmd_unlock(&unlock_args, &ks).is_err());

        Ok(())
    }

    #[test]
    fn test_recovery_add_remove() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        let lock_args = LockArgs { dir: dir.path().into(), all_users: false };

        let password = "1234";

        // Encrypt the directory and lock it
        push_test_password(password);
        cmd_encrypt(&test_encrypt_args(dir.path()), &ks)?;
        cmd_lock(&lock_args, &ks)?;

        // Add the recovery key
        push_test_password(password);
        cmd_recovery_add(&RecoveryAddArgs { protector: None, dir: dir.path().into() }, &ks)?;

        // Verify that the recovery key is present
        let encrypted_dir = EncryptedDir::open(dir.path(), &ks, LockState::Locked)?;
        assert!(encrypted_dir.recovery.is_some());

        // Remove the recovery key
        cmd_recovery_remove(&RecoveryRemoveArgs { dir: dir.path().into() }, &ks)?;

        // Verify that the recovery key is gone
        let encrypted_dir = EncryptedDir::open(dir.path(), &ks, LockState::Locked)?;
        assert!(encrypted_dir.recovery.is_none());

        Ok(())
    }

    #[test]
    fn test_recovery_verify() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        let password = "1234";

        // Encrypt the directory and lock it
        push_test_password(password);
        cmd_encrypt(&test_encrypt_args(dir.path()), &ks)?;
        cmd_lock(&LockArgs { dir: dir.path().into(), all_users: false }, &ks)?;

        // Add a recovery key using the library API so we can capture its value
        let mut encrypted_dir = EncryptedDir::open(dir.path(), &ks, LockState::Locked)?;
        let protkey = encrypted_dir.protectors.usable[0].protector
            .unwrap_key(password.as_bytes())?.unwrap();
        let recovery_key = encrypted_dir.add_recovery_key(&protkey)?;

        let verify_args = RecoveryVerifyArgs { dir: dir.path().into() };

        // Verify the correct recovery key
        push_test_password(&recovery_key.to_string());
        cmd_recovery_verify(&verify_args, &ks)?;

        // Try to verify the wrong recovery key (malformed key)
        push_test_password("wrong");
        assert!(cmd_recovery_verify(&verify_args, &ks).is_err());

        // Try to verify the wrong recovery key (valid but wrong key)
        push_test_password(&RecoveryKey::new_random().to_string());
        assert!(cmd_recovery_verify(&verify_args, &ks).is_err());

        Ok(())
    }

    #[test]
    fn test_recovery_restore() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        let lock_args = LockArgs { dir: dir.path().into(), all_users: false };
        let unlock_args = UnlockArgs { dir: dir.path().into(), protector: None, recovery: false };

        // Encrypt the directory and lock it
        let password = "1234";
        push_test_password(password);
        cmd_encrypt(&test_encrypt_args(dir.path()), &ks)?;
        cmd_lock(&lock_args, &ks)?;

        // Add a recovery key using the library API so we can capture its value
        let mut encrypted_dir = EncryptedDir::open(dir.path(), &ks, LockState::Locked)?;
        let protkey = encrypted_dir.protectors.usable[0].protector
            .unwrap_key(password.as_bytes())?.unwrap();
        let recovery_key = encrypted_dir.add_recovery_key(&protkey)?;

        // Replace the old keystore with a new, empty one
        let ks_dir = TempDir::new("new-keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        // Unlock should fail now
        push_test_password(password);
        assert!(cmd_unlock(&unlock_args, &ks).is_err());

        // The new keystore is empty but the recovery key xattr is still on the directory
        let new_password = "5678";
        push_test_password(&recovery_key.to_string());
        push_test_password(new_password);
        cmd_recovery_restore(&RecoveryRestoreArgs {
            protector_type: None,
            protector_name: Some("restored".into()),
            protector: None,
            user: None,
            dir: dir.path().into(),
        }, &ks)?;

        // Verify that the new password can unlock the directory
        push_test_password(new_password);
        cmd_unlock(&unlock_args, &ks)?;
        EncryptedDir::open(dir.path(), &ks, LockState::Unlocked)?;
        cmd_lock(&lock_args, &ks)?;

        Ok(())
    }

    #[test]
    fn test_unlock_recovery() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        let password = "1234";

        // Encrypt the directory and lock it
        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        let lock_args = LockArgs { dir: dir.path().into(), all_users: false };
        push_test_password(password);
        cmd_encrypt(&test_encrypt_args(dir.path()), &ks)?;
        cmd_lock(&lock_args, &ks)?;

        // Add a recovery key using the library API so we can capture its value
        let mut encrypted_dir = EncryptedDir::open(dir.path(), &ks, LockState::Locked)?;
        let protkey = encrypted_dir.protectors.usable[0].protector
            .unwrap_key(password.as_bytes())?.unwrap();
        let recovery_key = encrypted_dir.add_recovery_key(&protkey)?;

        // Unlock using --recovery
        push_test_password(&recovery_key.to_string());
        cmd_unlock(&UnlockArgs {
            dir: dir.path().into(),
            protector: None,
            recovery: true
        }, &ks)?;
        EncryptedDir::open(dir.path(), &ks, LockState::Unlocked)?;
        cmd_lock(&lock_args, &ks)?;

        // The recovery key is always accepted,
        // also when dirlock expects the password of the protector
        push_test_password(&recovery_key.to_string());
        cmd_unlock(&UnlockArgs {
            dir: dir.path().into(),
            protector: None,
            recovery: false
        }, &ks)?;
        EncryptedDir::open(dir.path(), &ks, LockState::Unlocked)?;
        cmd_lock(&lock_args, &ks)?;

        // But if we use --recovery explicitly
        // then the password won't unlock the directory
        push_test_password(&password);
        cmd_unlock(&UnlockArgs {
            dir: dir.path().into(),
            protector: None,
            recovery: true
        }, &ks).expect_err("unlock --recovery succeeded unexpectedly");
        EncryptedDir::open(dir.path(), &ks, LockState::Locked)?;

        Ok(())
    }

    #[test]
    fn test_admin_protector() -> Result<()> {
        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        let password = "1234";
        let new_password = "5678";

        // Create a protector
        assert!(ks.protector_ids()?.is_empty());
        let id = create_test_protector(&ks, "test", password)?;
        assert_eq!(ks.protector_ids()?.len(), 1);

        // Verify the password
        push_test_password(password);
        cmd_verify_protector(&ProtectorVerifyPassArgs { protector: Some(id) }, &ks)?;

        // Test an incorrect password
        push_test_password(new_password);
        assert!(cmd_verify_protector(&ProtectorVerifyPassArgs { protector: Some(id) }, &ks).is_err());

        // Change the password
        push_test_password(password);
        push_test_password(new_password);
        cmd_change_protector_pass(&ProtectorChangePassArgs { protector: Some(id) }, &ks)?;

        // Verify the new password
        push_test_password(new_password);
        cmd_verify_protector(&ProtectorVerifyPassArgs { protector: Some(id) }, &ks)?;

        // Test that the old password fails
        push_test_password(password);
        assert!(cmd_verify_protector(&ProtectorVerifyPassArgs { protector: Some(id) }, &ks).is_err());

        // Remove the protector
        cmd_remove_protector(&ProtectorRemoveArgs { protector: Some(id) }, &ks)?;
        assert!(ks.protector_ids()?.is_empty());

        Ok(())
    }

    #[test]
    fn test_admin_policy() -> Result<()> {
        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        // Create a protector
        let password = "1234";
        let protector_id = create_test_protector(&ks, "test", password)?;

        // Verify that the key store has no policies
        assert!(ks.policy_key_ids()?.is_empty());

        // Create a policy
        push_test_password(password);
        cmd_create_policy(&PolicyCreateArgs { protector: Some(protector_id) }, &ks)?;

        // Verify the policy was saved to the keystore
        assert_eq!(ks.policy_key_ids()?.len(), 1);

        // Remove the policy
        let policy_id = ks.policy_key_ids()?[0].clone();
        cmd_remove_policy(&PolicyRemoveArgs { policy: Some(policy_id), force: true }, &ks)?;

        // Verify the policy is gone
        assert!(ks.policy_key_ids()?.is_empty());

        Ok(())
    }

    #[test]
    fn test_admin_policy_purge() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        // Encrypt the directory
        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        push_test_password("1234");
        cmd_encrypt(&test_encrypt_args(dir.path()), &ks)?;

        // encrypt leaves the directory unlocked
        let encrypted_dir = EncryptedDir::open(dir.path(), &ks, LockState::Unlocked)?;
        assert_eq!(encrypted_dir.key_status, KeyStatus::Present);

        // purge removes the key from memory (locking the directory)
        cmd_policy_purge(&PolicyPurgeArgs {
            policy: Some(encrypted_dir.policy.keyid.clone()),
            mntpoint: dir.path().into()
        }, &ks)?;
        let encrypted_dir = EncryptedDir::open(dir.path(), &ks, LockState::Locked)?;
        assert_eq!(encrypted_dir.key_status, KeyStatus::Absent);

        Ok(())
    }

    #[test]
    fn test_admin_policy_add_remove_protector() -> Result<()> {
        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        let pass1 = "1234";
        let pass2 = "5678";

        // Create two protectors
        let prot1_id = create_test_protector(&ks, "prot1", pass1)?;
        let prot2_id = create_test_protector(&ks, "prot2", pass2)?;

        // Create a policy using prot1
        push_test_password(pass1);
        cmd_create_policy(&PolicyCreateArgs { protector: Some(prot1_id) }, &ks)?;
        let policy_id = ks.policy_key_ids()?[0].clone();

        // Add prot2 to the policy
        push_test_password(pass2); // 'policy add-protector' asks for pass2 first
        push_test_password(pass1);
        cmd_policy_add_protector(&PolicyAddProtectorArgs {
            policy: policy_id.clone(),
            protector: prot2_id,
            unlock_with: Some(prot1_id),
        }, &ks)?;

        // Check that both protectors are in the policy
        let policy = ks.load_policy_data(&policy_id)?;
        assert_eq!(policy.keys.len(), 2);
        assert!(policy.keys.contains_key(&prot1_id));
        assert!(policy.keys.contains_key(&prot2_id));

        // Remove prot1 from the policy
        cmd_policy_remove_protector(&PolicyRemoveProtectorArgs {
            policy: policy_id.clone(),
            protector: prot1_id,
        }, &ks)?;

        // Check that only prot2 remains
        let policy = ks.load_policy_data(&policy_id)?;
        assert_eq!(policy.keys.len(), 1);
        assert!(policy.keys.contains_key(&prot2_id));

        // Add prot1 back to the policy. This time we leave 'unlock_with' unset
        push_test_password(pass1);
        push_test_password(pass2);
        cmd_policy_add_protector(&PolicyAddProtectorArgs {
            policy: policy_id.clone(),
            protector: prot1_id,
            unlock_with: None,
        }, &ks)?;

        // Check that both protectors are in the policy
        let policy = ks.load_policy_data(&policy_id)?;
        assert_eq!(policy.keys.len(), 2);
        assert!(policy.keys.contains_key(&prot1_id));
        assert!(policy.keys.contains_key(&prot2_id));

        // With multiple protectors, adding a new one without 'unlock_with' should fail
        let pass3 = "abcd";
        let prot3_id = create_test_protector(&ks, "prot3", pass3)?;
        push_test_password(pass3);
        push_test_password(pass1);
        cmd_policy_add_protector(&PolicyAddProtectorArgs {
            policy: policy_id.clone(),
            protector: prot3_id,
            unlock_with: None,
        }, &ks).expect_err("Expected error calling add-protector without unlock-with");

        Ok(())
    }

    fn test_convert_args(dir: &Path, protid: Option<ProtectorId>) -> ConvertArgs {
        // If not using an existing protector, set a name
        let name = protid.is_none().then(|| "test1".to_string());
        ConvertArgs {
            protector_type: None,
            protector_name: name,
            protector: protid,
            user: None,
            force: true,
            dir: dir.into(),
        }
    }

    #[test]
    fn test_convert() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        // Create a directory with some files
        let dir = TempDir::new_in(&mntpoint, "convert")?;
        std::fs::write(dir.path().join("file.txt"), "hello")?;
        std::fs::create_dir(dir.path().join("subdir"))?;
        std::fs::write(dir.path().join("subdir/nested.txt"), "world")?;

        // Convert it to an encrypted directory
        let password = "1234";
        push_test_password(password);
        cmd_convert(&test_convert_args(dir.path(), None), &ks)?;

        // Verify that the directory is encrypted and unlocked
        let encrypted_dir = EncryptedDir::open(dir.path(), &ks, LockState::Unlocked)?;
        assert_eq!(encrypted_dir.protectors.usable.len(), 1);

        // Verify that the data was preserved
        assert_eq!(std::fs::read_to_string(dir.path().join("file.txt"))?, "hello");
        assert_eq!(std::fs::read_to_string(dir.path().join("subdir/nested.txt"))?, "world");

        // Lock and unlock to verify that the protector works
        let lock_args = LockArgs { dir: dir.path().into(), all_users: false };
        cmd_lock(&lock_args, &ks)?;
        EncryptedDir::open(dir.path(), &ks, LockState::Locked)?;

        push_test_password(password);
        cmd_unlock(&UnlockArgs { dir: dir.path().into(), protector: None, recovery: false }, &ks)?;
        EncryptedDir::open(dir.path(), &ks, LockState::Unlocked)?;

        // Verify the data again
        assert_eq!(std::fs::read_to_string(dir.path().join("file.txt"))?, "hello");
        assert_eq!(std::fs::read_to_string(dir.path().join("subdir/nested.txt"))?, "world");

        cmd_lock(&lock_args, &ks)?;

        Ok(())
    }

    #[test]
    fn test_convert_existing_protector() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        let password = "1234";
        let prot_id = create_test_protector(&ks, "prot", password)?;

        // Convert a directory with data using the existing protector
        let dir = TempDir::new_in(&mntpoint, "convert")?;
        std::fs::write(dir.path().join("data.txt"), "test data")?;

        push_test_password(password);
        cmd_convert(&test_convert_args(dir.path(), Some(prot_id)), &ks)?;

        // Verify that the directory is encrypted with the protector
        let encrypted_dir = EncryptedDir::open(dir.path(), &ks, LockState::Unlocked)?;
        assert_eq!(encrypted_dir.protectors.usable.len(), 1);
        assert!(encrypted_dir.protectors.usable[0].protector.id == prot_id);

        let lock_args = LockArgs { dir: dir.path().into(), all_users: false };
        cmd_lock(&lock_args, &ks)?;

        Ok(())
    }

    #[test]
    fn test_convert_empty_dir() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        // Converting an empty directory should fail
        let dir = TempDir::new_in(&mntpoint, "convert")?;
        push_test_password("1234");
        let err = cmd_convert(&test_convert_args(dir.path(), None), &ks).unwrap_err();
        assert!(err.to_string().contains("empty"), "unexpected error: {err}");

        Ok(())
    }

    #[test]
    fn test_convert_already_encrypted() -> Result<()> {
        let Some(mntpoint) = get_mntpoint()? else { return Ok(()) };

        let ks_dir = TempDir::new("keystore")?;
        let ks = Keystore::from_path(ks_dir.path());

        // Encrypt a directory first, then put a file in it
        let dir = TempDir::new_in(&mntpoint, "encrypted")?;
        push_test_password("1234");
        cmd_encrypt(&test_encrypt_args(dir.path()), &ks)?;
        std::fs::write(dir.path().join("file.txt"), "data")?;

        // Trying to convert an already-encrypted directory should fail
        push_test_password("5678");
        let err = cmd_convert(&test_convert_args(dir.path(), None), &ks).unwrap_err();
        assert!(err.to_string().contains("encrypted"), "unexpected error: {err}");

        Ok(())
    }
}
