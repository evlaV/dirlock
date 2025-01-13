
use anyhow::{anyhow, bail, ensure, Result};
use argh::FromArgs;
use std::path::PathBuf;
use fscrypt_rs::{fscrypt, config};
use fscrypt_rs::protector::{Protector, PasswordProtector};

#[derive(FromArgs)]
/// Disk encryption tool.
struct Args {
    #[argh(subcommand)]
    command: Command,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Command {
    Lock(LockArgs),
    Unlock(UnlockArgs),
    Encrypt(EncryptArgs),
    Status(StatusArgs),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "lock")]
/// Lock a directory
struct LockArgs {
    /// directory
    #[argh(positional)]
    dir: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "unlock")]
/// Unlock a directory
struct UnlockArgs {
    /// directory
    #[argh(positional)]
    dir: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "encrypt")]
/// Encrypt a directory
struct EncryptArgs {
    /// directory
    #[argh(positional)]
    dir: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "status")]
/// Get the status of a directory
struct StatusArgs {
    /// directory
    #[argh(positional)]
    dir: PathBuf,
}

fn cmd_lock(args: &LockArgs) -> Result<()> {
    let keyid = match fscrypt::get_policy(&args.dir)? {
        Some(fscrypt::Policy::V2(p)) => p.master_key_identifier,
        Some(_) => bail!("Unsupported policy version"),
        None => bail!("{} is not encrypted", args.dir.display()),
    };

    let (status, _) = fscrypt::get_key_status(&args.dir, &keyid)?;
    ensure!(status != fscrypt::KeyStatus::Absent,
            "Directory {} is already locked", args.dir.display());

    let flags = fscrypt::remove_key(&args.dir, &keyid, fscrypt::RemoveKeyUsers::CurrentUser)?;

    if flags.contains(fscrypt::RemovalStatusFlags::FilesBusy) {
        println!("Key removed, but some files are still busy");
    };

    if flags.contains(fscrypt::RemovalStatusFlags::OtherUsers) {
        println!("Only this user's claim was removed");
    };

    Ok(())
}

fn cmd_unlock(args: &UnlockArgs) -> Result<()> {
    let keyid = match fscrypt::get_policy(&args.dir)? {
        Some(fscrypt::Policy::V2(p)) => p.master_key_identifier,
        Some(_) => bail!("Directory {} is encrypted with an unsupported fscrypt policy", args.dir.display()),
        None => bail!("Directory {} is not encrypted", args.dir.display()),
    };

    let (status, _) = fscrypt::get_key_status(&args.dir, &keyid)?;
    ensure!(status == fscrypt::KeyStatus::Absent,
            "Directory {} is already unlocked", args.dir.display());

    let cfg = config::Config::new_from_file()
        .map_err(|e| anyhow!("Failed to read config: {e}"))?;
    let Some(prot) = cfg.get_protector(&keyid) else {
        bail!("No key found for directory {}", args.dir.display());
    };

    eprint!("Enter encryption password: ");
    let pass = rpassword::read_password()?;

    let key = prot.decrypt(pass.as_bytes());
    let new_id = key.get_id();
    ensure!(new_id == keyid, "Wrong password");

    fscrypt::add_key(&args.dir, &key)?;

    Ok(())
}

fn cmd_encrypt(args: &EncryptArgs) -> Result<()> {
    if fscrypt::get_policy(&args.dir)?.is_some() {
        bail!("Directory {} is already encrypted", args.dir.display());
    }
    let key = fscrypt::RawKey::new_random();
    let keyid = fscrypt::add_key(&args.dir, &key)?;
    fscrypt::set_policy(&args.dir, &keyid)?;

    eprint!("Enter encryption password: ");
    let pass1 = rpassword::read_password()?;
    eprint!("Repeat encryption password: ");
    let pass2 = rpassword::read_password()?;
    ensure!(pass1 == pass2, "Passwords don't match");

    let prot = PasswordProtector::new(&key, pass1.as_bytes())?;

    let mut cfg = config::Config::new_from_file()
        .map_err(|e| anyhow!("Failed to read config: {e}"))?;
    cfg.add_protector(&keyid, Protector::Password(prot));
    cfg.save().map_err(|e| anyhow!("Failed to save config: {e}"))?;

    Ok(())
}

fn cmd_status(args: &StatusArgs) -> Result<()> {
    let Some(policy) = fscrypt::get_policy(&args.dir)? else {
        println!("Not encrypted");
        return Ok(());
    };

    match policy {
        fscrypt::Policy::V1(_) => println!("Encrypted with policy v1"),
        fscrypt::Policy::V2(p) => {
            let (status, _) = fscrypt::get_key_status(&args.dir, &p.master_key_identifier)?;
            println!("Encrypted with policy v2, key id {}", p.master_key_identifier);
            println!("Key status: {:?}", status);
        },
        fscrypt::Policy::Unknown(_) => println!("Encrypted with an unknown policy"),
    }

    Ok(())
}

fn main() -> Result<()> {
    use Command::*;

    let args: Args = argh::from_env();

    match &args.command {
        Lock(args) => cmd_lock(args),
        Unlock(args) => cmd_unlock(args),
        Encrypt(args) => cmd_encrypt(args),
        Status(args) => cmd_status(args),
    }
}
