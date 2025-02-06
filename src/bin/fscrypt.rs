
use anyhow::{bail, ensure, Result};
use argh::FromArgs;
use std::path::PathBuf;
use fscrypt_rs::{fscrypt, config};
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
    let cfg = config::Config::new_from_file()?;
    let flags = fscrypt_rs::lock_dir(&args.dir, &cfg)?;

    if flags.contains(fscrypt::RemovalStatusFlags::FilesBusy) {
        println!("Key removed, but some files are still busy");
    };

    if flags.contains(fscrypt::RemovalStatusFlags::OtherUsers) {
        println!("Only this user's claim was removed");
    };

    Ok(())
}

fn cmd_unlock(args: &UnlockArgs) -> Result<()> {
    use fscrypt_rs::DirStatus::*;

    let cfg = config::Config::new_from_file()?;
    match fscrypt_rs::get_encrypted_dir_data(&args.dir, &cfg)? {
        Encrypted(d) if d.key_status == fscrypt::KeyStatus::Present =>
            bail!("The directory {} is already unlocked", args.dir.display()),
        Encrypted(_) => (),
        x => bail!("{}", x),
    };

    eprint!("Enter encryption password: ");
    let pass = Zeroizing::new(rpassword::read_password()?);

    fscrypt_rs::unlock_dir(&args.dir, pass.as_bytes(), &cfg)
}

fn cmd_encrypt(args: &EncryptArgs) -> Result<()> {
    let mut cfg = config::Config::new_from_file()?;
    match fscrypt_rs::get_encrypted_dir_data(&args.dir, &cfg)? {
        fscrypt_rs::DirStatus::Unencrypted => (),
        x => bail!("{}", x),
    };

    eprint!("Enter encryption password: ");
    let pass1 = Zeroizing::new(rpassword::read_password()?);
    eprint!("Repeat encryption password: ");
    let pass2 = Zeroizing::new(rpassword::read_password()?);
    ensure!(pass1 == pass2, "Passwords don't match");

    let keyid = fscrypt_rs::encrypt_dir(&args.dir, pass1.as_bytes(), &mut cfg)?;
    println!("{}", keyid);

    Ok(())
}

fn cmd_status(args: &StatusArgs) -> Result<()> {
    use fscrypt_rs::DirStatus::*;
    use fscrypt::KeyStatus::*;

    let cfg = config::Config::new_from_file()?;
    let dir_data = match fscrypt_rs::get_encrypted_dir_data(&args.dir, &cfg)? {
        Encrypted(d) => d,
        x => {
            println!("{x}");
            return Ok(());
        }
    };

    let locked = match dir_data.key_status {
        Absent => "locked",
        Present => "unlocked",
        IncompletelyRemoved => "partially locked",
    };
    println!("Encrypted, {locked} (key id {})", dir_data.policy.keyid);

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
