
use anyhow::{bail, ensure, Result};
use argh::FromArgs;
use std::io::{self, Write};
use std::path::PathBuf;
use dirlock::{fscrypt, util};
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
    ChangePass(ChangePassArgs),
    Encrypt(EncryptArgs),
    ExportMasterKey(ExportMasterKeyArgs),
    ImportMasterKey(ImportMasterKeyArgs),
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
#[argh(subcommand, name = "change-password")]
/// Change the encryption password of a directory
struct ChangePassArgs {
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
#[argh(subcommand, name = "export-master-key")]
/// Export the master encryption key of a given directory
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
/// Get the status of a directory
struct StatusArgs {
    /// directory
    #[argh(positional)]
    dir: PathBuf,
}

fn cmd_lock(args: &LockArgs) -> Result<()> {
    use dirlock::DirStatus::*;

    let dir_data = match dirlock::get_encrypted_dir_data(&args.dir)? {
        Encrypted(d) if d.key_status == fscrypt::KeyStatus::Absent =>
            bail!("The directory {} is already locked", args.dir.display()),
        Encrypted(d) => d,
        x => bail!("{}", x),
    };

    let flags = dirlock::lock_dir(&dir_data)?;

    if flags.contains(fscrypt::RemovalStatusFlags::FilesBusy) {
        println!("Key removed, but some files are still busy");
    };

    if flags.contains(fscrypt::RemovalStatusFlags::OtherUsers) {
        println!("Only this user's claim was removed");
    };

    Ok(())
}

fn cmd_unlock(args: &UnlockArgs) -> Result<()> {
    use dirlock::{DirStatus::*, UnlockAction};

    let dir_data = match dirlock::get_encrypted_dir_data(&args.dir)? {
        Encrypted(d) if d.key_status == fscrypt::KeyStatus::Present =>
            bail!("The directory {} is already unlocked", args.dir.display()),
        Encrypted(d) => d,
        x => bail!("{}", x),
    };

    eprint!("Enter encryption password: ");
    let pass = Zeroizing::new(rpassword::read_password()?);

    if ! dirlock::unlock_dir(&dir_data, pass.as_bytes(), UnlockAction::AuthAndUnlock)? {
        bail!("Unable to unlock directory {}: wrong password", args.dir.display())
    }

    Ok(())
}

fn cmd_change_pass(args: &ChangePassArgs) -> Result<()> {
    use dirlock::{DirStatus::*, UnlockAction};

    let mut dir_data = match dirlock::get_encrypted_dir_data(&args.dir)? {
        Encrypted(d) => d,
        x => bail!("{}", x),
    };

    eprint!("Enter the current password: ");
    let pass = Zeroizing::new(rpassword::read_password()?);

    if ! dirlock::unlock_dir(&dir_data, pass.as_bytes(), UnlockAction::AuthOnly)? {
        bail!("Password not valid for directory {}", args.dir.display())
    }

    eprint!("Enter the new password: ");
    let npass1 = Zeroizing::new(rpassword::read_password()?);
    eprint!("Repeat the new password: ");
    let npass2 = Zeroizing::new(rpassword::read_password()?);
    ensure!(npass1 == npass2, "Passwords don't match");

    if ! dirlock::change_dir_password(&mut dir_data, pass.as_bytes(), npass1.as_bytes())? {
        bail!("Unable to change the password for directory {}", args.dir.display())
    }

    Ok(())
}

fn cmd_encrypt(args: &EncryptArgs) -> Result<()> {
    match dirlock::get_encrypted_dir_data(&args.dir)? {
        dirlock::DirStatus::Unencrypted => (),
        x => bail!("{}", x),
    };

    let empty_dir = util::dir_is_empty(&args.dir)?;

    if args.force && !empty_dir {
        println!("You are about to encrypt a directory that contains data.");
        println!("This feature is *experimental*. Make sure that you are not");
        println!("accessing the files while they are being encrypted in order");
        println!("to avoid unexpected behaviors.");
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
        println!("Encrypting the contents of {}, this can take a while", args.dir.display());
        dirlock::convert::convert_dir(&args.dir, pass1.as_bytes())?
    } else {
        dirlock::encrypt_dir(&args.dir, pass1.as_bytes())?
    };
    println!("{}", keyid);

    Ok(())
}

fn cmd_export_master_key(args: &ExportMasterKeyArgs) -> Result<()> {
    use base64::prelude::*;
    let dir_data = match dirlock::get_encrypted_dir_data(&args.dir)? {
        dirlock::DirStatus::Encrypted(d) => d,
        x => {
            println!("{x}");
            return Ok(());
        }
    };

    eprintln!("This will print to stdout the master key with ID {}", dir_data.policy.keyid);
    eprintln!("- This is the encryption key for directory {}", args.dir.display());
    eprintln!("- This feature is only available while this tool is under development");
    eprintln!("- The printed key is *raw and unprotected*, you are reponsible for keeping it safe");
    eprintln!();
    eprint!("Enter the current encryption password: ");
    let pass = Zeroizing::new(rpassword::read_password()?);

    for (_, prot, policykey) in &dir_data.protectors {
        if let Some(master_key) = prot.decrypt(policykey, pass.as_bytes()) {
            println!("{}", BASE64_STANDARD.encode(master_key.secret()));
            return Ok(());
        }
    }

    Err(anyhow::anyhow!("Unable to unlock master key for directory {}", args.dir.display()))
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
    use dirlock::DirStatus::*;
    use fscrypt::KeyStatus::*;

    let dir_data = match dirlock::get_encrypted_dir_data(&args.dir)? {
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
        ChangePass(args) => cmd_change_pass(args),
        Encrypt(args) => cmd_encrypt(args),
        ExportMasterKey(args) => cmd_export_master_key(args),
        ImportMasterKey(_) => cmd_import_master_key(),
        Status(args) => cmd_status(args),
    }
}
