
use anyhow::Result;
use std::io::Read;
use std::os::linux::fs::MetadataExt;
use argh::FromArgs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use fscrypt_rs::{fscrypt, linux};

#[derive(FromArgs)]
/// Disk encryption tool.
struct Args {
    #[argh(subcommand)]
    command: Command,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Command {
    GetPolicy(GetPolicyArgs),
    SetPolicy(SetPolicyArgs),
    KeyStatus(KeyStatusArgs),
    AddKey(AddKeyArgs),
    RemoveKey(RemoveKeyArgs),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "get-policy")]
/// Get the encryption policy for a directory
struct GetPolicyArgs {
    /// directory
    #[argh(positional)]
    dir: PathBuf
}

#[derive(FromArgs)]
#[argh(subcommand, name = "set-policy")]
/// Set an encryption policy on a directory
struct SetPolicyArgs {
    /// directory
    #[argh(positional)]
    dir: PathBuf,
    /// key id
    #[argh(positional)]
    keyid: String
}

#[derive(FromArgs)]
#[argh(subcommand, name = "key-status")]
/// Get the status of a key on a filesystem
struct KeyStatusArgs {
    /// mount point
    #[argh(positional)]
    mountpoint: PathBuf,
    /// key id
    #[argh(positional)]
    keyid: String
}

#[derive(FromArgs)]
#[argh(subcommand, name = "add-key")]
/// Add a key to a filesystem. The key is read from stdin and must be 64 bytes long.
struct AddKeyArgs {
    /// mount point
    #[argh(positional)]
    mountpoint: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "remove-key")]
/// Remove a key from a filesystem
struct RemoveKeyArgs {
    /// mount point
    #[argh(positional)]
    mountpoint: PathBuf,
    /// key id
    #[argh(positional)]
    keyid: String
}

fn get_mountpoint(dir: &Path) -> Result<std::path::PathBuf> {
    let mut current = dir.canonicalize()?;
    loop {
        let parent = current.parent().unwrap_or(&current);
        let md1 = std::fs::metadata(&current)?;
        let md2 = std::fs::metadata(parent)?;
        if md2.st_ino() == md1.st_ino() || md2.st_dev() != md1.st_dev() {
            return Ok(current);
        }
        current.pop();
    }
}

fn cmd_get_policy(args: &GetPolicyArgs) -> Result<()> {
    match fscrypt::get_policy(&args.dir)? {
        None => println!("Directory not encrypted"),
        Some(fscrypt::Policy::V1(p)) => println!("Policy v1, key id: {}", p.master_key_descriptor),
        Some(fscrypt::Policy::V2(p)) => println!("Policy v2, key id: {}", p.master_key_identifier),
        Some(fscrypt::Policy::Unknown(v)) => println!("Encrypted with unknown policy ({v})"),
    };

    Ok(())
}

fn cmd_set_policy(args: &SetPolicyArgs) -> Result<()> {
    let keyid = fscrypt::KeyIdentifier::try_from(args.keyid.as_str())?;
    fscrypt::set_policy(&args.dir, &keyid)?;
    println!("Set policy {} in directory {}", args.keyid, &args.dir.display());
    Ok(())
}

fn cmd_key_status(args: &KeyStatusArgs) -> Result<()> {
    let keyid = fscrypt::KeyIdentifier::try_from(args.keyid.as_str())?;
    let mnt = get_mountpoint(&args.mountpoint)?;
    let (status, flags) = fscrypt::get_key_status(&mnt, &keyid)?;
    println!("Got status of key {} in directory {}: {:?}", &args.keyid, mnt.display(), status);
    if flags.contains(fscrypt::KeyStatusFlags::AddedBySelf) {
        println!("(key added by self)");
    }
    Ok(())
}

fn cmd_add_key(args: &AddKeyArgs) -> Result<()> {
    let mut key = Zeroizing::new([0; linux::FSCRYPT_MAX_KEY_SIZE + 1]);
    let keylen = std::io::stdin().read(&mut key[..])?;
    let keyid = fscrypt::add_key(&args.mountpoint, &key[0..keylen])?;
    println!("Added key {} to directory {}", keyid, args.mountpoint.display());
    Ok(())
}

fn cmd_remove_key(args: &RemoveKeyArgs) -> Result<()> {
    let keyid = fscrypt::KeyIdentifier::try_from(args.keyid.as_str())?;
    fscrypt::remove_key(&args.mountpoint, &keyid, fscrypt::RemoveKeyUsers::CurrentUser)?;
    println!("Removed key {} from directory {}", &args.keyid, args.mountpoint.display());
    Ok(())
}

fn main() -> Result<()> {
    use Command::*;

    let args: Args = argh::from_env();

    match &args.command {
        GetPolicy(args) => cmd_get_policy(args),
        SetPolicy(args) => cmd_set_policy(args),
        KeyStatus(args) => cmd_key_status(args),
        AddKey(args)    => cmd_add_key(args),
        RemoveKey(args) => cmd_remove_key(args),
    }
}
