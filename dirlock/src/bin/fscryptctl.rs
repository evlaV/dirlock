/*
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

use anyhow::{ensure, Result};
use std::io::Read;
use argh::FromArgs;
use std::path::PathBuf;

use dirlock::fscrypt::{self, PolicyKeyId};

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
    keyid: PolicyKeyId
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
    keyid: PolicyKeyId
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
    keyid: PolicyKeyId
}

fn cmd_get_policy(args: &GetPolicyArgs) -> Result<()> {
    match fscrypt::get_policy(&args.dir)? {
        None => println!("Directory not encrypted"),
        Some(fscrypt::Policy::V1(p)) => println!("Policy v1, key id: {}", p.keyid),
        Some(fscrypt::Policy::V2(p)) => println!("Policy v2, key id: {}", p.keyid),
        Some(fscrypt::Policy::Unknown(v)) => println!("Encrypted with unknown policy ({v})"),
    };

    Ok(())
}

fn cmd_set_policy(args: &SetPolicyArgs) -> Result<()> {
    fscrypt::set_policy(&args.dir, &args.keyid)?;
    println!("Set policy {} in directory {}", args.keyid, &args.dir.display());
    Ok(())
}

fn cmd_key_status(args: &KeyStatusArgs) -> Result<()> {
    let (status, flags) = fscrypt::get_key_status(&args.mountpoint, &args.keyid)?;
    println!("Got status of key {} in directory {}: {:?}", &args.keyid, args.mountpoint.display(), status);
    if flags.contains(fscrypt::KeyStatusFlags::AddedBySelf) {
        println!("(key added by self)");
    }
    Ok(())
}

fn cmd_add_key(args: &AddKeyArgs) -> Result<()> {
    let mut stdin = std::io::stdin();
    let key = fscrypt::PolicyKey::new_from_reader(&mut stdin)?;
    ensure!(stdin.read(&mut [0])? == 0, "Too much data when reading key from stdin");
    let keyid = fscrypt::add_key(&args.mountpoint, &key)?;
    println!("Added key {} to directory {}", keyid, args.mountpoint.display());
    Ok(())
}

fn cmd_remove_key(args: &RemoveKeyArgs) -> Result<()> {
    fscrypt::remove_key(&args.mountpoint, &args.keyid, fscrypt::RemoveKeyUsers::CurrentUser)?;
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
