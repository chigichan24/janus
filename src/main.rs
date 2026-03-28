use std::error::Error;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process;

use clap::Parser;

mod cli;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        let mut source = e.source();
        while let Some(cause) = source {
            eprintln!("  caused by: {cause}");
            source = cause.source();
        }
        process::exit(1);
    }
}

fn run() -> Result<(), janus::JanusError> {
    let cli = cli::Cli::parse();

    match cli.command {
        cli::Command::Encrypt {
            recipients,
            group,
            message,
            output,
            armor,
        } => cmd_encrypt(recipients, group, message, output, armor),
        cli::Command::Decrypt {
            identity,
            group,
            input,
            output,
        } => cmd_decrypt(identity, group, input, output),
        cli::Command::Group(cmd) => match cmd {
            cli::GroupCommand::Create { name, members } => cmd_group_create(&name, &members),
            cli::GroupCommand::Import { name, identity } => cmd_group_import(&name, identity),
            cli::GroupCommand::List => cmd_group_list(),
            cli::GroupCommand::Show { name } => cmd_group_show(&name),
            cli::GroupCommand::Rotate { name, members } => cmd_group_rotate(&name, &members),
        },
    }
}

fn read_plaintext(message: Option<String>) -> Result<Vec<u8>, janus::JanusError> {
    match message {
        Some(msg) => Ok(msg.into_bytes()),
        None => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

fn write_output(output: Option<PathBuf>, data: &[u8]) -> Result<(), janus::JanusError> {
    match output {
        Some(path) => std::fs::write(path, data)?,
        None => io::stdout().write_all(data)?,
    }
    Ok(())
}

fn read_input(input: Option<PathBuf>) -> Result<Vec<u8>, janus::JanusError> {
    match input {
        Some(path) => Ok(std::fs::read(path)?),
        None => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

fn expand_tilde(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    path.to_path_buf()
}

fn default_identity() -> PathBuf {
    expand_tilde(&PathBuf::from("~/.ssh/id_ed25519"))
}

fn repo_root() -> Result<PathBuf, janus::JanusError> {
    std::env::current_dir().map_err(janus::JanusError::from)
}

fn cmd_encrypt(
    recipients: Vec<String>,
    group: Option<String>,
    message: Option<String>,
    output: Option<PathBuf>,
    armor: bool,
) -> Result<(), janus::JanusError> {
    let plaintext = read_plaintext(message)?;

    let ciphertext = if let Some(group_name) = group {
        let group = janus::group::load(&group_name, &repo_root()?)?;
        janus::encrypt_for_group(&group, &plaintext)?
    } else if !recipients.is_empty() {
        let ssh_recipients = janus::github::fetch_all_recipients(&recipients)?;
        if armor {
            return write_output(
                output,
                janus::encrypt_armor(&ssh_recipients, &plaintext)?.as_bytes(),
            );
        }
        janus::encrypt(&ssh_recipients, &plaintext)?
    } else {
        return Err(janus::JanusError::Config(
            "specify --to <user> or --group <name>".into(),
        ));
    };

    write_output(output, &ciphertext)
}

fn cmd_decrypt(
    identity: Option<PathBuf>,
    group: Option<String>,
    input: Option<PathBuf>,
    output: Option<PathBuf>,
) -> Result<(), janus::JanusError> {
    let ciphertext = read_input(input)?;

    let plaintext = if let Some(group_name) = group {
        janus::decrypt_with_group(&group_name, &ciphertext)?
    } else {
        let id_path = identity
            .map(|p| expand_tilde(&p))
            .unwrap_or_else(default_identity);
        janus::decrypt(&id_path, &ciphertext)?
    };

    write_output(output, &plaintext)
}

fn cmd_group_create(name: &str, members: &[String]) -> Result<(), janus::JanusError> {
    let group = janus::group::create(name, members, &repo_root()?)?;
    eprintln!(
        "created group '{}' with {} members",
        group.name,
        group.members.len()
    );
    eprintln!("public key: {}", group.public_key);
    eprintln!();
    eprintln!("next steps:");
    eprintln!("  git add .janus/groups/{name}/");
    eprintln!("  git commit -m \"add group {name}\"");
    eprintln!("  git push");
    eprintln!();
    eprintln!("members can then run: janus group import {name}");
    Ok(())
}

fn cmd_group_import(name: &str, identity: Option<PathBuf>) -> Result<(), janus::JanusError> {
    let id_path = identity
        .map(|p| expand_tilde(&p))
        .unwrap_or_else(default_identity);
    janus::group::import(name, &id_path, &repo_root()?)?;
    eprintln!("imported group key for '{name}'");
    Ok(())
}

fn cmd_group_list() -> Result<(), janus::JanusError> {
    let root = repo_root()?;
    let groups_dir = root.join(".janus").join("groups");
    if !groups_dir.exists() {
        eprintln!("no groups found");
        return Ok(());
    }

    for entry in std::fs::read_dir(&groups_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let meta_path = entry.path().join("meta.toml");
            if meta_path.exists() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Ok(group) = janus::group::load(&name, &root) {
                    println!(
                        "{} ({} members: {})",
                        group.name,
                        group.members.len(),
                        group.members.join(", ")
                    );
                }
            }
        }
    }
    Ok(())
}

fn cmd_group_show(name: &str) -> Result<(), janus::JanusError> {
    let group = janus::group::load(name, &repo_root()?)?;
    println!("name: {}", group.name);
    println!("public_key: {}", group.public_key);
    println!("members: {}", group.members.join(", "));
    println!("created_at: {}", group.created_at);
    Ok(())
}

fn cmd_group_rotate(name: &str, members: &[String]) -> Result<(), janus::JanusError> {
    let group = janus::group::rotate(name, members, &repo_root()?)?;
    eprintln!(
        "rotated group '{}' with {} members",
        group.name,
        group.members.len()
    );
    eprintln!("new public key: {}", group.public_key);
    eprintln!();
    eprintln!("next steps:");
    eprintln!("  git add .janus/groups/{name}/");
    eprintln!("  git commit -m \"rotate group {name}\"");
    eprintln!("  git push");
    eprintln!();
    eprintln!("all members must re-import: janus group import {name}");
    Ok(())
}
