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

fn expand_tilde(path: &Path) -> Result<PathBuf, janus::JanusError> {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        let home = std::env::var("HOME").map_err(|_| {
            janus::JanusError::Config("HOME environment variable is not set".into())
        })?;
        return Ok(PathBuf::from(home).join(rest));
    }
    Ok(path.to_path_buf())
}

fn default_identity() -> Result<PathBuf, janus::JanusError> {
    expand_tilde(Path::new("~/.ssh/id_ed25519"))
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

    let ciphertext: Vec<u8> = if let Some(group_name) = group {
        let group = janus::group::load(&group_name, &repo_root()?)?;
        janus::encrypt_for_group(&group, &plaintext)?
    } else {
        let ssh_recipients = janus::github::fetch_all_recipients(&recipients)?;
        if armor {
            janus::encrypt_armor(&ssh_recipients, &plaintext)?.into_bytes()
        } else {
            janus::encrypt(&ssh_recipients, &plaintext)?
        }
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
        let id_path = match identity {
            Some(p) => expand_tilde(&p)?,
            None => default_identity()?,
        };
        janus::decrypt(&id_path, &ciphertext)?
    };

    write_output(output, &plaintext)
}

enum GroupAction {
    Created,
    Rotated,
}

impl GroupAction {
    fn label(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Rotated => "rotated",
        }
    }
}

fn print_group_result(group: &janus::Group, action: GroupAction) {
    let name = &group.name;
    let label = action.label();
    eprintln!(
        "{label} group '{name}' with {} members",
        group.members.len()
    );
    match action {
        GroupAction::Rotated => eprintln!("new public key: {}", group.public_key),
        GroupAction::Created => eprintln!("public key: {}", group.public_key),
    }
    eprintln!();
    eprintln!("next steps:");
    eprintln!("  git add .janus/groups/{name}/");
    eprintln!("  git commit -m \"{label} group {name}\"");
    eprintln!("  git push");
    eprintln!();
    match action {
        GroupAction::Rotated => {
            eprintln!("all members must re-import: janus group import {name}");
        }
        GroupAction::Created => {
            eprintln!("members can then run: janus group import {name}");
        }
    }
}

fn cmd_group_create(name: &str, members: &[String]) -> Result<(), janus::JanusError> {
    let group = janus::group::create(name, members, &repo_root()?)?;
    print_group_result(&group, GroupAction::Created);
    Ok(())
}

fn cmd_group_import(name: &str, identity: Option<PathBuf>) -> Result<(), janus::JanusError> {
    let id_path = match identity {
        Some(p) => expand_tilde(&p)?,
        None => default_identity()?,
    };
    janus::group::import(name, &id_path, &repo_root()?)?;
    eprintln!("imported group key for '{name}'");
    Ok(())
}

fn cmd_group_list() -> Result<(), janus::JanusError> {
    let groups = janus::group::list(&repo_root()?)?;
    if groups.is_empty() {
        eprintln!("no groups found");
        return Ok(());
    }
    for group in &groups {
        println!(
            "{} ({} members: {})",
            group.name,
            group.members.len(),
            group.members.join(", ")
        );
    }
    Ok(())
}

fn cmd_group_show(name: &str) -> Result<(), janus::JanusError> {
    let group = janus::group::load(name, &repo_root()?)?;
    println!("name: {}", group.name);
    println!("public_key: {}", group.public_key);
    println!("members: {}", group.members.join(", "));
    if let Some(ts) = group.created_at {
        println!("created_at: {ts}");
    }
    Ok(())
}

fn cmd_group_rotate(name: &str, members: &[String]) -> Result<(), janus::JanusError> {
    let group = janus::group::rotate(name, members, &repo_root()?)?;
    print_group_result(&group, GroupAction::Rotated);
    Ok(())
}
