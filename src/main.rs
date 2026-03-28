use std::error::Error;
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
        cli::Command::Encrypt { .. } => {
            todo!("encrypt command")
        }
        cli::Command::Decrypt { .. } => {
            todo!("decrypt command")
        }
        cli::Command::Group(cmd) => match cmd {
            cli::GroupCommand::Create { .. } => {
                todo!("group create command")
            }
            cli::GroupCommand::Import { .. } => {
                todo!("group import command")
            }
            cli::GroupCommand::List => {
                todo!("group list command")
            }
            cli::GroupCommand::Show { .. } => {
                todo!("group show command")
            }
            cli::GroupCommand::Rotate { .. } => {
                todo!("group rotate command")
            }
        },
    }
}
