use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "janus",
    version,
    about = "GitHub SSH key-based encryption with LINE-style group key management"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Encrypt a message for GitHub users or a group
    Encrypt {
        /// GitHub usernames to encrypt for
        #[arg(short = 't', long = "to", required_unless_present = "group")]
        recipients: Vec<String>,

        /// Group name to encrypt for
        #[arg(short, long, conflicts_with = "recipients")]
        group: Option<String>,

        /// Message to encrypt (reads from stdin if not provided)
        message: Option<String>,

        /// Output file (writes to stdout if not provided)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Use ASCII armor (text-safe output)
        #[arg(short, long, conflicts_with = "group")]
        armor: bool,
    },

    /// Decrypt a message using an SSH private key or a group key
    Decrypt {
        /// Path to SSH private key
        #[arg(short = 'i', long = "identity", conflicts_with = "group")]
        identity: Option<PathBuf>,

        /// Group name to decrypt with
        #[arg(short, long)]
        group: Option<String>,

        /// Input file (reads from stdin if not provided)
        #[arg(long)]
        input: Option<PathBuf>,

        /// Output file (writes to stdout if not provided)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Manage groups
    #[command(subcommand)]
    Group(GroupCommand),
}

#[derive(Subcommand)]
pub enum GroupCommand {
    /// Create a new group with a shared key
    Create {
        /// Group name
        name: String,

        /// GitHub usernames of group members
        #[arg(short, long = "members", required = true, num_args = 1..)]
        members: Vec<String>,
    },

    /// Import a group's shared key
    Import {
        /// Group name
        name: String,

        /// Path to SSH private key for decryption
        #[arg(short = 'i', long = "identity")]
        identity: Option<PathBuf>,
    },

    /// List all known groups
    List,

    /// Show details of a group
    Show {
        /// Group name
        name: String,
    },

    /// Rotate the group key with a new member list
    Rotate {
        /// Group name
        name: String,

        /// New GitHub usernames of group members
        #[arg(short, long = "members", required = true, num_args = 1..)]
        members: Vec<String>,
    },
}
