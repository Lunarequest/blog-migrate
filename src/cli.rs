use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(author="nullrequest",version="0.1",about, long_about = None)]
pub struct Cli {
    pub path: Option<PathBuf>,
}
