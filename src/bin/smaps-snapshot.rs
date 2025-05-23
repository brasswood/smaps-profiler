/* Copyright 2025 Andrew Riachi
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 only.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

use std::{collections::BinaryHeap, fs, io::{self, Write}, path::PathBuf};

use clap::Parser;
use env_logger::Builder;
use log::LevelFilter;
use regex::Regex;
use untitled_smaps_poller::{get_processes, get_smaps, sum_memory, MemoryExt, ProcListing};

#[derive(Parser)]
#[command(version, about = "Takes a snapshot of a program's memory usage categories using /proc/<pid>/smaps.", long_about = None)]
struct Args {
    ///Regex to match process cmdline against
    regex: Option<Regex>,

    ///If --regex is given, include children of matched processes, even if they don't match.
    #[arg(short = 'c', long, requires = "regex")]
    match_children: bool,

    ///Match the process for this program.
    #[arg(short = 's', long, default_value_t = false)]
    match_self: bool,

    ///Fail if permission is denied to read a process's info. Default behavior is to skip the
    ///process and continue running.
    #[arg(short, long)]
    fail_on_noperm: bool,

    ///File to output info to (stdout if unspecified)
    #[arg(short, long)]
    output: Option<PathBuf>,

    ///Print warnings to stderr
    #[arg(short = 'w', long)]
    show_warnings: bool,
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    if args.show_warnings {
        Builder::from_default_env()
            .filter_level(LevelFilter::Warn)
            .init();
    } else {
        env_logger::init();
    }
    let procs = get_processes(
        &args.regex,
        args.match_children,
        args.match_self,
        args.fail_on_noperm,
    )
    .unwrap();
    let procs = get_smaps(procs, args.fail_on_noperm).unwrap();
    match args.output {
        Some(path) => write_out(procs, fs::File::open(path)?),
        None => write_out(procs, io::stdout()),
    }
}

fn write_out<T: Write>(procs: Vec<ProcListing>, out: T) -> io::Result<()> {
    let summary = sum_memory(&procs);
    let summary_stats: BinaryHeap<()>
    Ok(())
}