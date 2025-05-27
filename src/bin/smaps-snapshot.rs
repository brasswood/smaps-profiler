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

use std::{
    cmp::Ordering,
    collections::BinaryHeap,
    fs,
    io::{self, BufWriter, Write},
    path::PathBuf,
};

use clap::Parser;
use env_logger::Builder;
use log::{info, LevelFilter};
use procfs::process::MMPermissions;
use regex::Regex;
use untitled_smaps_poller::{
    get_processes, get_smaps, sum_memory, FileMapping, MemCategory, MemoryExt, ProcListing,
};

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

    ///Print info messages
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    if args.verbose {
        Builder::from_default_env()
            .filter_level(LevelFilter::Info)
            .init();
    } else if args.show_warnings {
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
    let width = match terminal_size::terminal_size() {
        Some((w, _)) => w.0,
        None => {
            const DEFAULT: u16 = 80;
            info!("terminal width not found, defaulting to {DEFAULT}");
            DEFAULT
        }
    };
    match args.output {
        Some(path) => {
            let mut writer = BufWriter::new(fs::File::open(path)?);
            write_out_all(&mut writer, procs, width as usize)
        }
        None => {
            let mut writer = BufWriter::new(io::stdout().lock());
            write_out_all(&mut writer, procs, width as usize)
        }
    }
}

#[derive(Eq)]
struct Field(MemCategory, u64);
impl PartialEq for Field {
    fn eq(&self, other: &Self) -> bool {
        self.1 == other.1
    }
}
impl PartialOrd for Field {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.1.partial_cmp(&other.1)
    }
}
impl Ord for Field {
    fn cmp(&self, other: &Self) -> Ordering {
        self.1.cmp(&other.1)
    }
}

fn display_perms(perms: MMPermissions) -> String {
    let mut res = String::with_capacity(4);
    if perms.contains(MMPermissions::READ) {
        res.push('r');
    } else {
        res.push('-');
    }
    if perms.contains(MMPermissions::WRITE) {
        res.push('w');
    } else {
        res.push('-');
    }
    if perms.contains(MMPermissions::EXECUTE) {
        res.push('x');
    } else {
        res.push('-');
    }
    if perms.contains(MMPermissions::SHARED) {
        res.push('s');
    } else if perms.contains(MMPermissions::PRIVATE) {
        res.push('p');
    } else {
        res.push('-');
    }
    res
}

fn chop_str(s: &str, width: usize) -> Vec<String> {
    // https://users.rust-lang.org/t/solved-how-to-split-string-into-multiple-sub-strings-with-given-length/10542/2
    let mut v = vec![];
    let mut cur = s;
    while !cur.is_empty() {
        let (chunk, rest) = cur.split_at(cur.len().min(width));
        v.push(chunk.to_string());
        cur = rest;
    }
    v
}

fn write_out<T, U, V>(
    out: &mut T,
    mem: MemoryExt,
    width: usize,
    mut header_hook: U,
    mut footer_hook: V,
) -> io::Result<()>
where
    T: Write,
    U: FnMut(&mut T, usize) -> io::Result<()>,
    V: FnMut(&mut T, usize) -> io::Result<()>,
{
    // TODO: should I do the above ceremony just to get it into a binary heap, or should
    // I just use Vec::sort_by?
    let mut fields = BinaryHeap::new();
    let mut total_mem = 0;
    for (cat, pss) in mem.iter() {
        total_mem += pss;
        fields.push(Field(cat, pss))
    }
    const MIN_PATH: usize = 20;
    const PERCENT: usize = 4;
    const SEPS: usize = 2;
    let u64_digits = (fields.peek().unwrap().1.ilog10() + 1) as usize;
    let width_nopath = PERCENT + u64_digits + 2 * SEPS;
    let width = width.max(width_nopath + MIN_PATH);
    let path_width = width - width_nopath;
    header_hook(out, width)?;
    for Field(cat, pss) in fields {
        let percent = (pss / 100) + if pss % 100 >= 50 { 1 } else { 0 };
        let path = match cat {
            MemCategory::File(FileMapping {
                is_self: _,
                path,
                perms,
            }) => {
                let path_str = format!(
                    "{} {}",
                    path.to_str().unwrap_or("<path not unicode>"),
                    display_perms(perms)
                );
                chop_str(&path_str, path_width)
            }
            MemCategory::Heap => vec!["Heap".to_string()],
            MemCategory::Stack => vec!["Stack".to_string()],
            MemCategory::TStack => vec!["Thread Stack".to_string()],
            MemCategory::Vdso => vec!["Vdso".to_string()],
            MemCategory::Vvar => vec!["Vvar".to_string()],
            MemCategory::Vsyscall => vec!["Vsyscall".to_string()],
            MemCategory::Anonymous => vec!["Anonymous Mappings".to_string()],
            MemCategory::Vsys => vec!["Vsys".to_string()],
            MemCategory::Other(s) => chop_str(&s, path_width),
        };
        let chunk = path.first().map_or("<blank>", |v| v);
        writeln!(out, "{percent:3}%  {pss:u64_digits$}  {chunk:path_width$}")?;
        for chunk in &path[1..] {
            writeln!(out, "{}{}", " ".repeat(width_nopath), chunk)?;
        }
    }
    writeln!(out, "Total: {total_mem} bytes")?;
    footer_hook(out, width)
}

fn write_out_all<T: Write>(out: &mut T, procs: Vec<ProcListing>, width: usize) -> io::Result<()> {
    let all = sum_memory(&procs);
    let header_hook = |out: &mut T, width| {
        writeln!(out, "Summary (all processes)")?;
        writeln!(out, "{}", "-".repeat(width))
    };
    let footer_hook = |out: &mut T, width| writeln!(out, "{}", "-".repeat(width));
    write_out(out, all, width, header_hook, footer_hook)?;
    for proc in procs {
        let header_hook = |out: &mut T, width| {
            let header = chop_str(&format!("(PID {}, {})", proc.pid, proc.cmdline), width);
            for line in header {
                writeln!(out, "{}", line)?;
            }
            writeln!(out, "{}", "-".repeat(width))
        };
        write_out(out, proc.memory_ext, width, header_hook, footer_hook)?;
    }
    Ok(())
}
