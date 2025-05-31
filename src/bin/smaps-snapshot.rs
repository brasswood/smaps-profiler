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

use crate::{MemCategory::*, Tag::*};
use clap::Parser;
use env_logger::Builder;
use log::{info, LevelFilter};
use regex::{Error::*, Regex};
use std::{
    cmp::{Ordering, Reverse},
    fs,
    io::{self, BufWriter, Write},
    path::PathBuf,
    process,
};
use untitled_smaps_poller::{
    get_processes, get_smaps, sum_memory, FMask, MMPermissions, MemCategory, MemoryExt, ProcListing,
};

#[derive(Parser)]
#[command(version, about = "Takes a snapshot of a program's memory usage categories using /proc/<pid>/smaps.", long_about = None)]
struct Args {
    ///Regex to match process cmdline against
    regex: Option<String>,

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

    ///A string of any combination of the characters "bfrwxsp" that specifies the mask to use
    ///when aggregating file-backed mappings. An empty string here (created by passing "-m=")
    ///will cause all of the mappings be aggregated into one entry. If the option is not present,
    ///the default behavior will be the same as passing "frwxsp".
    #[arg(short, long)]
    mask: Option<String>,

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

fn delete(s: &mut String, c: char) -> bool {
    if let Some(i) = s.find(c) {
        s.remove(i);
        true
    } else {
        false
    }
}

fn get_mask(mut s: String) -> Result<FMask, ()> {
    let is_self = delete(&mut s, 'b');
    let path = delete(&mut s, 'f');
    let mut perms = MMPermissions::NONE;
    perms.set(MMPermissions::READ, delete(&mut s, 'r'));
    perms.set(MMPermissions::WRITE, delete(&mut s, 'w'));
    perms.set(MMPermissions::EXECUTE, delete(&mut s, 'x'));
    perms.set(MMPermissions::SHARED, delete(&mut s, 's'));
    perms.set(MMPermissions::PRIVATE, delete(&mut s, 'p'));
    if s.is_empty() {
        Ok(FMask::new(is_self, path, perms))
    } else {
        Err(())
    }
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
    let mask = match args.mask {
        Some(s) => match get_mask(s.clone()) {
            Ok(m) => m,
            Err(_) => {
                eprintln!("Invalid mask \"{s}\"");
                process::exit(1)
            }
        },
        None => FMask::new(false, true, MMPermissions::all()),
    };
    let regex = &args.regex.map(|r| {
        match Regex::new(r.as_str()) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{e}");
                process::exit(1)
            },
        }
    });
    let procs = get_processes(
        &regex,
        args.match_children,
        args.match_self,
        args.fail_on_noperm,
    )
    .unwrap();
    if procs.is_empty() {
        match regex {
            Some(r) => println!("No processes match \"{r}\"."),
            None => println!("No processes found."),
        };
        return Ok(());
    }
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
            write_out_all(&mut writer, procs, &mask, width as usize)
        }
        None => {
            let mut writer = BufWriter::new(io::stdout().lock());
            write_out_all(&mut writer, procs, &mask, width as usize)
        }
    }
}

fn display_perms(perms: MMPermissions, mask: MMPermissions) -> String {
    let mut res = String::with_capacity(4);
    if perms.contains(MMPermissions::READ) {
        res.push('r');
    } else if mask.contains(MMPermissions::READ) {
        res.push('-');
    }
    if perms.contains(MMPermissions::WRITE) {
        res.push('w');
    } else if mask.contains(MMPermissions::WRITE) {
        res.push('-');
    }
    if perms.contains(MMPermissions::EXECUTE) {
        res.push('x');
    } else if mask.contains(MMPermissions::EXECUTE) {
        res.push('-');
    }
    if perms.contains(MMPermissions::SHARED) {
        res.push('s');
    } else if mask.contains(MMPermissions::SHARED) {
        res.push('-');
    }
    if perms.contains(MMPermissions::PRIVATE) {
        res.push('p');
    } else if mask.contains(MMPermissions::PRIVATE) {
        res.push('-');
    }
    res
}

fn chop_str(s: &str, width: usize) -> Vec<String> {
    // https://users.rust-lang.org/t/solved-how-to-split-string-into-multiple-sub-strings-with-given-length/10542/2
    let mut v = vec![];
    for s in s.split('\n') {
        let mut cur = s;
        while !cur.is_empty() {
            let (chunk, rest) = cur.split_at(cur.len().min(width));
            v.push(chunk.to_string());
            cur = rest;
        }
    }
    v
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Tag {
    Small,
    Normal(MemCategory),
}

impl Tag {
    fn constructor_rank(&self) -> u8 {
        match self {
            Normal(Stack) => 0,
            Normal(Heap) => 1,
            Normal(TStack) => 2,
            Normal(Vdso) => 3,
            Normal(Vvar) => 4,
            Normal(Vsyscall) => 5,
            Normal(Anonymous) => 6,
            Normal(Vsys) => 7,
            Small => 8,
            Normal(Other(_)) => 9,
            Normal(File(_)) => 10,
        }
    }
}

impl Ord for Tag {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.constructor_rank().cmp(&other.constructor_rank()) {
            Ordering::Equal => {
                let (Normal(l), Normal(r)) = (self, other) else {
                    return Ordering::Equal;
                };
                match (l, r) {
                    (Other(l), Other(r)) => l.cmp(r),
                    (File(l), File(r)) => {
                        (&l.path, Reverse(l.masked_perms)).cmp(&(&r.path, Reverse(r.masked_perms)))
                    }
                    _ => Ordering::Equal,
                }
            }
            o => o,
        }
    }
}

impl PartialOrd for Tag {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Item {
    percent: u8,
    pss: u64,
    tag: Tag,
}

impl Item {
    fn new(percent: u8, pss: u64, tag: Tag) -> Item {
        Item { percent, pss, tag }
    }
}

impl Ord for Item {
    fn cmp(&self, other: &Self) -> Ordering {
        (Reverse(self.pss), &self.tag).cmp(&(Reverse(other.pss), &other.tag))
    }
}

impl PartialOrd for Item {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn category_to_label(cat: MemCategory, perms_mask: MMPermissions) -> String {
    match cat {
        File(f) => {
            let path = match &f.path {
                Some(path) => path.to_str().unwrap_or("<path not unicode>"),
                None => "File-Backed Mappings",
            };
            let is_self = match &f.is_self {
                Some(b) => {
                    if *b {
                        "(original executable)".to_string()
                    } else {
                        "(external)".to_string()
                    }
                },
                None => String::new()
            };
            format!("{path} {} {is_self}", display_perms(f.masked_perms, perms_mask))
        }
        Heap => "Heap".to_string(),
        Stack => "Stack".to_string(),
        TStack => "Thread Stack".to_string(),
        Vdso => "Vdso".to_string(),
        Vvar => "Vvar".to_string(),
        Vsyscall => "Vsyscall".to_string(),
        Anonymous => "Anonymous Mappings".to_string(),
        Vsys => "Vsys".to_string(),
        Other(s) if s.is_empty() => "<other unnamed mapping>".to_string(),
        Other(s) => s,
    }
}

fn write_out<T, U>(
    out: &mut T,
    mem: MemoryExt,
    file_mask: &FMask,
    width: usize,
    mut header_hook: U,
) -> io::Result<()>
where
    T: Write,
    U: FnMut(&mut T, u64, usize) -> io::Result<()>,
{
    let total_mem = mem.total();
    if total_mem == 0 {
        return Ok(());
    }
    let mut items: Vec<Item> = Vec::new();
    let mut small_total = 0;
    for (cat, pss) in mem.iter_aggregate(file_mask) {
        // there's a cleverer way to do this but I don't know it
        let tenths_percent = pss * 1000 / total_mem;
        let percent = tenths_percent / 10 + if tenths_percent % 10 >= 5 { 1 } else { 0 };
        if tenths_percent < 5 {
            small_total += pss;
        }
        items.push(Item::new(percent as u8, pss, Normal(cat)));
    }
    let tenths_percent = small_total * 1000 / total_mem;
    let percent = tenths_percent / 10 + if tenths_percent % 10 >= 5 { 1 } else { 0 };
    items.push(Item::new(percent as u8, small_total, Small));
    items.sort_unstable();
    const MIN_PATH: usize = 20;
    const PERCENT: usize = 4;
    const SEPS: usize = 2;
    let u64_digits = (items.first().unwrap().pss.max(1).ilog10() + 1) as usize;
    let width_nopath = PERCENT + u64_digits + 2 * SEPS;
    let width = width.max(width_nopath + MIN_PATH);
    let path_width = width - width_nopath;
    header_hook(out, total_mem, width)?;
    let mut small_header_printed = false;
    for Item { percent, pss, tag } in items {
        let label;
        match tag {
            Normal(cat) => {
                label = category_to_label(cat, file_mask.perms);
                if percent == 0 && !small_header_printed {
                    for s in chop_str("Small categories (<0.5%):", width) {
                        writeln!(out, "{}", s)?;
                    }
                    small_header_printed = true;
                }
            }
            Small => {
                label = "<small categories>".to_string();
            }
        }
        let chunks = chop_str(&label, path_width);
        let chunk = &chunks[0];
        writeln!(out, "{percent:3}%  {pss:u64_digits$}  {chunk:path_width$}")?;
        for chunk in &chunks[1..] {
            writeln!(out, "{}{}", " ".repeat(width_nopath), chunk)?;
        }
    }
    Ok(())
}

fn write_out_all<T: Write>(
    out: &mut T,
    mut procs: Vec<ProcListing>,
    file_mask: &FMask,
    width: usize,
) -> io::Result<()> {
    procs.sort_unstable_by_key(|p| Reverse(p.memory_ext.total()));
    let all = sum_memory(&procs);
    let header_hook = |out: &mut T, total, width| {
        let header = chop_str(
            &format!("Summary ({} processes)\nTotal: {total} bytes", procs.len()),
            width,
        );
        writeln!(out, "{}", "-".repeat(width))?;
        for line in header {
            writeln!(out, "{}", line)?;
        }
        writeln!(out, "{}", "-".repeat(width))
    };
    write_out(out, all, file_mask, width, header_hook)?;
    for proc in procs {
        let header_hook = |out: &mut T, total, width| {
            let header = chop_str(
                &format!("PID {}\n{}\nTotal: {total} bytes", proc.pid, proc.cmdline),
                width,
            );
            writeln!(out, "{}", "-".repeat(width))?;
            for line in header {
                writeln!(out, "{}", line)?;
            }
            writeln!(out, "{}", "-".repeat(width))
        };
        write_out(out, proc.memory_ext, file_mask, width, header_hook)?;
    }
    Ok(())
}
