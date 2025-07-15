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

use clap::Parser;
use env_logger::Builder;
use gnuplot::TickOption::Mirror;
use gnuplot::XAxis::X1;
use gnuplot::YAxis::Y2;
use gnuplot::{
    AutoOption::*, AxesCommon, ColorType, Coordinate::*, DashType::*, Figure, LegendOption::*,
    PlotOption::*, RGBString,
};
use log::{warn, LevelFilter};
use serde::ser::SerializeStruct;
use serde::Serialize;
use signal_hook::consts::signal::SIGINT;
use signal_hook::flag as signal_flag;
use smaps_profiler::{
    add_maps, get_processes, get_smaps, FMask, Faults, MMPermissions, MaskedFileMapping, MemoryExt,
    ProcListing,
};
use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

// TODO: Summing the output from this program appears to underestimate memory usage by ~20kB
// compared to smaps_rollup. Gotta figure out why.
// TODO: x-axis on graph is somewhat broken. Need to record the time that a sample was taken and
// print that on stdout and use that as the x position in the graph.
#[derive(Parser)]
#[command(version, about = "Reports process stack, heap, text, and data memory usage. Output is in bytes.", long_about = None)]
struct Args {
    ///Regex to match process cmdline against
    regex: Option<String>,

    ///If --regex is given, include children of matched processes, even if they don't match the
    ///regex.
    #[arg(short = 'c', long, requires = "regex")]
    match_children: bool,

    ///Match the process for this program.
    #[arg(short = 's', long, default_value_t = false)]
    match_self: bool,

    ///Refresh interval in seconds
    #[arg(short, long, default_value_t = 1.0_f64)]
    interval: f64,

    ///Fail if permission is denied to read a process's info. Default behavior is to skip the
    ///process and continue running.
    #[arg(short, long)]
    fail_on_noperm: bool,

    ///Output newline delimited JSON instead of TSV to stdout
    #[arg(short, long)]
    json: bool,

    ///Save graph as SVG to <FILE>
    #[arg(short, long, value_name = "FILE")]
    graph: Option<PathBuf>,

    ///Graph major + minor page faults (only affects graph, not TSV or JSON)
    #[arg(short = 'm', long, requires = "graph")]
    graph_faults: bool,

    ///Print warnings to stderr
    #[arg(short = 'w', long)]
    show_warnings: bool,
}

// http://vrl.cs.brown.edu/color
const _PALETTE1: [ColorType<&str>; 20] = [
    RGBString("#35618f"),
    RGBString("#61a3dc"),
    RGBString("#7244b9"),
    RGBString("#26cdca"),
    RGBString("#1c875c"),
    RGBString("#ade47c"),
    RGBString("#707b5d"),
    RGBString("#3fd34a"),
    RGBString("#709f0f"),
    RGBString("#c5c9b4"),
    RGBString("#88502e"),
    RGBString("#fd5925"),
    RGBString("#8e1023"),
    RGBString("#eac328"),
    RGBString("#ed3e7e"),
    RGBString("#fb9fa8"),
    RGBString("#f7931e"),
    RGBString("#a18ff8"),
    RGBString("#bf11af"),
    RGBString("#f27ff5"),
];

const _PALETTE2: [ColorType<&str>; 20] = [
    RGBString("#48bf8e"),
    RGBString("#8a0458"),
    RGBString("#93c920"),
    RGBString("#7125bd"),
    RGBString("#65f112"),
    RGBString("#fd2c3b"),
    RGBString("#1b511d"),
    RGBString("#ef4cd0"),
    RGBString("#40b8e1"),
    RGBString("#73350e"),
    RGBString("#f1cbd5"),
    RGBString("#26496d"),
    RGBString("#c6dbae"),
    RGBString("#3447b4"),
    RGBString("#f7d153"),
    RGBString("#ca81e6"),
    RGBString("#83976d"),
    RGBString("#87a9fd"),
    RGBString("#cd6810"),
    RGBString("#ea7c97"),
];

const PALETTE3: [ColorType<&str>; 20] = [
    RGBString("#58b5e1"),
    RGBString("#76295f"),
    RGBString("#c0e15c"),
    RGBString("#b825af"),
    RGBString("#55f17b"),
    RGBString("#e32851"),
    RGBString("#15dec5"),
    RGBString("#852405"),
    RGBString("#b5ceaa"),
    RGBString("#0e503e"),
    RGBString("#f6b0ec"),
    RGBString("#658114"),
    RGBString("#5425df"),
    RGBString("#fad139"),
    RGBString("#1c4585"),
    RGBString("#3aa609"),
    RGBString("#fa79f5"),
    RGBString("#6d4c2b"),
    RGBString("#fcb790"),
    RGBString("#7377ec"),
];

const _PALETTE4: [ColorType<&str>; 20] = [
    RGBString("#a1def0"),
    RGBString("#8b123a"),
    RGBString("#4dc172"),
    RGBString("#e3488e"),
    RGBString("#73f02e"),
    RGBString("#ae4acd"),
    RGBString("#add51f"),
    RGBString("#333a9e"),
    RGBString("#fcd107"),
    RGBString("#2b3fff"),
    RGBString("#cddb9b"),
    RGBString("#de19f7"),
    RGBString("#056e12"),
    RGBString("#cc99d9"),
    RGBString("#6e390d"),
    RGBString("#3d99ce"),
    RGBString("#f24219"),
    RGBString("#145a6a"),
    RGBString("#fc8f3b"),
    RGBString("#447cfe"),
];

const PALETTE: [ColorType<&str>; 20] = PALETTE3;

#[derive(Debug, Clone, Copy)]
struct Interval {
    ///Duration since program start
    start: Duration,
    ///Duration since this interval's start
    duration: Duration,
}

impl Interval {
    ///Duration since program start of the end of this interval
    fn end(&self) -> Duration {
        self.start + self.duration
    }
}

impl Serialize for Interval {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Interval", 2)?;
        state.serialize_field("start_millis", &self.start.as_millis())?;
        state.serialize_field("end_millis", &self.end().as_millis())?;
        state.end()
    }
}

#[derive(Clone, Debug, Serialize)]
struct SimpleProcListing {
    pid: i32,
    ppid: i32,
    cmdline: String,
    faults: Faults,
    memory: SimpleMemory,
}

impl From<ProcListing> for SimpleProcListing {
    fn from(proc: ProcListing) -> Self {
        SimpleProcListing {
            pid: proc.pid,
            ppid: proc.ppid,
            cmdline: proc.cmdline,
            faults: proc.faults,
            memory: proc.memory_ext.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Default)]
struct SimpleMemory {
    stack: u64,
    heap: u64,
    thread_stack: u64,
    bin_text: u64,
    lib_text: u64,
    bin_data: u64,
    lib_data: u64,
    anon_mappings: u64,
    vdso: u64,
    vvar: u64,
    vsyscall: u64,
    vsys: u64,
    other: HashMap<String, u64>,
}

impl From<MemoryExt> for SimpleMemory {
    fn from(mem: MemoryExt) -> Self {
        let files = get_aggregated(&mem);
        SimpleMemory {
            stack: mem.stack_pss,
            heap: mem.heap_pss,
            thread_stack: mem.thread_stack_pss,
            bin_text: files.bin_text,
            lib_text: files.lib_text,
            bin_data: files.bin_data,
            lib_data: files.lib_data,
            anon_mappings: mem.anon_map_pss,
            vdso: mem.vdso_pss,
            vvar: mem.vvar_pss,
            vsyscall: mem.vsyscall_pss,
            vsys: mem.vsys_pss,
            other: mem.other_map,
        }
    }
}

impl std::ops::Add<&SimpleMemory> for SimpleMemory {
    type Output = SimpleMemory;

    fn add(self, rhs: &SimpleMemory) -> SimpleMemory {
        SimpleMemory {
            stack: self.stack + rhs.stack,
            heap: self.heap + rhs.heap,
            thread_stack: self.thread_stack + rhs.thread_stack,
            bin_text: self.bin_text + rhs.bin_text,
            lib_text: self.lib_text + rhs.lib_text,
            bin_data: self.bin_data + rhs.bin_data,
            lib_data: self.lib_data + rhs.lib_data,
            anon_mappings: self.anon_mappings + rhs.anon_mappings,
            vdso: self.vdso + rhs.vdso,
            vvar: self.vvar + rhs.vvar,
            vsyscall: self.vsyscall + rhs.vvar,
            vsys: self.vsys + rhs.vsys,
            other: add_maps(self.other, &rhs.other),
        }
    }
}

impl std::iter::Sum for SimpleMemory {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|l, r| l + &r).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct FileCategoryTotals {
    bin_text: u64,
    lib_text: u64,
    bin_data: u64,
    lib_data: u64,
}

fn get_aggregated(mem: &MemoryExt) -> FileCategoryTotals {
    let aggregated = mem.aggregate_file_maps(&FMask::new(true, false, MMPermissions::EXECUTE));
    FileCategoryTotals {
        bin_text: *aggregated
            .get(&MaskedFileMapping::new(
                Some(true),
                None,
                MMPermissions::EXECUTE,
            ))
            .unwrap_or(&0),
        lib_text: *aggregated
            .get(&MaskedFileMapping::new(
                Some(false),
                None,
                MMPermissions::EXECUTE,
            ))
            .unwrap_or(&0),
        bin_data: *aggregated
            .get(&MaskedFileMapping::new(
                Some(true),
                None,
                MMPermissions::NONE,
            ))
            .unwrap_or(&0),
        lib_data: *aggregated
            .get(&MaskedFileMapping::new(
                Some(false),
                None,
                MMPermissions::NONE,
            ))
            .unwrap_or(&0),
    }
}

#[derive(Debug, Clone, Serialize)]
struct Message {
    interval: Interval,
    all: SimpleMemory,
    procs: Vec<SimpleProcListing>,
    acc_faults: Faults,
}

impl Message {
    fn new(procs: Vec<ProcListing>, interval: Interval, acc_faults: Faults) -> Message {
        let procs: Vec<SimpleProcListing> = procs.into_iter().map(|p| p.into()).collect();
        Message {
            interval,
            all: procs.iter().map(|p| p.memory.clone()).sum(),
            procs,
            acc_faults,
        }
    }
}

fn main() -> io::Result<()> {
    // Design: incrementally gather the data we need from each process
    // get_processes: () -> [{pid, ppid, cmdline, Process}]
    // get_smaps: [{pid, ppid, cmdline, Process}] -> [{pid, ppid, cmdline, memory_ext}], where the
    // open Process is used by get_smaps to get memory_ext, then dropped in the resulting struct.
    //
    // This isn't super extensible, e.g., if I want to make it so the user can pick which columns
    // are shown, then there has to at least be a type for every possible combination of
    // columns, and then possibly a unique function for every possible type that could be used as
    // input. But I get some special guarantee from the typechecker here. For instance, one way to
    // make the struct more flexible with the user choice of columns is to have a sturct
    // {pid, ppid, cmdline, Option<memory_ext>, Option<other_field>, etc...}
    // We lose a guarantee from this: that in a list of these structs, either memory_ext is defined
    // for all of the elements or it's defined for none of them. The first type does provide that
    // guarantee, though. Another possibility is to make get_smaps return [memory_ext] instead, but
    // then there's no inherent guarantee from the signature alone that the length of that list is
    // the same as the length of the input list. At least, I know of no way to do this in Rust.
    let program_start = Instant::now();
    let args = Args::parse();
    if args.show_warnings {
        Builder::from_default_env()
            .filter_level(LevelFilter::Warn)
            .init();
    } else {
        env_logger::init();
    }
    let target_duration = Duration::try_from_secs_f64(args.interval).unwrap();
    let re = args.regex.map(|s| regex::Regex::new(&s).unwrap());
    let mut all_messages: Option<Vec<Message>> = args.graph.as_ref().map(|_| Vec::new());
    let term = Arc::new(AtomicBool::new(false));
    signal_flag::register(SIGINT, Arc::clone(&term))?;
    let mut pid_faults_map = HashMap::new();
    while !term.load(Ordering::Relaxed) {
        let start = program_start.elapsed();
        let procs = get_processes(
            &re,
            args.match_children,
            args.match_self,
            args.fail_on_noperm,
        )
        .unwrap();
        let procs = get_smaps(procs, args.fail_on_noperm).unwrap();
        let interval = Interval {
            start,
            duration: program_start.elapsed() - start,
        };
        update_faults_map(&mut pid_faults_map, &procs);
        let acc_faults = pid_faults_map.values().copied().sum();
        let message = Message::new(procs, interval.clone(), acc_faults);
        // do this first
        if args.json {
            print_json(&message)?;
        } else {
            print_tsv(&message)?;
        }
        // do this second due to moving
        if let Some(all_messages) = &mut all_messages {
            all_messages.push(message);
        }
        let now_elapsed = program_start.elapsed() - interval.start;
        if now_elapsed < target_duration {
            thread::sleep(target_duration - now_elapsed);
        } else if now_elapsed > target_duration {
            warn!(
                "polling smaps and writing data took {}s, overran configured interval of {}s",
                now_elapsed.as_secs_f64(),
                target_duration.as_secs_f64()
            );
        }
    } // end loop

    // generate graph
    if let Some(path) = args.graph {
        graph_memory(all_messages.unwrap(), args.graph_faults, path);
    }
    Ok(())
}

fn update_faults_map(map: &mut HashMap<i32, Faults>, procs: &Vec<ProcListing>) {
    // Each process already keeps a running total, so just replace counts for existing
    // processes in the map. If new pids appear, they will be added to the map.
    // This will only be wrong if a process dies and then a new one appears with
    // the same pid.
    for proc in procs {
        map.insert(proc.pid, proc.faults);
    }
}

fn print_tsv(message: &Message) -> io::Result<()> {
    // https://rust-cli.github.io/book/tutorial/output.html#a-note-on-printing-performance
    let mut writer = BufWriter::new(io::stdout().lock());
    writeln!(&mut writer, "PID\tSTACK_PSS\tHEAP_PSS\tTHREAD_STACK_PSS\tBIN_TEXT_PSS\tLIB_TEXT_PSS\tBIN_DATA_PSS\tLIB_DATA_PSS\tANON_MAP_PSS\tVDSO_PSS\tVVAR_PSS\tVSYSCALL_PSS\tSHM_PSS\tOTHER_PSS\tMIN_FAULTS\tMAJ_FAULTS\tCMD")?;
    for proc_listing in &message.procs {
        let SimpleProcListing {
            pid,
            cmdline,
            memory,
            faults,
            ..
        } = proc_listing;
        let SimpleMemory {
            stack,
            heap,
            thread_stack,
            bin_text,
            lib_text,
            bin_data,
            lib_data,
            anon_mappings,
            vdso,
            vvar,
            vsyscall,
            vsys,
            other,
        } = memory;
        let Faults {
            minor: min_faults,
            major: maj_faults,
        } = faults;
        let other: u64 = other.values().sum();
        writeln!(&mut writer, "{pid}\t{stack}\t{heap}\t{thread_stack}\t{bin_text}\t{lib_text}\t{bin_data}\t{lib_data}\t{anon_mappings}\t{vdso}\t{vvar}\t{vsyscall}\t{vsys}\t{other}\t{min_faults}\t{maj_faults}\t{cmdline}")?;
    }
    writer.flush()
}

fn print_json(messages: &Message) -> io::Result<()> {
    let mut writer = BufWriter::new(io::stdout().lock());
    let s = serde_json::to_string(messages).unwrap();
    writeln!(&mut writer, "{s}")?;
    writer.flush()
}

fn graph_memory(messages: Vec<Message>, graph_faults: bool, out: PathBuf) {
    if messages.is_empty() {
        eprintln!("Nothing to plot.");
    }
    let empty_vec: Vec<u64> = Vec::with_capacity(messages.len());
    let mut stack_series = empty_vec.clone();
    let mut heap_series = empty_vec.clone();
    let mut thread_stack_series = empty_vec.clone();
    let mut bin_text_series = empty_vec.clone();
    let mut lib_text_series = empty_vec.clone();
    let mut bin_data_series = empty_vec.clone();
    let mut lib_data_series = empty_vec.clone();
    let mut anon_map_series = empty_vec.clone();
    let mut vdso_series = empty_vec.clone();
    let mut vvar_series = empty_vec.clone();
    let mut vsyscall_series = empty_vec.clone();
    let mut vsys_series = empty_vec.clone();
    // want a BTreeMap here to make the order of categories as consistent as possible in final graph
    let mut other_series = BTreeMap::new();
    let mut faults_series = graph_faults.then(|| empty_vec.clone());
    let mut zero_series = Vec::new();
    let mut xs: Vec<f64> = Vec::with_capacity(messages.len());
    for message in messages {
        let time = message.interval.start.as_secs_f64();
        xs.push(time);

        // do this first because the next operation will move it
        if let Some(faults_series) = &mut faults_series {
            faults_series.push(message.acc_faults.total());
        }

        // aggregate processes
        let all = message.all;
        stack_series.push(all.stack);
        heap_series.push(all.heap);
        thread_stack_series.push(all.thread_stack);
        bin_text_series.push(all.bin_text);
        lib_text_series.push(all.lib_text);
        bin_data_series.push(all.bin_data);
        lib_data_series.push(all.lib_data);
        anon_map_series.push(all.anon_mappings);
        vdso_series.push(all.vdso);
        vvar_series.push(all.vvar);
        vsyscall_series.push(all.vsyscall);
        vsys_series.push(all.vsys);
        for (path, pss) in all.other {
            other_series
                .entry(path)
                .or_insert(zero_series.clone())
                .push(pss);
        }

        zero_series.push(0);
    }

    let to_kb = |val: u64| (val as f32) / 1000.0;
    let mut fg = Figure::new();
    let axes = fg.axes2d();
    let x_len = (zero_series.len() - 1) as f64 / 0.75; // hack to make legend appear outside of chart area :(
    axes.set_x_range(Fix(0.0), Fix(x_len))
        .set_y_ticks(Some((Auto, 4)), &[Mirror(false)], &[])
        .set_y_grid(true)
        .set_y_minor_grid(true)
        .set_grid_options(false, &[LineStyle(Solid)]) // LineStyle seems to be getting ignored
        .set_minor_grid_options(&[LineStyle(Solid)])
        .set_legend(Graph(1.0), Graph(1.0), &[Invert], &[])
        .set_x_label("Time (s)", &[])
        .set_y_label("Total Proportional Set Size (KB)", &[]);
    if faults_series.is_some() {
        axes.set_y2_ticks(Some((Auto, 4)), &[], &[])
            .set_y2_label("Major+Minor Page Faults", &[]);
    }
    let first_series = vec![0.0; zero_series.len()];
    let mut prev_series = first_series;
    let mut i = 0;
    let mut draw_series = |series: &Vec<u64>, label: &str| {
        let mut is_used = false;
        let series = prev_series
            .iter()
            .zip(series)
            .map(|(a, b)| {
                if *b != 0 {
                    is_used = true;
                }
                a + to_kb(*b)
            })
            .collect();
        let label = if is_used {
            label
        } else {
            &format!("{label} (unused)")
        };
        let label = &label.replace("_", "\\_"); // escape LaTeX _
        axes.fill_between(
            &xs,
            &prev_series,
            &series,
            &[Caption(label), FillAlpha(0.7), Color(PALETTE[i].clone())],
        );
        prev_series = series;
        i = (i + 1) % PALETTE.len();
    };

    draw_series(&stack_series, "Stack");
    draw_series(&heap_series, "Heap");
    draw_series(&thread_stack_series, "Thread Stack");
    draw_series(&bin_text_series, "Binary Text");
    draw_series(&lib_text_series, "Library Text");
    draw_series(&bin_data_series, "Binary Data");
    draw_series(&lib_data_series, "Library Data");
    draw_series(&anon_map_series, "Anonymous Mappings");
    draw_series(&vdso_series, "VDSO");
    draw_series(&vvar_series, "Shared Kernel Vars");
    draw_series(&vsyscall_series, "Virtual Syscalls");
    draw_series(&vsys_series, "Shared Memory");
    for (path, series) in other_series {
        draw_series(&series, &path);
    }
    if let Some(faults_series) = faults_series {
        axes.lines(&xs, &faults_series, &[Axes(X1, Y2)]);
    }
    /*
    let last_series = prev_series;
    let iter = last_series.iter().enumerate();
    let (max_idx, _) = iter.clone().max_by_key(|(_, x)| **x).expect("tried to find maximum of empty series somehow");
    fn get_median_idx<T: Iterator>(iter: Enumerate<T>, range: RangeInclusive<usize>) -> usize where <T as Iterator>::Item: Ord {
        let mut v: Vec<_> = iter.skip(*range.start()).take(range.end() - range.start() + 1).collect();
        // can't use sort_by_key here: https://users.rust-lang.org/t/lifetime-problem-with-sort-unstable-by-key/21748/2
        v.sort_by(|(_, x1), (_, x2)| x1.cmp(x2));
        v[v.len()/2].0
    }
    let lmedian_idx = if max_idx == 0 {None} else {Some(get_median_idx(iter.clone(), 0..=max_idx))};
    let rmedian_idx = if max_idx == last_series.len() {None} else {Some(get_median_idx(iter.clone(), max_idx..=last_series.len()))};
    */

    fg.save_to_svg(out.as_path(), 1024, 768).unwrap();
}
