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
use gnuplot::{
    AutoOption::*, AxesCommon, ColorType, Coordinate::*, DashType::*, Figure, LegendOption::*,
    PlotOption::*, RGBString,
};
use log::{warn, LevelFilter};
use signal_hook::consts::signal::SIGINT;
use signal_hook::flag as signal_flag;
use smaps_profiler::{
    get_processes, get_smaps, sum_memory, FMask, MMPermissions, MaskedFileMapping, MemoryExt,
    ProcListing,
};
use std::collections::BTreeMap;
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

    ///Save graph as SVG to <FILE>
    #[arg(short, long)]
    graph: Option<PathBuf>,

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
    let args = Args::parse();
    if args.show_warnings {
        Builder::from_default_env()
            .filter_level(LevelFilter::Warn)
            .init();
    } else {
        env_logger::init();
    }
    let duration = Duration::try_from_secs_f64(args.interval).unwrap();
    let re = args.regex.map(|s| regex::Regex::new(&s).unwrap());
    let mut memory_series = Vec::new();
    let term = Arc::new(AtomicBool::new(false));
    signal_flag::register(SIGINT, Arc::clone(&term))?;
    while !term.load(Ordering::Relaxed) {
        let start = Instant::now();
        let procs = get_processes(
            &re,
            args.match_children,
            args.match_self,
            args.fail_on_noperm,
        )
        .unwrap();
        let procs = get_smaps(procs, args.fail_on_noperm).unwrap();
        print_processes(&procs)?;
        memory_series.push(sum_memory(&procs));
        let elapsed = Instant::now() - start;
        if elapsed < duration {
            thread::sleep(duration - (Instant::now() - start));
        } else if elapsed > duration {
            warn!(
                "polling smaps took {}s, overran configured interval of {}s",
                elapsed.as_secs_f64(),
                duration.as_secs_f64()
            );
        }
    }
    if let Some(path) = args.graph {
        graph_memory(memory_series, path);
    }
    Ok(())
}

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

fn print_processes(processes: &Vec<ProcListing>) -> io::Result<()> {
    // https://rust-cli.github.io/book/tutorial/output.html#a-note-on-printing-performance
    let mut writer = BufWriter::new(io::stdout().lock());
    writeln!(&mut writer, "PID\tSTACK_PSS\tHEAP_PSS\tTHREAD_STACK_PSS\tBIN_TEXT_PSS\tLIB_TEXT_PSS\tBIN_DATA_PSS\tLIB_DATA_PSS\tANON_MAP_PSS\tVDSO_PSS\tVVAR_PSS\tVSYSCALL_PSS\tSHM_PSS\tOTHER_PSS\tCMD")?;
    for proc_listing in processes {
        let ProcListing {
            pid,
            cmdline,
            memory_ext,
            ..
        } = proc_listing;
        let MemoryExt {
            stack_pss: stack,
            heap_pss: heap,
            thread_stack_pss: thread_stack,
            file_map: _file_map,
            anon_map_pss: anon_map,
            vdso_pss: vdso,
            vvar_pss: vvar,
            vsyscall_pss: vsyscall,
            vsys_pss: vsys,
            other_map,
        } = memory_ext;
        let FileCategoryTotals {
            bin_text,
            lib_text,
            bin_data,
            lib_data,
        } = get_aggregated(memory_ext);
        let other: u64 = other_map.values().sum();
        writeln!(&mut writer, "{pid}\t{stack}\t{heap}\t{thread_stack}\t{bin_text}\t{lib_text}\t{bin_data}\t{lib_data}\t{anon_map}\t{vdso}\t{vvar}\t{vsyscall}\t{vsys}\t{other}\t{cmdline}")?;
    }
    writer.flush()?;
    Ok(())
}

fn graph_memory(memory_series: Vec<MemoryExt>, out: PathBuf) {
    if memory_series.is_empty() {
        println!("Nothing to plot.");
        return;
    }
    let empty_vec = Vec::with_capacity(memory_series.len());
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
    let mut zero_series = Vec::new();
    for m in memory_series {
        stack_series.push(m.stack_pss);
        heap_series.push(m.heap_pss);
        thread_stack_series.push(m.thread_stack_pss);
        let FileCategoryTotals {
            bin_text,
            lib_text,
            bin_data,
            lib_data,
        } = get_aggregated(&m);
        bin_text_series.push(bin_text);
        lib_text_series.push(lib_text);
        bin_data_series.push(bin_data);
        lib_data_series.push(lib_data);
        anon_map_series.push(m.anon_map_pss);
        vdso_series.push(m.vdso_pss);
        vvar_series.push(m.vvar_pss);
        vsyscall_series.push(m.vsyscall_pss);
        vsys_series.push(m.vsys_pss);
        for (path, pss) in m.other_map {
            other_series
                .entry(path)
                .or_insert(zero_series.clone())
                .push(pss);
        }
        zero_series.push(0);
    }

    let xs = Vec::from_iter(0..zero_series.len());
    let to_kb = |val: u64| (val as f32) / 1000.0;
    let mut fg = Figure::new();
    let axes = fg.axes2d();
    let x_len = (zero_series.len() - 1) as f64 / 0.75; // hack to make legend appear outside of chart area :(
    axes.set_x_range(Fix(0.0), Fix(x_len))
        .set_y_ticks(Some((Auto, 4)), &[], &[])
        .set_y_grid(true)
        .set_y_minor_grid(true)
        .set_grid_options(false, &[LineStyle(Solid)]) // LineStyle seems to be getting ignored
        .set_minor_grid_options(&[LineStyle(Solid)])
        .set_legend(Graph(1.0), Graph(1.0), &[Invert], &[])
        .set_x_label("Time (s)", &[])
        .set_y_label("Total Proportional Set Size (KB)", &[]);
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
