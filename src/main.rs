/* Copyright 2025 Andrew Riachi
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

use procfs::process::{self, Process};
use procfs::ProcResult;
use clap::Parser;
use regex;
use std::collections::{HashMap, HashSet};
use std::hash::RandomState;
use std::thread;
use std::time::Duration;

#[derive(Parser)]
#[command(version, about = "Reports process stack, heap, text, and data memory usage.", long_about = None)]
struct Args {
    ///Regex to match process cmdline against
    regex: Option<String>,

    ///If --regex is given, include children of matched processes, even if they don't match.
    #[arg(short = 'c', long, requires = "regex")]
    match_children: bool,
    
    ///Refresh interval in seconds
    #[arg(short, long, default_value_t = 1.0_f64)]
    interval: f64,
}

struct ProcNode { pid: i32, ppid: i32, cmdline: String, process: Process, children: Vec<usize> }

fn main() {
    let args = Args::parse();
    let duration = Duration::try_from_secs_f64(args.interval).unwrap();
    let re = args.regex.map(|s| regex::Regex::new(&s).unwrap());
    loop {
        let procs = get_processes(&re, args.match_children).unwrap();
        print_processes(&procs);
        thread::sleep(duration);
    }
}

/// Returns the list of matching `ProcNode`s.
/// If `regex` is None, returns all running process.
/// If `regex` is provided, every running process will have its /proc/pid/cmdline
/// checked against `regex`. If there's a match, it will be included in the list.
/// If `match_children` is `true`, then all children of the matched processes will
/// also be included, whether their cmdline matches or not.
fn get_processes(regex: &Option<regex::Regex>, match_children: bool) -> ProcResult<Vec<ProcNode>> {
    let all_processes = process::all_processes()?;
    let mut proc_tree = all_processes.map(|proc_result| {
        let process = proc_result?;
        let stat = process.stat()?;
        let pid = stat.pid;
        let ppid = stat.ppid;
        let cmdline = process.cmdline()?.into_iter().fold("".to_owned(), |acc, val| acc + " " + &val); // TODO: why is this a Vec?
        ProcResult::Ok(ProcNode { 
            pid,
            ppid, 
            cmdline,
            process,
            children: vec![] 
        })
    }).collect::<ProcResult<Vec<ProcNode>>>()?;
    let Some(regex) = regex else {
        return Ok(proc_tree);
    };
    let kv_pairs = (&proc_tree).into_iter().enumerate().map(|(i, proc_node)| (proc_node.pid, i));
    let proc_map: HashMap<_, _, RandomState> = HashMap::from_iter(kv_pairs);
    for idx in 0..proc_tree.len() {
        let proc_node = &proc_tree[idx];
        if proc_node.ppid != 0 {
            let parent_idx = proc_map.get(&proc_node.ppid)
                .expect(&format!("pid {} not found in proc_map", proc_node.ppid));
            proc_tree[*parent_idx].children.push(idx);
        }
    }

    fn add_process_recursive(matched: &mut HashSet<usize>, proc_tree: &Vec<ProcNode>, proc_map: &HashMap<i32, usize>, proc_idx: usize) {
        matched.insert(proc_idx);
        let proc_node = &proc_tree[proc_idx];
        for child_idx in &proc_node.children {
            add_process_recursive(matched, proc_tree, proc_map, *child_idx);
        }
    }

    let mut matched: HashSet<usize> = HashSet::new();
    for (proc_idx, proc_node) in (&proc_tree).into_iter().enumerate() {
        if regex.is_match(&proc_node.cmdline) {
            if match_children {
                add_process_recursive(&mut matched, &proc_tree, &proc_map, proc_idx);
            } else {
                matched.insert(proc_idx);
            }
        }
    }
    // Iterate through proc_tree; drop Processes that aren't matched, return ones that are.
    let result = proc_tree.into_iter()
        .enumerate()
        .filter_map(|(process_idx, process_node)| {
            if matched.contains(&process_idx) {
                Some(process_node)
            } else {
                None
            }
        })
        .collect();
    return Ok(result);
}

fn print_processes(processes: &Vec<ProcNode>) {
    println!("PID\tPPID\tCMD");
    for proc_node in processes {
        println!("{}\t{}\t{}", proc_node.pid, proc_node.ppid, proc_node.cmdline);
    }
}
