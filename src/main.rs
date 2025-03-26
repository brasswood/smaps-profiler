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
use std::collections::HashMap;
use std::hash::RandomState;

#[derive(Parser)]
#[command(version, about = "Reports process stack, heap, text, and data memory usage.", long_about = None)]
struct Args {
    ///Regex to match process cmdline against
    #[arg(short, long)]
    regex: Option<String>,

    ///If --regex is given, include children of matched processes, even if they don't match.
    #[arg(short = 'c', long, requires = "regex")]
    match_children: bool,
    
    ///Refresh interval in seconds
    #[arg(short, long, default_value_t = 1.0_f64)]
    interval: f64,
}


fn main() {
    let args = Args::parse();

    println!("Hello, world!");
}

fn get_processes(regex: Option<regex::Regex>, match_children: bool) -> ProcResult<Vec<Process>> {
    let all_processes = process::all_processes()?;
    let Some(regex) = regex else {
        return all_processes.collect();
    };
    struct ProcNode { process: Process, children: Vec<i32> }
    let mut proc_tree = all_processes.map(
        |p| ProcResult::Ok(ProcNode { process: p?, children: vec![] })
    ).collect::<ProcResult<Vec<ProcNode>>>()?;
    let kv_pairs = (&proc_tree).into_iter().enumerate().map(|(i, proc_node)| (proc_node.process.pid(), i));
    let proc_map: HashMap<_, _, RandomState> = HashMap::from_iter(kv_pairs);
    for idx in 0..proc_tree.len() {
        let proc_node = &proc_tree[idx];
        let pid = proc_node.process.pid();
        let ppid = proc_node.process.stat()?.ppid;
        let parent_idx = proc_map[&ppid];
        proc_tree[parent_idx].children.push(pid);
    }
    return Ok(vec![]);
}
