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

use log::warn;
use procfs::process::{self, MMPermissions, MMapPath::*, Process};
use procfs::ProcError::{NotFound, PermissionDenied};
use procfs::ProcResult;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, RandomState};
use std::ops::Add;

pub struct ProcNode {
    pub pid: i32,
    pub ppid: i32,
    pub cmdline: String,
    pub process: Process,
    pub children: Vec<usize>,
}
// I might want a new type that has all the same information as ProcNode, but also with smaps.
// function delegation for trait impls has been proposed in rust-lang/rfcs/#3530.
// property delegation as in Kotlin would be nice.
pub struct ProcListing {
    pub pid: i32,
    pub ppid: i32,
    pub cmdline: String,
    pub memory_ext: MemoryExt,
}
pub struct MemoryExt {
    pub stack_pss: u64,
    pub heap_pss: u64,
    pub thread_stack_pss: u64,
    pub bin_text_pss: u64,
    pub lib_text_pss: u64,
    pub bin_data_pss: u64,
    pub lib_data_pss: u64,
    pub anon_map_pss: u64,
    pub vdso_pss: u64,
    pub vvar_pss: u64,
    pub vsyscall_pss: u64,
    pub vsys_pss: u64,
    pub other_map: HashMap<String, u64>,
}

impl MemoryExt {
    pub fn new() -> MemoryExt {
        MemoryExt {
            stack_pss: 0,
            heap_pss: 0,
            thread_stack_pss: 0,
            bin_text_pss: 0,
            lib_text_pss: 0,
            bin_data_pss: 0,
            lib_data_pss: 0,
            anon_map_pss: 0,
            vdso_pss: 0,
            vvar_pss: 0,
            vsyscall_pss: 0,
            vsys_pss: 0,
            other_map: HashMap::new(),
        }
    }
}

impl Default for MemoryExt {
    fn default() -> Self {
        Self::new()
    }
}

fn add_maps<K, V>(mut lhs: HashMap<K, V>, rhs: &HashMap<K, V>) -> HashMap<K, V>
where
    K: Eq + Hash + Clone,
    V: Add<Output = V> + Default + Clone,
{
    for (k, v) in rhs {
        let entry = lhs.entry(k.clone()).or_default();
        *entry = entry.clone() + v.clone();
    }
    lhs
}

impl Add<&MemoryExt> for MemoryExt {
    type Output = MemoryExt;

    fn add(self, rhs: &MemoryExt) -> MemoryExt {
        MemoryExt {
            stack_pss: self.stack_pss + rhs.stack_pss,
            heap_pss: self.heap_pss + rhs.heap_pss,
            thread_stack_pss: self.thread_stack_pss + rhs.thread_stack_pss,
            bin_text_pss: self.bin_text_pss + rhs.bin_text_pss,
            lib_text_pss: self.lib_text_pss + rhs.lib_text_pss,
            bin_data_pss: self.bin_data_pss + rhs.bin_data_pss,
            lib_data_pss: self.lib_data_pss + rhs.lib_data_pss,
            anon_map_pss: self.anon_map_pss + rhs.anon_map_pss,
            vdso_pss: self.vdso_pss + rhs.vdso_pss,
            vvar_pss: self.vvar_pss + rhs.vvar_pss,
            vsyscall_pss: self.vsyscall_pss + rhs.vvar_pss,
            vsys_pss: self.vsys_pss + rhs.vsys_pss,
            other_map: add_maps(self.other_map, &rhs.other_map),
        }
    }
}
/*
impl Add<&MemoryExt> for MemoryExt {
    type Output = MemoryExt;

    fn add(self, rhs: &MemoryExt) -> MemoryExt {
        &self + rhs
    }
}
*/

fn filter_errors<T>(result: ProcResult<T>, fail_on_noperm: bool) -> Option<ProcResult<T>> {
    if let Err(PermissionDenied(_)) = result {
        if fail_on_noperm {
            Some(result)
        } else {
            None
        }
    } else if let Err(NotFound(Some(pathbuf))) = result {
        warn!("\"{}\" not found. The process may have exited before I could get its details. Ignoring.",
            pathbuf.display());
        None
    } else {
        Some(result)
    }
}

/// Returns the list of matching `ProcNode`s.
/// If `regex` is None, returns all running process.
/// If `regex` is provided, every running process will have its /proc/pid/cmdline
/// checked against `regex`. If there's a match, it will be included in the list.
/// If `match_children` is `true`, then all children of the matched processes will
/// also be included, whether their cmdline matches or not.
pub fn get_processes(
    regex: &Option<regex::Regex>,
    match_children: bool,
    match_self: bool,
    fail_on_noperm: bool,
) -> ProcResult<Vec<ProcNode>> {
    // https://users.rust-lang.org/t/std-id-vs-libc-pid-t-how-to-handle/78281
    let me = TryInto::<i32>::try_into(std::process::id()).unwrap();
    let all_processes = process::all_processes()?;
    let mut proc_tree = all_processes
        .filter_map(|proc_result| {
            let result = proc_result.and_then(|process| {
                process.stat().and_then(|stat| {
                    let pid = stat.pid;
                    if !match_self && pid == me {
                        return Ok(None);
                    }
                    let ppid = stat.ppid;
                    process.cmdline().map(|c| {
                        let cmdline = c // TODO: why is process.cmdline() a Vec<String>?
                            .into_iter()
                            .fold("".to_owned(), |acc, val| acc + " " + &val);
                        Some(ProcResult::Ok(ProcNode {
                            pid,
                            ppid,
                            cmdline,
                            process,
                            children: vec![],
                        }))
                    })
                })
            }); // This should probably be illegal

            match filter_errors(result, fail_on_noperm) {
                Some(Ok(tuple)) => tuple,
                Some(Err(e)) => Some(Err(e)),
                None => None,
            }
        })
        .collect::<ProcResult<Vec<ProcNode>>>()?; // TODO: un-haskellize this (sorry, I got curried away)
    let Some(regex) = regex else {
        return Ok(proc_tree);
    };
    let kv_pairs = proc_tree
        .iter()
        .enumerate()
        .map(|(i, proc_node)| (proc_node.pid, i));
    let proc_map: HashMap<_, _, RandomState> = HashMap::from_iter(kv_pairs);
    for idx in 0..proc_tree.len() {
        let proc_node = &proc_tree[idx];
        if proc_node.ppid != 0 {
            let parent_idx = proc_map
                .get(&proc_node.ppid)
                .unwrap_or_else(|| panic!("pid {} not found in proc_map", proc_node.ppid));
            proc_tree[*parent_idx].children.push(idx);
        }
    }

    fn add_process_recursive(
        matched: &mut HashSet<usize>,
        proc_tree: &Vec<ProcNode>,
        proc_idx: usize,
    ) {
        matched.insert(proc_idx);
        let proc_node = &proc_tree[proc_idx];
        for child_idx in &proc_node.children {
            add_process_recursive(matched, proc_tree, *child_idx);
        }
    }

    let mut matched: HashSet<usize> = HashSet::new();
    for (proc_idx, proc_node) in proc_tree.iter().enumerate() {
        if regex.is_match(&proc_node.cmdline) {
            if match_children {
                add_process_recursive(&mut matched, &proc_tree, proc_idx);
            } else {
                matched.insert(proc_idx);
            }
        }
    }
    // Iterate through proc_tree; drop Processes that aren't matched, return ones that are.
    let result = proc_tree
        .into_iter()
        .enumerate()
        .filter_map(|(process_idx, process_node)| {
            if matched.contains(&process_idx) {
                Some(process_node)
            } else {
                None
            }
        })
        .collect();
    Ok(result)
}

pub fn get_smaps(processes: Vec<ProcNode>, fail_on_noperm: bool) -> ProcResult<Vec<ProcListing>> {
    processes.into_iter().filter_map(|proc_node| {
        let ProcNode { pid, ppid, cmdline, process, .. } = proc_node;
        let maps_result = filter_errors(process.smaps(), fail_on_noperm);
        let maps = match maps_result {
            Some(Ok(maps)) => maps,
            Some(Err(e)) => return Some(Err(e)),
            None => return None,
        };
        let mut memory_ext = MemoryExt::new();
        for map in maps {
            let path = &map.pathname;
            // https://users.rust-lang.org/t/lazy-evaluation-in-pattern-matching/127565/2
            let get_pss_or_warn = |map_type: &str| {
                if let Some(&pss) = map.extension.map.get("Pss") {
                    pss
                } else if let Some(&rss) = map.extension.map.get("Rss") {
                    if rss == 0 {
                        warn!("PSS field not defined on {0}, but RSS is defined and is 0. Assuming 0.\
                            \n  The process is {2} {3}\
                            \n  The map is {1:?}", map_type, map, pid, cmdline);
                        0
                    } else {
                        panic!("FATAL: PSS field not defined on {0}, and its RSS is not 0.\
                            \n  The process is {2} {3}\
                            \n  The map is {1:?}", map_type, map, pid, cmdline);
                    }
                } else {
                    warn!("PSS field not defined on {0}, but neither is RSS. Assuming 0.\
                        \n  The process is {2} {3}\
                        \n  The map is {1:?}", map_type, map, pid, cmdline);
                    0
                }
            };
            match path {
                Path(pathbuf) => {
                    let exe_result = filter_errors(process.exe(), fail_on_noperm);
                    let exe = match exe_result {
                        Some(Ok(exe)) => exe,
                        Some(Err(e)) => return Some(Err(e)),
                        None => return None,
                    };
                    let pss = get_pss_or_warn("file-backed map");
                    let is_self = exe == *pathbuf;
                    let perms = map.perms;
                    let is_x = perms.contains(MMPermissions::EXECUTE);
                    let field = match (is_self, is_x) {
                        (true, true) => &mut memory_ext.bin_text_pss,
                        (true, false) => &mut memory_ext.bin_data_pss,
                        (false, true) => &mut memory_ext.lib_text_pss,
                        (false, false) => &mut memory_ext.lib_data_pss,
                    };
                    *field += pss;
                },
                Heap => memory_ext.heap_pss += get_pss_or_warn("heap"),
                Stack => memory_ext.stack_pss += get_pss_or_warn("stack"),
                TStack(tid) => memory_ext.thread_stack_pss += get_pss_or_warn(&format!("thread {} stack", tid)),
                Anonymous => memory_ext.anon_map_pss += get_pss_or_warn("anonymous map"),
                Vdso => memory_ext.vdso_pss += get_pss_or_warn("vdso"),
                Vvar => memory_ext.vvar_pss += get_pss_or_warn("vvar"),
                Vsyscall => memory_ext.vsyscall_pss += get_pss_or_warn("vsyscall"),
                Vsys(_) => memory_ext.vsys_pss += get_pss_or_warn("shared memory segment (key {})"),
                Other(path) => {
                    let pss = get_pss_or_warn(&format!("other path {}", path));
                    *memory_ext.other_map.entry(path.clone()).or_insert(0) += pss;
                },
                _ => {
                    let Some(&rss) = map.extension.map.get("Rss") else {
                        warn!("I don't know how to classify this map, and it doesn't have a RSS field.\
                            \n  The process is {1} {2}\
                            \n  The map is {0:?}", map, pid, cmdline);
                        continue;
                    };
                    if rss == 0 {
                        warn!("I don't know how to classify this map, but at least its RSS is 0.\
                            \n  The process is {1} {2}\
                            \n  The map is {0:?}", map, pid, cmdline);
                    } else {
                        panic!("FATAL: I don't know how to classify this map, and its RSS is not 0.\
                            \n  The process is {1} {2}\
                            \n  The map is {0:?}", map, pid, cmdline);
                    }
                },
            } // end match
        } // end for map in maps
        Some(Ok(ProcListing { pid, ppid, cmdline, memory_ext }))
    }).collect()
}
