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
use std::iter;
use std::ops::Add;
use std::path::PathBuf;

#[derive(Debug)]
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
impl ProcNode {
    fn try_from_process(process: Process, convert_self: bool) -> ProcResult<Option<ProcNode>> {
        let stat = process.stat()?;
        let pid = stat.pid;
        let me: i32 = std::process::id().try_into().unwrap();
        if !convert_self && pid == me {
            return Ok(None);
        }
        Ok(Some(ProcNode {
            pid,
            ppid: stat.ppid,
            cmdline: process.cmdline()?.join(" "),
            process,
            children: vec![],
        }))
    }
}

#[derive(Debug)]
pub struct ProcListing {
    pub pid: i32,
    pub ppid: i32,
    pub cmdline: String,
    pub memory_ext: MemoryExt,
}

///Almost the same as procfs::process::MMapPath. A dictionary key that will allow us to aggregate the maps of a process by their (Path, Permissions).
#[derive(Clone, Debug)]
pub enum MemCategory {
    File(FileMapping),
    Heap,
    Stack,
    TStack,
    Vdso,
    Vvar,
    Vsyscall,
    Anonymous,
    Vsys,
    Other(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct FileMapping {
    pub is_self: bool,
    pub path: PathBuf,
    pub perms: MMPermissions,
}

#[derive(Debug, Default)]
pub struct MemoryExt {
    pub stack_pss: u64,
    pub heap_pss: u64,
    pub thread_stack_pss: u64,
    pub file_map: HashMap<FileMapping, u64>,
    pub anon_map_pss: u64,
    pub vdso_pss: u64,
    pub vvar_pss: u64,
    pub vsyscall_pss: u64,
    pub vsys_pss: u64,
    pub other_map: HashMap<String, u64>,
}

pub struct FileCategoryTotals {
    pub bin_text: u64,
    pub lib_text: u64,
    pub bin_data: u64,
    pub lib_data: u64,
}

impl MemoryExt {
    pub fn new() -> MemoryExt {
        MemoryExt::default()
    }

    pub fn iter(&self) -> impl Iterator + use<'_> {
        iter::once((MemCategory::Stack, self.stack_pss))
            .chain(iter::once((MemCategory::Heap, self.heap_pss)))
            .chain(iter::once((MemCategory::TStack, self.thread_stack_pss)))
            .chain(iter::once((MemCategory::Anonymous, self.anon_map_pss)))
            .chain(iter::once((MemCategory::Vdso, self.vdso_pss)))
            .chain(iter::once((MemCategory::Vvar, self.vvar_pss)))
            .chain(iter::once((MemCategory::Vsyscall, self.vsyscall_pss)))
            .chain(iter::once((MemCategory::Vsys, self.vsys_pss)))
            .chain(
                self.file_map
                    .iter()
                    .map(|(f, pss)| (MemCategory::File(f.clone()), *pss)),
            )
            .chain(
                self.other_map
                    .iter()
                    .map(|(s, pss)| (MemCategory::Other(s.clone()), *pss)),
            )
    }

    pub fn aggregate_file_maps(&self) -> FileCategoryTotals {
        let mut bin_text = 0;
        let mut lib_text = 0;
        let mut bin_data = 0;
        let mut lib_data = 0;
        for (f, pss) in &self.file_map {
            let is_self = f.is_self;
            let is_x = f.perms.contains(MMPermissions::EXECUTE);
            let field = match (is_self, is_x) {
                (false, false) => &mut lib_data,
                (false, true) => &mut lib_text,
                (true, false) => &mut bin_data,
                (true, true) => &mut bin_text,
            };
            *field += pss;
        }
        FileCategoryTotals {
            bin_text,
            lib_text,
            bin_data,
            lib_data,
        }
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
            file_map: add_maps(self.file_map, &rhs.file_map),
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
    match result {
        Err(PermissionDenied(e)) => {
            if fail_on_noperm {
                Some(Err(PermissionDenied(e)))
            } else {
                None
            }
        }
        Err(NotFound(Some(pathbuf))) => {
            warn!("\"{}\" not found. The process may have exited before I could get its details. Ignoring.",
                pathbuf.display());
            None
        }
        other => Some(other),
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
    let all_processes = process::all_processes()?;
    let mut proc_tree: Vec<ProcNode> = all_processes
        .filter_map(|proc_result| {
            let result = proc_result
                .and_then(|process| ProcNode::try_from_process(process, match_self))
                .transpose()?;
            filter_errors(result, fail_on_noperm)
        })
        .collect::<ProcResult<_>>()?;
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
        let maps_result = filter_errors(process.smaps(), fail_on_noperm)?;
        let maps = match maps_result {
            Ok(maps) => maps,
            Err(e) => return Some(Err(e)),
        }; // TODO: moar elegance
        let exe_result = filter_errors(process.exe(), fail_on_noperm)?;
        let exe = match exe_result {
            Ok(exe) => exe,
            Err(e) => return Some(Err(e)),
        };
        let mut memory_ext = MemoryExt::new();
        for map in maps {
            // https://users.rust-lang.org/t/lazy-evaluation-in-pattern-matching/127565/2
            let get_pss_or_warn = |map_type: String| {
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
            let (field, label) = match &map.pathname {
                Path(pathbuf) => (
                    memory_ext.file_map.entry(FileMapping{ is_self: exe == *pathbuf, path: pathbuf.clone(), perms: map.perms }).or_default(),
                   "file-backed map".to_string()
                ),
                Heap => (&mut memory_ext.heap_pss, "heap".to_string()),
                Stack => (&mut memory_ext.stack_pss, "stack".to_string()),
                TStack(tid) => (&mut memory_ext.thread_stack_pss, format!("thread {tid} stack")),
                Anonymous => (&mut memory_ext.anon_map_pss, "anonymous map".to_string()),
                Vdso => (&mut memory_ext.vdso_pss, "vdso".to_string()),
                Vvar => (&mut memory_ext.vvar_pss, "vvar".to_string()),
                Vsyscall => (&mut memory_ext.vsyscall_pss, "vsyscall".to_string()),
                Vsys(key) => (&mut memory_ext.vsys_pss, format!("shared memory segment (key {key})")),
                Other(path) => (
                    memory_ext.other_map.entry(path.clone()).or_insert(0),
                    format!("other path {path}")
                ),
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
                        continue;
                    } else {
                        panic!("FATAL: I don't know how to classify this map, and its RSS is not 0.\
                            \n  The process is {1} {2}\
                            \n  The map is {0:?}", map, pid, cmdline);
                    }
                },
            }; // end match
            *field += get_pss_or_warn(label);
        } // end for map in maps
        Some(Ok(ProcListing { pid, ppid, cmdline, memory_ext }))
    }).collect()
}
