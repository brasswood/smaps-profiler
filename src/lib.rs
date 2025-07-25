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

use derive_more::{Add, Sum};
use log::warn;
use procfs::process::{self, MMapPath::*};
pub use procfs::process::{MMPermissions, Process};
use procfs::ProcError::{NotFound, PermissionDenied};
use procfs::ProcResult;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::iter;
use std::ops::Add;
use std::path::PathBuf;

#[derive(Debug)]
pub struct Proc {
    pub pid: i32,
    pub ppid: i32,
    pub cmdline: String,
    pub faults: Faults,
    pub process: Process,
}

// I might want a new type that has all the same information as ProcNode, but also with smaps.
// function delegation for trait impls has been proposed in rust-lang/rfcs/#3530.
// property delegation as in Kotlin would be nice.
impl Proc {
    fn try_from_process(process: Process, convert_self: bool) -> ProcResult<Option<Proc>> {
        let stat = process.stat()?;
        let pid = stat.pid;
        let me: i32 = std::process::id().try_into().unwrap();
        if !convert_self && pid == me {
            return Ok(None);
        }
        Ok(Some(Proc {
            pid,
            ppid: stat.ppid,
            cmdline: process.cmdline()?.join(" "),
            faults: Faults {
                minor: stat.minflt,
                major: stat.majflt,
            },
            process,
        }))
    }
}

#[derive(Debug)]
struct ProcNode {
    proc: Proc,
    children: Vec<usize>,
}

impl From<Proc> for ProcNode {
    fn from(proc: Proc) -> ProcNode {
        ProcNode {
            proc,
            children: vec![],
        }
    }
}

#[derive(Debug)]
pub struct ProcListing {
    pub pid: i32,
    pub ppid: i32,
    pub cmdline: String,
    pub faults: Faults,
    pub memory_ext: MemoryExt,
}

///Almost the same as procfs::process::MMapPath. A dictionary key that will allow us to aggregate the maps of a process by their (Path, Permissions).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemCategory {
    File(MaskedFileMapping),
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

impl FileMapping {
    pub fn new(is_self: bool, path: PathBuf, perms: MMPermissions) -> FileMapping {
        FileMapping {
            is_self,
            path,
            perms,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FMask {
    pub is_self: bool,
    pub path: bool,
    pub perms: MMPermissions,
}

impl FMask {
    pub fn new(is_self: bool, path: bool, perms: MMPermissions) -> FMask {
        FMask {
            is_self,
            path,
            perms,
        }
    }

    pub fn apply(&self, f: &FileMapping) -> MaskedFileMapping {
        MaskedFileMapping {
            is_self: if self.is_self { Some(f.is_self) } else { None },
            path: if self.path {
                Some(f.path.clone())
            } else {
                None
            },
            masked_perms: self.perms.intersection(f.perms),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MaskedFileMapping {
    pub is_self: Option<bool>,
    pub path: Option<PathBuf>,
    pub masked_perms: MMPermissions,
}

impl MaskedFileMapping {
    pub fn new(
        is_self: Option<bool>,
        path: Option<PathBuf>,
        masked_perms: MMPermissions,
    ) -> MaskedFileMapping {
        MaskedFileMapping {
            is_self,
            path,
            masked_perms,
        }
    }
}

impl From<FileMapping> for MaskedFileMapping {
    fn from(f: FileMapping) -> Self {
        MaskedFileMapping::new(Some(f.is_self), Some(f.path), f.perms)
    }
}

#[derive(Debug, Clone, Default)]
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

impl MemoryExt {
    pub fn new() -> MemoryExt {
        MemoryExt::default()
    }

    /// Aggregate the table of file-backed mappings based on their fields. Setting a parameter to `true` means,
    /// "store separate entries for distinct values of this field," while setting it to `false` means, "store
    /// distinct values of this field in the same entry." The `perms` parameter works the same way, but as a
    /// bitflag, so you can choose particular permissions you care about making a distinction on.
    pub fn aggregate_file_maps(&self, mask: &FMask) -> HashMap<MaskedFileMapping, u64> {
        let capacity = match (mask.is_self, mask.path, mask.perms) {
            (_, true, _) => self.file_map.len(),
            (s, false, p) => 1 << (num_bits_on(p.bits()) + s as u8),
        };
        let mut ret = HashMap::with_capacity(capacity);
        for (f, pss) in self.file_map.iter() {
            add_at(&mut ret, mask.apply(f), pss);
        }
        ret
    }

    /// Returns an iterator over all of the memory categories and their pss stored in this struct, where
    /// the table of file-backed mappings is aggregated as it is in `aggregate_file_maps`.
    pub fn iter_aggregate(
        &self,
        mask: &FMask,
    ) -> impl Iterator<Item = (MemCategory, u64)> + use<'_> {
        let MemoryExt {
            stack_pss,
            heap_pss,
            thread_stack_pss,
            file_map: _,
            anon_map_pss,
            vdso_pss,
            vvar_pss,
            vsyscall_pss,
            vsys_pss,
            other_map,
        } = self; // destructure self here so that I get a compiler error if fields change
        iter::once((MemCategory::Stack, *stack_pss))
            .chain(iter::once((MemCategory::Heap, *heap_pss)))
            .chain(iter::once((MemCategory::TStack, *thread_stack_pss)))
            .chain(iter::once((MemCategory::Anonymous, *anon_map_pss)))
            .chain(iter::once((MemCategory::Vdso, *vdso_pss)))
            .chain(iter::once((MemCategory::Vvar, *vvar_pss)))
            .chain(iter::once((MemCategory::Vsyscall, *vsyscall_pss)))
            .chain(iter::once((MemCategory::Vsys, *vsys_pss)))
            .chain(
                self.aggregate_file_maps(mask)
                    .into_iter()
                    .map(|(f, pss)| (MemCategory::File(f), pss)),
            )
            .chain(
                other_map
                    .iter()
                    .map(|(s, pss)| (MemCategory::Other(s.clone()), *pss)),
            )
    }

    pub fn total(&self) -> u64 {
        self.iter_aggregate(&FMask::new(true, true, MMPermissions::all()))
            .map(|(_, pss)| pss)
            .sum()
    }
}

pub fn add_maps<K, V, A>(mut lhs: HashMap<K, V>, rhs: &HashMap<K, A>) -> HashMap<K, V>
where
    K: Eq + Hash + Clone,
    V: Add<A, Output = V> + Default + Clone,
    A: Clone,
{
    for (k, v) in rhs {
        add_at(&mut lhs, k.clone(), v.clone());
    }
    lhs
}

fn add_at<K, V, A>(map: &mut HashMap<K, V>, k: K, a: A)
where
    K: Eq + Hash,
    V: Add<A, Output = V> + Default + Clone,
    A: Clone,
{
    let entry = map.entry(k).or_default();
    *entry = entry.clone() + a;
}

fn num_bits_on(mut bits: u8) -> u8 {
    let mut ret = 0;
    while bits != 0 {
        ret += bits & 1;
        bits >>= 1;
    }
    ret
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

#[derive(Add, Debug, Copy, Clone, Serialize, Default, Sum)]
pub struct Faults {
    pub minor: u64,
    pub major: u64,
}

impl Faults {
    pub fn total(&self) -> u64 {
        self.minor + self.major
    }
}

fn filter_errors<T>(result: ProcResult<T>, fail_on_noperm: bool) -> Option<ProcResult<T>> {
    match result {
        Err(PermissionDenied(path)) => {
            if fail_on_noperm {
                Some(Err(PermissionDenied(path)))
            } else {
                let path = path.as_ref().map_or("<empty path>", |p| {
                    p.as_path().to_str().unwrap_or("<non-unicode path>")
                });
                warn!("Permission denied when accessing {path}. Ignoring.");
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
) -> ProcResult<Vec<Proc>> {
    // https://users.rust-lang.org/t/std-id-vs-libc-pid-t-how-to-handle/78281
    let all_processes = process::all_processes()?;
    let procs: Vec<Proc> = all_processes
        .filter_map(|proc_result| {
            let result = proc_result
                .and_then(|process| Proc::try_from_process(process, match_self))
                .transpose()?;
            filter_errors(result, fail_on_noperm)
        })
        .collect::<ProcResult<_>>()?;
    let Some(regex) = regex else {
        return Ok(procs);
    };

    if !match_children {
        return Ok(procs
            .into_iter()
            .filter(|p| regex.is_match(&p.cmdline))
            .collect());
    }

    // slow path: build the entire process tree so we can use it to determine matches
    let proc_tree = build_tree(procs);
    let mut matched: HashSet<usize> = HashSet::new();

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

    for (proc_idx, proc_node) in proc_tree.iter().enumerate() {
        if regex.is_match(&proc_node.proc.cmdline) {
            add_process_recursive(&mut matched, &proc_tree, proc_idx);
        }
    }
    // Iterate through proc_tree; drop Processes that aren't matched, return ones that are.
    let result = proc_tree
        .into_iter()
        .enumerate()
        .filter_map(|(process_idx, process_node)| {
            matched.contains(&process_idx).then_some(process_node.proc)
        })
        .collect();
    Ok(result)
}

fn build_tree(processes: Vec<Proc>) -> Vec<ProcNode> {
    let pid_idx_map: HashMap<i32, usize> = processes
        .iter()
        .enumerate()
        .map(|(i, proc)| (proc.pid, i))
        .collect();

    let mut proc_tree: Vec<ProcNode> = processes.into_iter().map(|p| p.into()).collect();
    for idx in 0..proc_tree.len() {
        let proc_node = &proc_tree[idx];
        if proc_node.proc.ppid != 0 {
            let parent_idx = pid_idx_map
                .get(&proc_node.proc.ppid)
                .unwrap_or_else(|| panic!("pid {} not found in proc_map", proc_node.proc.ppid));
            proc_tree[*parent_idx].children.push(idx);
        }
    }
    proc_tree
}

pub fn get_smaps(processes: Vec<Proc>, fail_on_noperm: bool) -> ProcResult<Vec<ProcListing>> {
    processes.into_iter().filter_map(|proc| {
        let Proc { pid, ppid, cmdline, process, faults, .. } = proc;
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
                    memory_ext.file_map.entry(FileMapping::new(exe == *pathbuf, pathbuf.clone(), map.perms)).or_default(),
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
        Some(Ok(ProcListing { pid, ppid, cmdline, faults, memory_ext }))
    }).collect()
}

pub fn sum_memory(processes: &[ProcListing]) -> MemoryExt {
    processes
        .iter()
        .fold(MemoryExt::new(), |mem, proc_listing| {
            mem + &proc_listing.memory_ext
        })
}
