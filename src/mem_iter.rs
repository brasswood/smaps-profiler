use std::{collections::HashMap, iter, path::PathBuf};

use procfs::process::MMPermissions;

use crate::{add_at, FileMapping, MemoryExt};

///Almost the same as procfs::process::MMapPath. A dictionary key that will allow us to aggregate the maps of a process by their (Path, Permissions).
#[derive(Clone, Debug, PartialEq, Eq)]
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

impl MemoryExt {
    fn iter_common(&self) -> impl Iterator<Item = (MemCategory, u64)> + use<'_> {
        let MemoryExt {
            stack_pss,
            heap_pss,
            thread_stack_pss,
            file_map,
            anon_map_pss,
            vdso_pss,
            vvar_pss,
            vsyscall_pss,
            vsys_pss,
            other_map,
        } = self; // destructure self here so that I get a compiler error if fields change
        let mut new_file_map: HashMap<(PathBuf, MMPermissions), u64> =
            HashMap::with_capacity(file_map.len());
        for (f, pss) in file_map {
            add_at(&mut new_file_map, (f.path.clone(), f.perms), pss);
        }
        iter::once((MemCategory::Stack, *stack_pss))
            .chain(iter::once((MemCategory::Heap, *heap_pss)))
            .chain(iter::once((MemCategory::TStack, *thread_stack_pss)))
            .chain(iter::once((MemCategory::Anonymous, *anon_map_pss)))
            .chain(iter::once((MemCategory::Vdso, *vdso_pss)))
            .chain(iter::once((MemCategory::Vvar, *vvar_pss)))
            .chain(iter::once((MemCategory::Vsyscall, *vsyscall_pss)))
            .chain(iter::once((MemCategory::Vsys, *vsys_pss)))
            .chain(
                new_file_map
                    .into_iter()
                    .map(|((path, perms), pss)| (MemCategory::File(path, perms), pss)),
            )
            .chain(
                other_map
                    .iter()
                    .map(|(s, pss)| (MemCategory::Other(s.clone()), *pss)),
            )
    }

    pub fn iter(&self) -> impl Iterator<Item = FileMapping> + use<'_> {
        self.iter_common()
            .chain()
    }
}
