use std::{iter, path::PathBuf};

use procfs::process::MMPermissions;

use crate::{FileCategoryTotals, FileMapping, MemoryExt};
use FilesCombined::{BinData, BinText, LibData, LibText};
use NonFile::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NonFile {
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

///Almost the same as procfs::process::MMapPath. A dictionary key that will allow us to aggregate the maps of a process by their (Path, Permissions).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemCategory {
    File(FileMapping),
    NonFile(NonFile),
}

impl From<NonFile> for MemCategory {
    fn from(value: NonFile) -> Self {
        MemCategory::NonFile(value)
    }
}

impl From<FileMapping> for MemCategory {
    fn from(value: FileMapping) -> Self {
        MemCategory::File(value)
    }
}

pub enum FilesCombined {
    BinText,
    BinData,
    LibText,
    LibData,
    NonFile(NonFile),
}

impl From<NonFile> for FilesCombined {
    fn from(value: NonFile) -> Self {
        FilesCombined::NonFile(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IsSelfCombined {
    File(PathBuf, MMPermissions),
    NonFile(NonFile),
}

impl From<NonFile> for IsSelfCombined {
    fn from(value: NonFile) -> Self {
        IsSelfCombined::NonFile(value)
    }
}

impl From<(PathBuf, MMPermissions)> for IsSelfCombined {
    fn from((path, perms): (PathBuf, MMPermissions)) -> Self {
        IsSelfCombined::File(path, perms)
    }
}

impl MemoryExt {
    fn iter_common(&self) -> impl Iterator<Item = (NonFile, u64)> + use<'_> {
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

        iter::once((Stack, *stack_pss))
            .chain(iter::once((Heap, *heap_pss)))
            .chain(iter::once((TStack, *thread_stack_pss)))
            .chain(iter::once((Anonymous, *anon_map_pss)))
            .chain(iter::once((Vdso, *vdso_pss)))
            .chain(iter::once((Vvar, *vvar_pss)))
            .chain(iter::once((Vsyscall, *vsyscall_pss)))
            .chain(iter::once((Vsys, *vsys_pss)))
            .chain(other_map.iter().map(|(s, pss)| (Other(s.clone()), *pss)))
    }

    pub fn iter(&self) -> impl Iterator<Item = (MemCategory, u64)> + use<'_> {
        self.iter_common()
            .map(|(cat, pss)| (cat.into(), pss))
            .chain(
                self.file_map
                    .iter()
                    .map(|(f, pss)| (MemCategory::File(f.clone()), *pss)),
            )
    }

    pub fn iter_combine_file_maps(&self) -> impl Iterator<Item = (FilesCombined, u64)> + use<'_> {
        let FileCategoryTotals {
            bin_text,
            lib_text,
            bin_data,
            lib_data,
        } = self.aggregate_file_maps();
        self.iter_common()
            .map(|(cat, pss)| (cat.into(), pss))
            .chain(iter::once((BinText, bin_text)))
            .chain(iter::once((LibText, lib_text)))
            .chain(iter::once((BinData, bin_data)))
            .chain(iter::once((LibData, lib_data)))
    }

    pub fn iter_combine_is_self(&self) -> impl Iterator<Item = (IsSelfCombined, u64)> + use<'_> {
        self.iter_common()
            .map(|(cat, pss)| (cat.into(), pss))
            .chain(
                self.aggregate_is_self()
                    .into_iter()
                    .map(|(f, pss)| (f.into(), pss)),
            )
    }
}
