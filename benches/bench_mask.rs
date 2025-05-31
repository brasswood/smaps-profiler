use criterion::{
    criterion_group, criterion_main, BatchSize::SmallInput, BenchmarkId, Criterion,
    Throughput::Elements,
};
use itertools::Itertools;
use std::{collections::HashSet, time::Duration};
use untitled_smaps_poller::MMPermissions;

fn delete(s: &mut String, c: char) -> bool {
    if let Some(i) = s.find(c) {
        s.remove(i);
        true
    } else {
        false
    }
}

fn get_mask_list(mut s: String) -> Result<(bool, bool, MMPermissions), ()> {
    let is_self = delete(&mut s, 'b');
    let path = delete(&mut s, 'f');
    let mut perms = MMPermissions::NONE;
    perms.set(MMPermissions::READ, delete(&mut s, 'r'));
    perms.set(MMPermissions::WRITE, delete(&mut s, 'w'));
    perms.set(MMPermissions::EXECUTE, delete(&mut s, 'x'));
    perms.set(MMPermissions::SHARED, delete(&mut s, 's'));
    perms.set(MMPermissions::PRIVATE, delete(&mut s, 'p'));
    if s.is_empty() {
        Ok((is_self, path, perms))
    } else {
        Err(())
    }
}

fn get_mask_set(s: String) -> Result<(bool, bool, MMPermissions), ()> {
    let mut set = HashSet::new();
    for c in s.chars() {
        if !set.insert(c) {
            return Err(());
        }
    }
    let is_self = set.remove(&'b');
    let path = set.remove(&'f');
    let mut perms = MMPermissions::NONE;
    perms.set(MMPermissions::READ, set.remove(&'r'));
    perms.set(MMPermissions::WRITE, set.remove(&'w'));
    perms.set(MMPermissions::EXECUTE, set.remove(&'x'));
    perms.set(MMPermissions::SHARED, set.remove(&'s'));
    perms.set(MMPermissions::PRIVATE, set.remove(&'p'));
    if set.is_empty() {
        Ok((is_self, path, perms))
    } else {
        Err(())
    }
}

fn bench_fns(c: &mut Criterion) {
    let mut group = c.benchmark_group("Get Mask");
    group.warm_up_time(Duration::from_millis(300));
    group.measurement_time(Duration::from_millis(500));
    for n in 0..=7 {
        group.throughput(Elements(n));
        for input in "bfrwxsp".chars().permutations(n as usize) {
            let input: String = input.into_iter().collect();
            group.bench_with_input(BenchmarkId::new("List", &input), &input, |b, i| {
                b.iter_batched(|| i.clone(), |i| get_mask_list(i), SmallInput)
            });
            group.bench_with_input(BenchmarkId::new("HashSet", &input), &input, |b, i| {
                b.iter_batched(|| i.clone(), |i| get_mask_set(i), SmallInput)
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_fns);
criterion_main!(benches);
