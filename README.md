# Memory Identity Mapper

A Linux CLI tool that classifies **every physical page in System RAM** by cross-referencing three kernel introspection interfaces: `/proc/self/pagemap`, `/proc/iomem`, and `/proc/kpageflags`. It answers a question standard tools like `free` and `/proc/meminfo` can't: *for a given block of physical memory, is this page mine, is it free, is it kernel-owned, or is it broken hardware?*

## Why this exists

While investigating a coverage gap in how Linux reports page allocation (sys-type vs. buddy-type page interleaving), I needed a way to see physical memory at page granularity rather than trust aggregate counters. There wasn't a lightweight existing tool that did this cross-reference, so I built one.

## What it does

1. Either allocates a user-specified chunk of memory (`mmap` + `MAP_ANONYMOUS`, forcing every page resident via demand paging) — or, in `--baseline` mode, skips allocation entirely and just classifies memory as it currently stands.
2. Walks `/proc/self/pagemap` to resolve each virtual page to its physical frame number (PFN) — this is how the tool positively identifies "pages this process owns." (Skipped in baseline mode, since there's no allocation to identify.)
3. Parses `/proc/iomem` to find the physical address ranges the kernel reports as `System RAM`, which bounds the valid PFN space to query.
4. Reads `/proc/kpageflags` for every PFN in that range and classifies it against kernel-defined flags: `BUDDY` (free), `SLAB`, `KSM`, `HUGE`/`THP`, `HWPOISON`, `OFFLINE`, `PGTABLE`, `IDLE`, and more.
5. Writes a run-length-encoded report showing contiguous physical address ranges and what they are, plus a summary of system-in-use memory (and, in allocation mode, confirmed user allocation size).

## Example output

Allocation mode (`sudo ./memory_identity_mapper 512M`):

```
--- Memory Analysis Report (Request Size: 512M) ---
Physical Address Range                 | Identity
-----------------------------------------------------------------
0x100000 - 0x3fffff | FREE: buddy system (idle) : 3076 KB
0x400000 - 0x7fffff | SYS: other active kernel data : 4096 KB
0xfc00000 - 0xfda8fff | USER (program allocated) : 1700 KB
0xfda9000 - 0xfda9fff | SYS: other active kernel data : 4 KB
...
test allocation size (confirmed via pagemap): 512 MB
system-in-use size (excludes free/void/poison): 84 MB
```

Baseline mode (`sudo ./memory_identity_mapper --baseline`), no allocation, just the current system-wide picture:

```
--- Memory Analysis Report (Baseline, no allocation) ---
Physical Address Range                 | Identity
-----------------------------------------------------------------
0x1000 - 0x9cfff | SYS: other active kernel data : 628 KB
0x100000 - 0x3fffff | FREE: buddy system (idle) : 3076 KB
0x400000 - 0x7fffff | SYS: other active kernel data : 4096 KB
...
system-in-use size (excludes free/void/poison): 882 MB
```

Full real output for both modes is in [`examples/`](examples/).

## Build & run

Requires a Linux kernel with `/proc/kpageflags` enabled (most distro kernels; needs `CONFIG_PROC_PAGE_MONITOR`). Reading `/proc/kpageflags` requires root.

```bash
g++ -std=c++17 -O2 -o memory_identity_mapper memory_identity_mapper.cpp

# Allocate a chunk and see where it lands physically
sudo ./memory_identity_mapper 512M
cat memory_identity_map.txt

# Or just see the current system-wide page classification, no allocation
sudo ./memory_identity_mapper --baseline
cat memory_baseline_map.txt
```

Size argument accepts `K`/`M`/`G` suffixes and must be a multiple of the page size (4K).

Running baseline before and after an allocation is a useful way to see the
system-level cost of that allocation — e.g. how much the `SYS: page tables`
total grows once the kernel has to map a large chunk of new memory.

## Design notes

- **No dependencies beyond libc/STL** — deliberately kept to raw `pread`/`mmap`/`open` syscalls rather than a wrapper library, since the whole point is direct interaction with the kernel interfaces.
- **PFN identification via pagemap, not heuristics** — the tool doesn't guess which pages belong to the test allocation; it resolves them exactly via the pagemap present bit and PFN field, then treats everything else as an unknown to classify from kpageflags.
- **Run-length encoding on output** — physical memory tends to be allocated in large contiguous chunks of the same type, so the report collapses consecutive same-identity pages into one range rather than printing one line per 4KB page.

## Limitations

- Single-threaded, single-run snapshot — no continuous monitoring.
- Classification order matters: a page can have multiple kpageflags bits set (e.g. both `THP` and `COMPOUND_HEAD`); this tool reports the first match in a fixed priority order rather than all flags. This is a simplification worth knowing about if you extend it.
- Not NUMA-aware — doesn't distinguish which NUMA node a page belongs to.

## Possible extensions

- Multi-node NUMA breakdown per page range.
- JSON output for feeding into a visualization/plotting pipeline.
- Historical/repeated sampling to observe reclaim and compaction behavior over time.
