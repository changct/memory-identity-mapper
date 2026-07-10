#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <cstdint>
#include <cctype>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <set>

using namespace std;

// Linux kpageflags bit definitions actually used by the classifier below.
// This is a subset of the full flag set — see the kernel docs for the
// complete list (LOCKED, ERROR, REFERENCED, UPTODATE, DIRTY, ACTIVE,
// RECLAIM, and others are defined by the kernel but not classified here):
// https://www.kernel.org/doc/Documentation/admin-guide/mm/pagemap.rst
#define KPF_SLAB 7
#define KPF_BUDDY 10
#define KPF_COMPOUND_HEAD 15
#define KPF_COMPOUND_TAIL 16
#define KPF_HUGE 17
#define KPF_HWPOISON 19
#define KPF_NOPAGE 20
#define KPF_KSM 21
#define KPF_THP 22
#define KPF_OFFLINE 23
#define KPF_ZERO_PAGE 24
#define KPF_IDLE 25
#define KPF_PGTABLE 26

const size_t PAGE_SIZE = 4096;

// Parse a human-readable size string (e.g. "512M", "1G") into bytes.
// Returns 0 on any parse failure so the caller can reject the input.
size_t parse_size(string s) {
    if (s.empty()) return 0;

    char unit = s.back();
    size_t multiplier = 1;
    if (unit == 'K' || unit == 'k') { multiplier = 1024; s.pop_back(); }
    else if (unit == 'M' || unit == 'm') { multiplier = 1024 * 1024; s.pop_back(); }
    else if (unit == 'G' || unit == 'g') { multiplier = 1024ULL * 1024 * 1024; s.pop_back(); }

    if (s.empty()) return 0;
    // Reject anything that isn't a plain digit string (guards against
    // things like "12x3" or "--5" slipping through stoull's leading-prefix parsing).
    for (char c : s) {
        if (!isdigit(static_cast<unsigned char>(c))) return 0;
    }

    try {
        return stoull(s) * multiplier;
    } catch (...) {
        return 0;
    }
}

// Walk /proc/self/pagemap to translate our own virtual pages into physical
// frame numbers (PFNs), so later steps can positively identify "our" pages.
set<uint64_t> get_user_mapped_pfns(void* vaddr, size_t size) {
    set<uint64_t> user_pfns;
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        perror("open /proc/self/pagemap failed");
        return user_pfns;
    }

    for (size_t i = 0; i < size; i += PAGE_SIZE) {
        uint64_t value;
        off_t offset = (((uintptr_t)vaddr + i) / PAGE_SIZE) * sizeof(value);
        if (pread(fd, &value, sizeof(value), offset) == sizeof(value)) {
            // Bit 63 = page present in RAM (see kernel pagemap docs)
            if (value & (1ULL << 63)) {
                user_pfns.insert(value & ((1ULL << 55) - 1));
            }
        }
    }
    close(fd);
    return user_pfns;
}

// Parse /proc/iomem for "System RAM" regions, which bound the PFN ranges
// we're allowed to query via /proc/kpageflags.
vector<pair<uint64_t, uint64_t>> get_system_ram_ranges() {
    vector<pair<uint64_t, uint64_t>> ranges;
    ifstream iomem("/proc/iomem");
    if (!iomem.is_open()) {
        cerr << "warning: could not open /proc/iomem" << endl;
        return ranges;
    }

    string line;
    while (getline(iomem, line)) {
        if (line.find("System RAM") != string::npos) {
            size_t dash = line.find("-");
            size_t colon = line.find(":");
            if (dash == string::npos || colon == string::npos || colon <= dash) {
                // Malformed line; skip rather than crash on stoull.
                continue;
            }
            try {
                uint64_t start = stoull(line.substr(0, dash), nullptr, 16);
                uint64_t end = stoull(line.substr(dash + 1, colon - dash - 1), nullptr, 16);
                ranges.push_back({start, end});
            } catch (...) {
                cerr << "warning: skipping unparsable /proc/iomem line: " << line << endl;
            }
        }
    }
    return ranges;
}

// Classify every PFN in every System RAM range and write a run-length-encoded
// report. `user_owned` may be empty (baseline mode: nothing is "ours", so
// every page falls through to the FREE/SYS classification below).
// Returns false on a fatal setup error (kpageflags or iomem unavailable).
bool run_classification_report(const set<uint64_t>& user_owned,
                                const string& out_path,
                                const string& header_line) {
    auto ranges = get_system_ram_ranges();
    if (ranges.empty()) {
        cerr << "error: no System RAM ranges found in /proc/iomem" << endl;
        return false;
    }

    int kflags_fd = open("/proc/kpageflags", O_RDONLY);
    if (kflags_fd < 0) {
        perror("open /proc/kpageflags failed (are you running as root?)");
        return false;
    }

    ofstream outFile(out_path);
    outFile << header_line << endl;
    outFile << left << setw(38) << "Physical Address Range" << " | Identity" << endl;
    outFile << string(65, '-') << endl;

    uint64_t user_page_count = 0;
    uint64_t sys_page_count = 0;

    for (auto& range : ranges) {
        uint64_t start_pfn = range.first / PAGE_SIZE;
        uint64_t end_pfn = range.second / PAGE_SIZE;
        uint64_t current_start = range.first;
        string current_type = "";
        uint64_t run_page_count = 0;

        for (uint64_t pfn = start_pfn; pfn <= end_pfn; ++pfn) {
            uint64_t f = 0;
            if (pread(kflags_fd, &f, sizeof(f), pfn * sizeof(f)) != sizeof(f)) {
                // Some PFNs (e.g. reserved holes) may not be readable; skip them.
                continue;
            }

            string identity;
            bool is_user = user_owned.count(pfn) > 0;
            if (is_user) {
                identity = "USER (program allocated)";
                ++user_page_count;
            }
            else if (f & (1ULL << KPF_HWPOISON))
                identity = "CRITICAL: HW POISON (ECC error)";
            else if (f & (1ULL << KPF_OFFLINE))
                identity = "OFFLINE: logically offline";
            else if (f & (1ULL << KPF_NOPAGE))
                identity = "VOID: no page frame";
            else if (f & (1ULL << KPF_BUDDY))
                identity = "FREE: buddy system (idle)";
            else {
                ++sys_page_count;
                if (f & (1ULL << KPF_PGTABLE))
                    identity = "SYS: page tables (mapping info)";
                else if (f & (1ULL << KPF_SLAB))
                    identity = "SYS: slab/slub (kernel objects)";
                else if (f & (1ULL << KPF_KSM))
                    identity = "SYS: KSM shared (deduplicated)";
                else if (f & (1ULL << KPF_ZERO_PAGE))
                    identity = "SYS: zero page (empty filling)";
                else if (f & (1ULL << KPF_HUGE))
                    identity = "SYS: HugeTLB page";
                else if (f & (1ULL << KPF_THP))
                    identity = "SYS: transparent huge page";
                else if (f & (1ULL << KPF_COMPOUND_HEAD))
                    identity = "SYS: compound head";
                else if (f & (1ULL << KPF_COMPOUND_TAIL))
                    identity = "SYS: compound tail";
                else if (f & (1ULL << KPF_IDLE))
                    identity = "SYS: idle page (awaiting reclaim)";
                else
                    identity = "SYS: other active kernel data";
            }

            // run_page_count tracks the length of the *current* contiguous
            // run, regardless of which identity it is (this is what lets us
            // print "1700 k" etc. for any block, not just USER blocks).
            ++run_page_count;

            if (identity != current_type || pfn == end_pfn) {
                if (current_type != "") {
                    outFile << "0x" << hex << current_start
                            << " - 0x" << (pfn * PAGE_SIZE - 1)
                            << " | " << current_type
                            << " : " << dec << run_page_count * 4 << " KB" << endl;
                }
                current_start = pfn * PAGE_SIZE;
                current_type = identity;
                run_page_count = 0;
            }
        }
    }

    if (!user_owned.empty()) {
        outFile << dec << "test allocation size (confirmed via pagemap): "
                << user_page_count * 4 / 1024 << " MB" << endl;
    }
    outFile << dec << "system-in-use size (excludes free/void/poison): "
            << sys_page_count * 4 / 1024 << " MB" << endl;

    cout << "done -> " << out_path << endl;

    close(kflags_fd);
    return true;
}

void print_usage(const char* prog_name) {
    cout << "usage:" << endl;
    cout << "  sudo " << prog_name << " <size, e.g. 512M, 1G>   "
         << "allocate <size> and report where it lands physically" << endl;
    cout << "  sudo " << prog_name << " --baseline               "
         << "report the current system-wide page classification, no allocation" << endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    string arg1 = argv[1];

    if (arg1 == "--baseline") {
        cout << "scanning current System RAM classification (no allocation)..." << endl;
        set<uint64_t> empty_owned; // nothing is "ours" in baseline mode
        bool ok = run_classification_report(
            empty_owned,
            "memory_baseline_map.txt",
            "--- Memory Analysis Report (Baseline, no allocation) ---");
        return ok ? 0 : 1;
    }

    size_t test_size = parse_size(arg1);
    if (test_size == 0 || test_size % PAGE_SIZE != 0) {
        cerr << "error: need a valid size that is a multiple of 4K (e.g. 512M, 1G)" << endl;
        print_usage(argv[0]);
        return 1;
    }

    cout << "allocating " << arg1 << " and resolving to physical addresses..." << endl;

    // 1. Allocate the requested size anonymously.
    void* my_mem = mmap(NULL, test_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (my_mem == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    // Touch every page to force demand paging (fault pages into RAM now,
    // rather than lazily, so pagemap lookups below succeed).
    for (size_t i = 0; i < test_size; i += PAGE_SIZE) ((volatile char*)my_mem)[i] = 1;

    // 2. Resolve our own PFNs, then classify every System RAM page.
    set<uint64_t> user_owned = get_user_mapped_pfns(my_mem, test_size);

    bool ok = run_classification_report(
        user_owned,
        "memory_identity_map.txt",
        "--- Memory Analysis Report (Request Size: " + arg1 + ") ---");

    munmap(my_mem, test_size);
    return ok ? 0 : 1;
}
