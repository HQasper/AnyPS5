#include "prx/libc/include/GuestArena.hpp"
#include "prx/libc/include/GuestWriteWatch.hpp"

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <mutex>
#include <source_location>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#error These tests cover the Windows label read traps
#endif

using namespace GuestArena;
using namespace GuestWriteWatch;

namespace {

constexpr std::size_t Page = 4096;
constexpr std::size_t Bytes = 0x10000;

using Ranges = std::vector<std::pair<std::uintptr_t, std::uintptr_t>>;

void Require(bool value, std::source_location location = std::source_location::current()) {
    if (!value) throw std::runtime_error("Windows read trap regression at line " + std::to_string(location.line()));
}

std::mutex resolvedMutex;
Ranges resolved;
std::atomic<std::uint32_t> stamp{0};
std::atomic<bool> bypassing{false};

void Resolve(std::uintptr_t begin, std::uintptr_t end) {
    {
        std::lock_guard lock(resolvedMutex);
        resolved.emplace_back(begin, end);
    }
    *reinterpret_cast<volatile std::uint32_t*>(begin) = stamp.load();
}

Ranges TakeResolved() {
    std::lock_guard lock(resolvedMutex);
    return std::exchange(resolved, {});
}

std::uint32_t Read(std::uintptr_t address) {
    return *reinterpret_cast<const volatile std::uint32_t*>(address);
}

void Write(std::uintptr_t address, std::uint32_t value) {
    *reinterpret_cast<volatile std::uint32_t*>(address) = value;
}

DWORD ProtectionAt(std::uintptr_t address) {
    MEMORY_BASIC_INFORMATION memory{};
    Require(VirtualQuery(reinterpret_cast<const void*>(address), &memory, sizeof(memory)) == sizeof(memory));
    return memory.Protect;
}

struct Memory {
    Memory() : pointer(static_cast<std::uint8_t*>(GuestArenaAllocate_nid_postfix(Bytes, Bytes))) {
        Require(pointer != nullptr);
        GuestArenaCommit_nid_postfix(pointer, Bytes, PAGE_READWRITE, Bytes);
    }
    ~Memory() {
        GuestArenaReset_nid_postfix(pointer, Bytes);
        GuestArenaRelease_nid_postfix(pointer, Bytes);
    }
    std::uintptr_t At(std::size_t offset) const {
        return reinterpret_cast<std::uintptr_t>(pointer) + offset;
    }
    std::uint8_t* pointer;
};

void CheckReadResolvesOnce() {
    Memory memory;
    const auto label = memory.At(0x100);
    Require(GuestWriteWatchTrapReads_nid_postfix(label, 0x80));
    Require(GuestWriteWatchTrapReads_nid_postfix(label, 0x80));
    Require(ProtectionAt(memory.At(0)) == PAGE_NOACCESS && ProtectionAt(memory.At(Page)) == PAGE_READWRITE);
    stamp = 0x1234;
    Require(Read(label) == 0x1234);
    Require(TakeResolved() == Ranges{{label, label + 0x80}});
    Require(ProtectionAt(memory.At(0)) == PAGE_READWRITE);
    stamp = 0x5678;
    Require(Read(label) == 0x1234 && TakeResolved().empty());
}

void CheckReleaseSkipsResolver() {
    Memory memory;
    Require(GuestWriteWatchTrapReads_nid_postfix(memory.At(0), 64));
    GuestWriteWatchReleaseReads_nid_postfix(memory.At(0), 64);
    Require(ProtectionAt(memory.At(0)) == PAGE_READWRITE);
    Write(memory.At(0), 9);
    Require(Read(memory.At(0)) == 9 && TakeResolved().empty());
}

void CheckWriteResolvesFirst() {
    Memory memory;
    const auto label = memory.At(Page);
    Require(GuestWriteWatchTrapReads_nid_postfix(label, 16));
    stamp = 0x2222;
    Write(label + 8, 7);
    Require(TakeResolved() == Ranges{{label, label + 16}});
    Require(Read(label) == 0x2222 && Read(label + 8) == 7);
}

void CheckSharedPage() {
    Memory memory;
    const auto first = memory.At(2 * Page);
    const auto second = first + 64;
    Require(GuestWriteWatchTrapReads_nid_postfix(first, 16) && GuestWriteWatchTrapReads_nid_postfix(second, 16));
    GuestWriteWatchReleaseReads_nid_postfix(first, 16);
    Require(ProtectionAt(first) == PAGE_NOACCESS);
    Require(GuestWriteWatchTrapReads_nid_postfix(first, 16));
    stamp = 0x3333;
    Require(Read(first + 512) == 0);
    const auto ranges = TakeResolved();
    Require(ranges.size() == 2 && Read(first) == 0x3333 && Read(second) == 0x3333);
    Require(ProtectionAt(first) == PAGE_READWRITE);
}

void CheckProtectionChange() {
    Memory memory;
    const auto label = memory.At(3 * Page);
    Require(GuestWriteWatchTrapReads_nid_postfix(label, 32));
    stamp = 0x4444;
    GuestArenaSetProtection_nid_postfix(label, Page, PAGE_READONLY);
    Require(TakeResolved() == Ranges{{label, label + 32}});
    Require(!GuestWriteWatchTrapReads_nid_postfix(label, 32));
    DWORD previous = 0;
    Require(VirtualProtect(reinterpret_cast<void*>(label), Page, PAGE_READONLY, &previous) != 0);
    GuestArenaEndProtection_nid_postfix(label, Page);
    Require(Read(label) == 0x4444);
    Require(GuestWriteWatchTrapReads_nid_postfix(label, 32));
    GuestWriteWatchReleaseReads_nid_postfix(label, 32);
    Require(ProtectionAt(label) == PAGE_READONLY && TakeResolved().empty());
    GuestArenaSetProtection_nid_postfix(label, Page, PAGE_READWRITE);
    Require(VirtualProtect(reinterpret_cast<void*>(label), Page, PAGE_READWRITE, &previous) != 0);
    GuestArenaEndProtection_nid_postfix(label, Page);
}

void CheckHostWrite() {
    Memory memory;
    const auto label = memory.At(4 * Page);
    Require(GuestWriteWatchTrapReads_nid_postfix(label, 32));
    stamp = 0x5555;
    Require(GuestArenaBeginHostWrite_nid_postfix(reinterpret_cast<void*>(label), 64));
    Require(TakeResolved() == Ranges{{label, label + 32}});
    Require(!GuestWriteWatchTrapReads_nid_postfix(label, 32));
    Write(label + 4, 1);
    GuestArenaEndHostWrite_nid_postfix(reinterpret_cast<void*>(label), 64);
    Require(Read(label) == 0x5555 && Read(label + 4) == 1);
    Require(GuestWriteWatchTrapReads_nid_postfix(label, 32));
    GuestWriteWatchReleaseReads_nid_postfix(label, 32);
}

void CheckResetDropsTraps() {
    {
        Memory memory;
        Require(GuestWriteWatchTrapReads_nid_postfix(memory.At(5 * Page), 16));
    }
    Require(TakeResolved().empty());
    Memory memory;
    Write(memory.At(5 * Page), 3);
    Require(Read(memory.At(5 * Page)) == 3 && TakeResolved().empty());
}

void CheckRefusals() {
    Memory memory;
    auto* host = static_cast<std::uint8_t*>(VirtualAlloc(nullptr, Bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    Require(host != nullptr);
    Require(!GuestWriteWatchTrapReads_nid_postfix(reinterpret_cast<std::uintptr_t>(host), 16));
    Require(VirtualFree(host, 0, MEM_RELEASE) != 0);
    Require(!GuestWriteWatchTrapReads_nid_postfix(memory.At(0), 0));
    const auto closed = memory.At(6 * Page);
    GuestArenaSetProtection_nid_postfix(closed, Page, PAGE_NOACCESS);
    DWORD previous = 0;
    Require(VirtualProtect(reinterpret_cast<void*>(closed), Page, PAGE_NOACCESS, &previous) != 0);
    GuestArenaEndProtection_nid_postfix(closed, Page);
    Require(!GuestWriteWatchTrapReads_nid_postfix(closed, 16));
    Require(!GuestWriteWatchTrapReads_nid_postfix(closed - Page, 2 * Page));
    Require(ProtectionAt(closed - Page) == PAGE_READWRITE);
    Require(TakeResolved().empty());
}

void CheckConcurrentReaders() {
    constexpr std::size_t Readers = 8;
    Memory memory;
    for (std::size_t index = 0; index < Readers; ++index) Require(GuestWriteWatchTrapReads_nid_postfix(memory.At(index * Page + 0x40), 16));
    stamp = 0x6666;
    std::atomic<std::size_t> seen{0};
    std::vector<std::thread> readers;
    for (std::size_t index = 0; index < Readers; ++index) {
        readers.emplace_back([&, index] {
            if (Read(memory.At(index * Page + 0x40)) == 0x6666) ++seen;
        });
    }
    for (auto& reader : readers) reader.join();
    Require(seen == Readers && TakeResolved().size() == Readers);
}

void CheckWideStore() {
    Memory memory;
    const auto label = memory.At(0x40);
    std::uint64_t counters[18]{};
    GuestWriteWatchTakeReadTrapCounters_nid_postfix(counters, 18);
    Require(GuestWriteWatchSetReadTrapResolver_nid_postfix(+[](std::uintptr_t begin, std::uintptr_t end) {
        {
            std::lock_guard lock(resolvedMutex);
            resolved.emplace_back(begin, end);
        }
        for (auto at = begin; at < end; at += Page) Write(at, stamp.load());
    }));
    Require(GuestWriteWatchTrapReads_nid_postfix(label, 8 * Page));
    stamp = 0x8888;
    Require(Read(label + 5 * Page) == 0x8888 && Read(label) == 0x8888);
    Require(GuestWriteWatchTakeReadTrapCounters_nid_postfix(counters, 18) == 18);
    Require(counters[0] == 1 && counters[5] == 2 && counters[6] == 1 && counters[8] == 1 && counters[13] == 1);
    Require(TakeResolved().size() == 1);
    Require(GuestWriteWatchSetReadTrapResolver_nid_postfix(&Resolve));
}

void CheckBypass() {
    Memory memory;
    const auto label = memory.At(7 * Page);
    GuestWriteWatchSetReadTrapBypass_nid_postfix(+[] { return bypassing.load(); });
    bypassing = true;
    Require(GuestWriteWatchTrapReads_nid_postfix(label, 16));
    stamp = 0x7777;
    Require(Read(label) == 0 && TakeResolved().empty());
    bypassing = false;
    GuestWriteWatchReleaseReads_nid_postfix(label, 16);
    GuestWriteWatchSetReadTrapBypass_nid_postfix(nullptr);
    Require(GuestWriteWatchTrapReads_nid_postfix(label, 16));
    Require(Read(label) == 0x7777 && TakeResolved().size() == 1);
}

}

int main() {
    try {
        {
            Memory memory;
            Require(!GuestWriteWatchTrapReads_nid_postfix(memory.At(0), 64));
        }
        Require(GuestWriteWatchSetReadTrapResolver_nid_postfix(&Resolve));
        CheckReadResolvesOnce();
        CheckReleaseSkipsResolver();
        CheckWriteResolvesFirst();
        CheckSharedPage();
        CheckProtectionChange();
        CheckHostWrite();
        CheckResetDropsTraps();
        CheckRefusals();
        CheckConcurrentReaders();
        CheckWideStore();
        CheckBypass();
    } catch (const std::exception& error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
    std::puts("Windows read trap tests passed");
    return 0;
}
