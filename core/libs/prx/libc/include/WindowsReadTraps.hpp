#ifndef CORE_LIBS_PRX_LIBC_INCLUDE_WINDOWSREADTRAPS_HPP
#define CORE_LIBS_PRX_LIBC_INCLUDE_WINDOWSREADTRAPS_HPP

#ifdef _WIN32
#include <windows.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace GuestArena {

class WindowsReadTraps {
public:
    using Resolver = void (*)(std::uintptr_t begin, std::uintptr_t end);
    using Bypass = bool (*)();

    enum Counter : std::size_t {
        Traps,
        TrapsAgain,
        TrapsRefused,
        TrapBytes,
        Protects,
        Faults,
        Queued,
        QueuedWaitNs,
        OwnStores,
        ResolverThread,
        Bypassed,
        Untrapped,
        Retried,
        Resolves,
        ResolveNs,
        Releases,
        Drops,
        MappingRefused,
        CounterCount
    };

    static WindowsReadTraps& Get() {
        static auto* traps = new WindowsReadTraps;
        return *traps;
    }

    bool SetResolver(Resolver resolve) {
        if (resolve == nullptr) return false;
        std::call_once(started, [this] { start(); });
        if (!running.load(std::memory_order_acquire)) return false;
        resolver.store(resolve, std::memory_order_release);
        return true;
    }

    void SetBypass(Bypass pass) {
        bypass.store(pass, std::memory_order_release);
    }

    bool Enabled() const {
        return resolver.load(std::memory_order_acquire) != nullptr;
    }

    bool Trap(std::uintptr_t begin, std::uintptr_t end) {
        if (!Enabled() || end <= begin) return false;
        const auto first = pageStart(begin);
        const auto last = pageEnd(end);
        std::lock_guard lock(mutex);
        const auto [same, other] = traps.equal_range(begin);
        if (std::any_of(same, other, [&](const auto& trap) { return trap.second == end; })) {
            count(TrapsAgain);
            return true;
        }
        if (resolvingCovers(first, last, Owner::Any)) {
            count(TrapsRefused);
            return false;
        }
        std::vector<std::pair<std::uintptr_t, Span>> added;
        const auto rollback = [&] {
            for (const auto& [from, span] : added) {
                DWORD previous = 0;
                VirtualProtect(reinterpret_cast<void*>(from), span.end - from, span.protection, &previous);
                count(Protects);
            }
            count(TrapsRefused);
            return false;
        };
        for (auto cursor = first; cursor < last;) {
            if (const auto run = runAt(cursor); run != runs.end()) {
                cursor = std::min(last, run->second.end);
                continue;
            }
            const auto next = runs.lower_bound(cursor);
            const auto limit = next == runs.end() ? last : std::min(last, next->first);
            MEMORY_BASIC_INFORMATION memory{};
            if (VirtualQuery(reinterpret_cast<const void*>(cursor), &memory, sizeof(memory)) != sizeof(memory) || memory.State != MEM_COMMIT || memory.Type != MEM_PRIVATE || !readable(memory.Protect)) return rollback();
            const auto stop = std::min(limit, reinterpret_cast<std::uintptr_t>(memory.BaseAddress) + memory.RegionSize);
            DWORD previous = 0;
            count(Protects);
            if (!VirtualProtect(reinterpret_cast<void*>(cursor), stop - cursor, PAGE_NOACCESS, &previous)) return rollback();
            added.emplace_back(cursor, Span{stop, memory.Protect});
            cursor = stop;
        }
        for (const auto& [from, span] : added) runs.emplace(from, span);
        traps.emplace(begin, end);
        trapping.store(true, std::memory_order_release);
        count(Traps);
        count(TrapBytes, end - begin);
        return true;
    }

    void Release(std::uintptr_t begin, std::uintptr_t end) {
        if (end <= begin) return;
        std::lock_guard lock(mutex);
        const auto [first, last] = traps.equal_range(begin);
        const auto found = std::find_if(first, last, [&](const auto& trap) { return trap.second == end; });
        if (found == last) return;
        traps.erase(found);
        count(Releases);
        untrap(pageStart(begin), pageEnd(end));
    }

    void Drop(std::uintptr_t begin, std::uintptr_t end, bool restore) {
        if (end <= begin || !trapping.load(std::memory_order_acquire)) return;
        const auto first = pageStart(begin);
        const auto last = pageEnd(end);
        std::lock_guard lock(mutex);
        const auto taken = takeTraps(first, last);
        count(Drops, taken.size());
        for (const auto& [from, to] : taken) {
            if (from < first) untrap(pageStart(from), first);
            if (to > last) untrap(last, pageEnd(to));
        }
        if (restore) untrap(first, last);
        else forget(first, last);
    }

    void WithoutTraps(std::uintptr_t begin, std::uintptr_t end) {
        if (end <= begin) return;
        const auto first = pageStart(begin);
        const auto last = pageEnd(end);
        while (trapping.load(std::memory_order_acquire)) {
            waitForResolving(first, last);
            resolve(first, last);
            std::lock_guard lock(mutex);
            if (trapCovers(first, last) || resolvingCovers(first, last, Owner::Others)) continue;
            untrap(first, last);
            return;
        }
    }

    bool HandleFault(std::uintptr_t address, bool write) {
        if (!trapping.load(std::memory_order_acquire)) return false;
        const auto page = pageStart(address);
        {
            std::lock_guard lock(mutex);
            if (runAt(page) == runs.end()) {
                const bool retried = retryUntrapped(page, write);
                if (retried) count(Retried);
                return retried;
            }
            count(Faults);
            if (restoreOwnResolving(page)) {
                count(OwnStores);
                return true;
            }
            const auto pass = bypass.load(std::memory_order_acquire);
            const auto kind = GetCurrentThreadId() == resolverThread.load(std::memory_order_acquire) ? ResolverThread : pass != nullptr && pass() ? Bypassed : !trapCovers(page, page + PageBytes) && !resolvingCovers(page, page + PageBytes, Owner::Any) ? Untrapped : CounterCount;
            if (kind != CounterCount) {
                count(kind);
                restore(page, page + PageBytes);
                return true;
            }
        }
        count(Queued);
        const auto start = std::chrono::steady_clock::now();
        Request request{page};
        {
            std::unique_lock lock(queueMutex);
            queue.push_back(&request);
            wake.notify_one();
            finished.wait(lock, [&] { return request.done; });
        }
        count(QueuedWaitNs, elapsedNs(start));
        return true;
    }

    std::size_t TrappedPages() {
        std::lock_guard lock(mutex);
        std::size_t pages = 0;
        for (const auto& [from, span] : runs) pages += (span.end - from) / PageBytes;
        return pages;
    }

    void CountMappingRefusal() {
        count(MappingRefused);
    }

    std::size_t TakeCounters(std::uint64_t* values, std::size_t capacity) {
        const auto filled = std::min<std::size_t>(capacity, CounterCount);
        for (std::size_t index = 0; index < filled; ++index) values[index] = counters[index].exchange(0, std::memory_order_relaxed);
        return filled;
    }

private:
    static constexpr std::uintptr_t PageBytes = 4096;
    static constexpr std::size_t RecentUntraps = 64;
    static constexpr unsigned UntrappedRetries = 16;

    enum class Owner { Self, Others, Any };

    struct Span {
        std::uintptr_t end = 0;
        DWORD protection = 0;
    };

    struct Resolving {
        std::uintptr_t begin = 0;
        std::uintptr_t end = 0;
        DWORD owner = 0;
    };

    struct Request {
        std::uintptr_t page = 0;
        bool done = false;
    };

    static std::uintptr_t pageStart(std::uintptr_t address) {
        return address & ~(PageBytes - 1);
    }

    static std::uintptr_t pageEnd(std::uintptr_t address) {
        return (address + PageBytes - 1) & ~(PageBytes - 1);
    }

    void count(Counter counter, std::uint64_t amount = 1) {
        counters[counter].fetch_add(amount, std::memory_order_relaxed);
    }

    static std::uint64_t elapsedNs(std::chrono::steady_clock::time_point start) {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start).count());
    }

    bool restoreOwnResolving(std::uintptr_t page) {
        const auto self = GetCurrentThreadId();
        std::vector<std::pair<std::uintptr_t, std::uintptr_t>> own;
        for (const auto& entry : resolving) {
            if (entry.owner == self && pageStart(entry.begin) <= page && page < pageEnd(entry.end)) own.emplace_back(pageStart(entry.begin), pageEnd(entry.end));
        }
        for (const auto& [from, to] : own) restore(from, to);
        return !own.empty();
    }

    static bool readable(DWORD protection) {
        if ((protection & ~DWORD{0xff}) != 0) return false;
        switch (protection) {
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    static bool allows(DWORD protection, bool write) {
        if ((protection & (PAGE_GUARD | PAGE_NOACCESS)) != 0) return false;
        const auto base = protection & 0xffu;
        if (write) return base == PAGE_READWRITE || base == PAGE_WRITECOPY || base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
        return base != 0 && base != PAGE_EXECUTE;
    }

    std::map<std::uintptr_t, Span>::iterator runAt(std::uintptr_t page) {
        auto next = runs.upper_bound(page);
        if (next == runs.begin()) return runs.end();
        const auto run = std::prev(next);
        return page < run->second.end ? run : runs.end();
    }

    bool trapCovers(std::uintptr_t first, std::uintptr_t last) const {
        return std::any_of(traps.begin(), traps.end(), [&](const auto& trap) { return pageStart(trap.first) < last && first < pageEnd(trap.second); });
    }

    bool resolvingCovers(std::uintptr_t first, std::uintptr_t last, Owner owner) const {
        const auto self = GetCurrentThreadId();
        return std::any_of(resolving.begin(), resolving.end(), [&](const Resolving& entry) {
            if (pageStart(entry.begin) >= last || first >= pageEnd(entry.end)) return false;
            return owner == Owner::Any || (entry.owner == self) == (owner == Owner::Self);
        });
    }

    std::vector<std::pair<std::uintptr_t, std::uintptr_t>> takeTraps(std::uintptr_t first, std::uintptr_t last) {
        std::vector<std::pair<std::uintptr_t, std::uintptr_t>> taken;
        for (bool grew = true; grew;) {
            grew = false;
            for (auto it = traps.begin(); it != traps.end();) {
                if (pageStart(it->first) >= last || pageEnd(it->second) <= first) {
                    ++it;
                    continue;
                }
                first = std::min(first, pageStart(it->first));
                last = std::max(last, pageEnd(it->second));
                taken.emplace_back(*it);
                it = traps.erase(it);
                grew = true;
            }
        }
        return taken;
    }

    template<typename Visit>
    void carve(std::uintptr_t first, std::uintptr_t last, Visit visit) {
        auto it = runs.upper_bound(first);
        if (it != runs.begin() && std::prev(it)->second.end > first) --it;
        while (it != runs.end() && it->first < last) {
            const auto from = it->first;
            const auto span = it->second;
            it = runs.erase(it);
            if (from < first) runs.emplace(from, Span{first, span.protection});
            if (span.end > last) it = runs.emplace(last, Span{span.end, span.protection}).first;
            visit(std::max(from, first), std::min(span.end, last), span.protection);
        }
    }

    void restore(std::uintptr_t first, std::uintptr_t last) {
        carve(first, last, [&](std::uintptr_t from, std::uintptr_t to, DWORD protection) {
            DWORD previous = 0;
            VirtualProtect(reinterpret_cast<void*>(from), to - from, protection, &previous);
            count(Protects);
            noteUntrapped(from, to);
        });
    }

    void forget(std::uintptr_t first, std::uintptr_t last) {
        carve(first, last, [&](std::uintptr_t from, std::uintptr_t to, DWORD) { noteUntrapped(from, to); });
    }

    void untrap(std::uintptr_t first, std::uintptr_t last) {
        std::vector<std::pair<std::uintptr_t, std::uintptr_t>> held;
        for (const auto& [from, to] : traps) {
            if (pageStart(from) < last && first < pageEnd(to)) held.emplace_back(pageStart(from), pageEnd(to));
        }
        const auto self = GetCurrentThreadId();
        for (const auto& entry : resolving) {
            if (entry.owner != self && pageStart(entry.begin) < last && first < pageEnd(entry.end)) held.emplace_back(pageStart(entry.begin), pageEnd(entry.end));
        }
        std::sort(held.begin(), held.end());
        auto cursor = first;
        for (const auto& [from, to] : held) {
            if (to <= cursor) continue;
            if (from >= last) break;
            if (from > cursor) restore(cursor, std::min(from, last));
            cursor = std::max(cursor, to);
        }
        if (cursor < last) restore(cursor, last);
    }

    void noteUntrapped(std::uintptr_t from, std::uintptr_t to) {
        recent[recentNext++ % recent.size()] = {from, to};
        ++untrapGeneration;
    }

    bool retryUntrapped(std::uintptr_t page, bool write) {
        if (std::none_of(recent.begin(), recent.end(), [&](const auto& range) { return range.first <= page && page < range.second; })) return false;
        struct Retry {
            std::uintptr_t page = 0;
            std::uint64_t generation = 0;
            unsigned count = 0;
        };
        thread_local Retry retry;
        if (retry.page != page || retry.generation != untrapGeneration) retry = {page, untrapGeneration, 0};
        if (++retry.count > UntrappedRetries) return false;
        MEMORY_BASIC_INFORMATION memory{};
        return VirtualQuery(reinterpret_cast<const void*>(page), &memory, sizeof(memory)) == sizeof(memory) && memory.State == MEM_COMMIT && allows(memory.Protect, write);
    }

    void waitForResolving(std::uintptr_t first, std::uintptr_t last) {
        for (;;) {
            {
                std::lock_guard lock(mutex);
                if (!resolvingCovers(first, last, Owner::Others)) return;
            }
            SwitchToThread();
        }
    }

    void resolve(std::uintptr_t first, std::uintptr_t last) {
        std::vector<std::pair<std::uintptr_t, std::uintptr_t>> taken;
        const auto self = GetCurrentThreadId();
        {
            std::lock_guard lock(mutex);
            taken = takeTraps(first, last);
            for (const auto& [from, to] : taken) resolving.push_back({from, to, self});
        }
        if (taken.empty()) return;
        const auto resolve = resolver.load(std::memory_order_acquire);
        const auto start = std::chrono::steady_clock::now();
        for (const auto& [from, to] : taken) resolve(from, to);
        count(Resolves, taken.size());
        count(ResolveNs, elapsedNs(start));
        std::lock_guard lock(mutex);
        for (const auto& [from, to] : taken) {
            const auto found = std::find_if(resolving.begin(), resolving.end(), [&](const Resolving& entry) { return entry.begin == from && entry.end == to && entry.owner == self; });
            if (found != resolving.end()) resolving.erase(found);
        }
        for (const auto& [from, to] : taken) untrap(pageStart(from), pageEnd(to));
    }

    void start() {
        try {
            std::thread([this] { resolveLoop(); }).detach();
        } catch (...) {
            return;
        }
        while (resolverThread.load(std::memory_order_acquire) == 0) SwitchToThread();
        running.store(true, std::memory_order_release);
    }

    void resolveLoop() {
        resolverThread.store(GetCurrentThreadId(), std::memory_order_release);
        for (;;) {
            Request* request = nullptr;
            {
                std::unique_lock lock(queueMutex);
                wake.wait(lock, [&] { return !queue.empty(); });
                request = queue.front();
                queue.pop_front();
            }
            const auto page = request->page;
            waitForResolving(page, page + PageBytes);
            resolve(page, page + PageBytes);
            {
                std::lock_guard lock(mutex);
                untrap(page, page + PageBytes);
            }
            {
                std::lock_guard lock(queueMutex);
                request->done = true;
            }
            finished.notify_all();
        }
    }

    std::mutex mutex;
    std::map<std::uintptr_t, Span> runs;
    std::multimap<std::uintptr_t, std::uintptr_t> traps;
    std::vector<Resolving> resolving;
    std::array<std::pair<std::uintptr_t, std::uintptr_t>, RecentUntraps> recent{};
    std::size_t recentNext = 0;
    std::uint64_t untrapGeneration = 0;
    std::atomic<bool> trapping{false};
    std::atomic<Resolver> resolver{nullptr};
    std::atomic<Bypass> bypass{nullptr};
    std::once_flag started;
    std::atomic<bool> running{false};
    std::atomic<DWORD> resolverThread{0};
    std::mutex queueMutex;
    std::condition_variable wake;
    std::condition_variable finished;
    std::deque<Request*> queue;
    std::array<std::atomic<std::uint64_t>, CounterCount> counters{};
};

}

#endif

#endif
