#include "prx/libSceAgcDriver/Execution/include/GuestMemory.hpp"
#include "prx/libSceAgcDriver/Graphics/include/RuntimeSwitches.hpp"
#include "prx/libc/include/GuestAllocations.hpp"
#include "prx/libc/include/GuestWriteWatch.hpp"
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

constexpr std::uint64_t Block = 65536;
constexpr std::uint64_t Page = 4096;
constexpr std::uint64_t Base = std::uint64_t{1} << 32;
constexpr std::uint64_t Span = 256 * Block;
constexpr std::chrono::seconds Patience{10};

struct FakeWatch {
    std::mutex mutex;
    std::condition_variable changed;
    std::vector<std::pair<std::uintptr_t, std::uintptr_t>> written;
    bool holdNextWalk = false;
    bool holding = false;
    bool released = false;
    bool timedOut = false;
    std::size_t walks = 0;
};

FakeWatch& Fake() {
    static FakeWatch fake;
    return fake;
}

void Require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

}

namespace GuestWriteWatch {

extern "C" {

bool GuestWriteWatchAvailable_nid_postfix() {
    return true;
}

bool GuestWriteWatchCovers_nid_postfix(std::uintptr_t address, std::size_t bytes) {
    return address >= Base && bytes <= Span && address - Base <= Span - bytes;
}

bool GuestWriteWatchCollect_nid_postfix(std::uintptr_t address, std::size_t bytes, void (*written)(void* context, std::uintptr_t begin, std::uintptr_t end), void* context) {
    auto& fake = Fake();
    const auto end = address + bytes;
    std::vector<std::pair<std::uintptr_t, std::uintptr_t>> runs;
    {
        std::unique_lock lock(fake.mutex);
        ++fake.walks;
        if (fake.holdNextWalk) {
            fake.holdNextWalk = false;
            fake.holding = true;
            fake.changed.notify_all();
            fake.timedOut = !fake.changed.wait_for(lock, Patience, [&] { return fake.released; });
        }
        for (auto it = fake.written.begin(); it != fake.written.end();) {
            if (it->first < end && address < it->second) {
                runs.emplace_back(std::max(it->first, address), std::min(it->second, end));
                it = fake.written.erase(it);
            } else ++it;
        }
    }
    for (const auto& [from, to] : runs) written(context, from, to);
    return true;
}

}

}

namespace {

using namespace AgcDriver::GuestMemory;

void CheckMemoHitDuringWalk() {
    auto& fake = Fake();
    BumpCollectEpoch();
    const auto collected = CollectWrites(Base, Block);
    Require(collected != 0 && UnchangedSince(Base, Block, collected), "the block was not collected");
    {
        const std::lock_guard lock(fake.mutex);
        fake.written.emplace_back(Base + Page, Base + 2 * Page);
        fake.holdNextWalk = true;
    }
    std::thread walker([] { CollectWritesUncached(Base, 2 * Block); });
    bool holding = false;
    {
        std::unique_lock lock(fake.mutex);
        holding = fake.changed.wait_for(lock, Patience, [&] { return fake.holding; });
    }
    const auto memoized = holding ? CollectWrites(Base, Block) : 0;
    {
        const std::lock_guard lock(fake.mutex);
        fake.released = true;
    }
    fake.changed.notify_all();
    walker.join();
    Require(holding, "the second walk did not reach the write watch");
    Require(!fake.timedOut, "the memoized collect waited for the walk in progress");
    Require(!UnchangedSince(Base + Page, Page, memoized), "a memoized collect returned the generation a walk in progress then stamped a write with");
    BumpCollectEpoch();
    Require(CollectWrites(Base, Block) > memoized && !UnchangedSince(Base, Block, memoized), "a later epoch trusts the write stamped by the walk in progress");
}

std::size_t Walks() {
    auto& fake = Fake();
    const std::lock_guard lock(fake.mutex);
    return fake.walks;
}

void Write(std::uint64_t begin, std::uint64_t end) {
    auto& fake = Fake();
    const std::lock_guard lock(fake.mutex);
    fake.written.emplace_back(begin, end);
}

std::uint64_t BlockAt(std::size_t index) {
    return Base + index * Block;
}

void EvictRing(std::size_t firstBlock) {
    for (std::size_t index = 0; index < 64; ++index) Require(CollectWrites(BlockAt(firstBlock + index) + Page, Page) != 0, "a ring filler was not collected");
}

void CheckBlockMemo(bool enabled) {
    namespace Switches = AgcDriver::Graphics::RuntimeSwitches;
    Switches::Assign(AgcDriver::Graphics::RuntimeSwitch::NoCollectBlockMemo, !enabled);
    const auto expect = [&](std::size_t before, std::size_t withMemo, std::size_t without, const char* what) {
        const auto walked = Walks() - before;
        Require(walked == (enabled ? withMemo : without), std::string(what) + (enabled ? " (block memo on): " : " (block memo off): ") + std::to_string(walked) + " walks");
    };
    BumpCollectEpoch();
    auto before = Walks();
    Require(CollectWrites(BlockAt(8) + Page, Page) != 0, "the first block was not collected");
    EvictRing(9);
    expect(before, 65, 65, "the fillers walked a different number of times");
    before = Walks();
    Require(CollectWrites(BlockAt(8) + 2 * Page, Page) != 0, "a page of a block walked this epoch was not collected");
    expect(before, 0, 1, "a page of a block walked this epoch after the ring forgot it");
    before = Walks();
    Require(CollectWrites(BlockAt(10) - Page, 2 * Page) != 0, "a range over two walked blocks was not collected");
    expect(before, 0, 1, "a range over two blocks walked separately this epoch");
    before = Walks();
    Require(CollectWrites(BlockAt(100) + Page, 3 * Block) != 0, "an unaligned range of several blocks was not collected");
    Require(CollectWrites(BlockAt(103) + 8 * Page, Page) != 0, "the last block of the unaligned range was not collected");
    expect(before, 1, 2, "the last block of an unaligned range walked this epoch");
    Write(BlockAt(8) + 3 * Page, BlockAt(8) + 4 * Page);
    before = Walks();
    const auto held = CollectWrites(BlockAt(8) + 3 * Page, Page);
    expect(before, 0, 0, "a store inside a block walked this epoch");
    BumpCollectEpoch();
    before = Walks();
    const auto next = CollectWrites(BlockAt(8) + 3 * Page, Page);
    Require(next != 0, "the block was not collected in the next epoch");
    expect(before, 1, 1, "the first collect of the next epoch");
    Require(!UnchangedSince(BlockAt(8) + 3 * Page, Page, held), "a store held over to the next epoch was not stamped");
    BumpCollectEpoch();
    Require(CollectWrites(BlockAt(8) + Page, Page) != 0, "the block was not collected before the mapping change");
    EvictRing(9);
    {
        auto mutation = GuestAllocations::Mutation();
        mutation.Add(reinterpret_cast<void*>(BlockAt(200)), Block, true, true, false);
    }
    before = Walks();
    Require(CollectWrites(BlockAt(8) + 2 * Page, Page) != 0, "the block was not collected after the mapping change");
    expect(before, 1, 1, "a page of a walked block after the guest mappings changed");
    GuestAllocations::Mutation().Remove(reinterpret_cast<void*>(BlockAt(200)));
    Switches::Assign(AgcDriver::Graphics::RuntimeSwitch::NoCollectBlockMemo, false);
}

}

int main() {
    try {
        CheckMemoHitDuringWalk();
        CheckBlockMemo(true);
        CheckBlockMemo(false);
    } catch (const std::exception& error) {
        std::cerr << "collect memo generation test failed: " << error.what() << "\n";
        return 1;
    }
    std::cout << "collect memo generation test passed\n";
    return 0;
}
