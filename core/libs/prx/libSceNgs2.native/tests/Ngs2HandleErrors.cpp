#include "Ngs2Test.hpp"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>

static void Status(int actual, int expected, const char* message) {
    if (actual != expected) throw std::runtime_error(message);
}

static void CheckResetOption() {
    Status(sceNgs2SystemResetOption(nullptr), static_cast<int>(0x804A8010u), "null system option did not return the invalid out address error");
    constexpr std::uint64_t size = 0x90;
    constexpr std::uint32_t maxGrainSamples = 512;
    constexpr std::uint32_t numGrainSamples = 256;
    constexpr std::uint32_t sampleRate = 48000;
    constexpr std::uint32_t maxVoiceChannels = 8;
    unsigned char expected[0x90] = {};
    std::memcpy(expected + 0x00, &size, sizeof(size));
    std::memcpy(expected + 0x6c, &maxGrainSamples, sizeof(maxGrainSamples));
    std::memcpy(expected + 0x70, &numGrainSamples, sizeof(numGrainSamples));
    std::memcpy(expected + 0x74, &sampleRate, sizeof(sampleRate));
    std::memcpy(expected + 0x78, &maxVoiceChannels, sizeof(maxVoiceChannels));
    static_assert(sizeof(Ngs2SystemOption) == sizeof(expected));
    Ngs2SystemOption option;
    std::memset(&option, 0xAB, sizeof(option));
    Status(sceNgs2SystemResetOption(&option), SCE_NGS2_OK, "system option reset failed");
    Require(std::memcmp(&option, expected, sizeof(expected)) == 0);
    Ngs2ContextBufferInfo query{};
    Status(sceNgs2SystemQueryBufferSize(&option, &query), SCE_NGS2_OK, "reset system option was rejected");
}

int main() {
    try {
        constexpr int systemError = static_cast<int>(0x804A8201u);
        constexpr int rackError = static_cast<int>(0x804A8202u);
        constexpr int outputError = static_cast<int>(0x804A8010u);
        constexpr uintptr_t sentinel = 0x5a5a;
        uintptr_t value = sentinel;
        Status(sceNgs2SystemGetUserData(0x1234, &value), systemError, "invalid system handle returned a non-PS5 error");
        Require(value == sentinel);
        Status(sceNgs2SystemDestroy(0x1234, nullptr), systemError, "system destroy returned a non-PS5 handle error");
        Status(sceNgs2RackGetVoiceHandle(0x1234, 0, &value), rackError, "invalid rack handle returned a non-PS5 error");
        Require(value == sentinel);
        Status(sceNgs2RackGetVoiceHandle(0x1234, 0, nullptr), rackError, "voice lookup checked output before the rack handle");
        Status(sceNgs2RackDestroy(0x1234, nullptr), rackError, "rack destroy returned a non-PS5 handle error");
        const auto system = CreateSystem();
        const auto rack = CreateRack(system, SCE_NGS2_RACK_ID_REVERB);
        Status(sceNgs2SystemGetUserData(rack, &value), systemError, "rack handle was accepted as a system");
        Require(value == sentinel);
        Status(sceNgs2RackGetVoiceHandle(system, 0, &value), rackError, "system handle was accepted as a rack");
        Require(value == sentinel);
        Status(sceNgs2RackGetVoiceHandle(system, 0, nullptr), rackError, "wrong-kind rack did not take precedence over null output");
        Status(sceNgs2RackGetVoiceHandle(rack, 0, nullptr), outputError, "valid rack lost null-output validation");
        Status(sceNgs2RackGetVoiceHandle(rack, 0, &value), SCE_NGS2_OK, "valid voice lookup failed");
        Require(value != 0 && value != sentinel);
        Status(sceNgs2RackDestroy(rack, nullptr), SCE_NGS2_OK, "valid rack destroy failed");
        value = sentinel;
        Status(sceNgs2RackGetVoiceHandle(rack, 0, &value), rackError, "retired rack returned the wrong error");
        Require(value == sentinel);
        Status(sceNgs2RackGetVoiceHandle(rack, 0, nullptr), rackError, "retired rack did not take precedence over null output");
        Status(sceNgs2SystemDestroy(system, nullptr), SCE_NGS2_OK, "valid system destroy failed");
        Status(sceNgs2SystemGetUserData(system, &value), systemError, "retired system returned the wrong error");
        Require(value == sentinel);
        CheckResetOption();
        std::cout << "NGS2 PS5 handle errors and validation precedence checked\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
