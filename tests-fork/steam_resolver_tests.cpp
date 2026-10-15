// Byte fixtures run on any platform. On Windows, an optional DLL path also
// runs the real resolver on a PE mapping without imports, TLS or DllMain.
// Sources: this file, sc_resolver.cpp, sig_scanner.cpp. Do not link log.cpp.
#include "../src/platform/win/steam_engine_layout.h"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "../src/platform/win/sc_resolver.h"
#include "../src/platform/win/sig_scanner.h"
#include "../src/platform/win/steam_message_layout.h"
namespace Log {
void Write(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    std::vprintf(fmt, args);
    std::putchar('\n');
    va_end(args);
}
}
#endif

static int failures = 0;
#define CHECK(x) do { if (!(x)) { ++failures; std::fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); } } while (0)

static std::vector<uint8_t> Bytes(const char* text) {
    std::vector<uint8_t> result;
    while (*text) {
        char* end = nullptr;
        result.push_back(static_cast<uint8_t>(std::strtoul(text, &end, 16)));
        text = end;
        while (*text == ' ') ++text;
    }
    return result;
}
static void Put32(std::vector<uint8_t>& bytes, size_t at, uint32_t value) {
    std::memcpy(bytes.data() + at, &value, sizeof(value));
}

static void Fixtures() {
    using namespace SteamEngineLayout;
    // Installed 11.12.30.07: actual maxnumfiles caller at RVA A3EC21.
    const auto kv = Bytes(
        "48 8b 1d e0 e3 dd 00 48 8b e8 48 8d 8b 08 12 00 00 "
        "e8 f9 8e a8 ff 4c 8d 0d e2 29 85 00 48 c7 44 24 20 00 00 00 00 "
        "41 b8 0a 00 00 00 48 8d 8b 08 12 00 00 8b d7 e8 55 a8 a8 ff");
    KvReference out;
    CHECK(DecodeKvReference(kv.data(), kv.size(), 0xA3EC21, 0x4C94B0, out));
    CHECK(out.global == 0x181D008 && out.cache == 0x1208 && out.key == 0x1291620);
    CHECK(DecodeKvReference(kv.data(), kv.size(), 0x7FF000A3EC21ULL, 0x7FF0004C94B0ULL, out));
    CHECK(out.global == 0x7FF00181D008ULL); // relocated module
    CHECK(!DecodeKvReference(nullptr, kv.size(), 0xA3EC21, 0x4C94B0, out));
    CHECK(!DecodeKvReference(kv.data(), kv.size(), 0xA3EC21, 0, out));
    for (size_t n = 0; n < kv.size(); ++n)
        CHECK(!DecodeKvReference(kv.data(), n, 0xA3EC21, 0x4C94B0, out));

    auto changed = kv;
    Put32(changed, 13, 0xE68);
    Put32(changed, 47, 0xE68);
    CHECK(DecodeKvReference(changed.data(), changed.size(), 0xA3EC21, 0x4C94B0, out));
    CHECK(out.cache == 0xE68); // operand extraction, not a new fixed offset
    Put32(changed, 47, 0x1208);
    CHECK(!DecodeKvReference(changed.data(), changed.size(), 0xA3EC21, 0x4C94B0, out));
    changed = kv;
    changed[9] = 0xD8; // overwrite RBX between load and use
    CHECK(!DecodeKvReference(changed.data(), changed.size(), 0xA3EC21, 0x4C94B0, out));
    changed = kv;
    changed[7] = 0xEB; // branch: no linear dataflow proof
    CHECK(!DecodeKvReference(changed.data(), changed.size(), 0xA3EC21, 0x4C94B0, out));
    changed = kv;
    changed[40] = 9; // section must be UFS
    CHECK(!DecodeKvReference(changed.data(), changed.size(), 0xA3EC21, 0x4C94B0, out));
    changed = kv;
    changed[53] = 0xE9; // tail jump/unknown form must not count as a verified call
    CHECK(!DecodeKvReference(changed.data(), changed.size(), 0xA3EC21, 0x4C94B0, out));

    // Actual user-map lookup at RVA 990600, including all return paths.
    const auto lookup = Bytes(
        "40 53 55 56 57 41 56 41 57 48 83 ec 38 8b b9 90 10 00 00 "
        "48 8b f1 83 ef 01 89 54 24 20 78 61 4c 8b b9 a0 10 00 00 "
        "33 ed 0f 1f 84 00 00 00 00 00 48 8b 8e 80 10 00 00 "
        "8d 1c 2f d1 fb 48 8d 54 24 20 4c 63 f3 4d 8b c7 49 c1 e6 04 "
        "49 03 ce ff 96 98 10 00 00 84 c0 74 05 8d 6b 01 eb 1f "
        "48 8b 96 80 10 00 00 48 8d 4c 24 20 49 03 d6 4d 8b c7 ff 96 "
        "98 10 00 00 84 c0 74 16 8d 7b ff 3b ef 7e b0 33 c0 "
        "48 83 c4 38 41 5f 41 5e 5f 5e 5d 5b c3 83 fb ff 74 ec "
        "48 8b 86 80 10 00 00 49 8b 44 06 08 48 83 c4 38 41 5f 41 5e 5f 5e 5d 5b c3");
    uint32_t map = 0;
    CHECK(DecodeUserMap(lookup.data(), lookup.size(), map));
    CHECK(map == 0x1080);
    CHECK(!DecodeUserMap(nullptr, lookup.size(), map));
    for (size_t n = 0; n < lookup.size(); ++n) CHECK(!DecodeUserMap(lookup.data(), n, map));
    auto badMap = lookup;
    badMap[0x4A] = 5; // 32-byte entries must not be interpreted as 16-byte entries
    CHECK(!DecodeUserMap(badMap.data(), badMap.size(), map));
    badMap = lookup;
    Put32(badMap, 0x97, 0xCE0); // inconsistent returned array
    CHECK(!DecodeUserMap(badMap.data(), badMap.size(), map));
    badMap = lookup;
    badMap[0x9F] = 0x10; // wrong pointer offset in each entry
    CHECK(!DecodeUserMap(badMap.data(), badMap.size(), map));
}

#ifdef _WIN32
static bool In(uintptr_t p, size_t width, uintptr_t start, size_t size) {
    return p >= start && p - start <= size && width <= size - (p - start);
}

static void Smoke(const wchar_t* path) {
    HMODULE module = LoadLibraryExW(path, nullptr, DONT_RESOLVE_DLL_REFERENCES);
    CHECK(module != nullptr);
    if (!module) {
        std::fprintf(stderr, "PE mapping failed: %lu\n", GetLastError());
        return;
    }
    const uintptr_t base = reinterpret_cast<uintptr_t>(module);
    const auto r = ScResolver::Resolve(base);
    const uintptr_t functions[] = {
        r.getAppInfo, r.getSection, r.readConfigU64, r.kvFindKey,
        r.kvGetUint64, r.kvGetInt, r.kvSetUint64, r.kvSetInt, r.kvSetString,
        r.serializeToArray, r.parseFromArray, r.bRouteMsgToJob,
        r.wrapPacket, r.releaseWrapped, r.findJob, r.refCountHelper
    };
    for (auto address : functions)
        CHECK(In(address, 1, SigScanner::GetTextBase(), SigScanner::GetTextSize()));
    CHECK(In(r.globalEngine, sizeof(void*), SigScanner::GetDataBase(), SigScanner::GetDataSize()));
    CHECK(In(r.ccmInterfaceVtable, sizeof(void*), SigScanner::GetRdataBase(), SigScanner::GetRdataSize()));
    const bool transportReadable = In(r.serviceTransportVtable, 9 * sizeof(uintptr_t),
                                     SigScanner::GetRdataBase(), SigScanner::GetRdataSize());
    CHECK(transportReadable);
    SteamMessageLayout::Layout messageLayout;
    if (transportReadable) {
        uintptr_t reply = 0, notify = 0;
        std::memcpy(&reply, reinterpret_cast<const void*>(r.serviceTransportVtable + 5 * sizeof(uintptr_t)), sizeof(reply));
        std::memcpy(&notify, reinterpret_cast<const void*>(r.serviceTransportVtable + 8 * sizeof(uintptr_t)), sizeof(notify));
        const bool replyReadable = In(reply, 0x100, SigScanner::GetTextBase(), SigScanner::GetTextSize());
        const bool notifyReadable = In(notify, 0x100, SigScanner::GetTextBase(), SigScanner::GetTextSize());
        CHECK(replyReadable && notifyReadable);
        if (replyReadable && notifyReadable) {
            CHECK(SteamMessageLayout::Resolve(reinterpret_cast<const uint8_t*>(reply), 0x100,
                reinterpret_cast<const uint8_t*>(notify), 0x100, messageLayout));
            std::printf("Service wrapper header=0x%X body=0x%X\n", messageLayout.header, messageLayout.body);
        }
    }
    CHECK(SteamEngineLayout::Offset(r.engineOffAppInfoCache));
    CHECK(SteamEngineLayout::Offset(r.engineOffGlobalHandle));
    CHECK(SteamEngineLayout::Offset(r.engineOffUserMap));
    CHECK(r.engineOffGlobalHandle < r.engineOffUserMap);
    CHECK(r.engineOffUserMap + 40 < r.engineOffAppInfoCache);
    CHECK(r.engineOffJobMgr == 0 && r.ccmOffConnContext == 0 && r.userOffCcmInterface == 0);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->FileHeader.TimeDateStamp == 0x6ACE7CC5 && nt->OptionalHeader.SizeOfImage == 0x19B3000) {
        CHECK(r.globalEngine - base == 0x181D008);
        CHECK(r.engineOffAppInfoCache == 0x1208);
        CHECK(r.engineOffGlobalHandle == 0xFE8);
        CHECK(r.engineOffUserMap == 0x1080);
        CHECK(messageLayout.header == 0x30 && messageLayout.body == 0x38);
    }
    std::printf("Engine RVA=0x%llX cache=0x%X handle=0x%X map=0x%X\n",
        static_cast<unsigned long long>(r.globalEngine ? r.globalEngine - base : 0),
        r.engineOffAppInfoCache, r.engineOffGlobalHandle, r.engineOffUserMap);
    FreeLibrary(module);
}

int wmain(int argc, wchar_t** argv) {
    Fixtures();
    if (argc > 1) Smoke(argv[1]);
    std::printf("steam_resolver_tests: %d failures\n", failures);
    return failures ? 1 : 0;
}
#else
int main() {
    Fixtures();
    std::printf("steam_resolver_tests: %d failures\n", failures);
    return failures ? 1 : 0;
}
#endif
