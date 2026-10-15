#include "steam_message_layout.h"

#include <array>
#include <cstdio>
#include <vector>

static int passed = 0, failed = 0;
#define CHECK(x) do { if (x) ++passed; else { ++failed; std::printf("FAIL line %d: %s\n", __LINE__, #x); } } while (0)

// Instruction sequences from the Windows service adapters. The old/new layouts
// differ only in these operands; neither test calls into a Steam process.
static std::vector<uint8_t> Reply(uint8_t header, uint8_t body) {
    return {0x49,0x8b,0x40,header, 0x48,0x89,0x7c,0x24,0x20,
            0x8b,0x48,0x74,0x89,0x0f,0x49,0x8b,0xca,0x49,0x8b,0x02,
            0x4d,0x8b,0x49,body,0x4d,0x8b,0x40,body,0xff,0x50,0x20};
}
static std::vector<uint8_t> Notify(uint8_t header, uint8_t body) {
    return {0x49,0x8b,0x40,header,0x4d,0x8b,0x40,body};
}
static bool Resolve(const std::vector<uint8_t>& r, const std::vector<uint8_t>& n,
                    SteamMessageLayout::Layout& layout) {
    return SteamMessageLayout::Resolve(r.data(),r.size(),n.data(),n.size(),layout);
}

int main() {
    SteamMessageLayout::Layout layout;
    for (uint8_t h : {0x28,0x30}) {
        auto r = Reply(h,h+8), n = Notify(h,h+8);
        CHECK(Resolve(r,n,layout));
        CHECK(layout.header == h && layout.body == h+8);
        // The regression: the old +0x30 is now a valid header pointer, not
        // null/garbage. Verify we select distinct body and header objects.
        int header = 1, body = 2;
        void* hp = &header; void* bp = &body;
        std::array<uint8_t,80> wrapper{};
        std::memcpy(wrapper.data()+h,&hp,sizeof(hp));
        std::memcpy(wrapper.data()+h+8,&bp,sizeof(bp));
        CHECK(SteamMessageLayout::Header(wrapper.data(),layout) == hp);
        CHECK(SteamMessageLayout::Body(wrapper.data(),layout) == bp);
        CHECK(SteamMessageLayout::Body(nullptr,layout) == nullptr);
        // Every truncated adapter must be rejected and clear a previous result.
        for (size_t size = 0; size < r.size(); ++size) {
            layout = {h,static_cast<uint32_t>(h+8)};
            CHECK(!SteamMessageLayout::Resolve(r.data(),size,n.data(),n.size(),layout));
            CHECK(layout.header == 0 && layout.body == 0);
        }
        for (size_t size = 0; size < n.size(); ++size)
            CHECK(!SteamMessageLayout::Resolve(r.data(),r.size(),n.data(),size,layout));
        r.insert(r.begin(),23,0x90); n.insert(n.begin(),17,0x90);
        CHECK(Resolve(r,n,layout));
    }
    CHECK(!Resolve(Reply(0x28,0x30),Notify(0x30,0x38),layout));
    CHECK(!Resolve(Reply(0x30,0x38),Notify(0x28,0x30),layout));
    CHECK(!Resolve(Reply(0x38,0x40),Notify(0x38,0x40),layout));
    CHECK(!Resolve(Reply(0x30,0x40),Notify(0x30,0x40),layout));
    auto r = Reply(0x30,0x38), n = Notify(0x30,0x38);
    r.back() = 0x28; // Not a call to the raw-body slot 4.
    CHECK(!Resolve(r,n,layout));
    r = Reply(0x30,0x38); r[23] = 0x30; // Response body disagrees.
    CHECK(!Resolve(r,n,layout));
    r = Reply(0x30,0x38); r[3] = 0x28; // Header disagrees.
    CHECK(!Resolve(r,n,layout));
    r = Reply(0x30,0x38); auto extra = r; r.insert(r.end(),extra.begin(),extra.end());
    CHECK(!Resolve(r,n,layout));
    r = Reply(0x30,0x38); extra = n; n.insert(n.end(),extra.begin(),extra.end());
    CHECK(!Resolve(r,n,layout));
    CHECK(!SteamMessageLayout::Resolve(nullptr,100,nullptr,100,layout));
    CHECK(SteamMessageLayout::Header(r.data(),layout) == nullptr);
    CHECK(SteamMessageLayout::Body(r.data(),layout) == nullptr);
    std::printf("Steam message layout: %d passed, %d failed\n",passed,failed);
    return failed ? 1 : 0;
}
