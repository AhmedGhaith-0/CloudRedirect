#pragma once
// Pure helpers for overwrite forensics: resolve a cloud filename to its local
// disk path, inspect the local file, and classify what serving a cloud blob
// would do to it. Header-only and side-effect free (except InspectLocalFile,
// which only reads) so tests can exercise the logic directly.

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "autocloud_util.h"
#include "file_util.h"

namespace ForensicUtil {

// Hash only local files up to this size; larger files compare size/mtime only.
static constexpr uintmax_t kMaxShaFileBytes = 16ULL * 1024 * 1024;
// Total hashing budget per changelist call (bounds BMainLoop stall).
static constexpr uint64_t kShaBudgetBytes = 64ULL * 1024 * 1024;

struct ForensicRule {
    std::string token;        // %WinAppDataLocalLow%
    std::string cloudPath;    // rule path, normalized, no leading/trailing slash
    std::string resolvedPath; // local-relative path (tokens expanded at use)
    std::string pattern;      // leaf glob like *.sav
    bool recursive = false;
};

struct LocalFileInfo {
    bool exists = false;
    uint64_t size = 0;
    uint64_t mtime = 0;            // unix seconds, 0 when unknown
    std::vector<uint8_t> sha;      // empty when skipped/unavailable
    bool shaSkipped = false;       // over cap, budget, or read error
};

enum class ServeVerdict {
    Match,        // local sha == served sha
    LocalNewer,   // content differs and local mtime > served ts (danger)
    CloudNewer,   // content differs and served ts >= local mtime (normal)
    LocalMissing, // no local file
    ShaSkipped,   // sha not computed; timestamps inconclusive
    NoServedSha,  // cloud entry carries no sha
};

inline const char* ServeVerdictName(ServeVerdict v) {
    switch (v) {
        case ServeVerdict::Match:        return "match";
        case ServeVerdict::LocalNewer:   return "LOCAL-NEWER";
        case ServeVerdict::CloudNewer:   return "cloud-newer";
        case ServeVerdict::LocalMissing: return "local-missing";
        case ServeVerdict::ShaSkipped:   return "sha-skipped";
        case ServeVerdict::NoServedSha:  return "no-served-sha";
    }
    return "unknown";
}

inline ServeVerdict ClassifyServeVerdict(const LocalFileInfo& local,
                                         const std::vector<uint8_t>& servedSha,
                                         uint64_t servedTs) {
    if (!local.exists) return ServeVerdict::LocalMissing;
    if (servedSha.empty()) return ServeVerdict::NoServedSha;
    if (local.sha.empty()) {
        // No local sha: fall back to timestamps. Local mtime past the served
        // timestamp is the dangerous direction even without content proof.
        if (local.mtime != 0 && servedTs != 0 && local.mtime > servedTs)
            return ServeVerdict::LocalNewer;
        return ServeVerdict::ShaSkipped;
    }
    if (local.sha == servedSha) return ServeVerdict::Match;
    if (local.mtime != 0 && servedTs != 0 && local.mtime > servedTs)
        return ServeVerdict::LocalNewer;
    return ServeVerdict::CloudNewer;
}

// Lowercase hex of the full SHA-1 (40 chars); empty input -> empty string.
inline std::string ShaHex(const std::vector<uint8_t>& sha) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(sha.size() * 2);
    for (uint8_t b : sha) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0xF]);
    }
    return out;
}

// Resolve a clean cloud filename to the local game-folder path using AutoCloud
// rules plus a token->directory map (AutoCloudScan::GetRootTokenDirectories).
// Returns empty when no rule matches or the matching root is unresolvable.
inline std::string ResolveLocalPathForCloudFile(
        const std::vector<ForensicRule>& rules,
        const std::unordered_map<std::string, std::string>& tokenDirs,
        uint32_t accountId,
        const std::string& cleanFilename) {
    using namespace AutoCloudUtil;
    for (const auto& rr : rules) {
        std::string rel;
        if (rr.cloudPath.empty()) {
            rel = cleanFilename;
        } else {
            std::string pfx = rr.cloudPath + "/";
            if (cleanFilename.size() <= pfx.size() ||
                ToLowerAscii(cleanFilename.substr(0, pfx.size())) != ToLowerAscii(pfx))
                continue;
            rel = cleanFilename.substr(pfx.size());
        }
        // Non-recursive rules only match files directly in the directory.
        if (!rr.recursive && rel.find('/') != std::string::npos) continue;
        std::string leafName = rel;
        size_t s = leafName.rfind('/');
        if (s != std::string::npos) leafName = leafName.substr(s + 1);
        const std::string& matchTarget =
            rr.pattern.find('/') == std::string::npos ? leafName : rel;
        std::string pattern = rr.pattern.empty() ? "*" : rr.pattern;
        if (!WildcardMatchInsensitive(pattern, matchTarget)) continue;

        auto dirIt = tokenDirs.find(rr.token);
        if (dirIt == tokenDirs.end()) continue;
        std::string local = dirIt->second;
        if (!local.empty() && local.back() != '/' && local.back() != '\\') {
#ifdef _WIN32
            local += '\\';
#else
            local += '/';
#endif
        }
        std::string resolved =
            ExpandAutoCloudPathTokens(NormalizeSlashes(rr.resolvedPath), accountId);
        if (resolved == ".") resolved.clear();
        while (!resolved.empty() && resolved.front() == '/') resolved.erase(0, 1);
        while (!resolved.empty() && resolved.back() == '/') resolved.pop_back();
        if (!resolved.empty()) {
            local += resolved;
            local += '/';
        }
        local += rel;
        return local;
    }
    return {};
}

// Stat (and, within caps/budget, SHA-1) the local file. shaBudget shrinks by
// the bytes hashed so callers can bound total I/O per invocation.
inline LocalFileInfo InspectLocalFile(const std::string& utf8Path,
                                      uint64_t& shaBudget) {
    LocalFileInfo out;
    std::error_code ec;
    auto path = FileUtil::Utf8ToPath(utf8Path);
    if (!std::filesystem::exists(path, ec) || ec) return out;
    out.exists = true;
    auto sz = std::filesystem::file_size(path, ec);
    if (!ec) out.size = sz;
    auto ft = std::filesystem::last_write_time(path, ec);
    if (!ec) out.mtime = AutoCloudUtil::FileTimeToUnixSeconds(ft);
    if (out.size == 0 || out.size > kMaxShaFileBytes || out.size > shaBudget) {
        out.shaSkipped = true;
        return out;
    }
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        out.shaSkipped = true;
        return out;
    }
    std::vector<uint8_t> buf((size_t)out.size);
    if (!f.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)out.size)) {
        out.shaSkipped = true;
        return out;
    }
    out.sha = FileUtil::SHA1(buf.data(), buf.size());
    shaBudget -= out.size;
    return out;
}

} // namespace ForensicUtil
