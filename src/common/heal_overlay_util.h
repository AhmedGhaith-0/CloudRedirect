#pragma once
// [NS-HEAL] Local-over-cloud manifest overlay. When the cloud CN fell behind a
// failed/interrupted publish, re-apply the local manifest on top of the cloud
// state so the next changelist serves the saves we already promoted locally.
// Pure merge logic (no I/O) shared by MaybeHealCloudDivergence and unit tests.
//
// Direction matters: overlaying local ON TOP of cloud keeps cloud-only files
// from other machines while local wins conflicts. The reverse overlay in
// MergeBatchIntoPublishState keeps cloud wins -- the wrong direction here.

#include <cstddef>
#include <cstdint>

#include "app_state.h"
#include "cloud_metadata_paths.h"
#include "manifest_store.h"

namespace CloudIntercept {

// Overlays local manifest entries over state.files: local wins conflicts,
// cloud-only files from other machines are kept, reserved metadata names
// (manifest/cn/tokens/...) are skipped. Sets state.cn = localCn and returns
// the number of entries added or overwritten.
inline size_t HealOverlayLocalOntoCloud(CloudStorage::CloudAppState& state,
                                        const CloudStorage::Manifest& localManifest,
                                        uint64_t localCn) {
    size_t overlayCount = 0;
    for (const auto& [name, me] : localManifest) {
        if (IsReservedBlobFilename(name)) continue;
        CloudStorage::FileEntry fe;
        fe.sha = me.sha;
        fe.timestamp = me.timestamp;
        fe.size = me.size;
        state.files[name] = std::move(fe);
        ++overlayCount;
    }
    state.cn = localCn;
    return overlayCount;
}

} // namespace CloudIntercept
