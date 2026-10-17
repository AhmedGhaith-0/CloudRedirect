# CloudRedirect

""Steam Cloud"" for 'lua' games.

**Fork of [Anniversor/CloudRedirect](https://github.com/Anniversor/CloudRedirect) that maintains only the native binaries** — the Windows DLL and the 32-bit Linux `.so`. The WPF/Qt companion apps, the Flatpak pipeline and the Steam Deck scripts from upstream are intentionally **not** maintained here; hosts like OpenSteamTool deploy the DLL directly. Releases of this fork are the source for the DLL's built-in auto-updater.

> ****This software is experimental and under active development.**** The underlying techniques are fairly insane. What this software tries to do is nuts to attempt. This software could damage your save files and probably will! It could overwrite your saves, cause weird conflicts, make your saves disappear, make you cry. Back up any saves you care about before using this software.

But it probably won't. It's been very solid for a long time.

>****Do not use this if you do not actively want cloud saves for "lua" games. If all you care about is the Steam Cloud error, disable Steam Cloud in properties for that game.****

## What it does

First, some back story:

Once upon a time, there was a tool called SteamTools. SteamTools supported cloud saving, kind of.

Later, Valve patched the (sinful) thing SteamTools did to sync saves. Specifically, SteamTools rewrote requests to AppID 760, which is Steam Screenshots. It sent all Steam Cloud requests for non-owned AppIDs there. It did not create prefixes for each individual game, which means that each lua app shared the saves with all others. This can cause saves to conflict if multiple games use the same save file name. This also means that your saves are replicated in the `Steam/Userdata/<steamid>/<appid for lua game>` folder for each lua app.

It also did not support Steam AutoCloud games at all. It would simply show a fake success message for those games.

What _this_ tool does is redirect Steam Cloud requests for games that are injected to Google Drive/OneDrive/a local folder, including AutoCloud games. Everything is native inside the Steam Client, but the actual data is read/written to and from your cloud account. This was much harder to do than just redirecting read/write to an AppID that your account owns, but it was fun to make. It also is less likely to piss off Valve.

## How it works

1. The native library (`cloud_redirect.dll` on Windows, `cloud_redirect.so` on Linux) hooks Steam's internal cloud save RPC handlers via ~~vtable interception~~ black magic.
2. When a lua game attempts to read or write cloud save data, the library intercepts the calls and redirects it. If the game is owned, the game uses normal Steam Cloud as expected. If a lua is present that only unlocks DLC, the game will use normal Steam Cloud.
3. More dark magic occurs. Saves sync. Bytes flow. This all is visible in the Steam UI and looks identical to normal Steam Cloud functionality.

## Supported cloud providers

- **Google Drive**
- **OneDrive**
- **Cloudflare R2**
- **S3-Compatible** - AWS S3, MinIO, Backblaze B2, Wasabi, DigitalOcean Spaces, and any self-hosted S3 server.
- **Local folder / mapped drive** - by request of literally one user.

With more to come over time.

## Usage

Grab the latest release from the [Releases page](https://github.com/eisora08/CloudRedirect/releases). Each release carries the platform binaries plus bare `sha256` files:

- Windows: `cloud_redirect.dll` (+ `.sha256`) — deploy it with your host tool of choice.
- Linux: `cloud_redirect.so` (+ `.sha256`) — 32-bit, drop-in for your existing SLSsteam/LD_AUDIT setup.

The built-in updater polls this fork's releases, so once a newer tag ships, the deployed library upgrades itself on the next Steam launch.

## Building from source (Windows)

### Prerequisites

- Visual Studio 2022 (or Build Tools) with the C++ workload
- CMake 3.20+

### Build

```bash
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release --target cloud_redirect
```

This builds the x64 DLL (`build/Release/cloud_redirect.dll`). The fork's unit tests are separate targets (`stats_store_fork_tests`, `autocloud_injection_tests`, `steam_message_layout_tests`, `steam_resolver_tests`).

## Building from source (Linux)

Oooooh boy. Yeah. Have fun.

You need to build against glibc 2.31 or older. Ubuntu 20.04 would work, if you dislike yourself. There's also an ancient version of Fedora that fits the bill. Or Debian 11. Distrobox is the way, here. Don't even bother trying to build under whatever distro you daily, you'll wind up fighting it for no reason. Distrobox exists for a reason.

If you are building under Ubuntu 20.04, GCC 12 is needed along with the 32-bit multilib stuff. System cmake is ancient garbage, you'll have to update it.

Then specify -DLINUX_32BIT=ON and wham bam.

Isn't building for weird distros _fun?_

## Contibuting

PRs welcome — fixes to the native library, new cloud providers and tests all belong upstream-or-here; this fork specifically exists to ship the binaries with its own release cadence.
