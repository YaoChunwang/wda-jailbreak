# wda-jailbreak — Full WebDriverAgent UI Automation on Jailbroken iOS (tested on iPhone SE 1 / iOS 15.8.8)

English | [简体中文](README.zh-CN.md)

Driving a **jailbroken** iPhone through the real Apple UI-testing stack:
WebDriverAgent + XCTestCore + XCUIAutomation + testmanagerd, with live XCUI
element trees over HTTP. No simulator, no Xcode, no developer signing.

```
GET http://<device>:8100/source
→ <?xml version="1.0"?><XCUIElementTypeApplication …>…232 real elements…
   蜂窝网络 / 中国联通 / 12:38 / 电池电量：100% …
```

## Why this repo exists

Running WebDriverAgent on a jailbroken device *without* Xcode sounds like it
should just work. It does not. The XCTest automation stack on iOS 15.8 has five
independent gates that each present as an unrelated error:

1. `kAXErrorAPIDisabled` on every AX call
2. `Timed out waiting for target to check in.` on the automation session
3. `No bundle at path /Developer/Library/PrivateFrameworks/XCTAutomationSupport.framework`
4. `Application … is not running` on every query resolve
5. A wall of `0x8badf00d` watchdog kills at 10 s / 19.7 s

This repo documents the actual keys for all five, and ships the original code
(the ObjC shim) that makes the stack work end to end.

## Architecture

```
┌─────────────────────────┐   HTTP :8100   ┌──────────────────────────────┐
│  client (Appium / curl) │──────────────▶│ WebDriverAgentRunner          │
└─────────────────────────┘               │  (Facebook WebDriverAgent,    │
                                          │   self-signed, TrollStore)    │
                                          ├──────────────────────────────┤
                                          │ objc_shim.dylib               │
                                          │  (this repo, replaces libobjc │
                                          │   + interposes exit)          │
                                          └──────────┬───────────────────┘
                                                     │ XPC / automation session
                                          ┌──────────▼───────────────────┐
                                          │ testmanagerd                  │
                                          │  (Apple binary from the DDI,  │
                                          │   re-signed with the FULL     │
                                          │   Apple entitlement set)      │
                                          └──────────┬───────────────────┘
                                                     │ AX (MIG)
                                          ┌──────────▼───────────────────┐
                                          │ AccessibilityUIServer / SB    │
                                          │  = the live UI of the device  │
                                          └──────────────────────────────┘
```

## The five keys

### 1. `com.apple.accessibility.api`
`AXDisableAccessibilityOnTermination` and friends fail with
`kAXErrorAPIDisabled` unless the **caller** (testmanagerd) carries
`com.apple.accessibility.api` in its signature. Extract the full entitlement
set from Apple's original binary (`ldid -e`) and re-sign with it — see
`docs/testmanagerd_entitlements.plist`. Also requires the Accessibility
preferences (`AutomationEnabled` etc.) to be written *before* cfprefsd can
clobber them, then kill cfprefsd and verify.

### 2. The check-in notification
`requestAutomationSessionForTestTargetWithPID:` blocks until
`com.apple.dt.xctestd.availability.<pid>` is posted. The shim posts it
(`notify_post`) pretending to be the target. Pass the **real** pid of
SpringBoard (it is not fixed across boots — resolve it at runtime).

### 3. `preferredBackendPath`
The daemon dlopens `XCTAutomationSupport.framework` from
`/Developer/Library/PrivateFrameworks/…` — which does not exist without a
mounted DDI. The second argument of
`requestAutomationSessionForTestTargetWithPID:preferredBackendPath:reply:`
overrides the load path. Point it at your own copy of the framework
(extracted from the same DDI).

### 4. `processID` → `accessibilityElement`
Every query resolve calls `-[XCUIElementQuery backingQueryWithError:]`, which
bails with `Application … is not running` when the app's
`accessibilityElement` is nil. The element is built from the process's
`processID` (0 ⇒ nil element). Chain discovered by disassembly:

```
XCUIApplication.accessibilityElement
  → XCUIApplicationImpl.accessibilityElement      (ivar 0x20)
    → XCUIApplicationProcess.accessibilityElement  (needs processID ≠ 0)
```

So: create the process, `setProcessID:<real pid>` **exactly once**
(the setter asserts `0→N or N→0` transitions only), and the real AX element —
the live SpringBoard UI — materialises.

### 5. The three watchdogs
| Watchdog | Budget | Defeat |
|---|---|---|
| process-launch | 20 s | `UIApplicationMain` on the main thread |
| scene-create | 19.7 s | create the `UIWindow` **first**, offload all MON work to a thread |
| scene-update | 10 s | `_XCTSetXPCRequestTimeout(7.0)` so XPC waits wake before the watchdog |

Also: `-[XCUIApplicationProcess waitForQuiescenceIncludingAnimationsIdle:]`
raises `Cannot pass nil activity` without a test context — swizzle it to a
no-op. `configuredForUITesting` must return YES or `commonInit` asserts.

## Components in this repo

| Path | What |
|---|---|
| `src/objc_shim.c` | The full shim (final iteration 168): libobjc passthrough, spec-reply hook, process/impl wiring, session install, state pinning, feed thread, watchdog evasion. Header comments mark each mechanism. |
| `src/wda_entitlements.plist` | Entitlements for the WDA runner + shim (`platform-application`, `com.apple.accessibility.api`, …) |
| `docs/testmanagerd_entitlements.plist` | The entitlement set extracted from Apple's testmanagerd (re-sign with this) |
| `docs/TECHNICAL.md` | Deep dive: disassembly notes, object graphs, the reply/block ABI trap |
| `scripts/build.sh` | Build the shim |
| `scripts/deploy.sh` | Deploy runner + shim + daemon to the device |

## Setup (outline)

Prereqs: jailbroken device (palera1n rootless here), TrollStore (persistent
spawn), OpenSSH, `ldid`, the device's DDI (DeveloperDiskImage 15.5 works for
15.8) for `testmanagerd` + `XCTestCore.framework` + `XCUIAutomation.framework`
+ `XCTAutomationSupport.framework`.

1. Build & install the WebDriverAgentRunner app (upstream
   [facebookarchive/WebDriverAgent](https://github.com/facebookarchive/WebDriverAgent)),
   self-signed with `src/wda_entitlements.plist`, registered in TrollStore for
   spawn rights.
2. `scripts/build.sh` → `objc_shim.dylib`, sign with the same entitlements,
   place at `/var/jb/objc_shim.dylib` (it re-exports libobjc — the app's
   loader picks it up via the jailbreak's objc replacement hook).
3. Deploy `testmanagerd` from the DDI to `/var/jb/usr/libexec/testmanagerd`,
   re-sign with `docs/testmanagerd_entitlements.plist`, load via a LaunchDaemon
   plist (`UserName mobile`).
4. Copy `XCTAutomationSupport.framework` to `/var/jb/usr/lib/xctfw/` — the
   shim passes this path as `preferredBackendPath`.
5. `scripts/deploy.sh` + launch the runner via `uiopen`, then
   `curl http://<device>:8100/source`.

## Legal

The shim and scripts are MIT. `testmanagerd`, `XCTestCore`, `XCUIAutomation`
and `XCTAutomationSupport` are Apple binaries — **not included**, obtain them
from your own device's DDI. This project is for research and personal
automation on devices you own. The techniques reverse-engineer Apple private
APIs and are unsupported by Apple.

## Status

Verified on iPhone SE 1 (iPhone8,4), iOS 15.8.8 (19H422), palera1n rootless +
TrollStore: `/source` returns the live SpringBoard element tree (232 elements)
repeatedly and stably. Tap/swipe endpoints build on the same tree (same WDA
upstream), untested here — patches welcome.
