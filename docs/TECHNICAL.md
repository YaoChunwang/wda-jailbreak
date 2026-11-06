# Technical deep dive

Notes from a two-day disassembly-and-telelemetry campaign against
XCUIAutomation / XCTestCore (iOS 15.8, fw20076/DDI 15.5). Everything below
was verified on-device; each claim names the evidence.

## 1. The reply-block ABI trap (SIGBUS with no fault)

`requestApplicationSpecifierForPID:reply:` hands you a **stack block**. Its
`invoke` lives at `block+2` (words), **not** `block+3`:

```c
struct blk_obj {
    void *isa;      // +0
    int flags;      // +1 (low word)
    int reserved;   // +1 (high word)
    void (*invoke)(void *, id, id);  // +2  ← the real slot
    void *desc;     // +3
};
```

Calling through `p[3]` jumps into the descriptor struct — CPU raises a
translation fault *without* delivering SIGBUS to the signal handler. The shim
telemetry (`BLK:`/`BLKISA:`) confirmed `__NSStackBlock__` at `p[0]`,
`invoke` at `p[2]` (`__68-[XCUIApplicationMonitor monitoredApplicationWithProcessIdentifier:]_block_invoke_2`).

## 2. Local reply to the spec request

The monitor calls `requestApplicationSpecifierForPID:reply:` asynchronously
and awaits the reply. The daemon's reply is unreliable without the full
session; the shim installs a hook that answers **locally and immediately**:

```objc
[XCUIApplicationSpecifier specifierWithBundleIdentifier:@"com.apple.springboard"
                                                   path:nil]
```

Never `specifierWithPID:bundleIdentifier:` — that factory does not exist on
this iOS (only `specifierWithBundleIdentifier:path:`). The pid instead rides
on the process object (`setProcessID:`), see §5.

## 3. AX enablement chain

`kAXErrorAPIDisabled` is a **caller-entitlement** check, not a preference
check. Evidence: the error text lives in testmanagerd itself
(`strings` ⇒ `Failed call to AXDisableAccessibilityOnTermination: %@`), and it
disappeared the moment testmanagerd was re-signed with
`com.apple.accessibility.api` (extracted via `ldid -e` from Apple's own
binary; full set in `testmanagerd_entitlements.plist`).

Pitfall: `AutomationEnabled` in `com.apple.Accessibility.plist` keeps getting
rewritten to 0 by cfprefsd. Write → `killall -9 cfprefsd` → verify. And note
`pkill -f testmanagerd` can silently fail while the old process keeps
running the *old signature* — always kill by PID and verify the process
start time after re-signing.

## 4. Automation session establishment

Three things must line up or you get `Timed out waiting for target to check in.`:

1. The target **check-in notification**: `notify_post("com.apple.dt.xctestd.availability.<pid>")`.
   The daemon's own strings name the channel: `com.apple.dt.xctestd.availability.%d`.
2. `preferredBackendPath:` must point at a real `XCTAutomationSupport.framework`
   (without a DDI mount, `/Developer/Library/PrivateFrameworks/…` does not
   exist and the daemon logs `No bundle at path …`).
3. The reply yields an `XCTRunnerAutomationSession` object — which must be
   **installed into the process**:
   `-[XCUIApplicationProcess setAutomationSession:]`. Without it, query
   resolution has no snapshot transport and falls back to
   `Application … is not running`.

Timing pitfall: the session reply can arrive before the process object
exists. The shim requests the session again after wiring `g_pproc`.

## 5. The `accessibilityElement` chain (the final key)

`-[XCUIElementQuery backingQueryWithError:]` (0x62080):

```asm
620c4  bl  -[XCUIElementQuery application]
620dc  bl  -[XCUIApplication accessibilityElement]   ; ← the gate
620f4  cbz x28, …        ; nil ⇒ "Application %@ is not running"
```

Forwarding chain (verified by disassembly and by a getter-swap probe):

```
XCUIApplication.accessibilityElement
 └─ XCUIApplicationImpl.accessibilityElement     ldr x0, [x0, #0x20] ; _currentProcess
     └─ XCUIApplicationProcess.accessibilityElement  ← nil unless processID ≠ 0
```

`setProcessID:` asserts "Invalid process ID transition … only allowed to
transition from 0 to non-zero or non-zero to 0" — set it **once**.

`running` is `(applicationState != 1)` after `_awaitKnownApplicationState`;
`isApplicationStateKnown` is `(applicationState != 0)`; `setApplicationState:`
is **asynchronous** (dispatch_async onto the process's private queue) and
KVO-notifying. The KVO expectation inside
`commonInitWithApplicationSpecifier:device:` observes `isApplicationStateKnown`
on the **app object**; the shim pins the getters and writes the state ivar
(offset 0x18) synchronously as a belt-and-braces measure.

## 6. Startup / watchdogs

With a *working* daemon the runner's launch path changes: `exit()` is never
called, the old park-in-exit-hook trick never runs, and the XCTest startup
blocks the main thread inside XPC waits. Three watchdogs feed on that:

- `scene-update` 10 s: wake the main thread first — `_XCTSetXPCRequestTimeout(7.0)`.
- `scene-create` 19.7 s: create the `UIWindow` at the top of
  `application:didFinishLaunchingWithOptions:` and return immediately;
  all MON wiring moves to a detached thread.
- Quiescence: `waitForQuiescenceIncludingAnimationsIdle:` builds an XCTContext
  activity and dies with `Cannot pass nil activity` outside a test run —
  swizzle to yes.

## 7. Telemetry discipline

Every shim iteration reports over UDP to the host (`net_report`); failure
modes were identified by telemetry tags (`SPECREQ:`/`BLK:`/`PROCCLS:`/`QAE:`),
not by guessing. If you extend the shim, add a tag before touching behavior.

## 8. Known-stale intel (kept so you don't repeat it)

- `specifierWithPID:bundleIdentifier:` — does not exist (crash with
  unrecognized selector).
- `setApplicationProcess:forPID:` with pid 0 asserts ("Invalid pid 0").
- Feeding `daemonDidUpdatePID:forApplicationWithBundleID:andState:` does not
  create processes; it only updates tracked ones.
- `method_setImplementation` on two classes sharing one inherited method
  chains the second hook onto the first — fine, but remember the first
  original is the true IMP.
- Killing `testmanagerd` with `pkill -f` may silently no-op; kill by PID.
