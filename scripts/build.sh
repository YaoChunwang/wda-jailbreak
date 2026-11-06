#!/bin/bash
# Build objc_shim.dylib (arm64, iOS 15). Requires Xcode command line tools.
set -euo pipefail
cd "$(dirname "$0")/../src"

# Two tiny stub dylibs satisfy the linker:
#  - stub.dylib        re-exports /usr/lib/libobjc.A.dylib (the shim *is* the
#                      objc runtime passthrough — dyld loads it in libobjc's
#                      place on the jailbroken device)
#  - uikit_stub.dylib  carries UIKit symbol references resolved at runtime
#                      via objc_msgSend (the shim never links UIKit directly)
#
# Regenerate stub dylibs (adjust SDK path):
#   SDK=$(xcrun --sdk iphoneos --show-sdk-path)
#   ld -r -reexport_library "$SDK/usr/lib/libobjc.A.dylib" -o stub.dylib 2>/dev/null || true
#   ld -r -o uikit_stub.dylib -u _OBJC_CLASS_$_UIWindow -u _OBJC_CLASS_$_UIViewController
#
# The final link keeps undefined symbols (dynamic_lookup) — everything
# resolves at runtime through objc_msgSend or the re-exported runtime.

clang -target arm64-apple-ios15.0 -nostdlib -dynamiclib objc_shim.c \
  -o objc_shim.dylib \
  -Wl,-install_name,/var/jb/objc_shim.dylib \
  -Wl,-reexport_library,stub.dylib \
  -Wl,uikit_stub.dylib \
  -Wl,-undefined,dynamic_lookup \
  -lSystem \
  -Wl,-no_dead_strip_inits_and_terms

echo "built: $(pwd)/objc_shim.dylib"
