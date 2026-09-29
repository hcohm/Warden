#!/bin/zsh
# Builds the real sources (minus the app entry point) into a throwaway test bundle and runs
# tests/main.swift. Spawns and kills only its own dummy processes. Needs Xcode command line tools.
set -euo pipefail
cd "${0:A:h}/.."
T=$(mktemp -d)
trap 'pkill -f "^$T/" 2>/dev/null; rm -rf "$T"' EXIT
mkdir -p $T/WT.app/Contents/MacOS $T/fake $T/Claude.app/Contents/MacOS
cc -O tests/sleeper.c -o $T/fake/sleeper
# A look-alike app that copies Claude's bundle ID but isn't signed by Anthropic.
cp $T/fake/sleeper $T/Claude.app/Contents/MacOS/Claude
/usr/libexec/PlistBuddy -c "Add :CFBundleIdentifier string com.anthropic.claudefordesktop" \
  -c "Add :CFBundleExecutable string Claude" $T/Claude.app/Contents/Info.plist >/dev/null
codesign -f -s - $T/Claude.app 2>/dev/null
sed 's/local.warden.app/local.warden.tests/; s/>Warden</>WardenTests</g' Info.plist > $T/WT.app/Contents/Info.plist
swiftc -swift-version 5 tests/main.swift $(ls Sources/*.swift | grep -v App.swift) -o $T/WT.app/Contents/MacOS/WT
codesign -f -s - $T/WT.app 2>/dev/null
# The harness raises two alerts; keep them out of the real log.
LOG=~/Library/Logs/Warden.log
[[ -f $LOG ]] && cp $LOG $T/log.bak
set +e; $T/WT.app/Contents/MacOS/WT $T; rc=$?; set -e
if [[ -f $T/log.bak ]]; then cp $T/log.bak $LOG; else rm -f $LOG; fi
exit $rc
