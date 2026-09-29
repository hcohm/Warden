#!/bin/zsh
# Builds a universal (Apple Silicon + Intel) Warden.app.
#   ./build.sh               build, install to ~/Applications and launch
#   ./build.sh --no-install  build into build/ only
#   ./build.sh --release     build, then zip universal/arm64/x86_64 variants into dist/
set -euo pipefail
cd "${0:A:h}"
APP=build/Warden.app
BIN=$APP/Contents/MacOS/Warden
rm -rf build && mkdir -p $APP/Contents/MacOS build/obj
for arch in arm64 x86_64; do
  swiftc -O -swift-version 5 -parse-as-library -target $arch-apple-macos14.0 \
    Sources/*.swift -o build/obj/Warden-$arch
done
lipo -create build/obj/Warden-arm64 build/obj/Warden-x86_64 -output $BIN
cp Info.plist $APP/Contents/
codesign --force --options runtime --sign - $APP
echo "built $APP ($(lipo -archs $BIN))"

if [[ "${1:-}" == "--release" ]]; then
  rm -rf dist && mkdir dist
  ditto -c -k --keepParent $APP dist/Warden-universal.zip
  for arch in arm64 x86_64; do
    rm -rf build/$arch && mkdir -p build/$arch
    cp -R $APP build/$arch/
    lipo -thin $arch $BIN -output build/$arch/Warden.app/Contents/MacOS/Warden
    codesign --force --options runtime --sign - build/$arch/Warden.app
    ditto -c -k --keepParent build/$arch/Warden.app dist/Warden-$arch.zip
  done
  (cd dist && shasum -a 256 *.zip > SHA256SUMS.txt)
  ls -lh dist
  exit 0
fi
[[ "${1:-}" == "--no-install" ]] && exit 0
DEST=~/Applications/Warden.app
pkill -f "^$HOME/Applications/Warden.app/Contents/MacOS/Warden" 2>/dev/null && sleep 1 || true
mkdir -p ~/Applications && rm -rf $DEST && cp -R $APP $DEST
open $DEST
echo "installed $DEST"
