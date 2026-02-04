# nostr-gdextension

## How to install
TODO:

## How to use

- Add the nostr folder to your addons folder in your Godot project

```gdscript

# Create new keypair
var kp = Nostr.create_new_keypair() # This creates a dictionary with seckey and pubkey
print(kp["seckey"])
print(kp["pubkey"])

# Create keypair for seckey hex
var kp = Nostr.keypair_from_seckey("...hexkeypair")
print(kp["seckey"])
print(kp["pubkey"])
```
## Notes for working on developing the extension

## Requirements
- [GitHub](https://github.com/) account because we are going to be using GitHub Actions for cross platform compilation
- [Git](https://git-scm.com/downloads) installed on your machine and configured correctly so you can push changes to remote
- [Python](https://www.python.org/) latest version and ensure it's available in <b>system environment PATH</b>
- [Scons](https://scons.org/) latest version and ensure it's available in <b>system environment PATH</b>
    - Windows command: `pip install scons`
    - macOS command: `python3 -m pip install scons`
    - Linux command `python3 -m pip install scons`
- C++ compiler
    - Windows: MSVC (Microsoft Visual C++) via Visual Studio or Build Tools.
    - macOS: Clang (included with Xcode or Xcode Command Line Tools).
    - Linux: GCC or Clang (available via package managers).
- [Visual Studio Code](https://code.visualstudio.com/) or any other editor that supports C++ and the `compile_commands.json`

The Nostr extension currently uses libsecp256k1 static library v0.7.1

If you want update secp256k1 libraries you have to build for each platform, then move the static lib's into their respective folders under vendor/secp256k1

macos-universal-debug
```bash
cmake -S . -B build-universal-debug \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON \
  -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON

cmake --build build-universal-debug
```

macos-universal-release
```bash
cmake -S . -B build-universal-release \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON \
  -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON

cmake --build build-universal-release

```

windows-x86_64-debug
```bash
cmake -S . -B build-win-debug `
  -G "Visual Studio 17 2022" -A x64 `
  -DCMAKE_BUILD_TYPE=Debug `
  -DBUILD_SHARED_LIBS=OFF `
  -DCMAKE_MSVC_RUNTIME_LIBRARY="MultiThreaded" `
  -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON `
  -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON

cmake --build build-win-debug --config Debug
```

windows-x86_64-release
```bash
cmake -S . -B build-win-release `
  -G "Visual Studio 17 2022" -A x64 `
  -DCMAKE_BUILD_TYPE=Release `
  -DBUILD_SHARED_LIBS=OFF `
  -DCMAKE_MSVC_RUNTIME_LIBRARY="MultiThreaded" `
  -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON `
  -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON

cmake --build build-win-release --config Release
```

linux-arm64-debug
```bash
cmake -S . -B build-linux-arm64-debug \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON \
  -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON

cmake --build build-linux-arm64-debug
```

linux-arm64-release
```bash
cmake -S . -B build-linux-arm64-release \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON \
  -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON

cmake --build build-linux-arm64-release
```

web-arm32-no-threads
```bash
# Load Emscripten environment first
source /path/to/emsdk/emsdk_env.sh

emcmake cmake -S . -B build-web-release \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON \
  -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON

cmake --build build-web-release
```

web-arm32-threads
```bash
# Load Emscripten environment first
source /path/to/emsdk/emsdk_env.sh
export CFLAGS="-pthread"
export CXXFLAGS="-pthread"
export LDFLAGS="-pthread -s USE_PTHREADS=1"

emcmake cmake -S . -B build-web-threads-release \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON \
  -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON

cmake --build build-web-threads-release
```

android-arm64-debug
```bash
export ANDROID_NDK="$HOME/Library/Android/sdk/ndk/26.3.11579264"
export TOOLCHAIN="$ANDROID_NDK/build/cmake/android.toolchain.cmake"

cmake -S . -B build-android-arm64-debug \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-35 \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON \
  -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON

cmake --build build-android-arm64-debug
```

android-arm64-release
```bash
export ANDROID_NDK="$HOME/Library/Android/sdk/ndk/26.3.11579264"
export TOOLCHAIN="$ANDROID_NDK/build/cmake/android.toolchain.cmake"
cmake -S . -B build-android-arm64-release \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-35 \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON \
  -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON

cmake --build build-android-arm64-release
```

linux-x86_64-debug
```bash
cmake -S . -B build-linux-debug \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON \
  -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON

cmake --build build-linux-debug
```

linux-x86_64-release
```bash
cmake -S . -B build-linux-release \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON \
  -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON

cmake --build build-linux-release
```

so on and so forth for each platform.




