# godot-plus-plus

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

## Notes

If you want update secp256k1 libraries you have to build for each platform, then move the static lib's into their respective folders under vendor/secp256k1

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

so on and so forth for each platform.

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


