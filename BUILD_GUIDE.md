# ThermoCrypt Lite v1.0.0 - Build Guide

## Linux (Debian/Ubuntu)

```bash
# 1. Install dependencies
sudo apt update
sudo apt install -y build-essential cmake libsodium-dev libssl-dev git

# 2. Build and install liboqs
git clone --depth 1 [https://github.com/open-quantum-safe/liboqs.git](https://github.com/open-quantum-safe/liboqs.git)
cd liboqs
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=OFF ..
make -j$(nproc)
sudo make install
cd ../..

# 3. Compile ThermoCrypt Lite
g++ -o thermo_core thermo_core.cpp \
    -std=c++17 -O2 \
    -Wall -Wextra \
    -fstack-protector-strong \
    /usr/local/lib/liboqs.a -lsodium -lpthread

# 4. Test
./thermo_core --help
```

### Linux with TPM Support

```bash
# Additional dependency
sudo apt install -y libtss2-dev

# Compile with TPM
g++ -o thermo_core thermo_core.cpp \
    -std=c++17 -O2 \
    -DENABLE_TPM \
    -Wall -Wextra \
    -fstack-protector-strong \
    /usr/local/lib/liboqs.a -lsodium -lpthread \
    -ltss2-esys -ltss2-mu -ltss2-tctildr
```

### Production Build (Hardened)

```bash
g++ -o thermo_core thermo_core.cpp \
    -std=c++17 -O2 \
    -Wall -Wextra -Werror \
    -fstack-protector-strong \
    -fPIE -pie \
    -D_FORTIFY_SOURCE=2 \
    -Wl,-z,relro,-z,now \
    /usr/local/lib/liboqs.a -lsodium -lpthread
```

## Windows (MSYS2/MinGW64)

```bash
# In MSYS2 MinGW64 shell
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-libsodium

# Build liboqs (follow liboqs Windows instructions or use prebuilt)

# Compile
g++ -o thermo_core.exe thermo_core.cpp \
    -std=c++17 -O2 \
    -static \
    -I/mingw64/include \
    -L/mingw64/lib \
    -loqs -lsodium -lws2_32 -lbcrypt
```

## Running the GUI

```bash
# Ensure Python 3.8+ with Tkinter
python3 thermo_gui.py

# Or on Windows
python thermo_gui.py
```

## Testing

```bash
# Generate test identity
./thermo_core --gen testuser

# Encrypt a message (redirect output to file)
echo "Hello, quantum world!" | ./thermo_core --encrypt-armor testuser.thermoid > encrypted.txt

# Decrypt (enter same password)
cat encrypted.txt | ./thermo_core --decrypt-armor testuser
```

## Troubleshooting

### "liboqs.a: No such file"

```bash
# Check liboqs installation
ls /usr/local/lib/liboqs.a

# If missing, rebuild liboqs with -DBUILD_SHARED_LIBS=OFF
```

### "sodium.h: No such file"

```bash
sudo apt install libsodium-dev
```

### TPM errors on Linux

```bash
# Check TPM availability
ls /dev/tpm*

# Ensure user is in tss group or run as root
sudo usermod -aG tss $USER
# Log out and back in
```
