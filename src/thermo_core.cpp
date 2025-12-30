/*
THERMOCRYPT LITE CORE v1.0.0
Licensed under the MIT License.

MIT License

Copyright (c) 2025 Herman Nythe

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

---------------------------------------------------------------------------
DISCLAIMER OF WARRANTY & SCOPE
---------------------------------------------------------------------------

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 

IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
DAMAGES (INCLUDING, BUT NOT LIMITED TO, LOSS OF DATA OR CRYPTOGRAPHIC 
FAILURE), OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE 
USE OR OTHER DEALINGS IN THE SOFTWARE.

THIS SOFTWARE IS A RESEARCH PROTOTYPE. IT HAS NOT UNDERGONE A FORMAL 
SECURITY AUDIT. USE FOR CRITICAL SECURITY APPLICATIONS IS AT THE USER'S 
SOLE RISK.

---------------------------------------------------------------------------
IMPLEMENTATION SCOPE & LIMITATIONS
---------------------------------------------------------------------------
This software is a research prototype implementing Hybrid Post-Quantum 
Cryptography (ML-KEM-768 + X25519) with Hardware Binding.

1. Verified Environment: Linux (x86_64), Windows.
2. Verified Binding: Disk-mode (Argon2id), tpm (Linux)

COMPILATION (Production - with security hardening):
  
  Linux (Hardened):
    g++ -o thermo_core thermo_core.cpp -std=c++17 -O2 \
        -Wall -Wextra -Wconversion -Werror=format-security \
        -fstack-protector-strong \
        -fPIE -pie \
        -D_FORTIFY_SOURCE=2 \
        -fno-strict-aliasing \
        -Wl,-z,relro,-z,now \
        /usr/local/lib/liboqs.a -lsodium -lpthread
  
  Linux with TPM (Hardened):
    g++ -o thermo_core thermo_core.cpp -std=c++17 -O2 -DENABLE_TPM \
        -Wall -Wextra -Wconversion -Werror=format-security \
        -fstack-protector-strong -fPIE -pie -D_FORTIFY_SOURCE=2 \
        -fno-strict-aliasing -Wl,-z,relro,-z,now \
        /usr/local/lib/liboqs.a -lsodium \
        -ltss2-esys -ltss2-mu -ltss2-tctildr -lpthread

  Windows (MSYS2):
    g++ -o thermo_core.exe thermo_core.cpp -std=c++17 -O2 \
        -Wall -Wextra -fstack-protector-strong \
        /ucrt64/local/lib/liboqs.a -lsodium -lws2_32 -lbcrypt

  Debug/Testing (with sanitizers - NOT for production):
    g++ -o thermo_core_debug thermo_core.cpp -std=c++17 -O1 -g \
        -fsanitize=address,undefined -fno-omit-frame-pointer \
        /usr/local/lib/liboqs.a -lsodium -lpthread

NOTE: liboqs must be compiled with -DOQS_USE_OPENSSL=OFF for standalone binaries.
      See BUILD_GUIDE.md for detailed instructions.

SECURITY HARDENING FLAGS EXPLAINED:
  -fstack-protector-strong  : Protects against stack buffer overflows
  -fPIE -pie               : Full ASLR (Address Space Layout Randomization)
  -D_FORTIFY_SOURCE=2      : Runtime buffer overflow detection
  -Wl,-z,relro,-z,now      : Makes GOT read-only (prevents GOT overwrite attacks)
  -fno-strict-aliasing     : Prevents dangerous optimizations

*/

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <sodium.h>
#include <oqs/oqs.h>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <thread>
#include <regex>
#include <memory>
#include <csignal>

#ifdef _WIN32
    #include <windows.h>
    #include <conio.h>
    #include <io.h>
    #include <fcntl.h>
#else
    #include <sys/resource.h>
    #include <sys/ptrace.h>
    #include <sys/mman.h>
    #include <termios.h>
    #include <unistd.h>
    #include <sys/stat.h>
    #include <fcntl.h>
#endif

#ifdef ENABLE_TPM
    #include <tss2/tss2_esys.h>
    #include <tss2/tss2_mu.h>
    #include <tss2/tss2_tctildr.h>
#endif

using namespace std;
namespace fs = std::filesystem;
const string HEADER_MAGIC_V1 = "THERMO_V1";
const string IDENTITY_EXT = ".thermoid";
const string VAULT_FILENAME = "resonance.vault";
const size_t CHUNK_SIZE = 64 * 1024;
const string ARMOR_BEGIN = "-----BEGIN THERMO MESSAGE-----";
const string ARMOR_END = "-----END THERMO MESSAGE-----";
const string PUBKEY_ARMOR_BEGIN = "-----BEGIN THERMO PUBLIC KEY-----";
const string PUBKEY_ARMOR_END = "-----END THERMO PUBLIC KEY-----";
const size_t ARMOR_LINE_WIDTH = 64;
string KEY_DIR = "keys/";
bool GLOBAL_RATE_LIMIT = false;
string ARGON_LEVEL = "interactive";
bool NO_PROGRESS = false;
size_t STREAM_SIZE_HINT = 0;
enum class BindingType : uint8_t { Disk = 0, TPM = 1 };
BindingType CURRENT_BINDING = BindingType::Disk;

// TPM Handle Configuration
// Base handle is 0x81018100, slot offset allows multiple identities
// Valid slots: 0-255 (giving handles 0x81018100 - 0x810181FF)
const uint32_t TPM_HANDLE_BASE = 0x81018100;
uint8_t TPM_SLOT = 0;  // Default slot

#ifdef ENABLE_TPM
TPM2_HANDLE get_tpm_handle() { return TPM_HANDLE_BASE + TPM_SLOT; }
#else
uint32_t get_tpm_handle() { return TPM_HANDLE_BASE + TPM_SLOT; }
#endif

unsigned long long get_opslimit() {
    if (ARGON_LEVEL == "sensitive") return crypto_pwhash_OPSLIMIT_SENSITIVE;
    if (ARGON_LEVEL == "moderate") return crypto_pwhash_OPSLIMIT_MODERATE;
    return crypto_pwhash_OPSLIMIT_INTERACTIVE;
}

size_t get_memlimit() {
    if (ARGON_LEVEL == "sensitive") return crypto_pwhash_MEMLIMIT_SENSITIVE;
    if (ARGON_LEVEL == "moderate") return crypto_pwhash_MEMLIMIT_MODERATE;
    return crypto_pwhash_MEMLIMIT_INTERACTIVE;
}

uint8_t get_argon_level_byte() {
    if (ARGON_LEVEL == "sensitive") return 2;
    if (ARGON_LEVEL == "moderate") return 1;
    return 0;
}

void get_argon_params_from_byte(uint8_t level_byte, unsigned long long& ops, size_t& mem) {
    if (level_byte == 2) {
        ops = crypto_pwhash_OPSLIMIT_SENSITIVE;
        mem = crypto_pwhash_MEMLIMIT_SENSITIVE;
    } else if (level_byte == 1) {
        ops = crypto_pwhash_OPSLIMIT_MODERATE;
        mem = crypto_pwhash_MEMLIMIT_MODERATE;
    } else {
        ops = crypto_pwhash_OPSLIMIT_INTERACTIVE;
        mem = crypto_pwhash_MEMLIMIT_INTERACTIVE;
    }
}

#pragma pack(push, 1)
struct ThermoHeader {
    uint8_t magic[9];
    uint8_t format_version;
    uint8_t binding_type;
    uint8_t pq_algo; uint8_t cl_algo; uint8_t sig_algo;
    uint8_t argon_level;     // 0 = interactive, 1 = moderate, 2 = sensitive
    uint8_t reserved[1];
    uint64_t timestamp;
    uint8_t fingerprint[32];
    uint8_t hmac[32];
};
#pragma pack(pop)

// =============================================================================
// SECURITY CONSTANTS - Sanity check limits
// =============================================================================
const size_t MAX_PUBKEY_SIZE = 64 * 1024;        // 64 KB max for public keys
const size_t MAX_SIGNATURE_SIZE = 16 * 1024;     // 16 KB max for signatures  
const size_t MAX_IDENTITY_FILE_SIZE = 256 * 1024; // 256 KB max for .thermoid
const size_t MAX_VAULT_FILE_SIZE = 512 * 1024;   // 512 KB max for vault
const size_t MAX_SEALED_DEK_SIZE = 4 * 1024;     // 4 KB max for sealed DEK

// DoS protection limits (CWE-400 mitigation)
const size_t MAX_MESSAGE_SIZE = 64 * 1024 * 1024;  // 64 MB max plaintext message
const size_t MAX_ARMORED_SIZE = 100 * 1024 * 1024; // 100 MB max armored input (base64 overhead)

// Minimum password length (CWE-521 mitigation)
const size_t MIN_PASSWORD_LENGTH = 8;

// =============================================================================
// SECURE MEMORY ALLOCATOR - Uses sodium_malloc for guaranteed secure memory
// =============================================================================
template <class T>
struct SodiumAllocator {
    typedef T value_type;
    typedef T* pointer;
    typedef const T* const_pointer;
    typedef T& reference;
    typedef const T& const_reference;
    typedef std::size_t size_type;
    typedef std::ptrdiff_t difference_type;
    
    template <class U> struct rebind { typedef SodiumAllocator<U> other; };
    
    SodiumAllocator() noexcept = default;
    template <class U> SodiumAllocator(const SodiumAllocator<U>&) noexcept {}
    
    T* allocate(std::size_t n) {
        if (n == 0) return nullptr;
        if (n > std::size_t(-1) / sizeof(T)) throw std::bad_alloc();
        
        // sodium_allocarray returns memory that is:
        // - Locked in RAM (no swap)
        // - Surrounded by guard pages
        // - Will be zeroed on free
        void* p = sodium_allocarray(n, sizeof(T));
        if (!p) throw std::bad_alloc();
        return static_cast<T*>(p);
    }
    
    void deallocate(T* p, std::size_t) noexcept {
        // sodium_free automatically zeros memory before freeing
        if (p) sodium_free(p);
    }
    
    template <class U, class... Args>
    void construct(U* p, Args&&... args) {
        new(p) U(std::forward<Args>(args)...);
    }
    
    template <class U>
    void destroy(U* p) {
        p->~U();
    }
};

template <class T, class U>
bool operator==(const SodiumAllocator<T>&, const SodiumAllocator<U>&) noexcept { return true; }
template <class T, class U>
bool operator!=(const SodiumAllocator<T>&, const SodiumAllocator<U>&) noexcept { return false; }

// Secure vector type that uses sodium memory management
using SecureByteVec = std::vector<uint8_t, SodiumAllocator<uint8_t>>;

// =============================================================================
// SECURE VECTOR STREAM - Zero-copy stream wrapper for SecureByteVec
// =============================================================================
// This class allows reading from a SecureByteVec as a standard istream
// WITHOUT copying the data to an insecure std::string buffer.
// This is critical because std::stringstream would copy sensitive plaintext
// to unprotected heap memory that could be swapped to disk.
// =============================================================================
class SecureVectorStream : public std::streambuf {
private:
    SecureByteVec& vec;
    size_t read_pos;
    
public:
    explicit SecureVectorStream(SecureByteVec& v) : vec(v), read_pos(0) {
        // Set up the get area to point directly to the secure memory
        char* start = reinterpret_cast<char*>(vec.data());
        char* end = start + vec.size();
        setg(start, start, end);
    }
    
    // Prevent copies
    SecureVectorStream(const SecureVectorStream&) = delete;
    SecureVectorStream& operator=(const SecureVectorStream&) = delete;
    
protected:
    // Called when more characters are needed
    int_type underflow() override {
        if (gptr() < egptr()) {
            return traits_type::to_int_type(*gptr());
        }
        return traits_type::eof();
    }
    
    // Support seeking (needed for some stream operations)
    std::streampos seekoff(std::streamoff off, std::ios_base::seekdir dir,
                          std::ios_base::openmode /*which*/) override {
        char* start = reinterpret_cast<char*>(vec.data());
        char* end = start + vec.size();
        
        char* new_pos;
        switch (dir) {
            case std::ios_base::beg:
                new_pos = start + off;
                break;
            case std::ios_base::cur:
                new_pos = gptr() + off;
                break;
            case std::ios_base::end:
                new_pos = end + off;
                break;
            default:
                return std::streampos(-1);
        }
        
        if (new_pos < start || new_pos > end) {
            return std::streampos(-1);
        }
        
        setg(start, new_pos, end);
        return std::streampos(new_pos - start);
    }
    
    std::streampos seekpos(std::streampos pos, std::ios_base::openmode which) override {
        return seekoff(pos, std::ios_base::beg, which);
    }
};

// =============================================================================
// INPUT SANITIZATION - Prevents terminal escape injection in error messages
// =============================================================================
// Paths and user input in exceptions can contain malicious escape sequences
// that could manipulate terminal output. This function removes or escapes
// potentially dangerous characters.
// =============================================================================
string sanitize_for_error(const string& input, size_t max_len = 256) {
    string result;
    result.reserve(std::min(input.size(), max_len));
    
    for (size_t i = 0; i < input.size() && result.size() < max_len; ++i) {
        char c = input[i];
        // Allow printable ASCII except control chars and escape
        if (c >= 32 && c < 127 && c != '\x1b') {
            result += c;
        } else if (c == '\x1b') {
            result += "[ESC]";  // Make escape visible
        } else if (c == '\n' || c == '\r' || c == '\t') {
            result += ' ';  // Replace whitespace with space
        } else {
            // Non-printable - show hex
            char hex[8];
            snprintf(hex, sizeof(hex), "[%02X]", (unsigned char)c);
            result += hex;
        }
    }
    
    if (input.size() > max_len) {
        result += "...(truncated)";
    }
    
    return result;
}

// =============================================================================
// SAFE BINARY READER - Prevents buffer over-reads with bounds checking
// =============================================================================
class SafeReader {
    const uint8_t* base_ptr;
    const uint8_t* ptr;
    size_t total_size;
    size_t remaining;
    
public:
    explicit SafeReader(const uint8_t* data, size_t size) 
        : base_ptr(data), ptr(data), total_size(size), remaining(size) {}
    
    template <typename T>
    T read() {
        static_assert(std::is_trivially_copyable<T>::value, "Type must be trivially copyable");
        if (remaining < sizeof(T)) {
            throw std::runtime_error("Buffer underflow: attempted to read " + 
                std::to_string(sizeof(T)) + " bytes with only " + 
                std::to_string(remaining) + " remaining");
        }
        T val;
        std::memcpy(&val, ptr, sizeof(T));
        ptr += sizeof(T);
        remaining -= sizeof(T);
        return val;
    }
    
    std::vector<uint8_t> read_bytes(size_t len, size_t max_allowed = 0) {
        // Sanity check: prevent gigantic allocations from malicious files
        if (max_allowed > 0 && len > max_allowed) {
            throw std::runtime_error("Security: Data length " + std::to_string(len) + 
                " exceeds maximum allowed " + std::to_string(max_allowed) + " (possible attack)");
        }
        if (remaining < len) {
            throw std::runtime_error("Buffer underflow: attempted to read " + 
                std::to_string(len) + " bytes with only " + 
                std::to_string(remaining) + " remaining");
        }
        
        std::vector<uint8_t> result(ptr, ptr + len);
        ptr += len;
        remaining -= len;
        return result;
    }
    
    SecureByteVec read_secure_bytes(size_t len, size_t max_allowed = 0) {
        if (max_allowed > 0 && len > max_allowed) {
            throw std::runtime_error("Security: Data length exceeds maximum allowed");
        }
        if (remaining < len) {
            throw std::runtime_error("Buffer underflow in secure read");
        }
        
        SecureByteVec result(len);
        std::memcpy(result.data(), ptr, len);
        ptr += len;
        remaining -= len;
        return result;
    }
    
    void skip(size_t len) {
        if (remaining < len) {
            throw std::runtime_error("Buffer underflow: cannot skip " + std::to_string(len) + " bytes");
        }
        ptr += len;
        remaining -= len;
    }
    
    const uint8_t* current_ptr() const { return ptr; }
    size_t bytes_remaining() const { return remaining; }
    size_t bytes_read() const { return total_size - remaining; }
    bool has_data() const { return remaining > 0; }
    
    // Read directly into existing buffer (for SecureBuffer)
    void read_into(uint8_t* dest, size_t len) {
        if (remaining < len) {
            throw std::runtime_error("Buffer underflow in read_into");
        }
        std::memcpy(dest, ptr, len);
        ptr += len;
        remaining -= len;
    }
};

// =============================================================================
// SMART POINTERS AND DELETERS
// =============================================================================
struct OQSKEMDeleter { void operator()(OQS_KEM* p) { if(p) OQS_KEM_free(p); } };
using OqsKemPtr = std::unique_ptr<OQS_KEM, OQSKEMDeleter>;
struct OQSSIGDeleter { void operator()(OQS_SIG* p) { if(p) OQS_SIG_free(p); } };
using OqsSigPtr = std::unique_ptr<OQS_SIG, OQSSIGDeleter>;

#ifdef ENABLE_TPM
struct EsysDeleter { void operator()(ESYS_CONTEXT* p) { if(p) Esys_Finalize(&p); } };
using EsysPtr = std::unique_ptr<ESYS_CONTEXT, EsysDeleter>;
#endif

// =============================================================================
// SECURE STRING AND BUFFER CLASSES
// =============================================================================
// =============================================================================
// SECURE SECRET STRING - NO SSO LEAKAGE
// =============================================================================
// This implementation avoids std::string's Small String Optimization (SSO)
// which can leak short passwords to stack memory. Instead, we always use
// sodium_malloc which provides:
// - Guard pages before and after the allocation
// - Memory locking (mlock) to prevent swap
// - Automatic zeroing on free
// =============================================================================

class SecretString {
private:
    char* _data;
    size_t _size;
    size_t _capacity;
    
public:
    SecretString() : _data(nullptr), _size(0), _capacity(0) {}
    
    explicit SecretString(const string& str) : _data(nullptr), _size(0), _capacity(0) {
        if (!str.empty()) {
            _capacity = str.size() + 1;
            _data = static_cast<char*>(sodium_malloc(_capacity));
            if (!_data) throw std::bad_alloc();
            memcpy(_data, str.c_str(), str.size());
            _data[str.size()] = '\0';
            _size = str.size();
        }
    }
    
    explicit SecretString(size_t reserve_size) : _data(nullptr), _size(0), _capacity(0) {
        if (reserve_size > 0) {
            _capacity = reserve_size + 1;
            _data = static_cast<char*>(sodium_malloc(_capacity));
            if (!_data) throw std::bad_alloc();
            _data[0] = '\0';
        }
    }
    
    ~SecretString() { 
        if (_data) {
            sodium_free(_data);
        }
    }
    
    SecretString(const SecretString&) = delete;
    SecretString& operator=(const SecretString&) = delete;
    SecretString(SecretString&& other) noexcept 
        : _data(other._data), _size(other._size), _capacity(other._capacity) {
        other._data = nullptr;
        other._size = 0;
        other._capacity = 0;
    }
    
    SecretString& operator=(SecretString&& other) noexcept {
        if (this != &other) {
            if (_data) sodium_free(_data);
            _data = other._data;
            _size = other._size;
            _capacity = other._capacity;
            other._data = nullptr;
            other._size = 0;
            other._capacity = 0;
        }
        return *this;
    }
    
    void push_back(char c) {
        if (_size + 1 >= _capacity) {
            size_t new_capacity = (_capacity == 0) ? 64 : _capacity * 2;
            char* new_data = static_cast<char*>(sodium_malloc(new_capacity));
            if (!new_data) throw std::bad_alloc();
            
            if (_data) {
                memcpy(new_data, _data, _size);
                sodium_free(_data);
            }
            _data = new_data;
            _capacity = new_capacity;
        }
        _data[_size++] = c;
        _data[_size] = '\0';
    }
    
    void pop_back() {
        if (_size > 0) {
            _data[--_size] = '\0';
        }
    }
    
    void clear() {
        if (_data && _size > 0) {
            sodium_memzero(_data, _size);
            _size = 0;
            _data[0] = '\0';
        }
    }
    
    void rtrim() {
        while (_size > 0 && (_data[_size-1] == ' ' || _data[_size-1] == '\n' || 
                            _data[_size-1] == '\r' || _data[_size-1] == '\t')) {
            _data[--_size] = '\0';
        }
    }
    
    const char* c_str() const { return _data ? _data : ""; }
    const char* data() const { return _data ? _data : ""; }
    size_t size() const { return _size; }
    size_t length() const { return _size; }
    bool empty() const { return _size == 0; }

    string get() const { return _data ? string(_data, _size) : string(); }
};

// SecureBuffer using sodium_malloc for guaranteed secure memory
struct SecureBuffer {
private:
    uint8_t* _data;
    size_t _size;
    
public:
    explicit SecureBuffer(size_t size) : _data(nullptr), _size(size) {
        if (size > 0) {
            _data = static_cast<uint8_t*>(sodium_malloc(size));
            if (!_data) throw std::bad_alloc();
        }
    }
    
    ~SecureBuffer() { 
        if (_data) {
            sodium_free(_data);
        }
    }
    
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    SecureBuffer(SecureBuffer&& other) noexcept : _data(other._data), _size(other._size) {
        other._data = nullptr;
        other._size = 0;
    }
    
    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            if (_data) sodium_free(_data);
            _data = other._data;
            _size = other._size;
            other._data = nullptr;
            other._size = 0;
        }
        return *this;
    }
    
    uint8_t* ptr() { return _data; }
    const uint8_t* ptr() const { return _data; }
    size_t size() const { return _size; }
};

string base64_encode(const vector<uint8_t>& data) {
    size_t b64_len = sodium_base64_encoded_len(data.size(), sodium_base64_VARIANT_ORIGINAL);
    vector<char> b64(b64_len);
    sodium_bin2base64(b64.data(), b64_len, data.data(), data.size(), sodium_base64_VARIANT_ORIGINAL);
    return string(b64.data());
}

string base64_encode(const uint8_t* data, size_t len) {
    size_t b64_len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    vector<char> b64(b64_len);
    sodium_bin2base64(b64.data(), b64_len, data, len, sodium_base64_VARIANT_ORIGINAL);
    return string(b64.data());
}

vector<uint8_t> base64_decode(const string& b64) {
    size_t bin_maxlen = b64.size();
    vector<uint8_t> bin(bin_maxlen);
    size_t bin_len;
    if (sodium_base642bin(bin.data(), bin_maxlen, b64.c_str(), b64.size(),
                          " \t\r\n", &bin_len, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0) {
        throw runtime_error("Invalid base64 data");
    }
    bin.resize(bin_len);
    return bin;
}

// Secure version for decoding secret data (private keys, etc.)
// Returns SecureByteVec which auto-wipes on destruction
SecureByteVec base64_decode_secure(const string& b64) {
    size_t bin_maxlen = b64.size();
    SecureByteVec bin(bin_maxlen);
    size_t bin_len;
    if (sodium_base642bin(bin.data(), bin_maxlen, b64.c_str(), b64.size(),
                          " \t\r\n", &bin_len, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0) {
        throw runtime_error("Invalid base64 data");
    }
    // Note: SecureByteVec doesn't support resize, so we create a new one with exact size
    SecureByteVec result(bin_len);
    memcpy(result.data(), bin.data(), bin_len);
    return result;
}

string wrap_armor(const string& b64) {
    ostringstream out;
    out << ARMOR_BEGIN << "\n";
    for (size_t i = 0; i < b64.size(); i += ARMOR_LINE_WIDTH) {
        out << b64.substr(i, ARMOR_LINE_WIDTH) << "\n";
    }
    out << ARMOR_END << "\n";
    return out.str();
}

string unwrap_armor(const string& armored) {
    size_t start = armored.find(ARMOR_BEGIN);
    if (start == string::npos) throw runtime_error("Missing armor header");
    start += ARMOR_BEGIN.size();
    
    size_t end = armored.find(ARMOR_END, start);
    if (end == string::npos) throw runtime_error("Missing armor footer");
    
    string body = armored.substr(start, end - start);
    string cleaned;
    for (char c : body) {
        if (!isspace(c)) cleaned += c;
    }
    return cleaned;
}

string wrap_pubkey_armor(const string& b64) {
    ostringstream out;
    out << PUBKEY_ARMOR_BEGIN << "\n";
    for (size_t i = 0; i < b64.size(); i += ARMOR_LINE_WIDTH) {
        out << b64.substr(i, ARMOR_LINE_WIDTH) << "\n";
    }
    out << PUBKEY_ARMOR_END << "\n";
    return out.str();
}

string unwrap_pubkey_armor(const string& armored) {
    size_t start = armored.find(PUBKEY_ARMOR_BEGIN);
    if (start == string::npos) throw runtime_error("Missing public key armor header");
    start += PUBKEY_ARMOR_BEGIN.size();
    
    size_t end = armored.find(PUBKEY_ARMOR_END, start);
    if (end == string::npos) throw runtime_error("Missing public key armor footer");
    
    string body = armored.substr(start, end - start);
    string cleaned;
    for (char c : body) {
        if (!isspace(c)) cleaned += c;
    }
    return cleaned;
}

// =============================================================================
// SECURE FILE OPERATIONS
// =============================================================================
// Note on TOCTOU: The ideal solution is to use file descriptors (open() with 
// O_NOFOLLOW, then fstat()). However, for portability, we use a defense-in-depth
// approach: check symlinks, use restricted directories, and verify file properties.

string resolve_safe_path(const string& path, bool input_mode = false) {
    try {
        fs::path p(path);
        
        // First pass: Check if it's a symlink BEFORE any other operations
        // This is still subject to TOCTOU, but we add additional checks
        if (fs::is_symlink(p)) {
            throw runtime_error("Security: Path is a symlink - symlinks are not allowed for security");
        }

        fs::path abs_path = fs::absolute(p);
        string s_path = abs_path.string();
        
        // Canonicalize to resolve any ".." or "." components
        // This helps detect path traversal attempts
        if (fs::exists(abs_path)) {
            fs::path canonical = fs::canonical(abs_path);
            s_path = canonical.string();
        }
        
        string lower = s_path;
        transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        
        // Block sensitive system paths (defense in depth)
        const vector<string> blocked_prefixes = {
            "/etc/", "/proc/", "/sys/", "/dev/", "/boot/", "/root/",
            "/var/log/", "/var/run/", "/run/", "/tmp/systemd"
        };
        const vector<string> blocked_contains = {
            "/.ssh", "/shadow", "/passwd", "/sudoers", "/.gnupg",
            "/private/", "/.config/", "/.local/share/"
        };
        
        for (const auto& prefix : blocked_prefixes) {
            if (lower.find(prefix) == 0) {
                throw runtime_error("Access to protected system path denied: " + sanitize_for_error(prefix));
            }
        }
        for (const auto& pattern : blocked_contains) {
            if (lower.find(pattern) != string::npos) {
                throw runtime_error("Access to protected path pattern denied: " + sanitize_for_error(pattern));
            }
        }
        
#ifdef _WIN32
        if (lower.find("c:\\windows\\") != string::npos || 
            lower.find("system32") != string::npos ||
            lower.find("\\system volume information\\") != string::npos) {
            throw runtime_error("Access to Windows system directory denied.");
        }
#endif
        
        if (input_mode && !fs::exists(abs_path)) {
            throw runtime_error("File not found: " + sanitize_for_error(path));
        }
        
        // Second symlink check after canonicalization (defense in depth)
        if (fs::exists(abs_path) && fs::is_symlink(abs_path)) {
            throw runtime_error("Security: Resolved path is a symlink");
        }
        
        return s_path;
    } catch (const fs::filesystem_error& e) {
        throw runtime_error("Invalid path: " + string(e.what()));
    }
}

void set_secure_permissions(const string& path) {
#ifndef _WIN32
    // Set file permissions to owner read/write only (0600)
    if (chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) {
        cerr << "Warning: Could not set secure permissions on " << path << endl;
    }
#endif
}

bool is_valid_identity_name(const string& name) {
    return regex_match(name, regex("^[a-zA-Z0-9_]+$"));
}

void enforce_rate_limit() {
    if (GLOBAL_RATE_LIMIT) this_thread::sleep_for(chrono::seconds(1));
}

void report_progress(size_t current, size_t total) {
    if (NO_PROGRESS) return;
    static size_t last_bytes = 0;
    static auto start = chrono::steady_clock::now();
    if (current < last_bytes) { start = chrono::steady_clock::now(); last_bytes = 0; }
    auto now = chrono::steady_clock::now();
    auto ms = chrono::duration_cast<chrono::milliseconds>(now - start).count();
    if (ms > 500 && (current - last_bytes > 1024*1024 || total > 0)) {
        double speed = ms > 0 ? static_cast<double>(current - last_bytes) / (static_cast<double>(ms) / 1000.0) : 0.0;
        long long eta = (total > 0 && speed > 0.001) ? static_cast<long long>(static_cast<double>(total - current) / speed) : -1;
        
        cerr << "PROGRESS_METRICS:" << static_cast<size_t>(speed) << ":" << eta << endl;
        if (total > 0) {
            int pct = static_cast<int>((static_cast<double>(current) / static_cast<double>(total)) * 100.0);
            cerr << "PROGRESS:" << pct << endl;
        }
        last_bytes = current;
        start = now;
    }
}

// =============================================================================
// SECURE PASSWORD INPUT
// =============================================================================
// Uses pre-allocated secure buffer to avoid heap fragmentation leaks.
// When std::string grows, it may leave password fragments in freed memory.
// This version reads directly into sodium-protected memory.

void get_password_secure(SecretString& out, const string& prompt) {
    cerr << prompt << flush;
    out.clear();
    
    // Pre-allocate buffer in secure memory to avoid reallocation leaks
    const size_t MAX_PASSWORD_LEN = 256;
    SecureBuffer temp_buf(MAX_PASSWORD_LEN);
    size_t len = 0;
    
#ifdef _WIN32
    if (!_isatty(_fileno(stdin))) {
        // Pipe input - read line
        string line;
        getline(cin, line);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        len = min(line.size(), MAX_PASSWORD_LEN - 1);
        memcpy(temp_buf.ptr(), line.data(), len);
        sodium_memzero(&line[0], line.size());
    } else {
        // Interactive - read char by char into secure buffer
        char ch;
        while ((ch = _getch()) != '\r' && len < MAX_PASSWORD_LEN - 1) {
            if (ch == '\b' && len > 0) {
                temp_buf.ptr()[--len] = 0;
                cerr << "\b \b";
            } else if (ch != '\b') {
                temp_buf.ptr()[len++] = ch;
                cerr << "*";
            }
        }
        cerr << endl;
    }
#else
    // Check if stdin is a pipe (non-interactive)
    if (!isatty(STDIN_FILENO)) {
        // Pipe input - read line directly
        string line;
        getline(cin, line);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        len = min(line.size(), MAX_PASSWORD_LEN - 1);
        memcpy(temp_buf.ptr(), line.data(), len);
        sodium_memzero(&line[0], line.size());
    } else {
        // Interactive mode - disable echo
        termios oldt{}, newt;
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        
        // Read directly into secure buffer
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF && len < MAX_PASSWORD_LEN - 1) {
            temp_buf.ptr()[len++] = static_cast<char>(ch);
        }
        
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        cerr << endl;
    }
#endif
    
    size_t start = 0, end = len;
    while (start < len && (temp_buf.ptr()[start] == ' ' || temp_buf.ptr()[start] == '\t' || 
                           temp_buf.ptr()[start] == '\r' || temp_buf.ptr()[start] == '\n')) start++;
    while (end > start && (temp_buf.ptr()[end-1] == ' ' || temp_buf.ptr()[end-1] == '\t' || 
                           temp_buf.ptr()[end-1] == '\r' || temp_buf.ptr()[end-1] == '\n')) end--;
    
    
    for (size_t i = start; i < end; i++) {
        out.push_back(static_cast<char>(temp_buf.ptr()[i]));
    }
}

// =============================================================================
// TOCTOU-SAFE FILE READING
// =============================================================================
// This function eliminates the Time-Of-Check-To-Time-Of-Use vulnerability by:
// 1. Using open() with O_NOFOLLOW to atomically reject symlinks
// 2. Using fstat() on the file descriptor to verify properties
// 3. Reading from the file descriptor directly
// This prevents an attacker from swapping a file with a symlink between
// the security check and the actual file read.
// =============================================================================
// -----------------------------------------------------------------------------
// SECURE READ (Atomic/Symlink-Aware)
// -----------------------------------------------------------------------------
SecureBuffer read_file_secure(const string& f, size_t max_size = 0) {
    string safe = resolve_safe_path(f, true);
    
#ifdef _WIN32
    HANDLE hFile = CreateFileA(safe.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                               
    if (hFile == INVALID_HANDLE_VALUE) {
        throw runtime_error("Cannot open file: " + sanitize_for_error(f));
    }

    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(hFile, &info)) {
        CloseHandle(hFile);
        throw runtime_error("Security: Cannot verify file attributes");
    }

    if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        CloseHandle(hFile);
        throw runtime_error("Security: File is a symlink/junction (Windows)");
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        throw runtime_error("Cannot get file size");
    }

    size_t sz = static_cast<size_t>(fileSize.QuadPart);
    if (max_size > 0 && sz > max_size) {
        CloseHandle(hFile);
        throw runtime_error("Security: File too large");
    }

    SecureBuffer buf(sz);
    DWORD bytesRead;
    if (!ReadFile(hFile, buf.ptr(), (DWORD)sz, &bytesRead, NULL) || bytesRead != sz) {
        CloseHandle(hFile);
        throw runtime_error("File read error or incomplete");
    }

    CloseHandle(hFile);
    return buf;

#else
    int fd = open(safe.c_str(), O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ELOOP) throw runtime_error("Security: Symlink detected");
        throw runtime_error("Cannot open file");
    }
    
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); throw runtime_error("Cannot stat file"); }
    if (!S_ISREG(st.st_mode)) { close(fd); throw runtime_error("Not a regular file"); }
    
    size_t sz = st.st_size;
    if (max_size > 0 && sz > max_size) { close(fd); throw runtime_error("File too large"); }
    
    SecureBuffer buf(sz);
    size_t total = 0;
    while (total < sz) {
        ssize_t r = read(fd, buf.ptr() + total, sz - total);
        if (r <= 0) break;
        total += r;
    }
    close(fd);
    if (total != sz) throw runtime_error("Read incomplete");
    return buf;
#endif
}

// -----------------------------------------------------------------------------
// SECURE WRITE (Atomic Creation)
// -----------------------------------------------------------------------------
void write_file_secure(const string& path, const uint8_t* data, size_t size, bool overwrite = false) {
    string safe = resolve_safe_path(path, false);
    
#ifdef _WIN32
    DWORD creationDisp = overwrite ? CREATE_ALWAYS : CREATE_NEW;
    
    HANDLE hFile = CreateFileA(safe.c_str(), GENERIC_WRITE, 0, NULL,
                               creationDisp, FILE_ATTRIBUTE_NORMAL, NULL);
                               
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_EXISTS) {
            throw runtime_error("File already exists: " + sanitize_for_error(path));
        }
        throw runtime_error("Cannot create file (Windows Error: " + to_string(err) + ")");
    }

    DWORD written;
    if (!WriteFile(hFile, data, (DWORD)size, &written, NULL) || written != size) {
        CloseHandle(hFile);
        DeleteFileA(safe.c_str());
        throw runtime_error("Write failed");
    }
    
    FlushFileBuffers(hFile);
    CloseHandle(hFile);
#else
    int flags = O_WRONLY | O_NOFOLLOW;
    if (overwrite) flags |= O_CREAT | O_TRUNC;
    else flags |= O_CREAT | O_EXCL;
    
    int fd = open(safe.c_str(), flags, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        if (errno == EEXIST) throw runtime_error("File already exists");
        if (errno == ELOOP) throw runtime_error("Cannot write to symlink");
        throw runtime_error("Cannot create file");
    }
    
    size_t total = 0;
    while (total < size) {
        ssize_t w = write(fd, data + total, size - total);
        if (w < 0) {
            close(fd); unlink(safe.c_str());
            throw runtime_error("Write failed");
        }
        total += w;
    }
    fsync(fd);
    close(fd);
#endif
}

void write_file_secure(const string& path, const vector<uint8_t>& data, bool overwrite = false) {
    write_file_secure(path, data.data(), data.size(), overwrite);
}

void clean_stale_artifacts() {
    if (!fs::exists(KEY_DIR)) return;
    auto now = fs::file_time_type::clock::now();
    for (const auto& entry : fs::directory_iterator(KEY_DIR)) {
        string ext = entry.path().extension().string();
        if (ext == ".lock" || ext == ".tmp") {
            try {
                if (chrono::duration_cast<chrono::minutes>(now - fs::last_write_time(entry)).count() > 60) {
                    fs::remove(entry);
                }
            } catch (...) {}
        }
    }
}

class HardwareBindingManager {
public:
    // generate_keypair returns encrypted data (not secret), so vector is OK
    static vector<uint8_t> generate_keypair(BindingType type, const vector<uint8_t>& payload);
    // decapsulate returns RAW SECRET KEY - must use SecureByteVec!
    static SecureByteVec decapsulate(const vector<uint8_t>& ct, BindingType type);
    static bool is_available(BindingType type);
};

vector<uint8_t> HardwareBindingManager::generate_keypair(BindingType type, [[maybe_unused]] const vector<uint8_t>& payload) {
    if (type == BindingType::Disk) return {};

    if (type == BindingType::TPM) {
#ifdef ENABLE_TPM
        ESYS_CONTEXT* ctx_raw = nullptr;
        if (Esys_Initialize(&ctx_raw, nullptr, nullptr) != TSS2_RC_SUCCESS) throw runtime_error("TPM initialization failed");
        EsysPtr ctx(ctx_raw);

        TPMS_CAPABILITY_DATA* capData = nullptr;
        bool exists = false;
        
        TSS2_RC rc = Esys_GetCapability(ctx.get(), ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                        TPM2_CAP_HANDLES, get_tpm_handle(), 1,
                                        nullptr, &capData);
        
        if (rc == TSS2_RC_SUCCESS && capData->data.handles.count > 0) {
            if (capData->data.handles.handle[0] == get_tpm_handle()) {
                exists = true;
            }
        }
        Esys_Free(capData);

        if (exists) {
            ostringstream err;
            err << "TPM key already exists at slot " << (int)TPM_SLOT 
                << " (handle 0x" << hex << get_tpm_handle() << "). "
                << "Run 'tpm2_evictcontrol -C o -c 0x" << hex << get_tpm_handle() 
                << "' to clear it, or use --tpm-slot <0-255> to use a different slot.";
            throw runtime_error(err.str());
        }

        TPM2B_PUBLIC inPublic = {};
        inPublic.publicArea.type = TPM2_ALG_RSA;
        inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
        inPublic.publicArea.objectAttributes = TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH;
        inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
        inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
        inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
        inPublic.publicArea.parameters.rsaDetail.exponent = 0;
        inPublic.publicArea.unique.rsa.size = 0;

        TPM2B_SENSITIVE_CREATE inSensitive = {};
        TPM2B_DATA outsideInfo = {};
        TPML_PCR_SELECTION creationPCR = {};
        ESYS_TR keyHandle = ESYS_TR_NONE;
        TPM2B_PUBLIC* outPublic = nullptr;

        if (Esys_CreatePrimary(ctx.get(), ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                               &inSensitive, &inPublic, &outsideInfo, &creationPCR, 
                               &keyHandle, &outPublic, nullptr, nullptr, nullptr) != TSS2_RC_SUCCESS) {
            throw runtime_error("TPM CreatePrimary failed");
        }
        free(outPublic);

        TPM2B_PUBLIC_KEY_RSA message = {};
        if (payload.size() > sizeof(message.buffer)) {
             Esys_FlushContext(ctx.get(), keyHandle);
             throw runtime_error("Payload too large for TPM");
        }
        
        message.size = static_cast<UINT16>(payload.size());
        memcpy(message.buffer, payload.data(), payload.size());

        TPMT_RSA_DECRYPT scheme{};
        scheme.scheme = TPM2_ALG_OAEP;
        scheme.details.oaep.hashAlg = TPM2_ALG_SHA256;
        TPM2B_DATA label = {};
        TPM2B_PUBLIC_KEY_RSA* outCipher = nullptr;

        if (Esys_RSA_Encrypt(ctx.get(), keyHandle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 
                             &message, &scheme, &label, &outCipher) != TSS2_RC_SUCCESS) {
            Esys_FlushContext(ctx.get(), keyHandle);
            throw runtime_error("TPM Encryption failed");
        }
        
        vector<uint8_t> encrypted_data(outCipher->buffer, outCipher->buffer + outCipher->size);
        free(outCipher);

        ESYS_TR newHandle = ESYS_TR_NONE;
        if (Esys_EvictControl(ctx.get(), ESYS_TR_RH_OWNER, keyHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, get_tpm_handle(), &newHandle) != TSS2_RC_SUCCESS) {
            Esys_FlushContext(ctx.get(), keyHandle);
            throw runtime_error("Failed to persist TPM key");
        }
        Esys_FlushContext(ctx.get(), keyHandle);

        return encrypted_data;
#else
        throw runtime_error("TPM not compiled");
#endif
    }
    return {};
}

SecureByteVec HardwareBindingManager::decapsulate([[maybe_unused]] const vector<uint8_t>& ct, BindingType type) {
    if (type == BindingType::Disk) throw runtime_error("Decapsulate not used for Disk binding");
    if (type == BindingType::TPM) {
#ifdef ENABLE_TPM
        ESYS_CONTEXT* ctx_raw = nullptr;
        if (Esys_Initialize(&ctx_raw, nullptr, nullptr) != TSS2_RC_SUCCESS) throw runtime_error("TPM init failed");
        EsysPtr ctx(ctx_raw);

        ESYS_TR keyHandle = ESYS_TR_NONE;
        TSS2_RC rc = Esys_TR_FromTPMPublic(ctx.get(), get_tpm_handle(), ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &keyHandle);
        if (rc != TSS2_RC_SUCCESS) throw runtime_error("TPM key not found – wrong machine or identity not bound");

        TPM2B_PUBLIC_KEY_RSA inData = {};
        
        if (ct.size() > sizeof(inData.buffer)) throw runtime_error("Ciphertext too large for TPM buffer");
        inData.size = static_cast<UINT16>(ct.size());
        
        memcpy(inData.buffer, ct.data(), ct.size());
        
        TPMT_RSA_DECRYPT scheme{};
        scheme.scheme = TPM2_ALG_OAEP;
        scheme.details.oaep.hashAlg = TPM2_ALG_SHA256;
        TPM2B_DATA label = {};
        TPM2B_PUBLIC_KEY_RSA* outData = nullptr;

        rc = Esys_RSA_Decrypt(ctx.get(), keyHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                              &inData, &scheme, &label, &outData);
        
        if (rc != TSS2_RC_SUCCESS) throw runtime_error("TPM decryption failed");
        
        SecureByteVec result(outData->size);
        memcpy(result.data(), outData->buffer, outData->size);
        sodium_memzero(outData->buffer, outData->size);
        free(outData);
        return result;
#else
        throw runtime_error("TPM support not compiled");
#endif
    }
    throw runtime_error("Unsupported binding type");
}

bool HardwareBindingManager::is_available(BindingType type) {
    if (type == BindingType::Disk) return true;
#ifdef ENABLE_TPM
    if (type == BindingType::TPM) {
        ESYS_CONTEXT* ctx = nullptr;
        if (Esys_Initialize(&ctx, nullptr, nullptr) == TSS2_RC_SUCCESS) {
            Esys_Finalize(&ctx);
            return true;
        }
        return false;
    }
#endif
    return false;
}

void create_header_v3(ThermoHeader& header, const string& password, BindingType bind_type, const vector<uint8_t>& pub_key) {
    sodium_memzero(&header, sizeof(header));
    memcpy(header.magic, HEADER_MAGIC_V1.c_str(), 9);
    header.format_version = 3;
    header.binding_type = static_cast<uint8_t>(bind_type);
    header.argon_level = get_argon_level_byte();
    header.timestamp = time(nullptr);
    crypto_hash_sha256(header.fingerprint, pub_key.data(), pub_key.size());
    SecureBuffer hmac_key(32);
    if (crypto_pwhash(hmac_key.ptr(), 32, password.c_str(), password.length(), header.fingerprint,
                      get_opslimit(), get_memlimit(), crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw runtime_error("Failed to derive HMAC key");
    }
    crypto_auth_hmacsha256(header.hmac, (const unsigned char*)&header, sizeof(header) - 32, hmac_key.ptr());
}

void verify_header_v3(const ThermoHeader& header, const string& password) {
    bool magic_ok = (memcmp(header.magic, HEADER_MAGIC_V1.c_str(), 9) == 0);
    
    unsigned long long ops;
    size_t mem;
    get_argon_params_from_byte(header.argon_level, ops, mem);
    
    SecureBuffer hmac_key(32);
    int pwhash_result = crypto_pwhash(hmac_key.ptr(), 32, password.c_str(), password.length(), header.fingerprint,
                      ops, mem, crypto_pwhash_ALG_ARGON2ID13);
    
    uint8_t computed[32];
    crypto_auth_hmacsha256(computed, (const unsigned char*)&header, sizeof(header) - 32, hmac_key.ptr());
    
    bool hmac_ok = (sodium_memcmp(computed, header.hmac, 32) == 0);
    
    // Zero sensitive data before potential error
    sodium_memzero(computed, sizeof(computed));
    
    // Always apply rate limit - this makes timing consistent regardless of outcome
    // The delay happens whether verification succeeds or fails
    if (GLOBAL_RATE_LIMIT) {
        // Small consistent delay for all operations
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Now check results and throw appropriate errors
    if (!magic_ok) {
        enforce_rate_limit();
        throw runtime_error("Invalid file format");
    }
    if (pwhash_result != 0) {
        enforce_rate_limit();
        throw runtime_error("Key derivation failed");
    }
    if (!hmac_ok) {
        enforce_rate_limit();
        throw runtime_error("Wrong password or corrupted file");
    }
}

void generate_identity_v4(const string& name) {
    if (sodium_init() < 0) throw runtime_error("Sodium init failed");
    
    OQS_init();
    if (!is_valid_identity_name(name)) throw runtime_error("Identity name must contain only letters, numbers and underscore");
    fs::create_directories(KEY_DIR);
    
    string id_path = KEY_DIR + name + IDENTITY_EXT;
    if (fs::exists(id_path)) throw runtime_error("Identity already exists");
    
    SecretString password;
    get_password_secure(password, "Set password for identity: ");
    
    // ==========================================================================
    // PASSWORD POLICY (CWE-521 mitigation)
    // Enforce minimum password strength to prevent weak key derivation
    // ==========================================================================
    if (password.length() < MIN_PASSWORD_LENGTH) {
        throw runtime_error("Password too short. Minimum " + to_string(MIN_PASSWORD_LENGTH) + " characters required for security.");
    }
    
    // Check for trivial passwords (all same character)
    bool trivial = true;
    const char* pwd_data = password.c_str();
    for (size_t i = 1; i < password.length(); i++) {
        if (pwd_data[i] != pwd_data[0]) {
            trivial = false;
            break;
        }
    }
    if (trivial) {
        throw runtime_error("Password too simple. Use a mix of different characters.");
    }
    
    OqsKemPtr kem(OQS_KEM_new("ML-KEM-768"));
    if (!kem) throw runtime_error("ML-KEM-768 not available");
    vector<uint8_t> pq_pk(kem->length_public_key);
    
    SecureBuffer pq_sk(kem->length_secret_key);
    OQS_KEM_keypair(kem.get(), pq_pk.data(), pq_sk.ptr());
    vector<uint8_t> x_pk(crypto_box_PUBLICKEYBYTES);
    
    SecureBuffer x_sk(crypto_box_SECRETKEYBYTES);
    crypto_box_keypair(x_pk.data(), x_sk.ptr());
    
    OqsSigPtr sig(OQS_SIG_new("ML-DSA-65"));
    if (!sig) throw runtime_error("ML-DSA-65 not available");
    
    vector<uint8_t> sig_pk(sig->length_public_key);
    SecureBuffer sig_sk(sig->length_secret_key);
    OQS_SIG_keypair(sig.get(), sig_pk.data(), sig_sk.ptr());
    vector<uint8_t> pub_keys;
    pub_keys.insert(pub_keys.end(), pq_pk.begin(), pq_pk.end());
    pub_keys.insert(pub_keys.end(), x_pk.begin(), x_pk.end());
    pub_keys.insert(pub_keys.end(), sig_pk.begin(), sig_pk.end());
    
    vector<uint8_t> signature(sig->length_signature);
    size_t sig_len;
    OQS_SIG_sign(sig.get(), signature.data(), &sig_len, pub_keys.data(), pub_keys.size(), sig_sk.ptr());
    
    SecureBuffer priv_blob(pq_sk.size() + x_sk.size() + sig_sk.size());
    uint8_t* p = priv_blob.ptr();
    memcpy(p, pq_sk.ptr(), pq_sk.size()); p += pq_sk.size();
    memcpy(p, x_sk.ptr(), x_sk.size()); p += x_sk.size();
    memcpy(p, sig_sk.ptr(), sig_sk.size());
    
    SecureBuffer dek(32);
    randombytes_buf(dek.ptr(), 32);
    SecureBuffer nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(nonce.ptr(), nonce.size());
    
    vector<uint8_t> enc_priv(priv_blob.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long clen;
    crypto_aead_xchacha20poly1305_ietf_encrypt(enc_priv.data(), &clen, priv_blob.ptr(), priv_blob.size(),
                                              nullptr, 0, nullptr, nonce.ptr(), dek.ptr());
    vector<uint8_t> sealed_dek;
    if (CURRENT_BINDING == BindingType::Disk) {
        SecureBuffer salt(crypto_pwhash_SALTBYTES);
        randombytes_buf(salt.ptr(), salt.size());
        SecureBuffer dek_nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        randombytes_buf(dek_nonce.ptr(), dek_nonce.size());
        SecureBuffer kek(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
        if (crypto_pwhash(kek.ptr(), kek.size(), password.get().c_str(), password.get().length(), salt.ptr(),
                          get_opslimit(), get_memlimit(), crypto_pwhash_ALG_ARGON2ID13) != 0) {
            throw runtime_error("Argon2id failed");
        }
        vector<uint8_t> enc_dek(32 + crypto_aead_xchacha20poly1305_ietf_ABYTES);
        unsigned long long dlen;
        crypto_aead_xchacha20poly1305_ietf_encrypt(enc_dek.data(), &dlen, dek.ptr(), 32, nullptr, 0, nullptr, dek_nonce.ptr(), kek.ptr());
        sealed_dek.insert(sealed_dek.end(), salt.ptr(), salt.ptr() + salt.size());
        sealed_dek.insert(sealed_dek.end(), dek_nonce.ptr(), dek_nonce.ptr() + dek_nonce.size());
        sealed_dek.insert(sealed_dek.end(), enc_dek.begin(), enc_dek.end());
    } else {
        sealed_dek = HardwareBindingManager::generate_keypair(CURRENT_BINDING, vector<uint8_t>(dek.ptr(), dek.ptr() + 32));
        if (sealed_dek.empty()) {
            throw runtime_error("Hardware binding returned empty data (Encryption failed)");
        }
    }
    
    // Build vault data
    string vault_path = KEY_DIR + name + "/" + VAULT_FILENAME;
    fs::create_directories(KEY_DIR + name);
    
    vector<uint8_t> vault_data;
    uint64_t sd_len = sealed_dek.size();
    vault_data.insert(vault_data.end(), reinterpret_cast<uint8_t*>(&sd_len), reinterpret_cast<uint8_t*>(&sd_len) + 8);
    vault_data.insert(vault_data.end(), sealed_dek.begin(), sealed_dek.end());
    vault_data.insert(vault_data.end(), nonce.ptr(), nonce.ptr() + nonce.size());
    vault_data.insert(vault_data.end(), enc_priv.data(), enc_priv.data() + clen);
    
    // Write vault with TOCTOU protection
    write_file_secure(vault_path, vault_data);
    
    // Build identity file data
    ThermoHeader header{};
    create_header_v3(header, password.get(), CURRENT_BINDING, pub_keys);
    
    vector<uint8_t> id_data;
    id_data.insert(id_data.end(), reinterpret_cast<uint8_t*>(&header), reinterpret_cast<uint8_t*>(&header) + sizeof(header));
    uint32_t pk_len = static_cast<uint32_t>(pub_keys.size());
    id_data.insert(id_data.end(), reinterpret_cast<uint8_t*>(&pk_len), reinterpret_cast<uint8_t*>(&pk_len) + 4);
    id_data.insert(id_data.end(), pub_keys.begin(), pub_keys.end());
    uint32_t slen = static_cast<uint32_t>(sig_len);
    id_data.insert(id_data.end(), reinterpret_cast<uint8_t*>(&slen), reinterpret_cast<uint8_t*>(&slen) + 4);
    id_data.insert(id_data.end(), signature.begin(), signature.begin() + sig_len);
    
    // Write identity with TOCTOU protection
    write_file_secure(id_path, id_data);
    
    set_secure_permissions(vault_path);
    set_secure_permissions(id_path);
    cerr << "Identity '" << name << "' created successfully." << endl;
}

void encrypt_stream_v3(istream& in, ostream& out, const string& recipient_file, size_t size_hint) {
    auto recipient_data = read_file_secure(recipient_file, MAX_IDENTITY_FILE_SIZE);
    
    // Use SafeReader for secure parsing
    SafeReader reader(recipient_data.ptr(), recipient_data.size());
    
    // Read and validate header
    if (reader.bytes_remaining() < sizeof(ThermoHeader)) {
        throw runtime_error("Invalid identity file (too small for header)");
    }
    ThermoHeader header{};
    reader.read_into(reinterpret_cast<uint8_t*>(&header), sizeof(header));
    
    if (memcmp(header.magic, HEADER_MAGIC_V1.c_str(), 9) != 0) {
        throw runtime_error("Invalid recipient identity magic");
    }
    
    // Read public keys with sanity check
    uint32_t pk_len = reader.read<uint32_t>();
    vector<uint8_t> pub_keys = reader.read_bytes(pk_len, MAX_PUBKEY_SIZE);
    
    // Read signature with sanity check
    uint32_t sig_len = reader.read<uint32_t>();
    vector<uint8_t> signature = reader.read_bytes(sig_len, MAX_SIGNATURE_SIZE);
    
    // Verify signature
    OqsSigPtr sig(OQS_SIG_new("ML-DSA-65"));
    if (!sig) throw runtime_error("ML-DSA-65 not supported");
    
    OqsKemPtr kem_dummy(OQS_KEM_new("ML-KEM-768"));
    if (!kem_dummy) throw runtime_error("Failed to initialize ML-KEM-768 for offset calculation");
    
    size_t kem_len = kem_dummy->length_public_key;
    size_t x_len = crypto_box_PUBLICKEYBYTES;
    size_t sig_pk_offset = kem_len + x_len;
    
    if (pub_keys.size() < sig_pk_offset + sig->length_public_key) {
        throw runtime_error("Public key blob invalid size");
    }
    
    OQS_STATUS rc = OQS_SIG_verify(sig.get(), 
                                   pub_keys.data(), pub_keys.size(),
                                   signature.data(), signature.size(),
                                   pub_keys.data() + sig_pk_offset);
    if (rc != OQS_SUCCESS) {
        enforce_rate_limit();
        throw runtime_error("SECURITY ALERT: Identity signature verification FAILED! The file may be forged.");
    }
    
    // Proceed with encryption
    OqsKemPtr kem(OQS_KEM_new("ML-KEM-768"));
    if (!kem) throw runtime_error("ML-KEM-768 not supported");
    
    vector<uint8_t> pq_pk(pub_keys.begin(), pub_keys.begin() + kem->length_public_key);
    SecureBuffer shared_secret(kem->length_shared_secret);
    vector<uint8_t> ciphertext(kem->length_ciphertext);
    OQS_KEM_encaps(kem.get(), ciphertext.data(), shared_secret.ptr(), pq_pk.data());
    
    vector<uint8_t> x_eph_pk(crypto_box_PUBLICKEYBYTES);
    SecureBuffer x_eph_sk(crypto_box_SECRETKEYBYTES);
    crypto_box_keypair(x_eph_pk.data(), x_eph_sk.ptr());
    
    vector<uint8_t> x_pk(pub_keys.begin() + kem->length_public_key, 
                         pub_keys.begin() + kem->length_public_key + crypto_box_PUBLICKEYBYTES);
    
    SecureBuffer x_shared(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(x_shared.ptr(), x_eph_sk.ptr(), x_pk.data()) != 0) {
        throw runtime_error("X25519 scalar multiplication failed");
    }
    
    SecureBuffer master_key(crypto_secretstream_xchacha20poly1305_KEYBYTES);
    crypto_generichash_state st;
    crypto_generichash_init(&st, nullptr, 0, master_key.size());
    crypto_generichash_update(&st, shared_secret.ptr(), shared_secret.size());
    crypto_generichash_update(&st, x_shared.ptr(), x_shared.size());
    crypto_generichash_final(&st, master_key.ptr(), master_key.size());
    
    crypto_secretstream_xchacha20poly1305_state stream_state;
    unsigned char header_bytes[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_init_push(&stream_state, header_bytes, master_key.ptr());
    
    out.write(HEADER_MAGIC_V1.c_str(), 9);
    if (ciphertext.size() != 1088) throw runtime_error("Critical crypto failure: Invalid Kyber CT size");
    out.write((char*)ciphertext.data(), ciphertext.size());
    out.write((char*)x_eph_pk.data(), x_eph_pk.size());
    out.write((char*)header_bytes, sizeof(header_bytes));
    
    SecureBuffer in_buf(CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
    SecureBuffer out_buf(CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
    size_t processed = 0;
    
    while (in) {
        in.read((char*)in_buf.ptr(), CHUNK_SIZE);
        size_t read = in.gcount();
        if (read == 0) break;
        unsigned char tag = in.eof() ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        unsigned long long out_len;
        crypto_secretstream_xchacha20poly1305_push(&stream_state, out_buf.ptr(), &out_len,
                                                   in_buf.ptr(), read, nullptr, 0, tag);
        out.write((char*)out_buf.ptr(), out_len);
        processed += read;
        report_progress(processed, size_hint ? size_hint : STREAM_SIZE_HINT);
    }
    cerr << "[+] File encrypted successfully (Identity Verified)." << endl;
}

void decrypt_logic_v4(istream& in, ostream& out, const string& id_name, size_t hint) {
    if (sodium_init() < 0) throw runtime_error("Sodium init failed");
    OQS_init();
    
    string id_path = KEY_DIR + id_name + IDENTITY_EXT;
    auto id_data = read_file_secure(id_path, MAX_IDENTITY_FILE_SIZE);
    
    // Parse identity header with SafeReader
    SafeReader id_reader(id_data.ptr(), id_data.size());
    if (id_reader.bytes_remaining() < sizeof(ThermoHeader)) {
        throw runtime_error("Identity file too small");
    }
    ThermoHeader header{};
    id_reader.read_into(reinterpret_cast<uint8_t*>(&header), sizeof(header));
    BindingType bind = static_cast<BindingType>(header.binding_type);
    
    SecretString password;
    get_password_secure(password, "Password: ");
    
    verify_header_v3(header, password.get());
    
    // Parse vault with SafeReader
    string vault_path = KEY_DIR + id_name + "/" + VAULT_FILENAME;
    auto vault_data = read_file_secure(vault_path, MAX_VAULT_FILE_SIZE);
    SafeReader vault_reader(vault_data.ptr(), vault_data.size());
    
    uint64_t sealed_len = vault_reader.read<uint64_t>();
    if (sealed_len > MAX_SEALED_DEK_SIZE) {
        throw runtime_error("Security: Sealed DEK size exceeds maximum (possible attack)");
    }
    vector<uint8_t> sealed_dek = vault_reader.read_bytes(sealed_len, MAX_SEALED_DEK_SIZE);
    
    SecureBuffer dek(32);
    if (bind == BindingType::Disk) {
        size_t min_sealed_size = crypto_pwhash_SALTBYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        if (sealed_dek.size() < min_sealed_size) {
            throw runtime_error("Corrupted disk vault (sealed DEK too small)");
        }
        const uint8_t* salt = sealed_dek.data();
        const uint8_t* nonce = salt + crypto_pwhash_SALTBYTES;
        const uint8_t* ct = nonce + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        size_t ct_len = sealed_dek.size() - min_sealed_size;
        
        unsigned long long ops;
        size_t mem;
        get_argon_params_from_byte(header.argon_level, ops, mem);
        
        SecureBuffer kek(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
        if (crypto_pwhash(kek.ptr(), kek.size(), password.get().c_str(), password.get().length(),
                          salt, ops, mem, crypto_pwhash_ALG_ARGON2ID13) != 0) {
            enforce_rate_limit();
            throw runtime_error("Wrong password or corrupted vault");
        }
        unsigned long long mlen;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(dek.ptr(), &mlen, nullptr, ct, ct_len, nullptr, 0, nonce, kek.ptr()) != 0) {
            enforce_rate_limit();
            throw runtime_error("Wrong password");
        }
    } else {
        SecureByteVec raw_dek = HardwareBindingManager::decapsulate(sealed_dek, bind);
        if (raw_dek.size() != 32) throw runtime_error("Hardware returned invalid key");
        memcpy(dek.ptr(), raw_dek.data(), 32);
        // SecureByteVec auto-wipes on destruction
    }
    
    // Read nonce and encrypted private keys
    vector<uint8_t> main_nonce = vault_reader.read_bytes(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    size_t enc_priv_len = vault_reader.bytes_remaining();
    if (enc_priv_len < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        throw runtime_error("Corrupted vault (encrypted private keys too small)");
    }
    
    SecureBuffer priv_blob(enc_priv_len - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long mlen;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(priv_blob.ptr(), &mlen, nullptr, 
            vault_reader.current_ptr(), enc_priv_len, nullptr, 0, main_nonce.data(), dek.ptr()) != 0) {
        throw runtime_error("Vault integrity check failed");
    }
    
    // Extract private keys
    OqsKemPtr kem(OQS_KEM_new("ML-KEM-768"));
    if (!kem) throw runtime_error("ML-KEM-768 not available");
    
    SafeReader priv_reader(priv_blob.ptr(), priv_blob.size());
    SecureBuffer pq_sk(kem->length_secret_key);
    SecureBuffer x_sk(crypto_box_SECRETKEYBYTES);
    priv_reader.read_into(pq_sk.ptr(), pq_sk.size());
    priv_reader.read_into(x_sk.ptr(), x_sk.size());
    
    // Read encrypted message header
    char magic[9];
    in.read(magic, 9);
    if (memcmp(magic, HEADER_MAGIC_V1.c_str(), 9) != 0) throw runtime_error("Not a ThermoCrypt file");
    
    // Use dynamically queried ciphertext length (not hardcoded)
    const size_t kyber_ct_len = kem->length_ciphertext;
    vector<uint8_t> ct(kyber_ct_len);
    in.read((char*)ct.data(), kyber_ct_len);
    if (static_cast<size_t>(in.gcount()) != kyber_ct_len) throw runtime_error("File too short (truncated ciphertext)");
    
    vector<uint8_t> eph_x_pk(crypto_box_PUBLICKEYBYTES);
    in.read((char*)eph_x_pk.data(), eph_x_pk.size());
    
    unsigned char stream_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    in.read((char*)stream_header, sizeof(stream_header));
    
    // Derive shared secrets
    SecureBuffer ss_pq(kem->length_shared_secret);
    OQS_KEM_decaps(kem.get(), ss_pq.ptr(), ct.data(), pq_sk.ptr());
    
    SecureBuffer ss_x(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(ss_x.ptr(), x_sk.ptr(), eph_x_pk.data()) != 0) {
        throw runtime_error("X25519 scalar multiplication failed");
    }
    SecureBuffer master(crypto_secretstream_xchacha20poly1305_KEYBYTES);
    crypto_generichash_state h;
    crypto_generichash_init(&h, nullptr, 0, master.size());
    crypto_generichash_update(&h, ss_pq.ptr(), ss_pq.size());
    crypto_generichash_update(&h, ss_x.ptr(), ss_x.size());
    crypto_generichash_final(&h, master.ptr(), master.size());
    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, stream_header, master.ptr()) != 0) {
        throw runtime_error("Stream initialization failed");
    }
    SecureBuffer in_buf(CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
    SecureBuffer out_buf(CHUNK_SIZE);
    size_t processed = 0;
    while (in) {
        in.read((char*)in_buf.ptr(), CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
        streamsize read = in.gcount();
        if (read == 0) break;
        unsigned char tag;
        unsigned long long out_len;
        if (crypto_secretstream_xchacha20poly1305_pull(&st, out_buf.ptr(), &out_len, &tag,
                                                       in_buf.ptr(), read, nullptr, 0) != 0) {
            throw runtime_error("Corrupted or tampered file");
        }
        out.write((char*)out_buf.ptr(), out_len);
        processed += read;
        report_progress(processed, hint);
    }
    cerr << "[+] File decrypted successfully." << endl;
}


void encrypt_to_armor(const string& recipient_file) {
    // Initialize crypto libraries
    if (sodium_init() < 0) throw runtime_error("Sodium init failed");
    OQS_init();
    
    // Check if recipient file exists
    if (!fs::exists(recipient_file)) {
        throw runtime_error("Recipient file not found: " + sanitize_for_error(recipient_file));
    }
    
    // ==========================================================================
    // Use SecureByteVec instead of std::vector
    // This ensures plaintext is stored in sodium_malloc memory which:
    // - Is locked to RAM (cannot be swapped to disk)
    // - Has guard pages to detect buffer overflows
    // - Is automatically zeroed when freed
    // ==========================================================================
    SecureByteVec plaintext;
    plaintext.reserve(64 * 1024);  // Pre-allocate 64KB to reduce reallocations
    
    // Read stdin with size limit (CWE-400 DoS mitigation)
    char c;
    while (cin.get(c)) {
        if (plaintext.size() >= MAX_MESSAGE_SIZE) {
            throw runtime_error("Input too large. Maximum message size is " + 
                to_string(MAX_MESSAGE_SIZE / (1024*1024)) + " MB");
        }
        plaintext.push_back(static_cast<uint8_t>(c));
    }
    
    if (plaintext.empty()) {
        throw runtime_error("No input data provided");
    }
    
    // ==========================================================================
    // Use SecureVectorStream for ZERO-COPY streaming
    // Read directly from the locked SecureByteVec memory.
    // ==========================================================================
    SecureVectorStream secure_buf(plaintext);
    std::istream plain_stream(&secure_buf);
    
    // Encrypt to memory buffer (ciphertext is not sensitive)
    ostringstream encrypted_stream(ios::binary);
    encrypt_stream_v3(plain_stream, encrypted_stream, recipient_file, plaintext.size());
    
    // SecureByteVec destructor will zero and free plaintext automatically
    // But we can clear it early for extra safety
    sodium_memzero(plaintext.data(), plaintext.size());
    
    // Get encrypted bytes (ciphertext - not sensitive)
    string encrypted_str = encrypted_stream.str();
    vector<uint8_t> encrypted_bytes(encrypted_str.begin(), encrypted_str.end());
    
    string b64 = base64_encode(encrypted_bytes);
    string armored = wrap_armor(b64);
    
    cout << armored;
    cout.flush();
    
    cerr << "[+] Message encrypted and armored successfully." << endl;
}

void export_pubkey_armor(const string& id_name) {
    string id_path = KEY_DIR + id_name + IDENTITY_EXT;
    if (!fs::exists(id_path)) {
        throw runtime_error("Identity not found: " + id_name);
    }
    
    ifstream fin(id_path, ios::binary | ios::ate);
    if (!fin) throw runtime_error("Cannot open identity file");
    size_t sz = fin.tellg();
    fin.seekg(0);
    vector<uint8_t> data(sz);
    fin.read((char*)data.data(), sz);
    fin.close();
    
    string b64 = base64_encode(data);
    string armored = wrap_pubkey_armor(b64);
    
    cout << armored;
    cout.flush();
    cerr << "[+] Public key exported successfully." << endl;
}

void import_pubkey_armor(const string& name) {
    if (!is_valid_identity_name(name)) {
        throw runtime_error("Invalid identity name. Use only letters, numbers and underscore.");
    }
    
    fs::create_directories(KEY_DIR);
    string id_path = KEY_DIR + name + IDENTITY_EXT;
    
    if (fs::exists(id_path)) {
        throw runtime_error("Identity already exists: " + name);
    }
    
    // Read armored input from stdin
    ostringstream armored_stream;
    armored_stream << cin.rdbuf();
    string armored = armored_stream.str();
    
    if (armored.empty()) {
        throw runtime_error("No input data provided");
    }
    
    // Unwrap and decode
    string b64 = unwrap_pubkey_armor(armored);
    vector<uint8_t> data = base64_decode(b64);
    
    // Sanity check on total size
    if (data.size() > MAX_IDENTITY_FILE_SIZE) {
        throw runtime_error("Security: Public key data exceeds maximum size (possible attack)");
    }
    
    // Parse with SafeReader
    SafeReader reader(data.data(), data.size());
    
    if (reader.bytes_remaining() < sizeof(ThermoHeader)) {
        throw runtime_error("Invalid public key data (too small for header)");
    }
    
    ThermoHeader header{};
    reader.read_into(reinterpret_cast<uint8_t*>(&header), sizeof(header));
    
    if (memcmp(header.magic, HEADER_MAGIC_V1.c_str(), 9) != 0) {
        throw runtime_error("Invalid public key format (bad magic)");
    }
    
    // Read public keys with sanity check
    uint32_t pk_len = reader.read<uint32_t>();
    vector<uint8_t> pub_keys = reader.read_bytes(pk_len, MAX_PUBKEY_SIZE);
    
    // Read signature with sanity check
    uint32_t sig_len = reader.read<uint32_t>();
    vector<uint8_t> signature = reader.read_bytes(sig_len, MAX_SIGNATURE_SIZE);
    
    // Verify signature
    OQS_init();
    OqsSigPtr sig(OQS_SIG_new("ML-DSA-65"));
    if (!sig) throw runtime_error("ML-DSA-65 not supported");
    OqsKemPtr kem_dummy(OQS_KEM_new("ML-KEM-768"));
    if (!kem_dummy) throw runtime_error("ML-KEM-768 not supported");
    
    size_t kem_len = kem_dummy->length_public_key;
    size_t x_len = crypto_box_PUBLICKEYBYTES;
    size_t sig_pk_offset = kem_len + x_len;
    
    if (pub_keys.size() < sig_pk_offset + sig->length_public_key) {
        throw runtime_error("Invalid public key structure (too small for all keys)");
    }
    
    OQS_STATUS rc = OQS_SIG_verify(sig.get(),
                                   pub_keys.data(), pub_keys.size(),
                                   signature.data(), signature.size(),
                                   pub_keys.data() + sig_pk_offset);
    if (rc != OQS_SUCCESS) {
        throw runtime_error("SECURITY ALERT: Public key signature verification FAILED! The key may be forged or corrupted.");
    }
    
    // Write to file with TOCTOU protection
    write_file_secure(id_path, data);
    set_secure_permissions(id_path);
    
    cerr << "[+] Public key imported and verified as '" << name << "'." << endl;
}

// Helper function to read stdin with size limit (CWE-400 DoS mitigation)
string read_stdin_limited(size_t max_size) {
    string result;
    result.reserve(64 * 1024);  // Pre-allocate 64KB
    
    char c;
    while (cin.get(c)) {
        if (result.size() >= max_size) {
            throw runtime_error("Input too large. Maximum size is " + 
                to_string(max_size / (1024*1024)) + " MB");
        }
        result += c;
    }
    return result;
}

void decrypt_from_armor(const string& id_name) {
    if (sodium_init() < 0) throw runtime_error("Sodium init failed");
    OQS_init();
    
    SecretString password;
    string armored;
    
    // Check if stdin is a terminal or pipe
    bool is_tty = false;
#ifdef _WIN32
    is_tty = _isatty(_fileno(stdin));
#else
    is_tty = isatty(STDIN_FILENO);
#endif
    
    if (is_tty) {
        // Interactive mode - prompt for password, then read armored from remaining stdin
        get_password_secure(password, "Password: ");
        armored = read_stdin_limited(MAX_ARMORED_SIZE);
    } else {
        // Pipe mode - first line is password, rest is armored content
        string pw_line;
        getline(cin, pw_line);
        // Secure copy to SecretString
        password = SecretString(pw_line);
        sodium_memzero(&pw_line[0], pw_line.size());
        
        armored = read_stdin_limited(MAX_ARMORED_SIZE);
    }
    
    if (armored.empty()) {
        throw runtime_error("No input data provided");
    }
    
    // Unwrap and decode
    string b64 = unwrap_armor(armored);
    vector<uint8_t> encrypted = base64_decode(b64);
    
    // Clear armored data from memory
    sodium_memzero(&armored[0], armored.size());
    
    if (encrypted.empty()) {
        throw runtime_error("Failed to decode armored message");
    }
    
    // Load identity and verify with SafeReader
    string id_path = KEY_DIR + id_name + IDENTITY_EXT;
    auto id_data = read_file_secure(id_path, MAX_IDENTITY_FILE_SIZE);
    
    SafeReader id_reader(id_data.ptr(), id_data.size());
    if (id_reader.bytes_remaining() < sizeof(ThermoHeader)) {
        throw runtime_error("Identity file too small");
    }
    ThermoHeader header{};
    id_reader.read_into(reinterpret_cast<uint8_t*>(&header), sizeof(header));
    BindingType bind = static_cast<BindingType>(header.binding_type);
    
    verify_header_v3(header, password.get());
    
    // Load vault with SafeReader
    string vault_path = KEY_DIR + id_name + "/" + VAULT_FILENAME;
    auto vault_data = read_file_secure(vault_path, MAX_VAULT_FILE_SIZE);
    SafeReader vault_reader(vault_data.ptr(), vault_data.size());
    
    uint64_t sealed_len = vault_reader.read<uint64_t>();
    if (sealed_len > MAX_SEALED_DEK_SIZE) {
        throw runtime_error("Security: Sealed DEK size exceeds maximum");
    }
    vector<uint8_t> sealed_dek = vault_reader.read_bytes(sealed_len, MAX_SEALED_DEK_SIZE);
    
    SecureBuffer dek(32);
    if (bind == BindingType::Disk) {
        size_t min_sealed = crypto_pwhash_SALTBYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        if (sealed_dek.size() < min_sealed) {
            throw runtime_error("Corrupted disk vault");
        }
        const uint8_t* salt = sealed_dek.data();
        const uint8_t* nonce = salt + crypto_pwhash_SALTBYTES;
        const uint8_t* ct = nonce + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        size_t ct_len = sealed_dek.size() - min_sealed;
        
        unsigned long long ops;
        size_t mem;
        get_argon_params_from_byte(header.argon_level, ops, mem);
        
        SecureBuffer kek(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
        if (crypto_pwhash(kek.ptr(), kek.size(), password.get().c_str(), password.get().length(),
                          salt, ops, mem, crypto_pwhash_ALG_ARGON2ID13) != 0) {
            enforce_rate_limit();
            throw runtime_error("Wrong password or corrupted vault");
        }
        unsigned long long mlen;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(dek.ptr(), &mlen, nullptr, ct, ct_len, nullptr, 0, nonce, kek.ptr()) != 0) {
            enforce_rate_limit();
            throw runtime_error("Wrong password");
        }
    } else {
        SecureByteVec raw_dek = HardwareBindingManager::decapsulate(sealed_dek, bind);
        if (raw_dek.size() != 32) throw runtime_error("Hardware returned invalid key");
        memcpy(dek.ptr(), raw_dek.data(), 32);
        // SecureByteVec auto-wipes on destruction
    }
    
    // Read nonce and encrypted private keys
    vector<uint8_t> main_nonce = vault_reader.read_bytes(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    size_t enc_priv_len = vault_reader.bytes_remaining();
    if (enc_priv_len < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        throw runtime_error("Corrupted vault");
    }
    
    SecureBuffer priv_blob(enc_priv_len - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long mlen;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(priv_blob.ptr(), &mlen, nullptr,
            vault_reader.current_ptr(), enc_priv_len, nullptr, 0, main_nonce.data(), dek.ptr()) != 0) {
        throw runtime_error("Vault integrity check failed");
    }
    
    // Extract private keys with SafeReader
    OqsKemPtr kem(OQS_KEM_new("ML-KEM-768"));
    if (!kem) throw runtime_error("ML-KEM-768 not available");
    
    SafeReader priv_reader(priv_blob.ptr(), priv_blob.size());
    SecureBuffer pq_sk(kem->length_secret_key);
    SecureBuffer x_sk(crypto_box_SECRETKEYBYTES);
    priv_reader.read_into(pq_sk.ptr(), pq_sk.size());
    priv_reader.read_into(x_sk.ptr(), x_sk.size());
    
    // Now decrypt the message from memory
    istringstream encrypted_stream(string((char*)encrypted.data(), encrypted.size()), ios::binary);
    
    char magic[9];
    encrypted_stream.read(magic, 9);
    if (memcmp(magic, HEADER_MAGIC_V1.c_str(), 9) != 0) throw runtime_error("Not a ThermoCrypt message");
    
    // Use dynamically queried ciphertext length (not hardcoded)
    const size_t kyber_ct_len = kem->length_ciphertext;
    vector<uint8_t> ct(kyber_ct_len);
    encrypted_stream.read((char*)ct.data(), kyber_ct_len);
    if (static_cast<size_t>(encrypted_stream.gcount()) != kyber_ct_len) throw runtime_error("Message too short");
    
    vector<uint8_t> eph_x_pk(crypto_box_PUBLICKEYBYTES);
    encrypted_stream.read((char*)eph_x_pk.data(), eph_x_pk.size());
    
    unsigned char stream_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    encrypted_stream.read((char*)stream_header, sizeof(stream_header));
    
    SecureBuffer ss_pq(kem->length_shared_secret);
    OQS_KEM_decaps(kem.get(), ss_pq.ptr(), ct.data(), pq_sk.ptr());
    
    SecureBuffer ss_x(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(ss_x.ptr(), x_sk.ptr(), eph_x_pk.data()) != 0) {
        throw runtime_error("X25519 scalar multiplication failed");
    }
    
    SecureBuffer master(crypto_secretstream_xchacha20poly1305_KEYBYTES);
    crypto_generichash_state h;
    crypto_generichash_init(&h, nullptr, 0, master.size());
    crypto_generichash_update(&h, ss_pq.ptr(), ss_pq.size());
    crypto_generichash_update(&h, ss_x.ptr(), ss_x.size());
    crypto_generichash_final(&h, master.ptr(), master.size());
    
    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, stream_header, master.ptr()) != 0) {
        throw runtime_error("Stream initialization failed");
    }
    
#ifdef _WIN32
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    
    SecureBuffer in_buf(CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
    SecureBuffer out_buf(CHUNK_SIZE);
    
    while (encrypted_stream) {
        encrypted_stream.read((char*)in_buf.ptr(), CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
        streamsize read = encrypted_stream.gcount();
        if (read == 0) break;
        unsigned char tag;
        unsigned long long out_len;
        if (crypto_secretstream_xchacha20poly1305_pull(&st, out_buf.ptr(), &out_len, &tag,
                                                       in_buf.ptr(), read, nullptr, 0) != 0) {
            throw runtime_error("Corrupted or tampered message");
        }
        cout.write((char*)out_buf.ptr(), out_len);
    }
    cout.flush();
    cerr << "[+] Message decrypted successfully." << endl;
}

void disable_core_dumps() {
#ifndef _WIN32
    struct rlimit rlim;
    rlim.rlim_cur = rlim.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rlim);
#endif
}

void prevent_debugger_attach() {
#ifndef _WIN32
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        raise(SIGKILL); 
    }
#endif
}


void print_help() {
    cerr << "ThermoCrypt Lite v1.0.0 - PGP-inspired Quantum-Resistant Text Encryption\n"
         << "Hybrid Encryption (ML-KEM-768 + X25519) with Hardware Binding\n"
         << "Copyright (c) 2025 Herman Nythe\n\n"
         << "USAGE:\n"
         << "  ./thermo_core <command> [options]\n\n"
         << "IDENTITY MANAGEMENT:\n"
         << "  --gen <alias>                     Generate a new identity and vault.\n\n"
         << "MESSAGE ENCRYPTION (ASCII Armor):\n"
         << "  --encrypt-armor <id_file>         Encrypt stdin, output armored text to stdout.\n"
         << "  --decrypt-armor <alias>           Decrypt armored text from stdin to stdout.\n\n"
         << "PUBLIC KEY MANAGEMENT:\n"
         << "  --export-pubkey <alias>           Export public key as armored text to stdout.\n"
         << "  --import-pubkey <name>            Import armored public key from stdin.\n\n"
         << "OPTIONS:\n"
         << "  --bind <type>         Hardware binding mode (Linux Only).\n"
         << "                        Supported: disk (Standard), tpm (Machine Bound).\n"
         << "                        Default: disk\n\n"
         << "  --tpm-slot <0-255>    TPM handle slot (allows multiple TPM-bound identities).\n"
         << "                        Default: 0 (handle 0x81018100)\n"
         << "                        Example: --tpm-slot 1 uses handle 0x81018101\n\n"
         << "  --argon-level <lvl>   Set Argon2id cost parameters (interactive/moderate/sensitive).\n"
         << "  --keydir <path>       Specify custom directory for keys.\n"
         << "  --rate-limit          Enable artificial delay to slow brute-force.\n\n"
         << "EXAMPLES:\n"
         << "  # Generate identity\n"
         << "  ./thermo_core --gen alice\n\n"
         << "  # Generate TPM-bound identity in slot 1\n"
         << "  ./thermo_core --gen bob --bind tpm --tpm-slot 1\n\n"
         << "  # Encrypt a message\n"
         << "  echo 'Secret message' | ./thermo_core --encrypt-armor bob.thermoid\n\n"
         << "  # Decrypt a message\n"
         << "  cat encrypted.txt | ./thermo_core --decrypt-armor alice\n\n"
         << "TPM MANAGEMENT (Linux Only):\n"
         << "  TPM handles range from 0x81018100 (slot 0) to 0x810181FF (slot 255).\n"
         << "  Each slot can hold one identity. Use --tpm-slot to manage multiple.\n"
         << "  To clear a slot: tpm2_evictcontrol -C o -c 0x81018100\n\n"
         << "SECURITY NOTE:\n"
         << "  'disk' mode protects keys with a password (Argon2id).\n"
         << "  'tpm' mode binds keys to this specific machine's TPM chip AND a password.\n"
         << "  For maximum security, use the CLI directly (not the GUI).\n";
}

// =============================================================================
// DEPENDENCY VERIFICATION
// =============================================================================
// Verify that required cryptographic algorithms are available at runtime.
// This prevents cryptic errors if liboqs was compiled without required algorithms.
// =============================================================================
void verify_dependencies() {
    // Check libsodium
    if (sodium_init() < 0) {
        throw runtime_error("FATAL: libsodium initialization failed. Ensure libsodium is properly installed.");
    }
    
    // Check required OQS algorithms
    OQS_init();
    
    if (!OQS_KEM_alg_is_enabled("ML-KEM-768")) {
        throw runtime_error("FATAL: ML-KEM-768 (Kyber) not available. Rebuild liboqs with ML-KEM support.");
    }
    
    if (!OQS_SIG_alg_is_enabled("ML-DSA-65")) {
        throw runtime_error("FATAL: ML-DSA-65 (Dilithium) not available. Rebuild liboqs with ML-DSA support.");
    }
    
    // Verify we can actually create the algorithm instances
    OqsKemPtr kem_test(OQS_KEM_new("ML-KEM-768"));
    if (!kem_test) {
        throw runtime_error("FATAL: Cannot instantiate ML-KEM-768");
    }
    
    OqsSigPtr sig_test(OQS_SIG_new("ML-DSA-65"));
    if (!sig_test) {
        throw runtime_error("FATAL: Cannot instantiate ML-DSA-65");
    }
}

int main(int argc, char* argv[]) {
    try {
        prevent_debugger_attach();
        #ifndef _WIN32
        if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
            cerr << "Warning: Could not lock entire process in RAM (Swap risk). Run as root for max security." << endl;
        }
        #endif
        disable_core_dumps();
        clean_stale_artifacts();
        verify_dependencies();  // Check crypto libraries are available
        if (argc < 2 || (argc == 2 && (string(argv[1]) == "-h" || string(argv[1]) == "--help"))) {
            print_help();
            return 0;
        }
        vector<string> args(argv + 1, argv + argc);
        string cmd = "";
        for (size_t i = 0; i < args.size(); ++i) {
            if (args[i] == "--keydir") {
                if (i + 1 < args.size()) KEY_DIR = args[++i] + "/";
                else throw runtime_error("Missing value for --keydir");
            } 
            else if (args[i] == "--bind") {
                if (i + 1 < args.size()) {
                    string b = args[++i];
                    if (b == "tpm") CURRENT_BINDING = BindingType::TPM;
                    else CURRENT_BINDING = BindingType::Disk;
                } else throw runtime_error("Missing value for --bind");
            } 
            else if (args[i] == "--tpm-slot") {
                if (i + 1 < args.size()) {
                    try {
                        int slot = stoi(args[++i]);
                        if (slot < 0 || slot > 255) {
                            throw runtime_error("TPM slot must be 0-255");
                        }
                        TPM_SLOT = static_cast<uint8_t>(slot);
                    } catch (const invalid_argument&) {
                        throw runtime_error("Invalid TPM slot number (must be 0-255)");
                    } catch (const out_of_range&) {
                        throw runtime_error("TPM slot number out of range (must be 0-255)");
                    }
                } else throw runtime_error("Missing value for --tpm-slot");
            } 
            else if (args[i] == "--rate-limit") {
                GLOBAL_RATE_LIMIT = true;
            } 
            else if (args[i] == "--argon-level") {
                if (i + 1 < args.size()) ARGON_LEVEL = args[++i];
                else throw runtime_error("Missing value for --argon-level");
            } 
            else if (args[i] == "--no-progress") {
                NO_PROGRESS = true;
            } 
            else if (args[i] == "--stream-size") {
                if (i + 1 < args.size()) {
                    try { STREAM_SIZE_HINT = stoull(args[++i]); } catch(...) {}
                }
            } 
            else if (cmd.empty()) {
                cmd = args[i];
            }
        }
        if (cmd.empty()) throw runtime_error("No command specified");
        vector<string> clean_args;
        for (size_t i = 0; i < args.size(); ++i) {
            if (args[i].rfind("--", 0) == 0) {
                if (args[i] == "--rate-limit" || args[i] == "--no-progress") continue;
                if (args[i] == cmd) continue;
                i++;
            } else {
                clean_args.push_back(args[i]);
            }
        }
        if (cmd == "--gen") {
            if (clean_args.empty()) throw runtime_error("Missing identity name");
            generate_identity_v4(clean_args[0]);
        } 
        else if (cmd == "--encrypt-armor") {
            if (clean_args.empty()) throw runtime_error("Usage: --encrypt-armor <identity_file>");
            #ifdef _WIN32
                _setmode(_fileno(stdin), _O_BINARY);
            #endif
            encrypt_to_armor(clean_args[0]);
        }
        else if (cmd == "--decrypt-armor") {
            if (clean_args.empty()) throw runtime_error("Usage: --decrypt-armor <identity_name>");
            decrypt_from_armor(clean_args[0]);
        }
        else if (cmd == "--export-pubkey") {
            if (clean_args.empty()) throw runtime_error("Usage: --export-pubkey <identity_name>");
            export_pubkey_armor(clean_args[0]);
        }
        else if (cmd == "--import-pubkey") {
            if (clean_args.empty()) throw runtime_error("Usage: --import-pubkey <name>");
            import_pubkey_armor(clean_args[0]);
        }
        else {
            throw runtime_error("Unknown command: " + cmd);
        }
    } catch (const exception& e) {
        enforce_rate_limit();
        cerr << "CRITICAL ERROR: " << e.what() << endl;
        return 1;
    }
    return 0;
}