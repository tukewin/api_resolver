#ifndef APIMANAGER_H
#define APIMANAGER_H

#include <Windows.h>
#include <cstdint>
#include <algorithm>

#define FNV1A_PRIME 0x01000193
#define FNV1A_BASIS 0x811c9dc5

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

constexpr uint32_t fnv1a_hash(const char *str, uint32_t hash = FNV1A_BASIS) {
    return *str ? fnv1a_hash(str + 1, (hash ^ *str) * FNV1A_PRIME) : hash;
}

static inline PPEB get_peb() {
#ifdef _WIN64
    return (PPEB) __readgsqword(0x60); // x64
#else
    return (PPEB)__readfsdword(0x30);  // x86
#endif
}

static inline void *find_export(HMODULE module, uint32_t hash);

//get module base by name hash
static inline HMODULE get_module(uint32_t hash) {
    PPEB peb = get_peb();
    if (!peb || !peb->Ldr) return nullptr;

    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    while (current != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        // convert module name to ascii for hashing
        if (entry->BaseDllName.Length > 0 && entry->BaseDllName.Buffer) {
            // create a local buffer for our ascii conversion
            char module_name[256] = {0};

            // we do this to avoid WideCharToMultiByte call
            int max_chars = std::min(entry->BaseDllName.Length / 2, 255);
            for (int i = 0; i < max_chars; i++) {
                module_name[i] = (char) tolower(entry->BaseDllName.Buffer[i]);
            }

            // woohoo! we won!
            if (fnv1a_hash(module_name) == hash) {
                return (HMODULE) entry->DllBase;
            }
        }

        current = current->Flink;
    }

    return nullptr;
}

// helper to find a forwarded module directly from PEB
static inline HMODULE get_module_by_name(const char *name) {
    char name_lower[256] = {0};
    size_t name_len = strlen(name);
    for (size_t i = 0; i < name_len && i < 255; i++) {
        name_lower[i] = (char) tolower(name[i]);
    }

    uint32_t name_hash = fnv1a_hash(name_lower);
    return get_module(name_hash);
}

// process a forwarded export
static __forceinline void *process_forwarded_export(const char *forward_str) {
    // copy the forwarded string
    char forward[256] = {0};
    size_t forward_len = strlen(forward_str);
    for (size_t i = 0; i < forward_len && i < 255; i++) {
        forward[i] = forward_str[i];
    }

    // split at the dot
    char *dot = nullptr;
    for (size_t i = 0; i < forward_len; i++) {
        if (forward[i] == '.') {
            dot = &forward[i];
            break;
        }
    }

    if (!dot) return nullptr;

    *dot = '\0'; // split
    char *forward_dll = forward;
    char *forward_fn = dot + 1;

    // append ".dll" if not present
    char forward_dll_full[256] = {0};
    if (strstr(forward_dll, ".dll") == nullptr) {
        // simple string concatenation without sprintf
        strcpy(forward_dll_full, forward_dll);
        strcat(forward_dll_full, ".dll");
    } else {
        strcpy(forward_dll_full, forward_dll);
    }

    HMODULE forward_mod = get_module_by_name(forward_dll_full);
    if (!forward_mod) return nullptr;

    uint32_t forward_fn_hash = fnv1a_hash(forward_fn);

    return find_export(forward_mod, forward_fn_hash);
}

static inline void *find_export(HMODULE module, uint32_t hash) {
    if (!module) return nullptr;

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER) module;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS) ((BYTE *) module + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    IMAGE_DATA_DIRECTORY export_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_dir.Size == 0) return nullptr;

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY) ((BYTE *) module + export_dir.VirtualAddress);
    DWORD *names = (DWORD *) ((BYTE *) module + exports->AddressOfNames);
    WORD *ordinals = (WORD *) ((BYTE *) module + exports->AddressOfNameOrdinals);
    DWORD *functions = (DWORD *) ((BYTE *) module + exports->AddressOfFunctions);

    // go through all exported functions
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char *name = (char *) ((BYTE *) module + names[i]);

        if (fnv1a_hash(name) == hash) {
            WORD ordinal = ordinals[i];
            DWORD function_rva = functions[ordinal];

            if (function_rva >= export_dir.VirtualAddress &&
                function_rva < export_dir.VirtualAddress + export_dir.Size) {
                char *forward = (char *) module + function_rva;
                return process_forwarded_export(forward);
            }

            // regular export
            return (BYTE *) module + function_rva;
        }
    }

    return nullptr;
}

__forceinline void *resolve_api(uint32_t hash) {
    const uint32_t common_modules[] = {
        fnv1a_hash("ntdll.dll"),
        fnv1a_hash("kernel32.dll"),
        fnv1a_hash("user32.dll"),
        fnv1a_hash("advapi32.dll"),
        fnv1a_hash("gdi32.dll"),
        fnv1a_hash("shell32.dll"),
        fnv1a_hash("ole32.dll")
    };

    // check common modules first
    for (uint32_t module_hash: common_modules) {
        HMODULE module = get_module(module_hash);
        if (!module) continue;

        void *func_addr = find_export(module, hash);
        if (func_addr) return func_addr;
    }

    // if not found in common modules, search all loaded modules
    PPEB peb = get_peb();
    if (!peb || !peb->Ldr) return nullptr;

    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    while (current != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        // skip what we already checked
        bool is_common = false;
        for (uint32_t module_hash: common_modules) {
            if (get_module(module_hash) == entry->DllBase) {
                is_common = true;
                break;
            }
        }

        if (!is_common) {
            void *func_addr = find_export((HMODULE) entry->DllBase, hash);
            if (func_addr) return func_addr;
        }

        current = current->Flink;
    }

    return nullptr;
}

// to cache apis globally
template<uint32_t hash>
__forceinline void *get_api_address() {
    static void *addr = nullptr;
    if (!addr) {
        addr = resolve_api(hash);
    }
    return addr;
}

//helper
#define API_HASH(name) fnv1a_hash(#name)

#define API(name) \
    ((decltype(&name))get_api_address<API_HASH(name)>())

// for address getting
#define API_ADDR(name) \
    (get_api_address<API_HASH(name)>())

// for native APIs that might not be defined in headers
#define API_NT(ret, name, ...) \
    ((ret(WINAPI*)(__VA_ARGS__))get_api_address<API_HASH(name)>())

#endif
