#include <windows.h>
#include <cstdio>
#include <cstdlib>

static void HexDump(const BYTE* data, size_t size) {
    for (size_t i = 0; i < size; i += 16) {
        printf("  %04zx: ", i);
        for (size_t j = 0; j < 16 && i + j < size; j++)
            printf("%02X ", data[i + j]);
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < size; j++) {
            BYTE c = data[i + j];
            putchar(c >= 32 && c < 127 ? c : '.');
        }
        printf("|\n");
    }
}

int main() {
    printf("=== Subkeys of System Resources ===\n");
    {
        HKEY hkSR;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                "HARDWARE\\RESOURCEMAP\\System Resources",
                0, KEY_READ, &hkSR) == ERROR_SUCCESS) {
            DWORD idx2 = 0;
            char  skName[256];
            DWORD skLen;
            for (;;) {
                skLen = sizeof(skName);
                if (RegEnumKeyExA(hkSR, idx2, skName, &skLen,
                                  nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                    break;
                printf("  [%lu] \"%s\"\n", idx2, skName);
                idx2++;
            }
            RegCloseKey(hkSR);
        }
    }

    HKEY hKey;
    LSTATUS st = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
        0, KEY_READ, &hKey);
    if (st != ERROR_SUCCESS) {
        printf("RegOpenKeyEx failed: %ld\n", st);
        return 1;
    }

    printf("\n=== Subkeys under Physical Memory ===\n");
    {
        DWORD idx2 = 0;
        char  skName[256];
        DWORD skLen;
        for (;;) {
            skLen = sizeof(skName);
            if (RegEnumKeyExA(hKey, idx2, skName, &skLen,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                break;
            printf("  [%lu] \"%s\"\n", idx2, skName);
            idx2++;
        }
    }

    printf("\n=== Values in Physical Memory ===\n");
    DWORD idx = 0;
    for (;;) {
        char  valName[256];
        DWORD valNameLen = sizeof(valName);
        DWORD valType, valSize;
        st = RegEnumValueA(hKey, idx, valName, &valNameLen, nullptr,
                           &valType, nullptr, &valSize);
        if (st != ERROR_SUCCESS) break;

        BYTE* vbuf = (BYTE*)malloc(valSize);
        if (!vbuf) break;
        RegEnumValueA(hKey, idx, valName, &valNameLen, nullptr,
                      &valType, vbuf, &valSize);

        printf("\n[%lu] \"%s\"  type=%lu  size=%lu\n", idx, valName, valType, valSize);
        if (valType == REG_RESOURCE_LIST) {
            HexDump(vbuf, valSize < 512 ? valSize : 512);

            printf("\n  --- Parse ---\n");
            size_t pos = 0;
            if (pos + 4 > valSize) { free(vbuf); idx++; continue; }
            ULONG count = *(ULONG*)(vbuf + pos); pos += 4;
            printf("  FullDescriptors: %lu\n", count);

            for (ULONG i = 0; i < count; i++) {
                if (pos + 8 > valSize) break;
                printf("  [FD %lu] InterfaceType=%lu BusNumber=%lu\n", i,
                       *(ULONG*)(vbuf + pos), *(ULONG*)(vbuf + pos + 4));
                pos += 8;

                if (pos + 8 > valSize) break;
                ULONG pCount = *(ULONG*)(vbuf + pos + 4);
                printf("  [FD %lu] PartialDescriptors: %lu\n", i, pCount);
                pos += 8;

                for (ULONG j = 0; j < pCount; j++) {
                    if (pos + 20 > valSize) { printf("    trunc\n"); break; }
                    BYTE rt = vbuf[pos];
                    printf("    [%lu] Type=%u  raw: ", j, rt);
                    for (int b = 0; b < 20; b++) printf("%02X ", vbuf[pos+b]);
                    printf("\n");
                    if (rt == 3) {
                        ULONG64 s = *(ULONG64*)(vbuf + pos + 4);
                        ULONG   l = *(ULONG*)(vbuf + pos + 12);
                        printf("         MEM: 0x%llX size=0x%lX (%lu MB)\n",
                               s, l, l >> 20);
                    }
                    pos += 20;
                }
            }
        } else {
            HexDump(vbuf, valSize < 256 ? valSize : 256);
        }
        free(vbuf);
        idx++;
    }

    RegCloseKey(hKey);
    return 0;
}
