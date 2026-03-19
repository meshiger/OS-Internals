\# OS Internals Research

\*\*Author:\*\* Meshi Gershon



Research into Operating System Internals, focusing on process memory manipulation, thread execution control, and system call interception.



\##  Windows: DLL Injection (OOP C++)

\* Virtual Memory Allocation (`VirtualAllocEx`).

\* Standard Injection (`CreateRemoteThread`).

\* APC Injection (`QueueUserAPC`).

\* Context Hijacking (`GetThreadContext`, modifying RIP/RCX registers).



\##  Linux: API Hooking (C)

\* `LD\_PRELOAD` dynamic linker manipulation.

\* File System Hooking: Auditing `unlink` for anti-forensics.

\* Memory Protection: Blocking RWX `mmap` requests (Anti-Shellcode IPS).

\* Execution Hooking: Blocking Reverse Shells via `execve`.


