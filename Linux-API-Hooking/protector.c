#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
/*
 * Logs intercepted system calls and security events to a centralized log file.
 * Appends a precise timestamp to each entry for forensic analysis.
 * input: message A null-terminated string containing the formatted event details.
 * output: none.
 */
void log_event(const char* message)
{
    FILE *f = fopen("/tmp/detector.log", "a");
    if (!f)
        return;
    time_t now = time(NULL);
    char *date = ctime(&now);
    date[strlen(date) - 1] = '\0'; 
    fprintf(f, "[%s] %s\n", date, message);
    fclose(f);
}
// --- 1. Hook for unlink ---
typedef int (*unlink_t)(const char* pathName);
/*
 * Intercepts the 'unlink' system call to monitor file deletion attempts.
 * Acts as a passive detection mechanism to identify potential anti-forensics behavior.
 * The function logs the attempt and then forwards the execution to the original libc function.
 * input: pathName A pointer to a null-terminated string containing the path of the file to be deleted.
 * output: On success, returns 0 (from the original function). On error, returns -1.
 */
int unlink(const char* pathName)
{
    char msg[256] = {'\0'};
    sprintf(msg, "Deletion attempt: %s by PID %d", pathName, getpid());
    log_event(msg);
    printf("%s\n", msg);
    unlink_t original = (unlink_t)dlsym(RTLD_NEXT, "unlink");
    return original(pathName);
}

// --- 2. Hook for mmap (Blocking RWX) ---
typedef void* (*mmap_t)(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
/**
 * Intercepts the 'mmap' system call to monitor memory allocation requests.
 * Actively blocks memory requests that ask for both Write and Execute (RWX) permissions
 * simultaneously, mitigating shellcode injection and memory-based payloads.
 * input: addr The starting address for the new memory mapping (usually NULL).
 *        length The length of the mapping in bytes.
 *         prot  The desired memory protection flags (e.g., PROT_READ, PROT_WRITE, PROT_EXEC).
 *         flags Determines the visibility and type of the mapping.
 *         fd The file descriptor (if mapped from a file).
 *         offset The offset within the file.
 * output: Returns a pointer to the allocated memory on success. Returns MAP_FAILED if the 
 *         RWX request is blocked by the security engine or if the original allocation fails.
 */
void* mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    if ((prot & PROT_WRITE) && (prot & PROT_EXEC))
    {
        char msg[256] = {'\0'};
        sprintf(msg, "BLOCKED RWX Memory request by PID %d", getpid());
        log_event(msg);
        printf("%s\n", msg);
        return MAP_FAILED;
    }
    mmap_t original = (mmap_t)dlsym(RTLD_NEXT, "mmap");
    return original(addr, length, prot, flags, fd, offset);
}

// --- 3. Hook for execve (Blocking Shells) ---
typedef int (*execve_t)(const char* path, char* const argv[], char* const envp[]);
/**
 * Intercepts the 'execve' system call to monitor process execution.
 * Actively blocks attempts to execute interactive shells ("/bin/sh", "bash") 
 * from within an existing process, preventing Reverse Shells and post-exploitation.
 * input: path A pointer to a null-terminated string containing the path of the executable.
 *        argv An array of argument strings passed to the new program.
 *        envp An array of environment variable strings.
 * output: Does not return on success (the calling process is replaced). 
 * Returns -1 if the execution is blocked by the security engine or if the original call fails.
 */
int execve(const char *path, char *const argv[], char *const envp[])
{
    if (strstr(path, "sh") || strstr(path, "bash"))
    {
        char msg[256] = {'\0'};
        sprintf(msg, "BLOCKED Reverse Shell attempt (%s) by PID %d", path, getpid());
        log_event(msg);
        printf("%s\n", msg);
        return -1;
    }
    execve_t original = (execve_t)dlsym(RTLD_NEXT, "execve");
    return original(path, argv, envp);
}

