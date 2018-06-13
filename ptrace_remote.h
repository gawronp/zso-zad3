#ifndef PTRACE_REMOTE_H
#define PTRACE_REMOTE_H

#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define PTRACE_REMOTE_MMAP	50
#define PTRACE_REMOTE_MUNMAP	51
#define PTRACE_REMOTE_MREMAP	52
#define PTRACE_REMOTE_MPROTECT	53
#define PTRACE_DUP_TO_REMOTE	54
#define PTRACE_DUP2_TO_REMOTE	55
#define PTRACE_DUP_FROM_REMOTE	56
#define PTRACE_REMOTE_CLOSE	57

struct ptrace_remote_mmap {
	uint64_t addr;
	uint64_t length;
	uint32_t prot;
	uint32_t flags;
	uint32_t fd;
	uint32_t _pad;
	uint64_t offset;
};

struct ptrace_remote_munmap {
	uint64_t addr;
	uint64_t length;
};

struct ptrace_remote_mremap {
	uint64_t old_addr;
	uint64_t old_size;
	uint64_t new_addr;
	uint64_t new_size;
	uint32_t flags;
	uint32_t _pad;
};

struct ptrace_remote_mprotect {
	uint64_t addr;
	uint64_t length;
	uint32_t prot;
	uint32_t _pad;
};

struct ptrace_dup_to_remote {
	uint32_t local_fd;
	uint32_t flags;
};

struct ptrace_dup2_to_remote {
	uint32_t local_fd;
	uint32_t remote_fd;
	uint32_t flags;
};

struct ptrace_dup_from_remote {
	uint32_t remote_fd;
	uint32_t flags;
};

struct ptrace_remote_close {
	uint32_t remote_fd;
};

#ifdef __KERNEL__
struct ptrace_remote_task {
    uint8_t request;
    int retval;
    void (* defered_fun)(void);
    void *data_from_user;
    struct file *file_ptr;
    struct completion remote_completion;
    long child_orig_state;
};

extern int ptrace_request_remote(struct task_struct *child, long request,
			unsigned long addr, unsigned long data);
#endif

#endif
