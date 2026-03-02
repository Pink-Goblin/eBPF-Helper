#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

int bpf_iter_task_new(struct bpf_iter_task *it,
		struct task_struct *task__nullable, unsigned int flags) __ksym;
struct task_struct *bpf_iter_task_next(struct bpf_iter_task *it) __ksym;
void bpf_iter_task_destroy(struct bpf_iter_task *it) __ksym;
#ifndef NO_RCU_KFUNCS
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
#endif
 
SEC("syscall")
s32 BPF_PROG(tst) {
	struct task_struct *ts = (struct task_struct*)bpf_get_current_task(),
										 *p;
	struct file **f;
	//f = BPF_CORE_READ(ts, files, fdt, fd);
	bpf_core_read(&f, sizeof(f), &ts->files->fdt->fd);

	return 0;
}


char _license[] SEC("license") = "Dual BSD/GPL";
