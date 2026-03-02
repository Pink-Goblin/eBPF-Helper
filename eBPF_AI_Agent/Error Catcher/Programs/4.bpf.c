#include <uapi/linux/ptrace.h>
#include <linux/irq.h>
#include <linux/spinlock.h>

struct event {
    int direction;
    u64 lock;
};

BPF_PERF_OUTPUT(events);

int kprobe___raw_spin_lock(struct pt_regs *ctx, u64 lock)
{
    struct event event = {
        .direction = 0,
        .lock = lock,
    };
    events.perf_submit(ctx, &event, sizeof event);
    bpf_trace_printk("lock %ld\n", lock);
    return 0;
}