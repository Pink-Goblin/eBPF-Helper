#include <bcc/proto.h>

struct automaton_s {
    int initial_state;
    int function[4][4];
};
typedef struct automaton_s automaton_t;

BPF_STACK(automaton, automaton_t, 1);
BPF_TABLE_PINNED("hash", int, int, state_store, 1, "/sys/fs/bpf/state");

int trace_connect_v4_return(struct pt_regs *ctx)
{
    int key = 0, init_val = 0;
    int *curr_state;
    curr_state = state_store.lookup_or_try_init(&key, &init_val);
    if (!curr_state) {
        bpf_trace_printk("State store is full");
        return -1;
    }
    bpf_trace_printk("curr state: %d", *curr_state);

    automaton_t aut;
    if (automaton.peek(&aut) < 0) {
        bpf_trace_printk("automaton init");
        aut = (automaton_t) {
            .initial_state = 0,
            .function = {
                { 1, -1, -1, -1 },
                { -1, 2, -1, -1 },
                { -1, -1, 3, -1 },
                { -1, -1, -1, 0 }
            }
        };
        automaton.push(&aut, BPF_EXIST);
    }

    int next = aut.function[*curr_state][0];
    bpf_trace_printk("next val: %d", next);
    state_store.update(&key, &next);
    return 0;
}