struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(char[TASK_COMM_LEN]));
    __uint(value_size, sizeof(struct job_info));
} predicted_times SEC(".maps");

// The following code is within a BPF implemented callback as a part of a sched-ext scheduler, the enqueue callback:
void BPF_STRUCT_OPS(sjf_enqueue, struct task_struct *p, u64 enq_flags) {
    // Check to see if the model has a prediction for this task
    struct job_info * ji = bpf_map_lookup_elem(&predicted_times, p->comm);