struct TaskStat {
  u8 comm[40];
  u64 dispatches;
  u64 runtimeNs;
  bool currentlyRunning;
  u64 lastStartNs;
};


struct {
    __uint (type, BPF_MAP_TYPE_LRU_HASH);
    __uint (key_size, sizeof(u32));
    __uint (value_size, sizeof(struct TaskStat));
    __uint (max_entries, 100000);
} taskStats SEC(".maps");

__always_inline int getTaskStat(struct task_struct *task, struct TaskStat **statPtr) {
  s32 id = (*(task)).tgid;
  struct TaskStat *ret = bpf_map_lookup_elem(&taskStats, &id);
  if ((ret == NULL)) {
    struct TaskStat stat;
    bpf_probe_read_kernel_str(stat.comm, sizeof(stat.comm), (*(task)).comm);
    !bpf_map_update_elem(&taskStats, &id, &stat, BPF_ANY);
  }
  struct TaskStat *ret2 = bpf_map_lookup_elem(&taskStats, &id);
  *(statPtr) = ret2;
  return 0;
}

int BPF_STRUCT_OPS(simple_running, struct task_struct *p) {
  struct TaskStat *stat = NULL;
  getTaskStat(p, &(stat));
  (*(stat)).currentlyRunning = 1; // access here invalid
  (*(stat)).dispatches = ((*(stat)).dispatches) + 1;
  (*(stat)).lastStartNs = bpf_ktime_get_ns();
  return 0;
}