unsigned int scx_bpf_nr_cpu_ids();

bool hasConstraints(struct task_struct *p) {
  u32 number = scx_bpf_nr_cpu_ids; // here
  s32 allowed = ((u32)(*(p)).nr_cpus_allowed);
  return (allowed >= number) && (allowed <= number);
}