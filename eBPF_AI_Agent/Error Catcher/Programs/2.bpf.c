@BPFMapDefinition(maxEntries = 256)
BPFHashMap<@Size(TASK_COMM_LEN) String, @Unsigned Integer> map;        

// ...

Ptr<@Unsigned Integer> counter = map.bpf_get(comm);
counter.set(counter.val() + 1);