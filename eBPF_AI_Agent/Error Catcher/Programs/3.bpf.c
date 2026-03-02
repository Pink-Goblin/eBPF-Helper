struct {
    __uint (type, BPF_MAP_TYPE_HASH);
    __uint (key_size, sizeof(u8[16]));
    __uint (value_size, sizeof(u32));
    __uint (max_entries, 256);
} map SEC(".maps");

// ...

u32 *counter = bpf_map_lookup_elem(&map, &comm);
*(counter) = (*(counter)) + 1;