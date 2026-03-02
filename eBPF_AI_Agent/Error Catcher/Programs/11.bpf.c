__u16 target_size = 1 * count_req;
__u8 *payload = (char *)(udp + 1);
{
    // check if we need to change the payload size to match our reply
    __u16 payload_len = (__u64)data_end - (__u64)payload;
    short delta = target_size - payload_len;
    if (delta != 0) {
        if (bpf_xdp_adjust_tail(xdp, delta) != 0) {
            bpf_printk(TAG"failed to resize the packet (%d)", delta);
            return XDP_PASS;
        }
        data = (void *)(__u64)xdp->data;
        data_end = (void *)(__u64)xdp->data_end;
        payload = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
    }
}

for (int i = 0; i < count_req; i++) {          // here
    if ((void *)(payload+1) > data_end) {
        bpf_printk(TAG"not enough space after adjusting the packet size");
        return XDP_DROP;
    }
    *payload = scratch->vals[i];
    payload++;
}