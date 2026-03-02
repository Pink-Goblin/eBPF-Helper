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

#define MAX_PATH_SIZE 128 // PATH_MAX from <linux/limits.h>
#define LIMIT_PATH_SIZE(x) ((x) & (MAX_PATH_SIZE - 1))
#define MAX_PATH_COMPONENTS 64
#define MAX_PERCPU_ARRAY_SIZE (1 << 15)
#define HALF_PERCPU_ARRAY_SIZE (MAX_PERCPU_ARRAY_SIZE >> 1)
#define LIMIT_PERCPU_ARRAY_SIZE(x) ((x) & (MAX_PERCPU_ARRAY_SIZE - 1))
#define LIMIT_HALF_PERCPU_ARRAY_SIZE(x) ((x) & (HALF_PERCPU_ARRAY_SIZE - 1))
#define statfunc static __always_inline
struct buffer {
	u8 data[MAX_PERCPU_ARRAY_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct buffer);
	__uint(max_entries, 1);
} heaps_map SEC(".maps");

statfunc struct buffer *get_buffer() {
	u32 zero = 0;
	return (struct buffer *)bpf_map_lookup_elem(&heaps_map, &zero);
}
/* functions */
statfunc s32 get_file_from_fd_ts(struct task_struct* ts, s32 fd, struct file **f);
statfunc s32 get_path_from_file(struct file *file, struct path **p);
statfunc s64 get_path_str_from_path(u_char **path_str,struct path *path, struct buffer *out_buf);
 
SEC("syscall")
s32 BPF_PROG(tst) {
	struct task_struct *ts = (struct task_struct*)bpf_get_current_task();
	struct file *f;
	struct path *p;
	s32 err = 0;
	err = get_file_from_fd_ts(ts, 1, &f);
	if (err) return -1;
	err = get_path_from_file(f, &p);
	if (err) return -1;
	struct buffer *string_buf = get_buffer();
	if (!string_buf) return -1;
	u_char *file_path = NULL;
	get_path_str_from_path(&file_path, p, string_buf);

	return 0;
}

statfunc s32 get_file_from_fd_ts(struct task_struct* ts, s32 fd, struct file **f) {
    struct file **files;

		if (!ts) return -1;

    files = BPF_CORE_READ(ts, files, fdt, fd);
    if (files == NULL) return -1;

    bpf_core_read(f, sizeof(void *), &files[fd]);
    if (*f == NULL) return -1;

    return 0;
}

statfunc s32 get_path_from_file(struct file *file, struct path **p)
{
	if (!file) return -1;
	bpf_probe_read(p, sizeof(p), (const void*)&file->f_path);
	if (!(*p)) return -1;
	return 0;
}


statfunc s64 get_path_str_from_path(u_char **path_str, struct path *path,
																		struct buffer *out_buf)
{
	long ret;
	struct dentry *dentry, *dentry_parent, *dentry_mnt;
	struct vfsmount *vfsmnt;
	struct mount *mnt, *mnt_parent;
	const u_char *name;
	size_t name_len;

	dentry = BPF_CORE_READ(path, dentry);
	//if (!dentry) return -1;
	vfsmnt = BPF_CORE_READ(path, mnt);
	//if (!vfsmnt) return -1;
	mnt = container_of(vfsmnt, struct mount, mnt);
	//if (!mnt) return -1;
	mnt_parent = BPF_CORE_READ(mnt, mnt_parent);
	//if (!mnt_parent) return -1;

	size_t buf_off = HALF_PERCPU_ARRAY_SIZE;

	for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
		dentry_mnt = BPF_CORE_READ(vfsmnt, mnt_root);
		dentry_parent = BPF_CORE_READ(dentry, d_parent);

		if (dentry == dentry_mnt || dentry == dentry_parent) {
			if (dentry != dentry_mnt) {
				// We reached root, but not mount root - escaped?
				break;
			}
			if (mnt != mnt_parent) {
				// We reached root, but not global root - continue with mount point path
				dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
				mnt_parent = BPF_CORE_READ(mnt, mnt_parent);
				vfsmnt = __builtin_preserve_access_index(&mnt->mnt);
				continue;
			}
			// Global root - path fully parsed
			break;
		}
		// Add this dentry name to path
		name_len = LIMIT_PATH_SIZE(BPF_CORE_READ(dentry, d_name.len));
		name = BPF_CORE_READ(dentry, d_name.name);

		name_len = name_len + 1; // add slash
		// Is string buffer big enough for dentry name?
		if (name_len > buf_off) { break; }
		volatile size_t new_buff_offset = buf_off - name_len; // satisfy verifier
		ret = bpf_probe_read_kernel_str(
			&(out_buf->data[LIMIT_HALF_PERCPU_ARRAY_SIZE(new_buff_offset) // satisfy verifier
			]), name_len,name);
		if (ret < 0) { return ret; }
		if (ret > 1) {
			buf_off -= 1;                                    // remove null byte termination with slash sign
			buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off); // satisfy verifier
			out_buf->data[buf_off] = '/';
			buf_off -= ret - 1;
			buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off); // satisfy verifier
		} else {
			// If sz is 0 or 1 we have an error (path can't be null nor an empty string)
			break;
		}
		dentry = dentry_parent;
	}
	// Is string buffer big enough for slash?
	if (buf_off != 0) {
		// Add leading slash
		buf_off -= 1;
		buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off); // satisfy verifier
		out_buf->data[buf_off] = '/';
	}

	// Null terminate the path string
	out_buf->data[HALF_PERCPU_ARRAY_SIZE - 1] = 0;
	*path_str = &out_buf->data[buf_off];
	return HALF_PERCPU_ARRAY_SIZE - buf_off - 1;
}

char _license[] SEC("license") = "Dual BSD/GPL";
