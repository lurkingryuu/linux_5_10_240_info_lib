// SPDX-License-Identifier: GPL-2.0

#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/pid_namespace.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
#include <linux/string.h>
#include <../kernel/sched/sched.h>

#define INFO_DATA_BUF_SZ 512


struct pid_info_data {
	pid_t pid;
	pid_t ppid;
	long state;
	int static_prio;
	unsigned int children_count;
	unsigned int siblings_count;
};

static inline unsigned int count_children(const struct task_struct *task)
{
	unsigned int count = 0;
	struct list_head *child;

	list_for_each (child, &task->children)
		count++;

	return count;
}

static inline unsigned int count_siblings(const struct task_struct *task)
{
	const struct task_struct *parent = rcu_dereference(task->real_parent);
	unsigned int count = 0;
	struct list_head *sibling;

	if (!parent)
		return 0;

	list_for_each (sibling, &task->sibling)
		count++;
	return count;
}

SYSCALL_DEFINE2(get_info_for_pid, pid_t, pid, char __user *, buf)
{
	struct task_struct *task;
	struct pid_info_data pid_info_data;
	char *kbuf;

	if (!buf)
		return -EFAULT;

	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (!task) {
		rcu_read_unlock();
		return -ESRCH;
	}

	kbuf = kzalloc(INFO_DATA_BUF_SZ, GFP_KERNEL);
	if (!kbuf) {
		kfree(kbuf);
		rcu_read_unlock();
		return -ENOMEM;
	}

	pid_info_data.pid = pid;
	pid_info_data.ppid = task_ppid_nr_ns(task, task_active_pid_ns(current));
	pid_info_data.state = task->state;
	pid_info_data.static_prio = task->static_prio;
	pid_info_data.children_count = count_children(task);
	pid_info_data.siblings_count = count_siblings(task);

	rcu_read_unlock();

	if (scnprintf(kbuf, INFO_DATA_BUF_SZ, "%d %d %ld %d %u %u", pid_info_data.pid, pid_info_data.ppid, pid_info_data.state, pid_info_data.static_prio, pid_info_data.children_count, pid_info_data.siblings_count) < 0) {
		kfree(kbuf);
		rcu_read_unlock();
		return -ENOMEM;
	}

	if (copy_to_user(buf, kbuf, INFO_DATA_BUF_SZ)) {
		kfree(kbuf);
		rcu_read_unlock();
		return -EFAULT;
	}

	kfree(kbuf);
	return 0;
}


/* External symbols in fair/rt sched classes */
extern const struct sched_class fair_sched_class;
extern const struct sched_class rt_sched_class;

/* Provided by fair scheduler */
extern struct sched_entity * __pick_first_entity(struct cfs_rq *cfs_rq);
extern unsigned int sysctl_sched_latency;  /* ms */

SYSCALL_DEFINE1(get_info, char __user *, ubuf)
{
    struct task_struct *p;
    char *kbuf;
    int len = 0;

    if (!ubuf) return -EFAULT;

    /* 1) Print all PIDs at the moment of the call */
    rcu_read_lock();
    for_each_process(p) {
        printk(KERN_INFO "[get_info] pid=%d comm=%s\n",
               task_pid_nr(p), p->comm);
    }
    rcu_read_unlock();

    /* 2) Aggregate stats */
    int total = 0, running = 0, interruptible = 0, uninterruptible = 0;
    int n_rt = 0, n_fair = 0;

    rcu_read_lock();
    for_each_process(p) {
        total++;

        if (READ_ONCE(p->state) == TASK_RUNNING)
            running++;
        else if (READ_ONCE(p->state) == TASK_INTERRUPTIBLE)
            interruptible++;
        else if (READ_ONCE(p->state) == TASK_UNINTERRUPTIBLE)
            uninterruptible++;

        if (p->sched_class == &rt_sched_class) n_rt++;
        else if (p->sched_class == &fair_sched_class) n_fair++;
    }

    /* 3) CFS runqueue for the rq where current task is enqueued */
    {
        struct rq *rq = task_rq_lock(current, NULL);      /* rq lock pairs with unlock below */
        struct cfs_rq *cfs = &rq->cfs;                    /* root cfs_rq */
        int cfs_nr = cfs->nr_running;

        /* min-vruntime entity & pid */
        struct sched_entity *se_min = __pick_first_entity(cfs);
        pid_t pid_min = -1;
        unsigned long long min_vruntime_ns = (unsigned long long)cfs->min_vruntime; /* monotonic increasing */

        if (se_min) {
            struct task_struct *t = container_of(se_min, struct task_struct, se);
            pid_min = task_pid_nr(t);
        }

        /* total load on CFS runqueue — use cfs->load.weight as a proxy */
        unsigned long total_load_w = cfs->load.weight;

        unsigned int target_latency_ms = READ_ONCE(sysctl_sched_latency);

        task_rq_unlock(rq, current, NULL);

        /* 4) Emit buffer (space-separated, exact order requested) */
        kbuf = kmalloc(INFO_DATA_BUF_SZ, GFP_KERNEL);
        if (!kbuf) {
            rcu_read_unlock();
            return -ENOMEM;
        }

        len = scnprintf(kbuf, INFO_DATA_BUF_SZ,
            "%d %d %d %d %d %d %d %d %llu %lu %u\n",
            total, running, interruptible, uninterruptible,
            n_rt, n_fair, cfs_nr, pid_min, min_vruntime_ns,
            total_load_w, target_latency_ms);

        rcu_read_unlock();

        if (copy_to_user(ubuf, kbuf, len + 1)) {
            kfree(kbuf);
            return -EFAULT;
        }
        kfree(kbuf);
    }

    return 0;
}