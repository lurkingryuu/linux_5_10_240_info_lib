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

/* Safety check to prevent early boot crashes */
static inline bool system_is_ready(void)
{
	return likely(system_state >= SYSTEM_RUNNING);
}


struct pid_info_data {
	pid_t pid;
	pid_t ppid;
	long state;
	int static_prio;
	unsigned int children_count;
	unsigned int siblings_count;
};

/*
Total number of processes in the process list
Number of processes in TASK
_
RUNNING state
Number of processes in TASK
_
INTERRUPTIBLE state
Number of processes in TASK
_
UNINTERRUPTIBLE state
Number of processes in rt class
Number of processes in fair class
Number of processes in CFS runqueue
PID of the process with min vruntime in the CFS runqueue
The corresponding min vruntime
Total load on the CFS runqueue
Current target latency (in ms)
*/
struct info_data {
	int total_processes;
	int running_processes;
	int interruptible_processes;
	int uninterruptible_processes;
	int rt_processes;
	int fair_processes;
	int cfs_processes;
	int min_vruntime_pid;
	int min_vruntime;
	int total_load_w;
	int target_latency_ms;
};

static inline unsigned int count_children(const struct task_struct *task)
{
	unsigned int count = 0;
	struct list_head *child;

	if (!task)
		return 0;

	/* Safely iterate through children list */
	list_for_each(child, &task->children) {
		if (child)
			count++;
	}

	return count;
}

static inline unsigned int count_siblings(const struct task_struct *task)
{
	const struct task_struct *parent;
	unsigned int count = 0;
	struct list_head *child;
	struct task_struct *child_task;

	if (!task)
		return 0;

	/* Get parent under RCU protection */
	parent = rcu_dereference(task->real_parent);
	if (!parent)
		return 0;

	/* Count all children of parent (siblings), excluding current task */
	list_for_each(child, &parent->children) {
		child_task = list_entry(child, struct task_struct, sibling);
		if (child_task && child_task != task)
			count++;
	}

	return count;
}

SYSCALL_DEFINE2(get_info_for_pid, pid_t, pid, char __user *, buf)
{
	struct task_struct *task;
	struct pid_info_data *pid_info_data;

	/* Safety check - don't run during early boot */
	if (!system_is_ready())
		return -EAGAIN;

	/* Validate parameters first */
	if (!buf)
		return -EFAULT;

	/* Allocate memory before acquiring any locks */
	pid_info_data = kzalloc(sizeof(struct pid_info_data), GFP_KERNEL);
	if (!pid_info_data)
		return -ENOMEM;

	/* Acquire RCU lock only for accessing task data */
	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (!task) {
		rcu_read_unlock();
		kfree(pid_info_data);
		return -ESRCH;
	}

	// kbuf = kzalloc(INFO_DATA_BUF_SZ, GFP_KERNEL);
	// if (!kbuf) {
	// 	kfree(kbuf);
	// 	rcu_read_unlock();
	// 	return -ENOMEM;
	// }

	/* Copy task data while holding RCU lock */
	pid_info_data->pid = pid;
	pid_info_data->ppid = task_ppid_nr_ns(task, task_active_pid_ns(current));
	pid_info_data->state = task->state;
	pid_info_data->static_prio = task->static_prio;
	pid_info_data->children_count = count_children(task);
	pid_info_data->siblings_count = count_siblings(task);

	/* Release RCU lock as soon as we're done with task data */
	rcu_read_unlock();

	// if (scnprintf(kbuf, INFO_DATA_BUF_SZ, "%d %d %ld %d %u %u", pid_info_data.pid, pid_info_data.ppid, pid_info_data.state, pid_info_data.static_prio, pid_info_data.children_count, pid_info_data.siblings_count) < 0) {
	// 	kfree(kbuf);
	// 	rcu_read_unlock();
	// 	return -ENOMEM;
	// }

	if (copy_to_user(buf, pid_info_data, sizeof(struct pid_info_data))) {
		kfree(pid_info_data);
		return -EFAULT;
	}

	kfree(pid_info_data);
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
    struct info_data *info_data;

    /* Safety check - don't run during early boot */
    if (!system_is_ready())
        return -EAGAIN;

    /* Validate parameters first */
    if (!ubuf)
        return -EFAULT;

    /* Allocate memory before acquiring any locks */
    info_data = kzalloc(sizeof(struct info_data), GFP_KERNEL);
    if (!info_data)
        return -ENOMEM;

    /* 1) Print all PIDs and aggregate stats in a single RCU section */
    rcu_read_lock();
    for_each_process(p) {
        if (unlikely(!p)) {
            printk(KERN_WARNING "[get_info] p is NULL\n");
            continue;
        }
        
        /* Print PID info */
        printk(KERN_INFO "[get_info] pid=%d comm=%s\n",
               task_pid_nr(p), p->comm);
        
        /* Aggregate stats */
        info_data->total_processes++;
        if (p->state == TASK_RUNNING)
            info_data->running_processes++;
        else if (p->state == TASK_INTERRUPTIBLE)
            info_data->interruptible_processes++;
        else if (p->state == TASK_UNINTERRUPTIBLE)
            info_data->uninterruptible_processes++;
            
        if (p->sched_class == &rt_sched_class)
            info_data->rt_processes++;
        else if (p->sched_class == &fair_sched_class)
            info_data->fair_processes++;
    }
    rcu_read_unlock();

    /* 2) CFS runqueue for the rq where current task is enqueued */
    {
        struct rq *rq;
        struct cfs_rq *cfs;
        struct rq_flags rf;
        struct sched_entity *se_min;
        
        /* Ensure current task is valid before accessing runqueue */
        if (unlikely(!current)) {
            printk(KERN_ERR "[get_info] Current task is NULL\n");
            kfree(info_data);
            return -EINVAL;
        }
        
        /* Get current task's runqueue with proper error handling */
        rq = task_rq_lock(current, &rf);
        if (unlikely(!rq)) {
            printk(KERN_ERR "[get_info] Failed to get runqueue\n");
            kfree(info_data);
            return -EINVAL;
        }
        
        cfs = &rq->cfs;
        if (unlikely(!cfs)) {
            printk(KERN_ERR "[get_info] CFS runqueue is NULL\n");
            task_rq_unlock(rq, current, &rf);
            kfree(info_data);
            return -EINVAL;
        }
        /* Extract CFS runqueue information */
        info_data->cfs_processes = cfs->nr_running;
        info_data->total_load_w = cfs->load.weight;
        info_data->target_latency_ms = READ_ONCE(sysctl_sched_latency);
        info_data->min_vruntime = (unsigned long long)cfs->min_vruntime;
        
        /* Get min-vruntime entity & pid */
        se_min = __pick_first_entity(cfs);
        if (se_min) {
            struct task_struct *t = container_of(se_min, struct task_struct, se);
            info_data->min_vruntime_pid = task_pid_nr(t);
        } else {
            info_data->min_vruntime_pid = -1;
        }

        task_rq_unlock(rq, current, &rf);

    }
    
    /* Copy data to user space */
    if (copy_to_user(ubuf, info_data, sizeof(struct info_data))) {
        kfree(info_data);
        return -EFAULT;
    }
    
    kfree(info_data);
    return 0;
}