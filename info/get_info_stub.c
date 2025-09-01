// SPDX-License-Identifier: GPL-2.0
#include <linux/syscalls.h>
#include <linux/errno.h>

#ifndef CONFIG_INFO_LIBRARY
SYSCALL_DEFINE2(get_info_for_pid, pid_t, pid, char __user *, ubuf)
{
    return -ENOSYS;
}
SYSCALL_DEFINE1(get_info, char __user *, ubuf)
{
    return -ENOSYS;
}
#endif
