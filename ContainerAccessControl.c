#include <linux/kernel.h>
#include <linux/module.h> 
#include <linux/moduleparam.h> /* which will have params */
#include <linux/unistd.h> /* The list of system calls */
#include <linux/cred.h>

#include <linux/syscalls.h>




#include <linux/sched.h>

#include "utilities.h"

#include "syscallTable.h"



int init_module(void)
{

rwlock_init(&test_read_lock);

rwlock_init(&kill_lock);

rwlock_init(&token_lock);

rwlock_init(&open_lock);

interceptSysKill();

return 0;
}


void cleanup_module()
{

 restoreSysKill();

}


MODULE_LICENSE("GPL");





