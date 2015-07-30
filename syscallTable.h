#ifndef SYSCALLTABLE_H_
#define SYSCALLTABLE_H_


#include <asm/uaccess.h>
#include <linux/highmem.h>
#include <asm/page.h>

#include <linux/syscalls.h>
#include <linux/ctype.h>

#include <linux/slab.h>

#include <linux/unistd.h> /* The list of system calls */

#include "fileio.h"

#define KERN {old_fs = get_fs(); set_fs(KERNEL_DS);}

#define END {set_fs(old_fs);}

int set_page_rw(long unsigned int addr);

void set_addr_ro(unsigned long addr);

struct task_struct * get_task (pid_t pid);

void interceptSysKill(void);

void restoreSysKill(void);


mm_segment_t old_fs;

rwlock_t kill_lock;

char *sep = "/";

void **sys_call_table;

asmlinkage int (* real_kill) (int, int);

asmlinkage long (*original_call) (const char *, int, int);


asmlinkage long our_sys_open(const char *filename, int flags, int mode)
{


char *strA, *strB;

 int ret, pos = 0;


if(strstr(filename, "/proc"))
{
	  
	  read_lock(&open_lock);
 
          char *strFilePath; 
	  strFilePath = kmalloc(sizeof(char) * 80, GFP_KERNEL);

	  strcpy(strFilePath, filename);

	  struct file *fp;	


      strA = strtok(strFilePath, sep); 
	  strB = strtok(NULL, sep);

      if(isdigit(strB[0]))
	  {

//		 read_lock(&open_lock);
		printk(KERN_INFO "\n it is a digit: %s", strB);

		char *strTargetFilePath;
		strTargetFilePath = kmalloc(sizeof(char) * 80, GFP_KERNEL);
		sprintf(strTargetFilePath, "/proc/%s/attr/current", strB);
		
		printk(KERN_INFO "\n strTargetFilePath: %s", strTargetFilePath);

			 

		fp = file_open(strTargetFilePath, O_RDONLY, 0644);

		ret = file_read_open(fp, strAttr1, sizeof(strAttr1), &pos);


	  file_close(fp);
	
	
	kfree(strTargetFilePath);
//	read_unlock(&open_lock);

    
    }
  
	
  kfree(strFilePath);

read_unlock(&open_lock);

if(strstr(strAttr1, "lxc-container-default"))
{
  printk(KERN_INFO "\n Container resource accessed");

  memset(strAttr1, 0, sizeof(strAttr1));

  return -ENOENT;

}

else
{
	goto out;
}


}


  
out:

memset(strAttr1, 0, sizeof(strAttr1));

/*

if(strstr(strAttr1, "lxc-container-default"))
{
  printk(KERN_INFO "\n Container resource accessed");

}

else
*/

	return (* original_call)(filename, flags, mode);
}



asmlinkage int hack_kill (pid_t pid, int sig) 
{
printk(KERN_INFO "\n Hell from hack fill");

   int ret, pos = 0;

//    struct task_struct * task = get_task(pid);
   
//if(task == NULL)

//{

//printk(KERN_INFO "\n Task is null");

//}

  //  if ((task != NULL) )//&& (pid > 1))
  	//{

      //  printk(KERN_INFO "\n task->comm: %s", task->comm);
		read_lock(&kill_lock);

        char *strProcFilePath;

        struct file *fp;   

		strProcFilePath = kmalloc(sizeof(char) * 100, GFP_KERNEL);

        sprintf(strProcFilePath, "/proc/%d/attr/current", pid);

        fp = file_open(strProcFilePath, O_RDONLY, 0644);

 		ret = file_read(fp, strAttr, sizeof(strAttr), &pos);


        file_close(fp); 

//		printk(KERN_INFO "\n Task killed: %s", task->comm);

      kfree(strProcFilePath);

			read_unlock(&kill_lock);
//	}

    /* Now check if the attribute value is: lxc_default_container */

     if(strstr(strAttr, "lxc-container-default") && (pid > 1000 ))//&& (sig == SIGKILL))
     {

        printk(KERN_INFO "\n Frank Underwood: the butchery begins" );
        
         memset(strAttr, 0, sizeof(strAttr));

         //send_sig_info(SIGKILL, NULL, current);
       return EPERM;
     }


else
{

memset(strAttr, 0, sizeof(strAttr));
goto out;
}
     
out:

		return (* real_kill) (pid, sig);
     

} 




/* Obtain pid */

struct task_struct * get_task (pid_t pid) 
{


//printk("\n Value of pid: %d", pid);
struct task_struct * p = current;
	do 
	{
	   if (p-> pid == pid) return p;
	    p = next_task(p);

	} while (p!= current);

return NULL;
} 



int set_page_rw(long unsigned int addr)
{


 // printk(KERN_ALERT "In set_page_rw \n");
 // return set_memory_rw (PAGE_ALIGN(_addr) - PAGE_SIZE, 1);

unsigned int level;
pte_t *pte = lookup_address(addr, &level);

if (pte->pte &~ _PAGE_RW) 

 {
    pte->pte |= _PAGE_RW;

 }

 else
   {
      printk (KERN_ALERT "\n Error in set page rw \n");

   }



return 0;


}

/* The following function changes the memory page access to be READ-ONLY */

void set_addr_ro(unsigned long addr)
{
  unsigned int level;
  pte_t *pte = lookup_address(addr, &level);
  pte->pte = pte->pte &~_PAGE_RW;

}



void interceptSysKill()
{

  sys_call_table = (void *) 0xffffffff81801360; //simple_strtoul("0xc15b6020", NULL, 16);

  if(!sys_call_table)
  {
     printk(KERN_ALERT "Nothing in sys_call_table \n");
  }

  else
  {
	real_kill = sys_call_table [__NR_kill] ;

	original_call = sys_call_table[__NR_open];  

    set_page_rw(sys_call_table);

	sys_call_table [__NR_kill] = hack_kill ;

    sys_call_table[__NR_open] = our_sys_open;

  }
}

void restoreSysKill()
{

sys_call_table [__NR_kill] = real_kill;

sys_call_table[__NR_open] = original_call;

set_addr_ro(sys_call_table);


}


#endif
