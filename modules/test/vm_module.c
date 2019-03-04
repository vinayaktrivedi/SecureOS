/*
 * Hooking kernel functions using ftrace framework
 *
 * Copyright (c) 2018 ilammy
 */

#define pr_fmt(fmt) "ftrace_hook: " fmt

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/binfmts.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/wait.h>

/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0

/**
 * struct ftrace_hook - describes a single hook to install
 *
 * @name:     name of the function to hook
 *
 * @function: pointer to the function to execute instead
 *
 * @original: pointer to the location where to save a pointer
 *            to the original function
 *
 * @address:  kernel address of the function entry
 *
 * @ops:      ftrace_ops state for this function hook
 *
 * The user should fill in only &name, &hook, &orig fields.
 * Other fields are considered implementation details.
 */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = kallsyms_lookup_name(hook->name);

	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct pt_regs *regs)
{
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long) hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long) hook->function;
#endif
}

/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	/*
	 * We're going to modify %rip register so we'll need IPMODIFY flag
	 * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
	 * is useless if we change %rip so disable it with RECURSION_SAFE.
	 * We'll perform our own checks for trace function reentry.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION_SAFE
	                | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

/*####################################################### Global/static variables  ######################################################## */

static DECLARE_WAIT_QUEUE_HEAD(wq);
static struct task_struct *thread_st;
struct request{
	int type;
	int fd;
	char * buffer;
	int length;
};
struct response{
	int type;
	int length; //important in case of read/write 
	char * buffer;
	int errno;
};
struct process_info{
	int pid;
	char wake_flag;
	struct request req[1];
	struct response res[1];
};

static int num_of_watched_processes=11;
static struct process_info watched_processes[11];
static int current_num_of_childs=0;


/*####################################################### KThread Functions  ######################################################## */
static void send_to_host(void){
	// int i;
	// for(i=0;i<num_of_watched_processes;i++){
	// 	if( (watched_processes[i]->pid !=-1) && (watched_processes[i]->req[0]->type != -1) ){
	// 		if(watched_processes[i]->req[0]->type == 1){  //read request
				
	// 		}
	// 		else if(watched_processes[i]->req[0]->type == 2){ //write request

	// 		}
	// 		watched_processes[i]->req[0]->type= -1;
	// 	}
	// }
	return;
}
static void receive_from_host(void){
	int i;
	for(i=0;i<num_of_watched_processes;i++){
		if( (watched_processes[i].pid !=-1) && (watched_processes[i].req[0].type != -1) ){
			if(watched_processes[i].req[0].type == 1){  //read request
				char * buffer = kmalloc(32*sizeof(char),GFP_KERNEL);
				strncpy(buffer,"tushargr@turing.cse.iitk.ac.in\n",31);
				watched_processes[i].res[0].buffer = (char *) buffer;
				watched_processes[i].res[0].length = 31;
				watched_processes[i].res[0].errno = 0;
			}
			else if(watched_processes[i].req[0].type == 2){ //write request
				//printk("SANDBOX: thread found write request\n");
				watched_processes[i].res[0].length = watched_processes[i].req[0].length;
				watched_processes[i].res[0].errno = 0;
			}
			watched_processes[i].req[0].type= -1;
			watched_processes[i].wake_flag = 'y';
			wake_up(&wq);
		}
	}
	return;
}

static int thread_fn(void *unused)
{
    while (!kthread_should_stop())
    {
        schedule_timeout_interruptible(5);
        send_to_host();  //send can also be done from process for efficiency 
	receive_from_host();
    }
    printk("SANDBOX: Thread Stopping\n");
    return 0;
}

/*####################################################### Read/Write Host Functions ################################################ */


static int ksys_write_to_host(unsigned int fd, const char __user *buf, size_t count)
{
	int i;
	char * buffer = kmalloc(((int)count)*sizeof(char),GFP_KERNEL);
	for(i=0;i<num_of_watched_processes;i++){
		if(watched_processes[i].pid == current->pid) break;
	}
	watched_processes[i].req[0].fd=fd;
	watched_processes[i].req[0].length=count;
	copy_from_user((void *)buffer, (const void __user *) buf, (unsigned long) count);
	watched_processes[i].req[0].buffer = (char *) buffer;                  //not sure if this buffer can be passed for writing.
	watched_processes[i].req[0].type = 2;                   // type 1 for read, 2 for write, IMP: THIS SHOULD BE LOADED IN req AT LAST
	wait_event_interruptible(wq, watched_processes[i].wake_flag == 'y');
	watched_processes[i].wake_flag = 'n';
	if(watched_processes[i].res[0].errno < 0)  //errorno is not yet set
	 	return -1;
	else 
		return watched_processes[i].res[0].length;
}


static int ksys_read_from_host(unsigned int fd, const char __user *buf, size_t count)
{
	int i;
	for(i=0;i<num_of_watched_processes;i++){
		if(watched_processes[i].pid == current->pid) break;
	}
	watched_processes[i].req[0].fd=fd;
	watched_processes[i].req[0].length=count;
	watched_processes[i].req[0].type = 1;                                     // IMP:THIS SHOULD BE LOADED IN req AT LAST

	wait_event_interruptible(wq, watched_processes[i].wake_flag == 'y');
	watched_processes[i].wake_flag = 'n';
	if(watched_processes[i].res[0].errno < 0){  //errorno is not yet set
		return -1;
	}
	else{ 
		copy_to_user( (void __user *) buf,(const void *)watched_processes[i].res[0].buffer, (unsigned long) watched_processes[i].res[0].length);
		kfree(watched_processes[i].res[0].buffer);
		return watched_processes[i].res[0].length;
	}
}

/*############################################################## Hooked Functions #################################################### */


static asmlinkage ssize_t (*real_ksys_write)(unsigned int fd, const char __user *buf, size_t count);

static asmlinkage ssize_t fake_ksys_write(unsigned int fd, const char __user *buf, size_t count)
{
	
	int watched_process_flag = 0;  //flag if this function is called by ssh proxy child
	int i;
	for(i=0;i<num_of_watched_processes;i++){
		if(watched_processes[i].pid == current->pid){
			watched_process_flag=1;
			break;
		}
	}
	if(watched_process_flag == 1 && (fd == 1)){
		return ksys_write_to_host(fd,buf,count);
	}
	else{
		char buffer[30];
		copy_from_user((void *)buffer, (const void __user *) buf, (unsigned long) 15);
		if(strncmp(buffer, "user_exec_agent", 15) == 0){                                // user_exec_agent is created
			watched_processes[0].pid = current->pid;                                   // watched process 0 is user_exec agent and remaining are its child
			printk("SANDBOX: user_exec_agent created with pid = %d \n",current->pid);
			return real_ksys_write(fd, buf,count);
		}
		else if(strncmp(buffer, "user_exec_child", 15) == 0){
			current_num_of_childs+=1;
			watched_processes[current_num_of_childs].pid = current->pid;
			printk("SANDBOX: user_exec_agent child created with pid = %d \n",current->pid);
			return real_ksys_write(fd, buf,count);
		}
		else{
			return real_ksys_write(fd, buf,count);	
		}
	}
	
}

static asmlinkage ssize_t (*real_ksys_read)(unsigned int fd, const char __user *buf, size_t count);

static asmlinkage ssize_t fake_ksys_read(unsigned int fd, const char __user *buf, size_t count)
{

	int watched_process_flag = 0;
	int i;
	for(i=0;i<num_of_watched_processes;i++){
		if(watched_processes[i].pid == current->pid){
			watched_process_flag=1;
			break;
		}
	}
	
	if(watched_process_flag && (fd==0) ){
		//read request from fd=0 must return \n other this function will be called again and again
		return ksys_read_from_host(fd,buf,count);
	}
	else{
		return real_ksys_read(fd, buf,count);	
	}
	
}



/*############################################################## HOOKS ####################################################### */

#define HOOK(_name, _function, _original)	\
	{					\
		.name = (_name),		\
		.function = (_function),	\
		.original = (_original),	\
	}

static struct ftrace_hook demo_hooks[] = {
	HOOK("ksys_write", fake_ksys_write, &real_ksys_write),
	HOOK("ksys_read", fake_ksys_read, &real_ksys_read),	
};





/*####################################################### Module Initialization ##############################################*/
int fh_init(void)
{
	int err;
	int i;

	err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	if (err)
		return err;

	for(i=0;i<num_of_watched_processes;i++){
		watched_processes[i].pid = -1;
		watched_processes[i].wake_flag = 'n';
		watched_processes[i].req[0].type = -1;         //-1 implies no request yet
		watched_processes[i].res[0].type = -1;		 // -1 implies no response yet
	}

	pr_info("SANDBOX: module loaded\n");

	printk("SANDBOX: Creating KThread\n");
        thread_st = kthread_run(thread_fn, NULL, "mythread");

        if (!IS_ERR(thread_st)){
           printk("SANDBOX: Thread Created successfully\n");
        }
       else{
            printk("SANDBOX: Thread creation failed\n");
	    thread_st = NULL;
       }

	return 0;
}
module_init(fh_init);

void fh_exit(void)
{
        printk("SANDBOX: module_exit\n");
	
	fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
        printk("SANDBOX: module_exit aftre remove ftrace\n");
	if (thread_st){
           kthread_stop(thread_st);
           printk("SANDBOX: Thread stopped\n");
   	}

	pr_info("SANDBOX: module unloaded\n");
}
module_exit(fh_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("iitk@iitk.ac.in");
