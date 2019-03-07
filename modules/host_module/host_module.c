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

MODULE_DESCRIPTION("Example module hooking clone() and execve() via ftrace");
MODULE_AUTHOR("ilammy <a.lozovsky@gmail.com>");
MODULE_LICENSE("GPL");

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
static DECLARE_WAIT_QUEUE_HEAD(wq2);
static DEFINE_SPINLOCK(process_counter_lock);
static DEFINE_SPINLOCK(exec_agent_res_lock);

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
	char wake_flag2;
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
        schedule_timeout(5);
        send_to_host();  //send can also be done from process for efficiency 
		receive_from_host();
    }
    printk("SANDBOX: Thread Stopping\n");
    return 0;
}


/*############################################################## Hooked Functions #################################################### */

static asmlinkage void (*real_finalize_exec)(struct linux_binprm *bprm);

static asmlinkage void fake_finalize_exec(struct linux_binprm *bprm)
{

	if(strncmp(bprm->filename, "/usr/bin/ssh", 12) == 0){
		int i;
		printk("finalize execve() %s\n",bprm->filename);
		printk("pid = %d, tgid= %d\n",current->pid,current->tgid);
		real_finalize_exec(bprm);

		//get argument of ssh
		spin_lock(&process_counter_lock);
		for(i=1;i<num_of_watched_processes;i++){
			if(watched_processes[i].pid == -1){
				watched_processes[i].pid = current->pid;
				break;
			}
		}
		spin_unlock(&process_counter_lock);
		
		spin_lock(&exec_agent_res_lock)
		if(watched_processes[0].req == -1) { //user agent in vm is not ready to take args
			wait_event_interruptible(wq2, watched_processes[i].wake_flag2 == 'y');
		}
		char * buffer = kmalloc(((int))*sizeof(char),GFP_KERNEL);
		strncpy(buffer,"tushargr@turing.cse.iitk.ac.in",28);
		watched_processes[0].res[0].error=0;
		watched_processes[0].res[0].length=28;
		watched_processes[0].res[0].buffer=28;
		watched_processes[0].res[0].type=0; //set at last
		watched_processes[0].req[0].type =-1;
		spin_unlock(&exec_agent_res_lock)

		while(1){
			wait_event_interruptible(wq, watched_processes[i].wake_flag == 'y');
			switch (watched_processes[i].req[0].type)
			{
				case 1:
					/* read */
					break;
				case 2:
					/* write */
					break;
				default:
					break;
			}		
		}  
	}
	else{
		real_finalize_exec(bprm);	
	}
	


	return;
}


/*############################################################## HOOKS ####################################################### */

#define HOOK(_name, _function, _original)	\
	{					\
		.name = (_name),		\
		.function = (_function),	\
		.original = (_original),	\
	}

static struct ftrace_hook demo_hooks[] = {
	HOOK("finalize_exec", fake_finalize_exec, &real_finalize_exec),
};





/*####################################################### Module Initialization ##############################################*/
static int fh_init(void)
{
	int err;
	int i;

	err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	if (err)
		return err;

	for(i=0;i<num_of_watched_processes;i++){
		watched_processes[i].pid = -1;
		watched_processes[i].wake_flag = 'n';
		watched_processes[i].wake_flag2 = 'n';
		watched_processes[i].req[0].type = -1;         //-1 implies no request yet
		watched_processes[i].res[0].type = -1;		 // -1 implies no response yet
	}

	pr_info("SANDBOX: module loaded\n");

	printk("SANDBOX: Creating KThread\n");
    thread_st = kthread_run(thread_fn, NULL, "mythread");
    if (thread_st){
        printk("SANDBOX: Thread Created successfully\n");
    }
    else{
        printk("SANDBOX: Thread creation failed\n");
    }

	return 0;
}
module_init(fh_init);

static void fh_exit(void)
{
	fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	if (thread_st){
       kthread_stop(thread_st);
       printk("SANDBOX: Thread stopped\n");
   	}

	pr_info("SANDBOX: module unloaded\n");
}
module_exit(fh_exit);
