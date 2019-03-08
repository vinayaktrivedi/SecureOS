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
static DEFINE_SPINLOCK(send_lock);

#define OPEN_REQUEST 0
#define WRITE_REQUEST 1
#define READ_REQUEST 2
#define MMAP_REQUEST 3
#define CLOSE_REQUEST 4
#define LSEEK_REQUEST 5
#define FSTAT_REQUEST 6
#define EXECVE_REQUEST 7 

#define HOST_ADDR 524289
#define max_msgs 50
extern void __iomem *regs;
static char* shared;
static int global_host_pid;
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
struct response{
	int length; //important in case of read/write 
	char * buffer;
};

struct msg_header
{
	u8 msg_status;
	int pid;
	int host_pid;
	u8 msg_type;
	u16 msg_length;
	int fd;
	size_t count;
	char msg[10000];
} ;


struct process_info{
	int pid;
	int host_pid;
	char wake_flag;
	struct response res[1];
};

static int num_of_watched_processes=11;
static struct process_info watched_processes[11];
static int current_num_of_childs=0;


/*####################################################### KThread Functions  ######################################################## */


static void send_to_host(struct msg_header* header){

	if(header==NULL || shared==NULL){
		return;
	}

	int flag = 0;
	int i;
	while(flag==0){
		for(i=0;i<max_msgs;i++){
			if(flag==1)
				break;

			u8* status = (u8*)(shared+HOST_ADDR+sizeof(struct msg_header)*i);
			if(*status == 0 || *status == 2){
				spin_lock(&send_lock);

				char* base = (char*)status;

				int* pid = (int*)(base+sizeof(u8));
				*pid = header->pid;
				int* host_pid = (int*)(base+sizeof(u8)+sizeof(int));
				*host_pid = header->host_pid;
				u8* msg_type = (u8*)(base+sizeof(u8)+sizeof(int)+sizeof(int));
				*msg_type = header->msg_type;
				u16* msg_length = (u16*)(base+sizeof(u8)+sizeof(int)+sizeof(int)+sizeof(u8));
				*msg_length = header->msg_length;
				int* fd = (int*)(base+sizeof(u8)+sizeof(int)+sizeof(int)+sizeof(u8)+sizeof(u16));
				*fd = header->fd;
				size_t* count = (size_t*)(base+sizeof(u8)+sizeof(int)+sizeof(int)+sizeof(u8)+sizeof(u16)+sizeof(int));
				*count = header->count;
				char* msg = (char*)(base+sizeof(u8)+sizeof(int)+sizeof(int)+sizeof(u8)+sizeof(u16)+sizeof(int)+sizeof(size_t));
				strcpy(msg,header->msg);
				*status = header->msg_status;   // this should be done at last
				flag=1;
				kfree(header);
				spin_unlock(&send_lock);
			}
		}	
	}
		
	return;
}


static void receive_from_host(void){
	if(shared==NULL){
		return;
	}

	int i;
	for(i=0;i<max_msgs;i++){

		u8* status = (u8*)(shared+sizeof(struct msg_header)*i);
		if(*status == 1){

			char* base = (char*)status;

			int* pid = (int*)(base+sizeof(u8));
			int temp_pid = *pid;

			int* host_pid = (int*)(base+sizeof(u8)+sizeof(int));
			int temp_host_pid = *host_pid;

			u8* msg_type = (u8*)(base+sizeof(u8)+sizeof(int)+sizeof(int));
			u8 temp_msg_type = *msg_type;			
	
			u16* msg_length = (u16*)(base+sizeof(u8)+sizeof(int)+sizeof(int)+sizeof(u8));
			u16 temp_msg_length = *msg_length;
			
			char* msg = (char*)(base+sizeof(u8)+sizeof(int)+sizeof(int)+sizeof(u8)+sizeof(u16)+sizeof(int)+sizeof(size_t));
			
			char* r = kmalloc(temp_msg_length*sizeof(char),GFP_KERNEL);
			strncpy(r,msg,temp_msg_length);

			int index=0;
			if(temp_msg_type == EXECVE_REQUEST && temp_pid == 0 ){
				global_host_pid = temp_host_pid;
				index = 0;
			}
			else{
				int j;
				for(j=0;j<num_of_watched_processes;j++){
					if(watched_processes[j].pid == temp_pid){
						index = j;
						break;
					}
				}
			}
			watched_processes[index].res[0].length = temp_msg_length;
			watched_processes[index].res[0].buffer = r;
			watched_processes[index].wake_flag = 'y';
			wake_up(&wq);
			*status = 2;   // this should be done at last
			
		}
	}

	return;

}

static int thread_fn(void *unused)
{
    while (!kthread_should_stop())
    {
        schedule_timeout_interruptible(5); 
		receive_from_host();
    }
    printk("SANDBOX: Thread Stopping\n");
    return 0;
}

/*####################################################### Read/Write Host Functions ################################################ */


static int ksys_write_to_host(unsigned int fd, const char __user *buf, size_t count,int i)
{
	
	struct msg_header* header = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
	header->pid = watched_processes[i].pid;
	header->host_pid = watched_processes[i].host_pid;
	header->msg_status = 1;
	header->msg_type = WRITE_REQUEST;
	header->msg_length = strlen(buf);
	header->fd = fd;
	header->count = count;
	strcpy(header->msg,buf);
	send_to_host(header);

	return count;
}


static asmlinkage ssize_t ksys_read_from_host(unsigned int fd, const char __user *buf, size_t count,int i)
{
	
	struct msg_header* header = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
	header->pid = watched_processes[i].pid;
	header->host_pid = watched_processes[i].host_pid;
	header->msg_status = 1;
	header->msg_type = READ_REQUEST;
	header->msg_length = 0;
	header->fd = fd;
	header->count = count;
	send_to_host(header);

	wait_event_interruptible(wq, watched_processes[i].wake_flag == 'y');
	watched_processes[i].wake_flag = 'n';

	if(watched_processes[i].res[0].length < 0){  //errorno is not yet set
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
	if(watched_process_flag == 1 && (fd==1|| fd==2) ){
		return ksys_write_to_host(fd,buf,count,i);
	}
	else{
		char buffer[16];
		copy_from_user((void *)buffer, (const void __user *) buf, (unsigned long) 15);
		if(strncmp(buffer, "user_exec_agent", 15) == 0){                                // user_exec_agent is created
			watched_processes[0].pid = current->pid; 
			watched_processes[0].host_pid = 0;                                  // watched process 0 is user_exec agent and remaining are its child
			printk("SANDBOX: user_exec_agent created with pid = %d \n",current->pid);
			return real_ksys_write(fd, buf,count);
		}
		else if(strncmp(buffer, "user_exec_child", 15) == 0){
			current_num_of_childs+=1;
			watched_processes[0].host_pid = global_host_pid;
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
		return ksys_read_from_host(fd,buf,count,i);
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
static int fh_init(void)
{
	int err;
	shared = (char*)regs;
	err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	if (err)
		return err;

	int i;
	for(i=0;i<num_of_watched_processes;i++){
		watched_processes[i].pid = -1;
		watched_processes[i].wake_flag = 'n';        //-1 implies no request yet
		watched_processes[i].res[0].length = -1;
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

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Cam Macdonell");