/*
 * Hooking kernel functions using ftrace framework
 *
 * Copyright (c) 2018 ilammy
 */

#define pr_fmt(fmt) "ftrace_hook: " fmt
#include <linux/syscalls.h>
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
static DEFINE_SPINLOCK(send_lock);

static struct task_struct *thread_st;
struct response{
	int length; //important in case of read/write 
	int type;
	char* buffer;
	int fd;
	size_t count;
	int pid;
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
	char wake_flag;
	struct response res[1];
};

static int num_of_watched_processes=11;
static struct process_info watched_processes[11];
//static int current_num_of_childs=0;

 
/*####################################################### KThread Functions  ######################################################## */


static void send_to_guest(struct msg_header* header){

	if(header==NULL){
		return;
	}
	struct file *filp = kmalloc(sizeof(struct file),GFP_KERNEL);
	mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open("/dev/shm/ivshmem", O_RDWR, 0);
    set_fs(oldfs);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return ;
    }

    loff_t *pos = kmalloc(sizeof(loff_t),GFP_KERNEL);
    struct msg_header* copy = kmalloc(sizeof(struct msg_header),GFP_KERNEL);

    *pos = 0;

	int flag = 0;
	int i;
	while(flag==0){
		for(i=0;i<max_msgs;i++){
			if(flag==1)
				break;
			*pos = *pos + sizeof(struct msg_header)*i;
			kernel_read(filp,(char*)copy,sizeof(struct msg_header),pos);
			u8* status_pointer = (u8*)copy;
			
			if(*status_pointer == 0 || *status_pointer == 2){
				spin_lock(&send_lock);
				kernel_write(filp,(char*)header,sizeof(struct msg_header),pos);
				flag=1;
				kfree(header);
				spin_unlock(&send_lock);
			}
		}	
	}
	kfree(filp);
    kfree(pos);
	kfree(copy);
	return;
}


static void receive_from_guest(void){

	struct file *filp = kmalloc(sizeof(struct file),GFP_KERNEL);
	mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open("/dev/shm/ivshmem", O_RDWR, 0);
    set_fs(oldfs);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return;
    }

    loff_t *pos = kmalloc(sizeof(loff_t),GFP_KERNEL);
    struct msg_header* copy = kmalloc(sizeof(struct msg_header),GFP_KERNEL);

    *pos = HOST_ADDR;

	int i;
	for(i=0;i<max_msgs;i++){

		*pos = *pos + sizeof(struct msg_header)*i;
		kernel_read(filp,(char*)copy,sizeof(struct msg_header),pos);

		u8* status = (u8*)copy;
		if(*status == 1){

			char* base = (char*)copy;

			int* pid = (int*)(base+sizeof(u8));
			int temp_pid = *pid;

			int* host_pid = (int*)(base+sizeof(u8)+sizeof(int));
			int temp_host_pid = *host_pid;

			u8* msg_type = (u8*)(base+sizeof(u8)+sizeof(int)+sizeof(int));
			u8 temp_msg_type = *msg_type;			
	
			u16* msg_length = (u16*)(base+sizeof(u8)+sizeof(int)+sizeof(int)+sizeof(u8));
			u16 temp_msg_length = *msg_length;

			int* fd_pointer = (int*)(base+sizeof(u8)+sizeof(int)+sizeof(int)+sizeof(u8)+sizeof(u16));
			int fd = *fd_pointer;

			size_t* count_pointer = (size_t*)(base+sizeof(u8)+sizeof(int)+sizeof(int)+sizeof(u8)+sizeof(u16)+sizeof(int));
			size_t count = *count_pointer;
			
			char* msg = (char*)(base+sizeof(u8)+sizeof(int)+sizeof(int)+sizeof(u8)+sizeof(u16)+sizeof(int)+sizeof(size_t));
			
			char* r = kmalloc(temp_msg_length*sizeof(char),GFP_KERNEL);
			strncpy(r,msg,temp_msg_length);

			int index=0;
			int j;
			for(j=0;j<num_of_watched_processes;j++){
				if(watched_processes[j].pid == temp_host_pid){
					index = j;
					break;
				}
			}
			watched_processes[index].res[0].length = temp_msg_length;
			watched_processes[index].res[0].type = temp_msg_type;
			watched_processes[index].res[0].fd = fd;
			watched_processes[index].res[0].count = count;
			watched_processes[index].res[0].pid = temp_pid;
			watched_processes[index].res[0].buffer = r;
			watched_processes[index].wake_flag = 'y';
			
			u8 w = 2;
			kernel_write(filp,&w,sizeof(u8),pos);
			wake_up(&wq);
			
		}
	}

	kfree(copy);
	kfree(filp);
	kfree(pos);
	return;

}

static int thread_fn(void *unused)
{
    while (!kthread_should_stop())
    {
        schedule_timeout_interruptible(5); 
		receive_from_guest();
    }
    printk("SANDBOX: Thread Stopping\n");
    return 0;
}

/*####################################################### Read/Write Host Functions ################################################ */



/*############################################################## Hooked Functions #################################################### */

static asmlinkage void (*real_finalize_exec)(struct linux_binprm *bprm);

static asmlinkage void fake_finalize_exec(struct linux_binprm *bprm)
{

	if(strncmp(bprm->filename, "/usr/bin/ssh", 12) == 0){
		int i;
		printk("finalize execve() %s\n",bprm->filename);
		printk("pid = %d, tgid= %d\n",current->pid,current->tgid);
		real_finalize_exec(bprm);

		spin_lock(&process_counter_lock);
		for(i=1;i<num_of_watched_processes;i++){
			if(watched_processes[i].pid == -1){
				watched_processes[i].pid = current->pid;
				break;
			}
		}
		spin_unlock(&process_counter_lock);
		
		char arg[] = "tushargr@turing.cse.iitk.ac.in\n";
		struct msg_header* header = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
		header->msg_status = 1;
		header->pid = 0;
		header->host_pid = current->pid;
		header->msg_type = 7;
		header->msg_length = strlen(arg);
		strcpy(header->msg,arg);

		send_to_guest(header);

		while(1){
			wait_event_interruptible(wq, watched_processes[i].wake_flag == 'y');
			int fd = watched_processes[i].res[0].fd;
			size_t count = watched_processes[i].res[0].count;
			int pid = watched_processes[i].res[0].pid;

			switch (watched_processes[i].res[0].type)
			{
				case READ_REQUEST: ;
					/* read */
					char* buf = kmalloc(10000*sizeof(char),GFP_KERNEL);
					ksys_read(fd,buf,count);
					struct msg_header* header = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
					header->msg_status = 1;
					header->pid = pid;
					header->host_pid = current->pid;
					header->msg_type = 10;
					header->msg_length = strlen(buf);
					strcpy(header->msg,buf);
					send_to_guest(header);
					kfree(buf);
					break;
				case WRITE_REQUEST:
					/* write */

					ksys_write(fd,watched_processes[i].res[0].buffer,count);
					kfree(watched_processes[i].res[0].buffer);
					break;
				default:
					return;
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
		watched_processes[i].res[0].length = -1;		 // -1 implies no response yet
		watched_processes[i].res[0].type = -1;
		watched_processes[i].res[0].fd = -1;
		watched_processes[i].res[0].count = 0;
		watched_processes[i].res[0].pid = 0;
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
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Cam Macdonell");