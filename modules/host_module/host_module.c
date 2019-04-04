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
#include <uapi/asm/termbits.h>
#include <linux/tty.h>
#include <linux/file.h>


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
#define IOCTL_REQUEST 8
#define HOST_ADDR 524289
#define max_msgs 50
static unsigned long user_address;

enum msg_type_t{
                   FREE=0, 
                   USED,  /*Yet to be read*/
                   CONSUMED,
                   MAX_MSG_TYPE
};
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
static DEFINE_SPINLOCK(copy_lock);

static struct task_struct *thread_st;
struct response{
	int length; //important in case of read/write 
	int type;
	char* buffer;
	int fd;
	size_t count;
	int pid;
};

struct open_req{
	int dfd;
	char filename[100]; 
	int flags; 
	umode_t mode;
};

struct ioctl_req{
	unsigned int fd;
	unsigned int cmd;
	unsigned long arg;
	char termios[sizeof(struct termios)];
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

struct open_file{
	int fd;
	struct file * filp;
};

struct process_info{
	int pid;
	char wake_flag;
	struct response res[1];
	struct open_file open_files[50];
	int ready;
};
static int num_of_watched_processes=11;
static struct process_info watched_processes[11];
//static int current_num_of_childs=0;

 
/*####################################################### KThread Functions  ######################################################## */
static void copy_bytes(char* dest, char* source, size_t length){
	int i;
	for ( i = 0; i <length ; ++i)
	{
		dest[i] = source[i];
	}
}

static void send_to_guest(struct msg_header* header){
 
    loff_t pos = 0, lpos = 0;
    struct msg_header* msg = kmalloc(sizeof(struct msg_header),GFP_KERNEL);\
	int i, err = 0;

	if(header==NULL){
		return;
	}
	//printk("Reached");
	struct file *filp = kmalloc(sizeof(struct file),GFP_KERNEL);
	mm_segment_t oldfs;
   

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open("/dev/shm/ivshmem", O_RDWR, 0);
    set_fs(oldfs);
    if (IS_ERR(filp)) {
    	printk("file open error\n");
        err = PTR_ERR(filp);
        return ;
    }

    
	printk(KERN_INFO "sending to guest [status = %d] [length = %d] [msg=%s] [type=%d]", header->msg_status, header->msg_length,header->msg,header->msg_type);
	
retry:
	for(i=0;i<max_msgs;i++){
     		lpos = i*sizeof(struct msg_header);
			pos = lpos;
			WARN_ON(kernel_read(filp,(char*)msg,sizeof(struct msg_header),&pos) <= 0);
            if(msg->msg_status == FREE || msg->msg_status == CONSUMED){
				spin_lock(&send_lock);
				pos = lpos;
				WARN_ON(kernel_write(filp,(char*)header,sizeof(struct msg_header), &pos) <= 0);
				kfree(header);	
				spin_unlock(&send_lock);
				pos = lpos;
				kernel_read(filp,(char*)msg,sizeof(struct msg_header), &pos);
				goto done;
			}
	}	
if(unlikely(i == max_msgs)){
	     schedule_timeout_interruptible(5);
         goto retry;		
}
	
done:

	kfree(filp);
	kfree(msg);
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
    loff_t lastpos = *pos;

	int i;
	for(i=0;i<max_msgs;i++){

		lastpos = *pos;
		kernel_read(filp,(char*)copy,sizeof(struct msg_header),pos);

		if(copy->msg_status == 1){
			
			char* r = kmalloc(copy->msg_length*sizeof(char),GFP_KERNEL);
			copy_bytes(r,copy->msg,copy->msg_length);

			int index=0;
			int j;
			for(j=0;j<num_of_watched_processes;j++){
				if(watched_processes[j].pid == copy->host_pid ){
					index = j;
					break;
				}
			}
 
			//printk("Index is %d\n",index);
			int start = 0;
			while(start == 0){
				if(watched_processes[index].pid == -1){
					break;
				}	
				else if(watched_processes[index].ready == 1){
					spin_lock(&copy_lock);
					watched_processes[index].res[0].length = copy->msg_length;
					watched_processes[index].res[0].type = copy->msg_type;
					watched_processes[index].res[0].fd = copy->fd;
					watched_processes[index].res[0].count = copy->count;
					watched_processes[index].res[0].pid = copy->pid;
					watched_processes[index].res[0].buffer = r;
					watched_processes[index].wake_flag = 'y';
					u8 w = 2;
					kernel_write(filp,&w,sizeof(u8),&lastpos);
					wake_up(&wq);
					watched_processes[index].ready = 0;
					start = 1;
					spin_unlock(&copy_lock);
				}
				else{
					//printk("Got message with index %d, ready %d",index,watched_processes[index].ready);
					break;
				}

			}
						
			
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
static asmlinkage ssize_t (*real_ksys_read)(unsigned int fd, const char __user *buf, size_t count);

static asmlinkage ssize_t fake_ksys_read(unsigned int fd, const char __user *buf, size_t count)
{
	return real_ksys_read(fd,buf,count);
	
}

static asmlinkage ssize_t (*real_ksys_write)(unsigned int fd, const char __user *buf, size_t count);

static asmlinkage ssize_t fake_ksys_write(unsigned int fd, const char __user *buf, size_t count)
{
	return real_ksys_write(fd,buf,count);
	
}
static asmlinkage long (*real_sys_open)(int dfd, const char __user *filename, int flags, umode_t mode);

static asmlinkage long fake_sys_open(int dfd, const char __user *filename, int flags, umode_t mode){
	return real_sys_open(dfd, filename,flags,mode);	
}



static asmlinkage void (*real_finalize_exec)(struct linux_binprm *bprm);

static asmlinkage void fake_finalize_exec(struct linux_binprm *bprm)
{

	if(strncmp(bprm->filename, "/usr/bin/ssh", 12) == 0){
		int i;
		printk("finalize execve() %s\n",bprm->filename);
		//real_finalize_exec(bprm);

		spin_lock(&process_counter_lock);
		for(i=1;i<num_of_watched_processes;i++){
			if(watched_processes[i].pid == -1){
				watched_processes[i].pid = current->pid;
				break;
			}
		}
		spin_unlock(&process_counter_lock);
		
		//char arg[] = "temp@localhost\n";

		char arg[] = "badguy@localhost\n";
		struct msg_header* header = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
		header->msg_status = USED;
		header->pid = 0;
		header->host_pid = current->pid;
		header->msg_type = 7;
		header->msg_length = strlen(arg);
		strcpy(header->msg,arg);

		send_to_guest(header);
		loff_t pos = 0;
	    mm_segment_t oldfs;
		int err = 0;
		watched_processes[i].open_files[0].fd = 0;
		watched_processes[i].open_files[0].filp = (fdget(0)).file;
		watched_processes[i].open_files[1].fd = 1;
		watched_processes[i].open_files[1].filp = (fdget(1)).file;
		watched_processes[i].open_files[2].fd = 2;
		watched_processes[i].open_files[2].filp = (fdget(2)).file;

		printk("data start is %x and stack start is %x\n",current->mm->start_data,current->mm->start_stack) ;
		//copy_to_user((void*)current->mm->start_data,(char*)"hahahaha",(unsigned long)sizeof("hahahaha") );
		char test[10];
		copy_from_user(test,(void*)current->mm->start_data,10);
		printk("Not failed and data is %s\n",test);

		while(1){
			int j;
			int ret;
			loff_t offset =0;
			if(wait_event_timeout(wq, watched_processes[i].wake_flag == 'y',10000000) != 0){
			}
			spin_lock(&copy_lock);
			watched_processes[i].wake_flag = 'n';
			int fd = watched_processes[i].res[0].fd;
			size_t count = watched_processes[i].res[0].length;
			int pid = watched_processes[i].res[0].pid;
			printk("Got message with index %d, msg_type %d, fd %d, length as %d and string as %s\n", i,watched_processes[i].res[0].type,watched_processes[i].res[0].fd,watched_processes[i].res[0].length,watched_processes[i].res[0].buffer);
			switch (watched_processes[i].res[0].type)
			{
				case READ_REQUEST: ;
					/* read */
					char* buf = kmalloc(10000*sizeof(char),GFP_KERNEL);
					for(j=0;j<50;j++){
						if(watched_processes[i].open_files[j].fd == fd)break;
					}
					offset =0;
					ret = kernel_read(watched_processes[i].open_files[j].filp, buf, 1024, &offset);

					struct msg_header* header = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
					header->msg_status = 1;
					header->pid = pid;
					header->host_pid = current->pid;
					header->msg_type = 10;
					header->msg_length = strlen(buf);
					strncpy(header->msg,buf,strlen(buf));
					send_to_guest(header);
					kfree(buf);
					break;
				case WRITE_REQUEST:
					if(watched_processes[i].res[0].buffer == NULL){
						printk("response error\n");
						break;
					}
					for(j=0;j<50;j++){
						if(watched_processes[i].open_files[j].fd == fd)break;
					}
					offset=0;
					ret = kernel_write(watched_processes[i].open_files[j].filp, watched_processes[i].res[0].buffer, count, &offset);
					offset=0;
					kfree(watched_processes[i].res[0].buffer);
					break;
				case OPEN_REQUEST:
					if(watched_processes[i].res[0].buffer == NULL){
						printk("response error\n");
						break;
					}
					struct open_req* open_r = (struct open_req*)watched_processes[i].res[0].buffer;
					struct msg_header* header2 = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
					header2->msg_status = 1;
					header2->pid = pid;
					header2->host_pid = current->pid;
					header2->msg_type = 10;                                                                //not sure what type is for open
					header2->msg_length = 0;
					int open_fd = real_sys_open(0, open_r->filename, open_r->flags, open_r->mode);
					struct file *filp_temp = (fdget(open_fd)).file;
					
					//guest may be already using fd's from 0 to 39 , therefore fake fd is given to guest starting from 40 for now
					for(j=40;j<50;j++){
						if(watched_processes[i].open_files[j].fd == -1)break;
					}
					if(j==50){
						printk("Error in open\n");
						break;
					}
					watched_processes[i].open_files[j].fd = open_fd;
					watched_processes[i].open_files[j].filp= filp_temp;
					header2->fd = open_fd;
					printk("Got open request for filename %s, opened with fd %d\n",open_r->filename,open_fd);
					send_to_guest(header2);
					kfree(watched_processes[i].res[0].buffer);
					break;	
				case CLOSE_REQUEST:
					if(watched_processes[i].res[0].buffer == NULL){
						printk("response error\n");
						break;
					}
					for(j=0;j<50;j++){
						if(watched_processes[i].open_files[j].fd == fd)break;
					}
					if(j==50){
						printk("Error in close\n");
					}
					oldfs = get_fs();
					set_fs(get_ds());
					ret = filp_close(watched_processes[i].open_files[j].filp, NULL);
					set_fs(oldfs);
					watched_processes[i].open_files[j].fd=-1;
					struct msg_header* header3 = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
					header3->msg_status = 1;
					header3->pid = pid;
					header3->host_pid = current->pid;
					header3->msg_type = 10;
					header3->msg_length = 0;
					header3->fd=ret; // fd here is used as checking if close done properly or not
					send_to_guest(header3);
					break;
				case IOCTL_REQUEST:
					if(watched_processes[i].res[0].buffer == NULL){
						printk("response error\n");
						break;
					}
					struct ioctl_req* ioctl_r = (struct ioctl_req*)watched_processes[i].res[0].buffer;
					for(j=0;j<50;j++){
						if(watched_processes[i].open_files[j].fd == ioctl_r->fd)break;
					}
					if(j==50 || (fdget(ioctl_r)).file == NULL){
						printk("fffile open error in ioctl\n");
						break;
					}
					oldfs = get_fs();
					set_fs(get_ds());

					struct termios* rr = (struct termios*)ioctl_r->termios;
					printk("Ioctl termios args %ld and %ld and %u\n",rr->c_iflag,rr->c_cflag,(unsigned long)ioctl_r->termios);

					
					copy_to_user((void*)current->mm->start_data,(char*)ioctl_r->termios,(unsigned long)sizeof(struct termios) );
					int ret = watched_processes[i].open_files[j].filp->f_op->unlocked_ioctl(ioctl_r->fd, ioctl_r->cmd, (unsigned long)current->mm->start_data );
					copy_from_user((char*) ioctl_r->termios ,(void*)current->mm->start_data,(unsigned long)sizeof(struct termios));
					
					// int ret = watched_processes[i].open_files[j].filp->f_op->unlocked_ioctl(ioctl_r->fd, ioctl_r->cmd, (unsigned long)user_address );
					// copy_from_user((char*) ioctl_r->termios ,(void*)user_address,(unsigned long)sizeof(struct termios));
					
					set_fs(oldfs);
					struct msg_header* header4 = kmalloc(sizeof(struct msg_header),GFP_KERNEL);
					header4->msg_status = 1;
					header4->pid = pid;
					header4->host_pid = current->pid;
					header4->msg_type = 10;
					header4->msg_length = 0;
					header4->fd=ret; // fd here is used as checking if ioctl done properly or not
					memcpy(header4->msg,ioctl_r->termios,sizeof(struct termios));
					send_to_guest(header4);
					break;
				default: ;
			}	
			watched_processes[i].ready = 1;	
			spin_unlock(&copy_lock);
		}

	}
	else{
		real_finalize_exec(bprm);	
	}
	


	return;
}

// static asmlinkage int (*real_ioctl) (unsigned int fd, unsigned int cmd, unsigned long arg);
// static asmlinkage int fake_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg){
// 	int i;
// 	for(i=1;i<num_of_watched_processes;i++){
// 			if(watched_processes[i].pid == current->pid){
// 				printk("hello I am here\n");
// 				user_address = arg;
// 				break;
// 			}
// 	}
	
// 	return real_ioctl(fd,cmd,arg);
// }


/*############################################################## HOOKS ####################################################### */

#define HOOK(_name, _function, _original)	\
	{					\
		.name = (_name),		\
		.function = (_function),	\
		.original = (_original),	\
	}

static struct ftrace_hook demo_hooks[] = {
	HOOK("finalize_exec", fake_finalize_exec, &real_finalize_exec),
	HOOK("ksys_read", fake_ksys_read, &real_ksys_read),	
	HOOK("ksys_write", fake_ksys_write, &real_ksys_write),
	HOOK("do_sys_open", fake_sys_open, &real_sys_open),
	//HOOK("ksys_ioctl",fake_ioctl,&real_ioctl),
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
		watched_processes[i].ready = 1;
		watched_processes[i].wake_flag = 'n';
		watched_processes[i].res[0].length = -1;		 // -1 implies no response yet
		watched_processes[i].res[0].type = -1;
		watched_processes[i].res[0].fd = -1;
		watched_processes[i].res[0].count = 0;
		watched_processes[i].res[0].pid = 0;
		int j;
		for(j=0;j<50;j++){
			watched_processes[i].open_files[j].fd=-1;
		}
	}
	watched_processes[0].ready = 1;

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
