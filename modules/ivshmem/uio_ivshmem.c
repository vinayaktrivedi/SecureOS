
#include <linux/device.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/uio_driver.h>
#include <linux/io.h>

#define IntrStatus 0x04
#define IntrMask 0x00
struct ivshmem_kern_client;
char *shared;

struct ivshmem_info {
        struct ivshmem_kern_client *client;
        struct pci_dev *dev;
};

/*
 * Hooking kernel functions using ftrace framework
 *
 * Copyright (c) 2018 ilammy
 */

//#define pr_fmt(fmt) "ftrace_hook: " fmt

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/binfmts.h>
#include <linux/module.h>  // Needed by all modules

#include <linux/fs.h>      // Needed by filp
#include <asm/uaccess.h>
#include<linux/syscalls.h>
#include <linux/sched.h>

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


/*############################################################## Hooked Functions / code here #################################################### */

static asmlinkage void (*real_finalize_exec)(struct linux_binprm *bprm);

static void read_msg(char* buf){
    
    if(shared[0]=='1'){
        strncpy(buf,shared+2,strlen(buf));
        shared[0] = '0';
        shared[1] = '1';
    }
    return;
}

static void send_msg(char* header,char* body){
    
    if(shared[524289]=='1'){
        strncpy(shared+524290,header,strlen(header));
        shared[524289]='0';
        shared[524288]='1';
    }
    return;
}

static asmlinkage void fh_finalize_exec(struct linux_binprm *bprm)
{   


    if(strncmp(bprm->filename, "/usr/bin/ssh", 12) == 0){
        printk("finalize execve() %s\n",bprm->filename);
        printk("pid = %d, tgid= %d\n",current->pid,current->tgid);
        char *buf = kmalloc(16*sizeof(char),GFP_KERNEL);
        read_msg(buf);
        printk("Data is %s\n",buf);
        kfree(buf);

        char *header = kmalloc(16*sizeof(char),GFP_KERNEL);
        char *body = kmalloc(16*sizeof(char),GFP_KERNEL);
        strcpy(header,"Header write");
        strcpy(body,"Body_write");
        send_msg(header,body);

        kfree(header);
        kfree(body);
        real_finalize_exec(bprm);
    }
    else{
        //send_msg("header","body");
        real_finalize_exec(bprm);   
    }
    


    return;
}



/*############################################################## HOOKS / code here ####################################################### */

#define HOOK(_name, _function, _original)   \
    {                   \
        .name = (_name),        \
        .function = (_function),    \
        .original = (_original),    \
    }

static struct ftrace_hook demo_hooks[] = {
    HOOK("finalize_exec", fh_finalize_exec, &real_finalize_exec),
};





/*####################################################### Module Initialization ##############################################*/
static int fh_init(void)
{
    int err;

    err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
    if (err)
        return err;

    pr_info("module loaded\n");

    return 0;
}
//module_init(fh_init);

static void fh_exit(void)
{
    fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));

    pr_info("module unloaded\n");
}
//module_exit(fh_exit);


struct ivshmem_kern_client{
           void __iomem *internal_address_bar1;
           unsigned long address_bar1;
           unsigned long size_bar1;
           void __iomem *internal_address_bar2;
           unsigned long address_bar2;
           unsigned long size_bar2;
           long irq;
           unsigned long irq_flags;
           char name[16];
           void *priv;
};
static irqreturn_t ivshmem_handler(int irq, void *arg)
{

        struct ivshmem_info *ivshmem_info;
        void __iomem *plx_intscr;
        struct ivshmem_kern_client *client = (struct ivshmem_kern_client *)arg;

        u32 val;

        ivshmem_info = client->priv;

        if (ivshmem_info->dev->msix_enabled)
                return IRQ_HANDLED;

        plx_intscr = client->internal_address_bar1 + IntrStatus;
        val = readl(plx_intscr);
        if (val == 0)
                return IRQ_NONE;

        return IRQ_HANDLED;
}

static int ivshmem_pci_probe(struct pci_dev *dev,
                                        const struct pci_device_id *id)
{       
        fh_init();
        struct ivshmem_kern_client *client;
        struct ivshmem_info *ivshmem_info;

        client = kzalloc(sizeof(struct ivshmem_kern_client), GFP_KERNEL);
        if (!client)
                return -ENOMEM;

        ivshmem_info = kzalloc(sizeof(struct ivshmem_info), GFP_KERNEL);
        if (!ivshmem_info) {
                kfree(client);
                return -ENOMEM;
        }
        client->priv = ivshmem_info;

        if (pci_enable_device(dev))
                goto out_free;

        if (pci_request_regions(dev, "ivshmem"))
                goto out_disable;

        client->address_bar1 = pci_resource_start(dev, 0);
        if (!client->address_bar1)
                goto out_release;

        client->size_bar1 = (pci_resource_len(dev, 0) + PAGE_SIZE - 1)
                & PAGE_MASK;
        client->internal_address_bar1 = pci_ioremap_bar(dev, 0);
        if (!client->internal_address_bar1)
                goto out_release;
        
        //printk(KERN_INFO "calling pci_alloc with dev->irq = %d\n", dev->irq);
        //if (1 > pci_alloc_irq_vectors(dev, 1, 1,
       //                               PCI_IRQ_LEGACY | PCI_IRQ_MSIX))
        //        goto out_vector;


        client->address_bar2 = pci_resource_start(dev, 2);
        if (!client->address_bar2)
                goto out_unmap;

        client->size_bar2 = pci_resource_len(dev, 2);
        strcpy(client->name, "ivshmem");

        ivshmem_info->client = client;
        ivshmem_info->dev = dev;

        /*if (pci_irq_vector(dev, 0)) {
                client->irq = pci_irq_vector(dev, 0);
                client->irq_flags = IRQF_SHARED;
                if(request_irq(client->irq, &ivshmem_handler, client->irq_flags, 
client->name, client))
                   dev_warn(&dev->dev, "Register IRQ failed\n");
        }else {
                dev_warn(&dev->dev, "No IRQ assigned to device: "
                         "no support for interrupts?\n");
        }*/
        pci_set_master(dev);


       /* if (!dev->msix_enabled)
                writel(0xffffffff, client->internal_address_bar1 + IntrMask);*/

        pci_set_drvdata(dev, ivshmem_info);
        void __iomem *regs = ioremap(client->address_bar2,client->size_bar2);
        shared = (char*)regs;
        // printk(KERN_INFO "Msg: %s\n",(char*)regs);
        // strcpy((char*)regs,"I m guest" );
        // iounmap(regs);
        return 0;
//out_vector:
        //pci_free_irq_vectors(dev);
out_unmap:
        iounmap(client->internal_address_bar1);
out_release:
        pci_release_regions(dev);
out_disable:
        pci_disable_device(dev);
out_free:
        kfree(ivshmem_info);
        kfree(client);
        dev_warn(&dev->dev, "Device registration failed\n");

        return -ENODEV;
}

static void ivshmem_pci_remove(struct pci_dev *dev)
{
        struct ivshmem_info *ivshmem_info = pci_get_drvdata(dev);
        struct ivshmem_kern_client *client = ivshmem_info->client;

        pci_set_drvdata(dev, NULL);
        pci_free_irq_vectors(dev);
        iounmap(client->internal_address_bar1);
        pci_release_regions(dev);
        pci_disable_device(dev);
        kfree(client);
        kfree(ivshmem_info);
        fh_exit();
}

static struct pci_device_id ivshmem_pci_ids[] = {
        {
                .vendor =       0x1af4,
                .device =       0x1110,
                .subvendor =    PCI_ANY_ID,
                .subdevice =    PCI_ANY_ID,
        },
        { 0, }
};

static struct pci_driver ivshmem_pci_driver = {
        .name = "uio_ivshmem",
        .id_table = ivshmem_pci_ids,
        .probe = ivshmem_pci_probe,
        .remove = ivshmem_pci_remove,
};

module_pci_driver(ivshmem_pci_driver);
MODULE_DEVICE_TABLE(pci, ivshmem_pci_ids);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Cam Macdonell");

