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
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/uio_driver.h>
#include <linux/io.h>

#define IntrStatus 0x04
#define IntrMask 0x00
void __iomem *regs;
EXPORT_SYMBOL(regs);
struct ivshmem_kern_client;
struct ivshmem_info {
        struct ivshmem_kern_client *client;
        struct pci_dev *dev;
};



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
        printk("number %ld",client->address_bar2);
        regs = ioremap(client->address_bar2,client->size_bar2);
        
        //printk(KERN_INFO "Msg: %#x\n",readl(regs));
        //strncpy((char*)regs,"I m guest",9 );
        //iounmap(regs);

        return 0;
//out_vector:
        //pci_free_irq_vectors(dev);
out_unmap:
        printk("error 1");
        iounmap(client->internal_address_bar1);
out_release:
        printk("error2");
        pci_release_regions(dev);
out_disable:
        printk("error3");
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
        //fh_exit();
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

