#include "linux/cdev.h"
#include "linux/device/class.h"
#include "linux/export.h"
#include "linux/fs.h"
#include "linux/printk.h"
#include "linux/types.h"
#include "linux/uaccess.h"
#include <linux/module.h>



MODULE_LICENSE("GPL");
MODULE_AUTHOR("nuoen");
MODULE_DESCRIPTION("Create /dev/fake_cpuinfo with custom content using chrdev");
MODULE_VERSION("0.3");

#define DEVICE_NAME  "cdevcpuinfo"
#define CLASS_NAME  "fakecpu"

static dev_t dev_number;
static struct class *fakecpu_class = NULL;
static struct cdev fakecpu_cdev;

#if LINUX_VERSION_CODE >=KERNEL_VERSION(6,8,0)
static char *fakecpu_devnode(const struct device *dev, umode_t *mode);
#else
static char *fakecpu_devnode(struct device *dev, umode_t *mode)
#endif
{
    if(mode)
        *mode = 0444; //r--r--r--
    return NULL;
}

static const char fake_cpuinfo_data[]=
    "Processor\t: Fake ARMv8 Processor rev 4 (v8l)\n"
    "Hardware\t: Custom Board\n"
    "CPU implementer\t: 0x41\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x0\n"
    "CPU part\t: 0xd03\n"
    "CPU revision\t: 4\n";

    
#if LINUX_VERSION_CODE >=KERNEL_VERSION(6, 4, 0)
#define CLASS_CREATE(owner,name) class_create(name)
#else
#define CLASS_CREATE(owner,name) class_create(owner,name)
#endif

static ssize_t fakecpu_read(struct file *filep,char __user *buf,size_t len ,loff_t *offset){
    size_t datalen = strlen(fake_cpuinfo_data);
    if(*offset>=datalen){
        return 0;
    }
    if(len>datalen-*offset)
        len = datalen-*offset;
    if(copy_to_user(buf, fake_cpuinfo_data+*offset, len)){
        return -EFAULT;
    }
    *offset +=len;
    return len;
}
static int fakecpu_open(struct inode *inodep, struct file *filep)
{
    pr_info("fake_cpuinfo: device opened\n");
    return 0;
}

static int fakecpu_release(struct inode *inodep, struct file *filep)
{
    pr_info("fake_cpuinfo: device closed\n");
    return 0;
}
static struct file_operations fops={
    .owner = THIS_MODULE,
    .read = fakecpu_read,
    .open = fakecpu_open,
    .release = fakecpu_release,
};

static int __init fakecpu_init(void){
    int ret;

    //分配设备号
    ret = alloc_chrdev_region(&dev_number, 0, 1, DEVICE_NAME);
    if(ret<0){
        pr_err("failedto alocate chrdev region\n");
        return ret;
    }
    // 创建cdev
    cdev_init(&fakecpu_cdev,&fops);
    fakecpu_cdev.owner = THIS_MODULE;
    ret = cdev_add(&fakecpu_cdev,dev_number,1);
    if(ret<0){
        unregister_chrdev_region(dev_number, 1);
        pr_err("failed to add cdev\n");
        return ret;
    }
    fakecpu_class = CLASS_CREATE(THIS_MODULE,CLASS_NAME);
    if(IS_ERR(fakecpu_class)){
        cdev_del(&fakecpu_cdev);
        unregister_chrdev_region(dev_number, 1);
        pr_err("failed to create class");
        return PTR_ERR(fakecpu_class);
    }

    fakecpu_class->devnode = fakecpu_devnode;

    if(IS_ERR(device_create(fakecpu_class,NULL,dev_number,NULL,DEVICE_NAME))){
        class_destroy(fakecpu_class);
        cdev_del(&fakecpu_cdev);
        unregister_chrdev_region(dev_number, 1);
        pr_err("failed to create device\n");
    }
    pr_info("/dev/%s created successfully\n", DEVICE_NAME);
    return 0;
}

static void __exit fakecpu_exit(void){
    device_destroy(fakecpu_class, dev_number);
    class_destroy(fakecpu_class);
    cdev_del(&fakecpu_cdev);
    unregister_chrdev_region(dev_number, 1);

    pr_info("/dev/%s removed\n", DEVICE_NAME);
}
module_init(fakecpu_init);
module_exit(fakecpu_exit);
