#include "linux/init.h"
#include "linux/proc_fs.h"
#include "linux/seq_file.h"
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("nuoen");
MODULE_DESCRIPTION("Create /proc/fake_cpuinfo with custom content");
MODULE_VERSION("0.1");

#define PROC_NAME "proccpuinfo"

static int fake_cpuinfo_show(struct seq_file *m,void *v){
        seq_printf(m,
        "Processor\t: Fake ARMv8 Processor rev 4 (v8l)\n"
        "Hardware\t: Custom Board\n"
        "CPU implementer\t: 0x41\n"
        "CPU architecture: 8\n"
        "CPU variant\t: 0x0\n"
        "CPU part\t: 0xd03\n"
        "CPU revision\t: 4\n");
    return 0;
}

static int fake_cpuinfo_open(struct inode *inode,struct file *file){
    return single_open(file, fake_cpuinfo_show, NULL);
}

static const struct proc_ops fake_cpuinfo_fops = {
    .proc_open = fake_cpuinfo_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
}


static int __init fake_cpuinfo_init(void){
    proc_create(PROC_NAME, 0, NULL, &fake_cpuinfo_fops);
    pr_info()
}



module_init();
module_exit()