#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include "linux/sysctl.h"
#include "linux/sysfs.h"
#include "asm-generic/errno-base.h"
#include "linux/kobject.h"
#include "linux/printk.h"
#include "linux/kprobes.h"
#include <linux/module.h>

//内核 system 参数hook
MODULE_LICENSE("GPL");
MODULE_AUTHOR("nuoen");
MODULE_DESCRIPTION("aaa");

static struct kobject *sysmodule_kobject;

static int * kptr_restrict_p;


/*
* Sysctl 相关部分
*/

static int min_val =0;
static int max_val =2;

static struct ctl_table sysmodule_sysctl_table[] ={
    {
        .procname ="status",
        .data=NULL, /*数据指针在运行时动态设置*/
        .maxlen = sizeof(int),
        .mode = 0644, /*权限：所有者和同组用户可读可写，其他用户只读*/
        .proc_handler = proc_dointvec_minmax,
        .extra1 = &min_val,
        .extra2 = &max_val,
    },{/*哨兵，标志表格结束*/}
};



typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

static kallsyms_lookup_name_t kallsyms_lookup_name_function;
static struct kprobe kp ={.symbol_name="kallsyms_lookup_name"};

/* sysfs show: 读取 /sys/kernel/sysmodule/status 时调用 */
static ssize_t status_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf){
    pr_info("status_show called\n");
    if(!kptr_restrict_p)
        return -ENODEV;
    return sprintf(buf, "%d\n", *kptr_restrict_p);
}

/* sysfs store: 写入 /sys/kernel/sysmodule/status 时调用 */
static ssize_t status_store(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count){
    pr_info("status_store called\n");
    int val;
    if(!kptr_restrict_p){
        return -ENODEV;
    }
    if(sscanf(buf,"%d",&val)!=1)
        return -EINVAL;

    if(val<0 || val >2){
        return -EINVAL;
    }
    if(*kptr_restrict_p == val){
        return count;
    }
    pr_info("change kptr_restrict from %d to %d\n",*kptr_restrict_p,val);
    *kptr_restrict_p = val;
    return count;
}


static struct kobj_attribute status_attribute =
	__ATTR(status, 0664, status_show, status_store);

static int __init sysmodule_init(void){
    int ret;
    ret =register_kprobe(&kp)>0;
    if(ret<0){
        pr_err("register kprobe failed,errno:%d\n",ret);
        return ret;
    }
    kallsyms_lookup_name_function = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    if(!kallsyms_lookup_name_function){
        pr_err("kallsyms_lookup_name address error\n");
        return -ENXIO;
    }

    kptr_restrict_p = (int*)kallsyms_lookup_name_function("kptr_restrict");
    if(!kptr_restrict_p){
        pr_err("lookup kptr_restrict_p failed");
        return -ENXIO;
    }
    sysmodule_kobject = kobject_create_and_add("sysmodule", kernel_kobj);
    if(!sysmodule_kobject){
        pr_err("kobject_create_and_add failed\n");
        return -ENOMEM;
    }

    ret = sysfs_create_file(sysmodule_kobject,&status_attribute.attr);

    /**
    sysctl = 动态修改内核参数的接口。
    可以让你在运行时读写 /proc/sys/ ** 下的内核变量。 
    同等于使用 直接用cat echo 对proc/sys进行读写
    */
    /*注册sysctl*/
    sysmodule_sysctl_table[0].data = kptr_restrict_p;
    ret = register_sysctl_table(sysmodule_sysctl_table)!=NULL;
    if(!ret){
        pr_err("register_sysctl_table failed\n");
        sysfs_remove_file(sysmodule_kobject, &status_attribute.attr);
        kobject_put(sysmodule_kobject);
        return -ENOMEM;
    }
    return 0;
}

static void __exit sysmodule_exit(void){

}

module_init(sysmodule_init);
module_exit(sysmodule_exit);