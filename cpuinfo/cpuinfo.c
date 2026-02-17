#define pr_fmt(fmt) "cpuinfo_ftrace: " fmt
#include "linux/cred.h"
#include "linux/seq_file.h"
#include "linux/uidgid.h"
#include "asm-generic/errno-base.h"
#include "linux/init.h"
#include "linux/moduleparam.h"
#include "linux/printk.h"
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
//内核函数hook
/*ftrace 函数指针
为什么这么定义，因为如果syms没有使用EXPORT_SYMBOL_GPL，就无法被外部模块用到
*/
typedef int (*ftrace_set_filter_ip_t)(struct ftrace_ops *ops, unsigned long ip,
			 int remove, int reset);
typedef int  (*register_ftrace_function_t)(struct ftrace_ops *ops);

typedef int  (*unregister_ftrace_function_t)(struct ftrace_ops *ops);
static ftrace_set_filter_ip_t ftrace_set_filter_ip_function = NULL;
static register_ftrace_function_t     register_ftrace_function_function =NULL;
static unregister_ftrace_function_t unregister_ftrace_function_function =NULL;
MODULE_LICENSE("GPL");
MODULE_AUTHOR("nuoen");
MODULE_DESCRIPTION("使用 ftrace hook /proc/cpuinfo");

//模块参数
static uint target_uid_val = 1000;
static int target_pid_val =0;
module_param(target_uid_val, uint, 0644);
MODULE_PARM_DESC(target_uid_val,"提供自定义cpuinfo的目标的UID");
module_param(target_pid_val,int,0644);
MODULE_PARM_DESC(target_pid_val, "提供自定义 cpuinfo 的目标 PID (0 表示不检查特定 PID)");


/* 自定义输出（按架构选择） */
#ifdef CONFIG_X86_64
static const char *custom_cpuinfo_output =
    "processor\t: 0\n"
    "vendor_id\t: MyHookedCPU-x86_64\n"
    "cpu family\t: 6\n"
    "model\t\t: 1\n"
    "model name\t: Hooked Intel CPU (Dynamic Mode)\n"
    "stepping\t: 1\n"
    "microcode\t: 0x1\n"
    "cpu MHz\t\t: 3000.000\n"
    "cache size\t: 1024 KB\n"
    "bogomips\t: 6000.00\n"
    "flags\t\t: hooked_flag dynamic_mode\n"
    "\n";
#elif defined(CONFIG_ARM64)
static const char *custom_cpuinfo_output =
    "processor\t: 0\n"
    "BogoMIPS\t: 200.00\n"
    "Features\t: hooked_feat_arm64 dynamic_mode\n"
    "CPU implementer\t: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x1\n"
    "CPU part\t: 0xd42\n"
    "CPU revision\t: 0\n"
    "Hardware\t: Hooked ARM64 (Dynamic Mode)\n"
    "\n";
#else
static const char *custom_cpuinfo_output =
    "processor\t: 0\n"
    "vendor_id\t: MyHookedCPU-Generic\n"
    "model name\t: Hooked Generic CPU (Dynamic Mode)\n"
    "cpu MHz\t\t: 2000.000\n"
    "Hardware\t: Hooked Unknown Platform (Dynamic Mode)\n"
    "\n";
#endif

/* 原始 show 指针（仅用于日志/恢复时参考） */
static unsigned long orig_show_addr = 0;

static unsigned long lookup_name(const char *name){
    //这样写，编译时会报
    // ERROR: modpost: "kallsyms_lookup_name" [../modules/cpuinfo/cpuinfo.ko] undefined!
    // unsigned int name_addr=0;
    // name_addr = kallsyms_lookup_name(name);
    // if(name_addr<=0){
    //     pr_err("not found the %s addr",name);
    // }
    // return name_addr;
    struct kprobe kp = {.symbol_name="kallsyms_lookup_name"};
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name_func;
    int ret;
    ret = register_kprobe(&kp);
    if(ret<0){
        pr_err("cpuinfo_ftrace: 无法注册kprobe 查找 kallsyms_lookup_name ,ret=%d\n",ret);
        return 0;
    }
    kallsyms_lookup_name_func = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    if(!kallsyms_lookup_name_func){
        pr_err("cpuinfo_trace:kallsyms_lookup_name 获取失败\n");
        return 0;
    }
    return kallsyms_lookup_name_func(name);
}

static int custom_show_cpuinfo(struct seq_file *m,void *v){
    kuid_t current_kuid = current_uid();
    pid_t current_pid = current->pid;
    uid_t uid = __kuid_val(current_kuid);
    bool should_override = false;
    pr_info("Hook 激活 PID=%d UID=%u (target PID =%d UID=%u)\n",current_pid,uid,target_pid_val,target_uid_val);
        if (target_uid_val != 0 && uid == target_uid_val)
        should_override = true;
    if (!should_override && target_pid_val != 0 && current_pid == target_pid_val)
        should_override = true;

    if (should_override || true)
    {
        pr_info("cpuinfo_ftrace: 为 PID=%d UID=%u 提供自定义 CPU 信息\n", current_pid, uid);
        seq_printf(m, "%s", custom_cpuinfo_output);
        return 0;
    }

    /*
     * 注意：这里我们没有尝试复杂地调用原始 show（那会涉及到避免 ftrace 递归的问题）。
     * 因此未匹配时我们直接返回 0（不输出）；如果你需要在未匹配时调用原始 show，
     * 我可以把安装逻辑改成 "只 hook cpuinfo_op 的调用者" 或在 ftrace 回调中更精细地处理（更复杂）。
     */
    return 0;

}

static void notrace ftrace_hook_thunk(unsigned long ip,unsigned long parent_ip ,
                                        struct ftrace_ops *ops, struct ftrace_regs *fregs){
    fregs->regs.pc = (unsigned long)custom_show_cpuinfo;
}


static struct ftrace_ops cpuinfo_fops = {
    .func = ftrace_hook_thunk,
    .flags = FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY,
};

static int resolve_ftrace_symbols(void){
    ftrace_set_filter_ip_function = (ftrace_set_filter_ip_t)lookup_name("ftrace_set_filter_ip");
    if(!ftrace_set_filter_ip_function){
        pr_err("cpuinfo_trace:无法解析 trace_set_filter_ip\n");
        return -ENOENT;
    }
    register_ftrace_function_function =(register_ftrace_function_t)lookup_name("register_ftrace_function");
    if(!register_ftrace_function_function){
        pr_err("cpuinfo_trace:无法解析 register_ftrace_function");
        return -ENOENT;
    }
    unregister_ftrace_function_function = (unregister_ftrace_function_t)lookup_name("unregister_ftrace_function");
    if(!unregister_ftrace_function_function){
        pr_err("cpuinfo_trace:无法解析 unregister_ftrace_function");
        return -ENOENT;        
    }
    return 0;
}


/**
虽然ftrace_set_filter_ip，在ftrace.c中使用了EXPORT_SYMBOL_GPL(ftrace_set_filter_ip);
但是还有一层GKI 符号白名单过滤，Module.symvers
*/
static int ftrace_install_hook(unsigned long func_addr){
    int err;
    if(!func_addr){
        pr_err("cpuinfo_ftrace:无效的func_addr\n");
        return -EINVAL;
    }
    err = ftrace_set_filter_ip_function(&cpuinfo_fops,func_addr,0,0);
    if(err){
        pr_err("ftrace_set_filter_ip 失败 err=%d\n", err);
        return err;
    }
    err = register_ftrace_function_function(&cpuinfo_fops);
    if(err){
        pr_err("register_ftrace_function 失败 err=%d\n",err);
        ftrace_set_filter_ip_function(&cpuinfo_fops, func_addr, 1, 0); /* undo filter */
        return err;
    }
    pr_info("已安装 ftrace hook @ %px\n",(void*)func_addr);
    return 0;
    // err = ftrace_set_filter_ip_function(&cpuinfo_fops,func_addr,0,0);
}

static void ftrace_remove_hook(unsigned long func_addr){
    unregister_ftrace_function_function(&cpuinfo_fops);
    ftrace_set_filter_ip_function(&cpuinfo_fops, func_addr, 1, 0); /* undo filter */
    pr_info("已移除 ftrace hook @ %pxd",(void*) func_addr);
 
}

static int install_ftrace_cpuinfo_hook(void){
    unsigned long func_addr = 0;
    unsigned long cpuinfo_op = 0;

    cpuinfo_op = lookup_name("cpuinfo_op");
    if(cpuinfo_op){
        /**
        const struct seq_operations cpuinfo_op = {
	    .start	= c_start,
	    .next	= c_next,
	    .stop	= c_stop,
	    .show	= show_cpuinfo,
        };
        */
        unsigned long off = 3*sizeof(void *);
        func_addr = *(unsigned long *)(cpuinfo_op+off);
        pr_info("cpuinfo_ftarce:尝试从 cpuinfo_op (%px)读取 show @ %px\n",(void *)cpuinfo_op,(void*)func_addr);
    }
    if(!func_addr){
        pr_err("cpuinfo_ftrace: 无法解析 cpuinfo show 地址，无法安装 hook\n");
        return -ENOENT;
    }
    orig_show_addr = func_addr;
    return ftrace_install_hook(func_addr);
}

static void uninstall_ftrace_cpuinfo_hook(void){
    if(orig_show_addr){
        ftrace_remove_hook(orig_show_addr);
    }
}

static int __init cpuinfo_ftrace_init(void){
    pr_info("cpuinfo_ftrace:初始化 （tartget_uid=%u,target_pid=%d)\n",target_uid_val,target_pid_val);
    if(resolve_ftrace_symbols()!=0){
        pr_err("cpuinfo_ftrace: 解析 trace symbols 失败\n");
        return -EINVAL;
    }
    if (install_ftrace_cpuinfo_hook() != 0)
    {
        pr_err("cpuinfo_ftrace: 安装 hook 失败\n");
        return -EINVAL;
    }

    pr_info("cpuinfo_ftrace: 安装完成\n");
    return 0;
}


static void __exit cpuinfo_ftrace_exit(void){
    uninstall_ftrace_cpuinfo_hook();
    pr_info("cpuinfo_ftrace:卸载完成\n");
}
module_init(cpuinfo_ftrace_init);
module_exit(cpuinfo_ftrace_exit);