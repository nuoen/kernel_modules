#include "ftracehook.h"
#include "linux/container_of.h"
#include "linux/export.h"
#include "linux/ftrace.h"
#include "linux/module.h"
#include "linux/printk.h"
#include "kprobehook.h"


/*ftrace 函数指针
为什么这么定义，虽然使用了ftrace.c中使用了EXPORT_SYMBOL_GPL，但是因为白名单限制无法被外部模块用到
*/
typedef int (*ftrace_set_filter_t)(struct ftrace_ops *ops, unsigned char *buf,
		       int len, int reset);
typedef int (*ftrace_set_filter_ip_t)(struct ftrace_ops *ops, unsigned long ip,
			 int remove, int reset);
typedef int  (*register_ftrace_function_t)(struct ftrace_ops *ops);

typedef int  (*unregister_ftrace_function_t)(struct ftrace_ops *ops);
static ftrace_set_filter_t ftrace_set_filter_function=NULL; 
static ftrace_set_filter_ip_t ftrace_set_filter_ip_function = NULL;
static register_ftrace_function_t     register_ftrace_function_function =NULL;
static unregister_ftrace_function_t unregister_ftrace_function_function =NULL;


/*
 * 什么是hook递归？
 	1.	内核函数 Foo() 被调用
	2.	ftrace 拦截 → 回调到你的 hook_handler
	3.	你修改 PC → 跳到你的 hook_func
	4.	hook_func 最后又调用 Foo()
 * 防止 Hook 递归的两种方式：
 * - 方式1 (USE_FENTRY_OFFSET=0)：通过返回地址检测递归
 当你进入 hook_handler 时，通过：parent_ip (调用者的返回地址) 来判断是否是从 hook_func 返回的，
 如果是，则说明是递归调用，直接返回即可。
 * - 方式2 (USE_FENTRY_OFFSET=1)：直接跳过 ftrace 调用位置
 直接跳过 ftrace/fentry 占位指令，让执行从“真正的第一条指令”开始。
 */
#define USE_FENTRY_OFFSET 0

static int fh_resolve_hook_address(struct ftrace_hook *hook){
    pr_info("fh_resolve_hook_address\n");
    hook->address = lookup_name(hook->name);
    if(!hook->address){
        pr_err("lookup_name failed for %s\n",hook->name);
        return -ENOENT;
    }
#if USE_FENTRY_OFFSET
    *((unsigned long *)hook->orig) = hook->address + MCOUNT_INSN_SIZE;
#else
    *((unsigned long *)hook->orig) = hook->address;
#endif
    return 0;
}



static void notrace fh_ftrace_thunk(unsigned long ip,unsigned long parent_ip,struct ftrace_ops *ops,
        struct ftrace_regs *fregs){
    struct pt_regs *regs = &(fregs->regs);
    //已知结构体中某个成员的地址 → 求整个结构体的起始地址。
    struct ftrace_hook * hook = container_of(ops, struct ftrace_hook, ops);
#if USE_FENTRY_OFFSET
    regs->pc = (unsigned long)hook->func;
#else
    if(!within_module(parent_ip, THIS_MODULE))
        regs->pc = (unsigned long)hook->func;
#endif
}


static int fh_install_hook(struct ftrace_hook *hook){
    pr_info("fh_install_hook:%s\n",hook->name);
    int err;
    err = fh_resolve_hook_address(hook);
    if(err){
        return err;
    }
    pr_info("target address:%s = 0x%lx\n",hook->name,hook->address);
    hook->ops.func = fh_ftrace_thunk;
    hook->ops.flags= FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED
                    | FTRACE_OPS_FL_RECURSION
                    | FTRACE_OPS_FL_IPMODIFY;
    err = ftrace_set_filter_function(&hook->ops, (unsigned char *)hook->name, strlen(hook->name), 0); 
    if(err){
        pr_err("ftrace_set_filter() failed: %d\n",err);
        return err;
    }
    err = register_ftrace_function_function(&hook->ops);
    if(err){
        pr_err("unregister_ftrace_function() failed: %d\n",err);
        //这里使用 ftrace_set_filter_ip 删除失败的过滤规则不是写错，
        //而是唯一正确、最稳健的清理方式，因为按 IP 删除永远正确，按名字删除并不可靠。
        ftrace_set_filter_ip_function(&hook->ops,hook->address,1,0);
        return err;
    }
    return 0;
}


static void fh_remove_hook(struct ftrace_hook *hook){
    int err;
    err = unregister_ftrace_function_function(&hook->ops);
    if(err){
        pr_err("unregister_ftrace_function failed: %d\n",err);
    }
    err = ftrace_set_filter_function(&hook->ops,NULL,0,1);
    if(err){
        pr_err("ftrace_set_filter failed: %d\n",err);
    }
    pr_info("fh_remove_hook:%s\n",hook->name);
}


int fh_install_hooks(struct ftrace_hook *hook,size_t count){

    pr_info("fh_install_hook\n");
    int err;
    size_t i;
    ftrace_set_filter_function = (ftrace_set_filter_t)lookup_name("ftrace_set_filter");
    ftrace_set_filter_ip_function = (ftrace_set_filter_ip_t)lookup_name("ftrace_set_filter_ip");
    register_ftrace_function_function = (register_ftrace_function_t)lookup_name("register_ftrace_function");
    unregister_ftrace_function_function = (unregister_ftrace_function_t)lookup_name("unregister_ftrace_function");
    for(i=0;i<count;i++){
        if(hook[i].valid){
            err = fh_install_hook(&hook[i]);
            if(err){
                goto error;
            }  
        }

    }
    return 0;
error:
    pr_err("fh_install_hook failed for %s,err=%d\n",hook[i].name,err);
    while(i-->0){
        fh_remove_hook(&hook[i]);
    }
    return err; 
}

int fh_remove_hooks(struct ftrace_hook *hook,size_t count){
    pr_info("fh_remove_hooks\n");
    size_t i;
    for(i=0;i<count;i++){
        if(hook[i].valid)
            fh_remove_hook(&hook[i]);
    }
    return 0;
}


int ftrace_hook_init(void){
    int ret=0;
    pr_info("ftrace_hook_init\n");
    return ret;
}
void ftrace_hook_exit(void){
    pr_info("ftrace_hook_exit\n");
}