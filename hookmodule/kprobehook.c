#include "asm-generic/errno-base.h"
#include "kprobehook.h"
#include "linux/kprobes.h"
#include "linux/printk.h"


unsigned long lookup_name(const char *name){
    if(!kallsyms_lookup_name_function){
        pr_err("kallsyms_lookup_name_function is NULL,plean to init\n");
        return -ENXIO;
    }
    return kallsyms_lookup_name_function(name);
}


int kprobehook_init(struct kprobe_wrap* kprobe_list,size_t kprobe_cnt,
    struct kretprobe_wrap* kretprobe_list,size_t kretporbe_cnt){
    int ret;
    ret =register_kprobe(&kallsyms_lookup_name_kp);
    if(ret<0){
        pr_err("register kprobe failed,errno:%d\n",ret);
        return ret;
    }
    kallsyms_lookup_name_function = (kallsyms_lookup_name_t)kallsyms_lookup_name_kp.addr;
    unregister_kprobe(&kallsyms_lookup_name_kp);
    if(!kallsyms_lookup_name_function){
        pr_err("kallsyms_lookup_name address error\n");
        return -ENXIO;
    }
    pr_info("kallsyms_lookup_name address:%px\n",(void*)kallsyms_lookup_name_function);
    int index=0;
    for(;index<kprobe_cnt;index++){
        if(kprobe_list[index].valid){
            ret =register_kprobe(&kprobe_list[index].kp);
            if(ret<0){
                goto error;
            }
            pr_info("Planted kprobe at %s:%p\n",kprobe_list[index].kp.symbol_name,kprobe_list[index].kp.addr);
        }
    }
    return 0;
error:
    pr_err("register kprobe failed,errno:%d\n",ret);
    for(int i=0;i<index;i++){
        if(kprobe_list[i].valid){
            unregister_kprobe(&kprobe_list[i].kp);
        }
    }
    return ret;
};



void kprobehook_exit(struct kprobe_wrap* kprobe_list,size_t kprobe_cnt,
    struct kretprobe_wrap* kretprobe_list,size_t kretporbe_cnt){
        int index=0;
        for(;index<kprobe_cnt;index++){
        if(kprobe_list[index].valid){
            unregister_kprobe(&kprobe_list[index].kp);
        }
    }
    kallsyms_lookup_name_function = NULL;
    pr_info("kprobehook exit\n");
}