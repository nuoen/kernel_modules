#include <linux/kprobes.h>

//所有参数从栈取，而不是从寄存器取
typedef asmlinkage long (*t_syscall)(const struct pt_regs *);


#define SYSTEMCALL_HOOK(__id,__func,__orig,__valid) \
    {\
      .id = (__id),\
      .func = (__func),\
      .orig = (__orig),\
      .valid = (__valid),\
    }


//关闭CFI才可以使用
struct systemcall_hook{
    unsigned long id; //系统调用id
    t_syscall func;      //我们的hook函数
    t_syscall *orig;      //保存原始函数指针的地址
    bool valid; //是否启用hook
};

int systemcall_hook_init(struct systemcall_hook *systemcall_list,size_t count);
void systemcall_hook_exit(struct systemcall_hook *systemcall_list,size_t count);