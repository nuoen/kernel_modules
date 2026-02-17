#include <linux/ftrace.h>


/* Hook 定义宏 */
#define FTRACEHOOK(_name, _function, _original, _valid)	\
	{					\
		.name = (_name),	\
		.func = (_function),	\
		.orig = (_original),	\
        .valid = (_valid),      \
	}

struct ftrace_hook{
    const char *name; //目标函数名
    void *func;      //我们的hook函数
    void *orig;      //保存原始函数指针的变量地址

    unsigned long address; //内核中函数地址
    struct ftrace_ops ops; //ftrace 操作结构体
    bool valid; //是否启用
};


int fh_install_hooks(struct ftrace_hook *hook,size_t count);
int fh_remove_hooks(struct ftrace_hook *hook,size_t count);