#include "uprobehook.h"
#include "linux/cred.h"
#include "linux/dcache.h"
#include "linux/elf.h"
#include "linux/err.h"
#include "linux/fs.h"
#include "linux/gfp_types.h"
#include "linux/namei.h"
#include "linux/printk.h"
#include "linux/slab.h"
#include "linux/tty.h"
#include "linux/types.h"
#include "linux/uidgid.h"
#include "linux/uprobes.h"

void print_string(char *str) {
    /* 获取当前任务的tty */
    struct tty_struct *my_tty = get_current_tty();

    /* 如果my_tty为NULL，当前任务没有可以打印到的tty
     * （例如，如果它是一个守护进程）。如果是这样，我们无能为力。
     */
    if (my_tty) {
        /* my_tty->driver是一个包含函数的结构体，
         * 其中一个函数（write）用于向tty写入字符串。
         * 它可以用来接受来自用户或内核内存段的字符串。
         *
         * write函数的第一个参数是要写入的tty，因为
         * 同一个函数通常会被某种类型的所有tty使用。
         * 第二个参数是指向字符串的指针。
         * 第三个参数是字符串的长度。
         */
        const struct tty_operations *ttyops = my_tty->driver->ops;
        (ttyops->write)(my_tty, "[feicong] ", strlen("[feicong] "));
        (ttyops->write)(my_tty, str, strlen(str));

        /* tty最初是硬件设备，通常严格遵循ASCII标准。
         * 在ASCII中，要移动到新行，您需要两个字符：
         * 回车（Carriage Return, CR）和换行（Line Feed, LF）。
         * 在Unix上，ASCII的换行符（LF, `\n`）通常被同时用于这两个目的，
         * 但在原始的tty设备上，如果只发送`\n`，
         * 光标只会移动到下一行，但不会回到行首，
         * 导致下一行输出从上一行结束的列开始。
         * 这也是Unix和MS-DOS/Windows系统中文本文件换行符不同的历史原因。
         *
         * 在CP/M及其衍生系统（如MS-DOS和MS Windows）中，
         * 严格遵循ASCII标准，换行必须由CR和LF两个字符来完成。
         * 因此，为了确保在所有类型的tty上都能正确换行，
         * 我们需要显式地发送回车（`\015`）和换行（`\012`）两个字符。
         */
        (ttyops->write)(my_tty, "\015\012", 2);
    }
}

static loff_t find_symbol_offset(const char* filename,const char*symbol){
    struct file *file;
    struct elfhdr elf_header;
    struct elf_shdr *section_headers;

    //运行时必须暴露的最小符号集
    Elf64_Sym *dynsym = NULL;

    char *dynstr =NULL;
    loff_t offset =0;
    ssize_t ret;
    int i,j;
    int dynsym_idx=-1,dynstr_idx =-1;
    size_t dynsym_size =0;

    file = filp_open(filename,O_RDONLY,0);
    if(IS_ERR(file)){
        pr_err("Failed to open %s\n",filename);
        return 0;
    }

    //读取ELF头部
    ret = kernel_read(file, &elf_header, sizeof(elf_header), 0);
    if(ret !=sizeof(elf_header)){
        pr_err("Failed to read ELF header\n");
        goto cleanup;
    }
    //验证ELF魔数
    if(memcmp(elf_header.e_ident,ELFMAG,SELFMAG)!=0){
        pr_err("Invalid ELF file\n");
        goto cleanup;
    }

    //读取节头表
    section_headers = kmalloc(elf_header.e_shentsize * elf_header.e_shnum,GFP_KERNEL);
    if(!section_headers){
        pr_err("Failed to allocate memory for section headers\n");
        goto cleanup;
    }
    loff_t shoff = elf_header.e_shoff;
    ret = kernel_read(file,section_headers,elf_header.e_shentsize * elf_header.e_shnum,&shoff);
    if (ret<0){
        pr_err("Failed to read section headers\n");
        goto cleanup_section_headers;
    }

    // 查找`.dynsym`和`.dynstr`节
    for(i=0;i<elf_header.e_shnum;i++){
        if(section_headers[i].sh_type == SHT_DYNSYM){
            dynsym_idx = i;
            dynsym_size = section_headers[i].sh_size;
        }
        if(section_headers[i].sh_type == SHT_STRTAB && dynstr_idx == -1){
            // 我们需要.dynstr节，通常是一个STRTAB
            dynstr_idx =i;
        }
    }
    if(dynsym_idx == -1 || dynstr_idx == -1){
        pr_err("Could not find .dynsym or .dynstr sections\n");
        goto cleanup_section_headers;
    }

    // 读取.dynsym节
    dynsym = kmalloc(dynsym_size, GFP_KERNEL);
    if(!dynsym){
        pr_err("Failed to allocate memory for dynsym\n");
        goto cleanup_section_headers;
    }

    loff_t dynsym_offset = section_headers[dynsym_idx].sh_offset;
    ret = kernel_read(file,dynsym,dynsym_size,&dynsym_offset);
    if(ret<0){
        pr_err("Failed to read .dynsym section\n");
        goto cleanup_dynsym;
    }

    // 读取.dynstr节
    dynstr = kmalloc(section_headers[dynstr_idx].sh_size, GFP_KERNEL);
    if(!dynstr){
        pr_err("Failed to allocate memory for dynstr\n");
        goto cleanup_dynsym;
    }

    loff_t dynstr_offset = section_headers[dynstr_idx].sh_offset;
    ret = kernel_read(file,dynstr,section_headers[dynstr_idx].sh_size,&dynstr_offset);
    if(ret<0){
        pr_err("Failed to read .dynstr section\n");
        goto cleanup_dynstr;
    }

    // 遍历`.dynsym`并查找符号
    for(j=0;j<dynsym_size/sizeof(Elf64_Sym);j++){
        /*
        •st_name：不是字符串指针，而是 在 .dynstr 中的偏移
	    •dynstr_idx：.dynstr 在 section header 表中的索引
	    •sh_size：.dynstr 字符串表的总大小
👉 这是边界检查，防止越界访问字符串表
        */
        if(dynsym[j].st_name < section_headers[dynstr_idx].sh_size){
            char *sym_name = dynstr+dynsym[i].st_name;
            if(strcmp(sym_name,symbol)==0){
                offset =dynsym[j].st_value;
                pr_info("Found  symbol %s at offset: 0x%llx\n",symbol,offset);
                break;
            }
        }
    }

    if(offset ==0){
        pr_err("Symbol %s not found\n",symbol);
    }

cleanup_dynstr:
    kfree(dynstr);

cleanup_dynsym:
    kfree(dynsym);
cleanup_section_headers:
    kfree(section_headers);
cleanup:
    filp_close(file,NULL);
    return offset;
}

int uprobe_init(struct uprobe_wrap* uprobe_lists,size_t cnt,int uid){
    int ret;
    char init_msg[256];
    int index=0;
    uid_t current_uid = from_kuid(&init_user_ns, current_uid());
    if(uid!=-1 && uid!=current_uid){
        print_string("uid not match,return");
        return 0;
    }
    for(;index<cnt;index++){
        struct uprobe_wrap  *upw = &uprobe_lists[index];
        struct path path;
        if(upw->valid){
            //把一个内核态字符串路径（如 /proc/1/status）解析成 struct path（dentry + vfsmount），供内核后续直接使用。
            ret = kern_path(upw->target_path,LOOKUP_FOLLOW,&path);
            if (ret){
                pr_err("uprobes: Make sure Android APEX runtime is available\n"); 
                return ret;
            }
            //使用路径信息
            upw->target_inode = d_inode(path.dentry);
            //释放路径引用，对应kern_path的引用获取
            path_put(&path);
            upw->offset = find_symbol_offset(upw->target_path,upw->symbol_name);

            if(upw->offset){
                pr_err("uprobes: Failed to find symbol %s in %s\n",upw->symbol_name,upw->target_path);
                return -ENOENT;
            }
            ret = uprobe_register(upw->target_inode, upw->offset, &upw->uprobe_consumer);
            if(ret){
                pr_err("uprobes: Failed to register uprobe (error: %d)\n", ret);
                goto err;
            }
            snprintf(init_msg, sizeof(init_msg), "uprobes: Successfully registered uprobe for %s at offset 0x%lx", upw->target_path, upw->offset);
            print_string(init_msg);
        }
    }
    return 0;
err:
    for(int i =0;i<index;i++){
        struct uprobe_wrap  *upw = &uprobe_lists[i];
        if(upw->target_inode && upw->valid){
            uprobe_unregister(upw->target_inode, upw->offset, &upw->uprobe_consumer);
            upw->target_inode=NULL;
        }
    }
    return ret;
}

void uprobe_exit(struct uprobe_wrap* uprobe_lists,size_t cnt,int uid){
    uid_t current_uid = from_kuid(&init_user_ns, current_uid());
    if(uid!=-1 && uid!=current_uid){
        print_string("uid not match,return");
        return;
    }
    for(int i=0;i<cnt;i++){
        struct uprobe_wrap  *upw = &uprobe_lists[i];
        if(upw->target_inode && upw->valid){
            uprobe_unregister(upw->target_inode, upw->offset, &upw->uprobe_consumer);
            upw->target_inode=NULL;
        };
    }
    print_string("uprobes: Unregisted uprobe");
}