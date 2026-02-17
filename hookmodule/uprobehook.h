#include "linux/types.h"
#include "linux/uprobes.h"


#define UPROBEHOOK(_target_path,_symbol_name,_uprobe_consumer_handler,_uprobe_consumer_ret_handler,_valid) { \
    .target_path = (_target_path), \
    .symbol_name = (_symbol_name), \
    .uprobe_consumer = { \
        .handler = (_uprobe_consumer_handler), \
        .ret_handler = (_uprobe_consumer_ret_handler), \
    }, \
    .valid = (_valid), \
}


struct uprobe_wrap{
    char* target_path;
    char* symbol_name;
    struct uprobe_consumer uprobe_consumer;
    struct inode *target_inode;
    unsigned long offset;
    bool valid;
};

void print_string(char *str);

int uprobe_init(struct uprobe_wrap* uprobe_lists,size_t cnt,int uid);
void uprobe_exit(struct uprobe_wrap* uprobe_lists,size_t cnt,int uid);

