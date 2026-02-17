#include <linux/module.h>

static int __init hello_init(void){
    pr_info("Hello, kernel!\n");
    return 0;
}

static void __exit hello_exit(void){
    pr_info("Googbye, kernel!\n");
}



module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("nuoen");
MODULE_DESCRIPTION("Simple hello module");