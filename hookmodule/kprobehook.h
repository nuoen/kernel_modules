#include <linux/kprobes.h>


typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

static bool inited=false;

/** 
struct kprobe {
	struct hlist_node hlist;

	* list of kprobes for multi-handler support *
	struct list_head list;

	*count the number of times this probe was temporarily disarmed *
	unsigned long nmissed;

	* location of the probe point *
	kprobe_opcode_t *addr;

	* Allow user to indicate symbol name of the probe point *
	const char *symbol_name;

	* Offset into the symbol *
	unsigned int offset;

	* Called before addr is executed. *
	kprobe_pre_handler_t pre_handler;

	* Called after addr is executed, unless... *
	kprobe_post_handler_t post_handler;

	* Saved opcode (which has been replaced with breakpoint) *
	kprobe_opcode_t opcode;

	* copy of the original instruction *
	struct arch_specific_insn ainsn;

	*
	 * Indicates various status flags.
	 * Protected by kprobe_mutex after this kprobe is registered.
	 *
	u32 flags;
};
*/

/* Hook 定义宏 */
#define KPROBEHOOK(_symbol, _pre_handler, _post_handler,_valid) \
    {                                   \
        .kp = {                         \
            .symbol_name  = (_symbol),  \
            .pre_handler  = (_pre_handler),     \
            .post_handler = (_post_handler),    \
        },                              \
        .valid = _valid,                  \
    }

struct kprobe_wrap{
  struct kprobe kp;
  bool valid;
};

struct kretprobe_data {
    int original_ptrace;
    long original_state;
    struct task_struct *task;
    int sequence_id;
};

/**
struct kretprobe {
	struct kprobe kp;
	kretprobe_handler_t handler;
	kretprobe_handler_t entry_handler;
	int maxactive;
	int nmissed;
	size_t data_size;
#ifdef CONFIG_KRETPROBE_ON_RETHOOK
	struct rethook *rh;
#else
	struct freelist_head freelist;
	struct kretprobe_holder *rph;
#endif
};

*/

#define KRETPROBEHOOK(_ret_handler, _entery_handler,_data_size,_symbol_name,_valid) \
	{     \
		.kretp = {                      \
			.handler = (_ret_handler),  \
			.entry_handler = (_entery_handler), \
			.data_size  = (_data_size),       \
			.maxactive = 20,       \
			.kp = {                     \
			  .symbol_name  = (_symbol_name) \
			},                          \
		},                              \
		.valid = (_valid),                \
	}

struct kretprobe_wrap{
  struct kretprobe kretp;
  bool valid;
};

int kprobehook_init(struct kprobe_wrap* kprobe_list,size_t kprobe_cnt,
    struct kretprobe_wrap* kretprobe_list,size_t kretporbe_cnt);
void kprobehook_exit(struct kprobe_wrap* kprobe_list,size_t kprobe_cnt,
    struct kretprobe_wrap* kretprobe_list,size_t kretporbe_cnt);
unsigned long lookup_name(const char *name);
