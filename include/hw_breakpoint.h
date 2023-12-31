#ifndef __ASM_HW_BREAKPOINT_H
#define __ASM_HW_BREAKPOINT_H

#include "asm-generic/int-ll64.h"
#include "asm/virt.h"
#include <asm/debug-monitors.h>
#include "linux/spinlock_types.h"
#include <linux/version.h>

/* Privilege Levels */
#define AARCH64_BREAKPOINT_EL1 1
#define AARCH64_BREAKPOINT_EL0 2

#define DBG_HMC_HYP (1 << 13)

/* Breakpoint */
#define ARM_BREAKPOINT_EXECUTE 0

/* Watchpoints */
#define ARM_BREAKPOINT_LOAD 1
#define ARM_BREAKPOINT_STORE 2
#define AARCH64_ESR_ACCESS_MASK (1 << 6)

/* Lengths */
#define ARM_BREAKPOINT_LEN_1 0x1
#define ARM_BREAKPOINT_LEN_2 0x3
#define ARM_BREAKPOINT_LEN_3 0x7
#define ARM_BREAKPOINT_LEN_4 0xf
#define ARM_BREAKPOINT_LEN_5 0x1f
#define ARM_BREAKPOINT_LEN_6 0x3f
#define ARM_BREAKPOINT_LEN_7 0x7f
#define ARM_BREAKPOINT_LEN_8 0xff

/* Kernel stepping */
#define ARM_KERNEL_STEP_NONE 0
#define ARM_KERNEL_STEP_ACTIVE 1
#define ARM_KERNEL_STEP_SUSPEND 2

/*
 * Limits.
 * Changing these will require modifications to the register accessors.
 */
#define ARM_MAX_BRP 16
#define ARM_MAX_WRP 16

/* Virtual debug register bases. */
#define AARCH64_DBG_REG_BVR 0
#define AARCH64_DBG_REG_BCR (AARCH64_DBG_REG_BVR + ARM_MAX_BRP)
#define AARCH64_DBG_REG_WVR (AARCH64_DBG_REG_BCR + ARM_MAX_BRP)
#define AARCH64_DBG_REG_WCR (AARCH64_DBG_REG_WVR + ARM_MAX_WRP)

/* Debug register names. */
#define AARCH64_DBG_REG_NAME_BVR bvr
#define AARCH64_DBG_REG_NAME_BCR bcr
#define AARCH64_DBG_REG_NAME_WVR wvr
#define AARCH64_DBG_REG_NAME_WCR wcr

/* Accessor macros for the debug registers. */
#define AARCH64_DBG_READ(N, REG, VAL)                 \
	do {                                          \
		VAL = read_sysreg(dbg##REG##N##_el1); \
	} while (0)

#define AARCH64_DBG_WRITE(N, REG, VAL)                \
	do {                                          \
		write_sysreg(VAL, dbg##REG##N##_el1); \
	} while (0)

enum {
	HW_BREAKPOINT_LEN_1 = 1,
	HW_BREAKPOINT_LEN_2 = 2,
	HW_BREAKPOINT_LEN_3 = 3,
	HW_BREAKPOINT_LEN_4 = 4,
	HW_BREAKPOINT_LEN_5 = 5,
	HW_BREAKPOINT_LEN_6 = 6,
	HW_BREAKPOINT_LEN_7 = 7,
	HW_BREAKPOINT_LEN_8 = 8,
};

enum {
	HW_BREAKPOINT_EMPTY = 0,
	HW_BREAKPOINT_R = 1,
	HW_BREAKPOINT_W = 2,
	HW_BREAKPOINT_RW = HW_BREAKPOINT_R | HW_BREAKPOINT_W,
	HW_BREAKPOINT_X = 4,
	HW_BREAKPOINT_INVALID = HW_BREAKPOINT_RW | HW_BREAKPOINT_X,
};

enum bp_type_idx { TYPE_INST = 0, TYPE_DATA = 1, TYPE_MAX };

typedef struct HW_breakpointAttr {
	u32 type; /*断点类型*/
	u64 addr; /*断点期望监控的地址*/
	u64 startAddr; /*断点实际监控的起始地址*/
	u64 endAddr; /*断点实际监控的结束*/
	u64 len; /*断点期望监控的长度*/
	u64 realLen; /*实际写入断点寄存器的len*/
	u32 mask; /*断点的mask码，区别于len，可以监控更大的地址范围*/
	u64 disabled : 1, //63bit
		reserved : 63; //0~62bit
} HW_breakpointAttr;

typedef struct HW_breakpointCtrlReg {
	u32 reserved2 : 3, //29~31bit, 保留位
		mask : 5, //24~28bit, 地址掩码，mask=0b11111时(屏蔽2^0b11111位低地址),最大支持2G的地址监控, 最小8字节
		reserved1 : 3, //21~23bit, 保留位
		wt : 1, //20bit, watchpointtype, Unlinked(0)/linked(1) data address match.
		lbn : 4, //16~19bit, wt设置时才需要设置，跟链接断点有关
		ssc : 2, //14,15bit, 安全状态控制，控制什么状态才会监听断点事件
		hmc : 1, //13bit, 结合上述字段使用
		len : 8, //5~12bit, 控制watchpoint监控的字节数量, 每一位代表1字节，最大8字节
		type : 2, //3~4bit， 断点类型: breakpoint/watchpoint
		privilege : 2, //1~2bit, 上次断点设置时的el等级，配合ssc, hmc使用
		enabled : 1; //0bit, watchpoint使能
} HW_breakpointCtrlReg;

typedef struct HW_breakpointVC {
	u64 address;
	u64 trigger;
	HW_breakpointCtrlReg ctrl;
} HW_breakpointVC;

/*以下接口皆是从Kernel中导出*/
struct fault_info {
	int (*fn)(unsigned long addr, unsigned int esr, struct pt_regs *regs);
	int sig;
	int code;
	const char *name;
};
typedef struct HW_kernelApi {
	struct {
		unsigned long (*kallsyms_lookup_name)(
			const char *name); /*根据符号查询地址函数*/
		void (*register_step_hook)(
			struct step_hook *hook); /*注册step调试异常hook的函数*/
		void (*unregister_step_hook)(
			struct step_hook
				*hook); /*取消注册step调试异常hook的函数*/
		void (*enable_debug_monitors)(
			enum dbg_active_el el); /*使能debug异常*/
		void (*disable_debug_monitors)(
			enum dbg_active_el el); /*失能debug异常*/
		int (*kernel_active_single_step)(void); /*单步调试是否激活*/
		void (*kernel_enable_single_step)(
			struct pt_regs *regs); /*使能单步调试异常*/
		void (*kernel_disable_single_step)(void); /*失能单步调试异常*/
		u64 (*read_sanitised_ftr_reg)(u32 id); /*读ftr寄存器*/
		void (*show_regs)(struct pt_regs *); /*显示堆栈*/
		void (*dump_backtrace)(struct pt_regs *regs,
				       struct task_struct *tsk); /**/
		void (*do_bad)(
			unsigned long addr, unsigned int esr,
			struct pt_regs *regs); /*调试异常的默认中断处理函数*/
	} __aligned(128) fun;
	struct {
#ifdef CONFIG_CPU_PM
		u64 *hw_breakpoint_restore; /*cpu从调试暂停恢复运行时执行的函数*/
		u64 default_hw_breakpoint_restore; /*接管之前的函数地址*/
#endif
		struct fault_info *
			debug_fault_info; /*接管硬件断点调试异常中断，替换回调函数*/
		struct fault_info default_fault_info[2]; /*接管之前的数据信息*/
		spinlock_t *vmap_area_lock; /*内核vm spinlock*/
		struct list_head *
			vmap_area_list /*内核vm链表，所有虚拟内存都在这个链表里*/
	} __aligned(128) val;

} HW_kernelApi;

extern HW_kernelApi kernelApi;

/*组装reg*/
static inline u32 HW_encodeCtrlReg(HW_breakpointCtrlReg ctrl)
{
	u32 val = (ctrl.mask << 24) | (ctrl.len << 5) | (ctrl.type << 3) |
		  (ctrl.privilege << 1) | ctrl.enabled;

	if (is_kernel_in_hyp_mode() && ctrl.privilege == AARCH64_BREAKPOINT_EL1)
		val |= DBG_HMC_HYP;

	return val;
}

static inline void HW_decodeCtrlReg(u32 reg, HW_breakpointCtrlReg *ctrl)
{
	ctrl->enabled = reg & 0x1;
	reg >>= 1;
	ctrl->privilege = reg & 0x3;
	reg >>= 2;
	ctrl->type = reg & 0x3;
	reg >>= 2;
	ctrl->len = reg & 0xff;
	reg >>= 19;
	ctrl->mask = reg & 0x1f;
}

/* Determine number of BRP registers available. */
static inline int HW_getNumBrps(void)
{
	u64 dfr0 = kernelApi.fun.read_sanitised_ftr_reg(SYS_ID_AA64DFR0_EL1);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	return 1 + cpuid_feature_extract_unsigned_field(
			   dfr0, ID_AA64DFR0_EL1_BRPs_SHIFT);
#else
	return 1 + cpuid_feature_extract_unsigned_field(dfr0,
							ID_AA64DFR0_BRPS_SHIFT);
#endif
}

/* Determine number of WRP registers available. */
static inline int HW_getNumWrps(void)
{
	u64 dfr0 = kernelApi.fun.read_sanitised_ftr_reg(SYS_ID_AA64DFR0_EL1);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	return 1 + cpuid_feature_extract_unsigned_field(
			   dfr0, ID_AA64DFR0_EL1_BRPs_SHIFT);
#else
	return 1 + cpuid_feature_extract_unsigned_field(dfr0,
							ID_AA64DFR0_WRPS_SHIFT);
#endif
}

#endif