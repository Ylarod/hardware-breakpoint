#include "hw_breakpoint.h"
#include <linux/module.h>
#include "asm/uaccess.h"
#include <asm-generic/kprobes.h>
#include "hw_breakpointApi.h"
#include "hw_proc.h"
#include "hw_breakpointManage.h"
#include "linux/kallsyms.h"
#include "linux/slab.h"

enum hw_breakpoint_ops
{
    HW_BREAKPOINT_INSTALL,
    HW_BREAKPOINT_UNINSTALL,
    HW_BREAKPOINT_RESTORE
};

/* Breakpoint currently in use for each BRP. */
static DEFINE_PER_CPU(struct HW_breakpointInfo *, bp_on_reg[ARM_MAX_BRP]);

/* Watchpoint currently in use for each WRP. */
static DEFINE_PER_CPU(struct HW_breakpointInfo *, wp_on_reg[ARM_MAX_WRP]);

/* Currently stepping a per-CPU kernel breakpoint. */
static DEFINE_PER_CPU(int, stepping_kernel_bp);

/* Number of BRP/WRP registers on this CPU. */
static int   core_num_brps;
static int   core_num_wrps;

HW_kernelApi kernelApi;

/*获取断点数量*/
int HW_getBreakpointNum(int type)
{
    /*
     * We can be called early, so don't rely on
     * our static variables being initialised.
     */
    switch (type)
    {
        case TYPE_INST:
            return HW_getNumBrps();
        case TYPE_DATA:
            return HW_getNumWrps();
        default:
            printk("unknown slot type: %d\n", type);
            return 0;
    }
}

#define READ_WB_REG_CASE(OFF, N, REG, VAL) \
    case (OFF + N):                        \
        AARCH64_DBG_READ(N, REG, VAL);     \
        break

#define WRITE_WB_REG_CASE(OFF, N, REG, VAL) \
    case (OFF + N):                         \
        AARCH64_DBG_WRITE(N, REG, VAL);     \
        break

#define GEN_READ_WB_REG_CASES(OFF, REG, VAL) \
    READ_WB_REG_CASE(OFF, 0, REG, VAL);      \
    READ_WB_REG_CASE(OFF, 1, REG, VAL);      \
    READ_WB_REG_CASE(OFF, 2, REG, VAL);      \
    READ_WB_REG_CASE(OFF, 3, REG, VAL);      \
    READ_WB_REG_CASE(OFF, 4, REG, VAL);      \
    READ_WB_REG_CASE(OFF, 5, REG, VAL);      \
    READ_WB_REG_CASE(OFF, 6, REG, VAL);      \
    READ_WB_REG_CASE(OFF, 7, REG, VAL);      \
    READ_WB_REG_CASE(OFF, 8, REG, VAL);      \
    READ_WB_REG_CASE(OFF, 9, REG, VAL);      \
    READ_WB_REG_CASE(OFF, 10, REG, VAL);     \
    READ_WB_REG_CASE(OFF, 11, REG, VAL);     \
    READ_WB_REG_CASE(OFF, 12, REG, VAL);     \
    READ_WB_REG_CASE(OFF, 13, REG, VAL);     \
    READ_WB_REG_CASE(OFF, 14, REG, VAL);     \
    READ_WB_REG_CASE(OFF, 15, REG, VAL)

#define GEN_WRITE_WB_REG_CASES(OFF, REG, VAL) \
    WRITE_WB_REG_CASE(OFF, 0, REG, VAL);      \
    WRITE_WB_REG_CASE(OFF, 1, REG, VAL);      \
    WRITE_WB_REG_CASE(OFF, 2, REG, VAL);      \
    WRITE_WB_REG_CASE(OFF, 3, REG, VAL);      \
    WRITE_WB_REG_CASE(OFF, 4, REG, VAL);      \
    WRITE_WB_REG_CASE(OFF, 5, REG, VAL);      \
    WRITE_WB_REG_CASE(OFF, 6, REG, VAL);      \
    WRITE_WB_REG_CASE(OFF, 7, REG, VAL);      \
    WRITE_WB_REG_CASE(OFF, 8, REG, VAL);      \
    WRITE_WB_REG_CASE(OFF, 9, REG, VAL);      \
    WRITE_WB_REG_CASE(OFF, 10, REG, VAL);     \
    WRITE_WB_REG_CASE(OFF, 11, REG, VAL);     \
    WRITE_WB_REG_CASE(OFF, 12, REG, VAL);     \
    WRITE_WB_REG_CASE(OFF, 13, REG, VAL);     \
    WRITE_WB_REG_CASE(OFF, 14, REG, VAL);     \
    WRITE_WB_REG_CASE(OFF, 15, REG, VAL)

/*读寄存器*/
static u64 HW_readBreakpointReg(int reg, int n)
{
    u64 val = 0;

    switch (reg + n)
    {
        GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_BVR, AARCH64_DBG_REG_NAME_BVR, val);
        GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_BCR, AARCH64_DBG_REG_NAME_BCR, val);
        GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_WVR, AARCH64_DBG_REG_NAME_WVR, val);
        GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_WCR, AARCH64_DBG_REG_NAME_WCR, val);
        default:
            printk("attempt to read from unknown breakpoint register %d\n", n);
    }

    return val;
}
NOKPROBE_SYMBOL(HW_readBreakpointReg);

/*写寄存器*/
static void HW_writeBreakpointReg(int reg, int n, u64 val)
{
    switch (reg + n)
    {
        GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_BVR, AARCH64_DBG_REG_NAME_BVR, val);
        GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_BCR, AARCH64_DBG_REG_NAME_BCR, val);
        GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_WVR, AARCH64_DBG_REG_NAME_WVR, val);
        GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_WCR, AARCH64_DBG_REG_NAME_WCR, val);
        default:
            printk("attempt to write to unknown breakpoint register %d\n", n);
    }
    /*清空流水线，确保在执行新的指令前，之前的指令都已经完成*/
    isb();
}
NOKPROBE_SYMBOL(HW_writeBreakpointReg);

/*获取异常等级*/
static enum dbg_active_el HW_getDebugExceptionLevel(int privilege)
{
    switch (privilege)
    {
        case AARCH64_BREAKPOINT_EL0:
            return DBG_ACTIVE_EL0;
        case AARCH64_BREAKPOINT_EL1:
            return DBG_ACTIVE_EL1;
        default:
            printk("invalid breakpoint privilege level %d\n", privilege);
            return -EINVAL;
    }
}
NOKPROBE_SYMBOL(HW_getDebugExceptionLevel);

/*
判断该断点是否是兼容断点？？
内核态调用register_wide_hw_breakpoint创建断点时,task参数传递的是NULL，故此直接返回false
*/
static int HW_isCompatBp(struct HW_breakpointInfo *bp)
{
    //待实现
    return 0;
}

/**
 * HW_breakpointSlotSetup - 在断点的全局变量数组中插入/删除一个断点
 *
 * @slots: 指向全局变量数组的指针
 * @max_slots: 支持的最大断点数量
 * @bp: 要操作的断点
 * @ops: 断点的操作类型：插入/删除
 *
 * Return:
 *    成功返回操作的第几个断点
 *    -ENOSPC 没有可插入的空闲断点或要删除的断点在全局变量中搜索不到
 *    -EINVAL 错误的操作类型
 */
static int HW_breakpointSlotSetup(struct HW_breakpointInfo **slots, int max_slots, struct HW_breakpointInfo *bp,
                                  enum hw_breakpoint_ops ops)
{
    int                        i;
    struct HW_breakpointInfo **slot;

    for (i = 0; i < max_slots; ++i)
    {
        slot = &slots[i];
        switch (ops)
        {
            case HW_BREAKPOINT_INSTALL:
                if (!*slot)
                {
                    *slot = bp;
                    return i;
                }
                break;
            case HW_BREAKPOINT_UNINSTALL:
                if (*slot == bp)
                {
                    *slot = NULL;
                    return i;
                }
                break;
            case HW_BREAKPOINT_RESTORE:
                if (*slot == bp)
                    return i;
                break;
            default:
                printk("Unhandled hw breakpoint ops %d\n", ops);
                return -EINVAL;
        }
    }
    return -ENOSPC;
}

/*断点的install/uninstall*/
static int HW_breakpointControl(struct HW_breakpointInfo *bp, enum hw_breakpoint_ops ops)
{
    HW_breakpointVC           *info = HW_counterArchbp(bp);
    struct HW_breakpointInfo **slots;
    int                        i, max_slots, ctrl_reg, val_reg;
    enum dbg_active_el         dbg_el = HW_getDebugExceptionLevel(info->ctrl.privilege);
    u32                        ctrl;

    printk("the real CPU = %d\n", raw_smp_processor_id());

    if (info->ctrl.type == ARM_BREAKPOINT_EXECUTE)
    {
        /* Breakpoint */
        ctrl_reg  = AARCH64_DBG_REG_BCR;
        val_reg   = AARCH64_DBG_REG_BVR;
        slots     = this_cpu_ptr(bp_on_reg);
        max_slots = core_num_brps;
    }
    else
    {
        /* Watchpoint */
        ctrl_reg  = AARCH64_DBG_REG_WCR;
        val_reg   = AARCH64_DBG_REG_WVR;
        slots     = this_cpu_ptr(wp_on_reg);
        max_slots = core_num_wrps;
    }

    i = HW_breakpointSlotSetup(slots, max_slots, bp, ops);

    if (WARN_ONCE(i < 0, "Can't find any breakpoint slot"))
        return i;

    switch (ops)
    {
        case HW_BREAKPOINT_INSTALL:
            /*
     * Ensure debug monitors are enabled at the correct exception
     * level.
     */
            kernelApi.fun.enable_debug_monitors(dbg_el);
            /* Fall through */
        case HW_BREAKPOINT_RESTORE:
            /* Setup the address register. */
            HW_writeBreakpointReg(val_reg, i, info->address);

            /* Setup the control register. */
            ctrl = HW_encodeCtrlReg(info->ctrl);
            printk("CTRL REG = %x\n", ctrl);
            HW_writeBreakpointReg(ctrl_reg, i, ctrl);
            break;
        case HW_BREAKPOINT_UNINSTALL:
            /* Reset the control register. */
            HW_writeBreakpointReg(ctrl_reg, i, 0);

            /*
     * Release the debug monitors for the correct exception
     * level.
     */
            kernelApi.fun.disable_debug_monitors(dbg_el);
            break;
    }

    return 0;
}

/*
 * Install a perf counter breakpoint.
 */
int HW_breakpointInstall(struct HW_breakpointInfo *bp)
{
    return HW_breakpointControl(bp, HW_BREAKPOINT_INSTALL);
}

int HW_breakpointUninstall(struct HW_breakpointInfo *bp)
{
    return HW_breakpointControl(bp, HW_BREAKPOINT_UNINSTALL);
}

static int HW_getHbpLen(u8 hbp_len)
{
    unsigned int len_in_bytes = 0;

    switch (hbp_len)
    {
        case ARM_BREAKPOINT_LEN_1:
            len_in_bytes = 1;
            break;
        case ARM_BREAKPOINT_LEN_2:
            len_in_bytes = 2;
            break;
        case ARM_BREAKPOINT_LEN_3:
            len_in_bytes = 3;
            break;
        case ARM_BREAKPOINT_LEN_4:
            len_in_bytes = 4;
            break;
        case ARM_BREAKPOINT_LEN_5:
            len_in_bytes = 5;
            break;
        case ARM_BREAKPOINT_LEN_6:
            len_in_bytes = 6;
            break;
        case ARM_BREAKPOINT_LEN_7:
            len_in_bytes = 7;
            break;
        case ARM_BREAKPOINT_LEN_8:
            len_in_bytes = 8;
            break;
    }

    return len_in_bytes;
}

/*
 * Check whether bp virtual address is in kernel space.
 */
int HW_archCheckBpInKernelspace(HW_breakpointVC *hw)
{
    unsigned int  len;
    unsigned long va;

    va  = hw->address;
    len = HW_getHbpLen(hw->ctrl.len);

    return (va >= TASK_SIZE) && ((va + len - 1) >= TASK_SIZE);
}

/*
 * Extract generic type and length encodings from an arch_hw_breakpoint_ctrl.
 * Hopefully this will disappear when ptrace can bypass the conversion
 * to generic breakpoint descriptions.
 */
int HW_archGetBpGenericFields(HW_breakpointCtrlReg ctrl, int *gen_len, int *gen_type, int *offset)
{
    /* Type */
    switch (ctrl.type)
    {
        case ARM_BREAKPOINT_EXECUTE:
            *gen_type = HW_BREAKPOINT_X;
            break;
        case ARM_BREAKPOINT_LOAD:
            *gen_type = HW_BREAKPOINT_R;
            break;
        case ARM_BREAKPOINT_STORE:
            *gen_type = HW_BREAKPOINT_W;
            break;
        case ARM_BREAKPOINT_LOAD | ARM_BREAKPOINT_STORE:
            *gen_type = HW_BREAKPOINT_RW;
            break;
        default:
            return -EINVAL;
    }

    if (!ctrl.len)
        return -EINVAL;
    *offset = __ffs(ctrl.len);

    /* Len */
    switch (ctrl.len >> *offset)
    {
        case ARM_BREAKPOINT_LEN_1:
            *gen_len = HW_BREAKPOINT_LEN_1;
            break;
        case ARM_BREAKPOINT_LEN_2:
            *gen_len = HW_BREAKPOINT_LEN_2;
            break;
        case ARM_BREAKPOINT_LEN_3:
            *gen_len = HW_BREAKPOINT_LEN_3;
            break;
        case ARM_BREAKPOINT_LEN_4:
            *gen_len = HW_BREAKPOINT_LEN_4;
            break;
        case ARM_BREAKPOINT_LEN_5:
            *gen_len = HW_BREAKPOINT_LEN_5;
            break;
        case ARM_BREAKPOINT_LEN_6:
            *gen_len = HW_BREAKPOINT_LEN_6;
            break;
        case ARM_BREAKPOINT_LEN_7:
            *gen_len = HW_BREAKPOINT_LEN_7;
            break;
        case ARM_BREAKPOINT_LEN_8:
            *gen_len = HW_BREAKPOINT_LEN_8;
            break;
        default:
            return -EINVAL;
    }

    return 0;
}

/*
 * Construct an arch_hw_breakpoint from a perf_event.
 */
static int HW_archBuildBpInfo(struct HW_breakpointInfo *bp, const HW_breakpointAttr *attr, HW_breakpointVC *hw)
{
    /* Type */
    switch (attr->type)
    {
        case HW_BREAKPOINT_X:
            hw->ctrl.type = ARM_BREAKPOINT_EXECUTE;
            break;
        case HW_BREAKPOINT_R:
            hw->ctrl.type = ARM_BREAKPOINT_LOAD;
            break;
        case HW_BREAKPOINT_W:
            hw->ctrl.type = ARM_BREAKPOINT_STORE;
            break;
        case HW_BREAKPOINT_RW:
            hw->ctrl.type = ARM_BREAKPOINT_LOAD | ARM_BREAKPOINT_STORE;
            break;
        default:
            return -EINVAL;
    }

    /* Len */
    switch (attr->realLen)
    {
        case HW_BREAKPOINT_LEN_1:
            hw->ctrl.len = ARM_BREAKPOINT_LEN_1;
            break;
        case HW_BREAKPOINT_LEN_2:
            hw->ctrl.len = ARM_BREAKPOINT_LEN_2;
            break;
        case HW_BREAKPOINT_LEN_3:
            hw->ctrl.len = ARM_BREAKPOINT_LEN_3;
            break;
        case HW_BREAKPOINT_LEN_4:
            hw->ctrl.len = ARM_BREAKPOINT_LEN_4;
            break;
        case HW_BREAKPOINT_LEN_5:
            hw->ctrl.len = ARM_BREAKPOINT_LEN_5;
            break;
        case HW_BREAKPOINT_LEN_6:
            hw->ctrl.len = ARM_BREAKPOINT_LEN_6;
            break;
        case HW_BREAKPOINT_LEN_7:
            hw->ctrl.len = ARM_BREAKPOINT_LEN_7;
            break;
        case HW_BREAKPOINT_LEN_8:
            hw->ctrl.len = ARM_BREAKPOINT_LEN_8;
            break;
        default:
            return -EINVAL;
    }

    /*
     * On AArch64, we only permit breakpoints of length 4, whereas
     * AArch32 also requires breakpoints of length 2 for Thumb.
     * Watchpoints can be of length 1, 2, 4 or 8 bytes.
     */
    if (hw->ctrl.type == ARM_BREAKPOINT_EXECUTE)
    {
        /*
     * FIXME: Some tools (I'm looking at you perf) assume
     *      that breakpoints should be sizeof(long). This
     *      is nonsense. For now, we fix up the parameter
     *      but we should probably return -EINVAL instead.
     */
        hw->ctrl.len = ARM_BREAKPOINT_LEN_4;
    }
    /*地址掩码*/
    hw->ctrl.mask = attr->mask;
    /* Address */
    hw->address = attr->startAddr;

    /*
     * Privilege
     * Note that we disallow combined EL0/EL1 breakpoints because
     * that would complicate the stepping code.
     */
    if (HW_archCheckBpInKernelspace(hw))
        hw->ctrl.privilege = AARCH64_BREAKPOINT_EL1;
    else
        hw->ctrl.privilege = AARCH64_BREAKPOINT_EL0;

    /* Enabled? */
    hw->ctrl.enabled = !attr->disabled;

    return 0;
}

/*
 * 解析并配置断点信息
 */
int HW_breakpointArchParse(struct HW_breakpointInfo *bp, const HW_breakpointAttr *attr, HW_breakpointVC *hw)
{
    int ret;

    /* Build the arch_hw_breakpoint. */
    ret = HW_archBuildBpInfo(bp, attr, hw);
    if (ret)
        return ret;

    printk("ctrl.len=%x,mask=%d,enabled=%d,address=%llx\n", hw->ctrl.len, hw->ctrl.mask, hw->ctrl.enabled, hw->address);

    /*
     * Disallow per-task kernel breakpoints since these would
     * complicate the stepping code.
     */
    if (hw->ctrl.privilege == AARCH64_BREAKPOINT_EL1 && NULL)
        return -EINVAL;

    return 0;
}

/*
enable/disable一个断点
 */
static void HW_toggleBpRegisters(int reg, enum dbg_active_el el, int enable)
{
    int                        i, max_slots, privilege;
    u32                        ctrl;
    struct HW_breakpointInfo **slots;

    switch (reg)
    {
        case AARCH64_DBG_REG_BCR:
            slots     = this_cpu_ptr(bp_on_reg);
            max_slots = core_num_brps;
            break;
        case AARCH64_DBG_REG_WCR:
            slots     = this_cpu_ptr(wp_on_reg);
            max_slots = core_num_wrps;
            break;
        default:
            return;
    }

    for (i = 0; i < max_slots; ++i)
    {
        if (!slots[i])
            continue;

        privilege = HW_counterArchbp(slots[i])->ctrl.privilege;
        if (HW_getDebugExceptionLevel(privilege) != el)
            continue;

        ctrl = HW_readBreakpointReg(reg, i);
        if (enable)
            ctrl |= 0x1;
        else
            ctrl &= ~0x1;
        HW_writeBreakpointReg(reg, i, ctrl);
    }
}
NOKPROBE_SYMBOL(HW_toggleBpRegisters);

/*breakpoint回调函数*/
static int HW_breakpointHandler(unsigned long unused, unsigned int esr, struct pt_regs *regs)
{
    int                       i, *kernel_step;
    u32                       ctrl_reg;
    u64                       addr, val;
    struct HW_breakpointInfo *bp, **slots;
    // struct debug_info *debug_info;
    HW_breakpointCtrlReg ctrl;

    slots = this_cpu_ptr(bp_on_reg);
    addr  = instruction_pointer(regs);
    // debug_info = &current->thread.debug;

    for (i = 0; i < core_num_brps; ++i)
    {
        rcu_read_lock();

        bp = slots[i];

        if (bp == NULL)
            goto unlock;

        /* Check if the breakpoint value matches. */
        val = HW_readBreakpointReg(AARCH64_DBG_REG_BVR, i);
        if (val != (addr & ~0x3))
            goto unlock;

        /* Possible match, check the byte address select to confirm. */
        ctrl_reg = HW_readBreakpointReg(AARCH64_DBG_REG_BCR, i);
        HW_decodeCtrlReg(ctrl_reg, &ctrl);
        if (!((1 << (addr & 0x3)) & ctrl.len))
            goto unlock;

        HW_counterArchbp(bp)->trigger = addr;

    unlock:
        rcu_read_unlock();
    }

    HW_toggleBpRegisters(AARCH64_DBG_REG_BCR, DBG_ACTIVE_EL1, 0);
    kernel_step = this_cpu_ptr(&stepping_kernel_bp);

    if (*kernel_step != ARM_KERNEL_STEP_NONE)
        return 0;

    if (kernelApi.fun.kernel_active_single_step())
    {
        *kernel_step = ARM_KERNEL_STEP_SUSPEND;
    }
    else
    {
        *kernel_step = ARM_KERNEL_STEP_ACTIVE;
        kernelApi.fun.kernel_enable_single_step(regs);
    }
    // }

    return 0;
}
NOKPROBE_SYMBOL(HW_breakpointHandler);

/*
 * Arm64 hardware does not always report a watchpoint hit address that matches
 * one of the watchpoints set. It can also report an address "near" the
 * watchpoint if a single instruction access both watched and unwatched
 * addresses. There is no straight-forward way, short of disassembling the
 * offending instruction, to map that address back to the watchpoint. This
 * function computes the distance of the memory access from the watchpoint as a
 * heuristic for the likelyhood that a given access triggered the watchpoint.
 *
 * See Section D2.10.5 "Determining the memory location that caused a Watchpoint
 * exception" of ARMv8 Architecture Reference Manual for details.
 *
 * The function returns the distance of the address from the bytes watched by
 * the watchpoint. In case of an exact match, it returns 0.
 */
static u64 HW_getDistanceFromWatchpoint(unsigned long addr, u64 val, HW_breakpointCtrlReg *ctrl)
{
    addr = untagged_addr(addr);
    val  = untagged_addr(val);
    return addr - val;
}

/*watchpoint回调函数*/
static int HW_watchpointHandler(unsigned long addr, unsigned int esr, struct pt_regs *regs)
{
    int                       i, *kernel_step, access, closest_match = -1;
    u64                       min_dist = -1, dist;
    u32                       ctrl_reg;
    u64                       val, startAddr, endAddr;
    struct HW_breakpointInfo *wp, **slots;
    HW_breakpointVC          *info = NULL;
    HW_breakpointCtrlReg      ctrl;

    slots = this_cpu_ptr(wp_on_reg);
    // debug_info = &current->thread.debug;

    /*寻找最近的触发地址*/
    rcu_read_lock();
    for (i = 0; i < core_num_wrps; ++i)
    {
        wp = slots[i];
        if (wp == NULL)
            continue;

        /*检测触发的断点类型*/
        access = (esr & AARCH64_ESR_ACCESS_MASK) ? HW_BREAKPOINT_W : HW_BREAKPOINT_R;
        if (!(access /*& hw_breakpoint_type(wp)待实现，将wp与attr->type关联*/))
            continue;

        /* Check if the watchpoint value and byte select match. */
        val      = HW_readBreakpointReg(AARCH64_DBG_REG_WVR, i);
        ctrl_reg = HW_readBreakpointReg(AARCH64_DBG_REG_WCR, i);
        HW_decodeCtrlReg(ctrl_reg, &ctrl);
        dist = HW_getDistanceFromWatchpoint(addr, wp->attr.addr, &ctrl);
        if (dist < min_dist)
        {
            min_dist      = dist;
            closest_match = i;
        }
        /* Is this an exact match? */
        if (dist != 0)
            continue;
        info          = HW_counterArchbp(wp);
        info->trigger = addr;
        closest_match = i;
    }
    if (min_dist > 0 && min_dist != -1)
    {
        /* No exact match found. */
        wp            = slots[closest_match];
        info          = HW_counterArchbp(wp);
        info->trigger = addr;
    }
    rcu_read_unlock();

    /*
     * We always disable EL0 watchpoints because the kernel can
     * cause these to fire via an unprivileged access.
     */
    HW_toggleBpRegisters(AARCH64_DBG_REG_WCR, DBG_ACTIVE_EL1, 0);
    kernel_step = this_cpu_ptr(&stepping_kernel_bp);

    // printk("watchpoint is trigger,addr=0x%lx, close = %d, dist = %d, mindist = %d, info = %lx\n",
    //        addr, closest_match, dist, min_dist);

    if (*kernel_step != ARM_KERNEL_STEP_NONE)
        return 0;

    if (kernelApi.fun.kernel_active_single_step())
    {
        *kernel_step = ARM_KERNEL_STEP_SUSPEND;
    }
    else
    {
        *kernel_step = ARM_KERNEL_STEP_ACTIVE;
        /*在当前regs触发step异常*/
        kernelApi.fun.kernel_enable_single_step(regs);
    }
    // }

    return 0;
}
NOKPROBE_SYMBOL(HW_watchpointHandler);

/*
 * 单步异常回调函数中调用，重新开启已经关闭的断点
 */
int HW_breakpointReinstall(struct pt_regs *regs)
{
    // struct debug_info *debug_info = &current->thread.debug;
    int handled_exception = 0, *kernel_step;

    /*获取当前CPU有没有使能signle step*/
    kernel_step = this_cpu_ptr(&stepping_kernel_bp);

    if (*kernel_step != ARM_KERNEL_STEP_NONE)
    {
        HW_toggleBpRegisters(AARCH64_DBG_REG_BCR, DBG_ACTIVE_EL1, 1);
        HW_toggleBpRegisters(AARCH64_DBG_REG_WCR, DBG_ACTIVE_EL1, 1);

        if (*kernel_step != ARM_KERNEL_STEP_SUSPEND)
        {
            kernelApi.fun.kernel_disable_single_step();
            handled_exception = 1;
        }
        else
        {
            handled_exception = 0;
        }

        *kernel_step = ARM_KERNEL_STEP_NONE;
    }

    return !handled_exception;
}
NOKPROBE_SYMBOL(HW_breakpointReinstall);

/*
 * 断点复位函数
 */
static int HW_breakpointReset(unsigned int cpu)
{
    int                        i;
    struct HW_breakpointInfo **slots;
    /*
     * When a CPU goes through cold-boot, it does not have any installed
     * slot, so it is safe to share the same function for restoring and
     * resetting breakpoints; when a CPU is hotplugged in, it goes
     * through the slots, which are all empty, hence it just resets control
     * and value for debug registers.
     * When this function is triggered on warm-boot through a CPU PM
     * notifier some slots might be initialized; if so they are
     * reprogrammed according to the debug slots content.
     */
    for (slots = this_cpu_ptr(bp_on_reg), i = 0; i < core_num_brps; ++i)
    {
        if (slots[i])
        {
            HW_breakpointControl(slots[i], HW_BREAKPOINT_RESTORE);
        }
        else
        {
            HW_writeBreakpointReg(AARCH64_DBG_REG_BCR, i, 0UL);
            HW_writeBreakpointReg(AARCH64_DBG_REG_BVR, i, 0UL);
        }
    }

    for (slots = this_cpu_ptr(wp_on_reg), i = 0; i < core_num_wrps; ++i)
    {
        if (slots[i])
        {
            HW_breakpointControl(slots[i], HW_BREAKPOINT_RESTORE);
        }
        else
        {
            HW_writeBreakpointReg(AARCH64_DBG_REG_WCR, i, 0UL);
            HW_writeBreakpointReg(AARCH64_DBG_REG_WVR, i, 0UL);
        }
    }

    return 0;
}

static void HW_showRegs(struct pt_regs *regs)
{
    int                       i = 0;
    struct HW_breakpointInfo *wp, **slots;

    rcu_read_lock();
    slots = this_cpu_ptr(bp_on_reg);
    for (i = 0; i < core_num_brps; ++i)
    {
        wp = slots[i];
        if (wp == NULL)
            continue;
        if (wp->info.trigger)
        {
            /*只要触发了就打印信息*/
            printk("bp is triger = 0x%llx, addr = 0x%llx, len = %d\n", wp->info.trigger, wp->attr.addr, wp->attr.len);
            kernelApi.fun.show_regs(regs);
            wp->info.trigger = 0;
        }
    }
    slots = this_cpu_ptr(wp_on_reg);
    for (i = 0; i < core_num_wrps; ++i)
    {
        wp = slots[i];
        if (wp == NULL)
            continue;
        if (!wp->info.trigger)
        {
            /*未触发跳过*/
            continue;
        }
        if (wp->info.trigger >= wp->attr.addr && wp->info.trigger < wp->attr.addr + wp->attr.len)
        {
            /*在期望检测的地址范围之内，才打印堆栈信息*/
            printk("wp is triger = 0x%llx, addr = 0x%llx, len = %d\n", wp->info.trigger, wp->attr.addr, wp->attr.len);
            kernelApi.fun.show_regs(regs);
        }
        wp->info.trigger = 0;
    }
    rcu_read_unlock();
}

/*单步异常回调函数，该函数将重新开启被关闭的断点*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
static int HW_stepBrkFn(struct pt_regs *regs, unsigned long esr)
#else
static int HW_stepBrkFn(struct pt_regs *regs, unsigned int esr)
#endif
{
    int *kernel_step;

    /*取step状态*/
    kernel_step = this_cpu_ptr(&stepping_kernel_bp);

    if (user_mode(regs) || !(*kernel_step))
        return DBG_HOOK_ERROR;

    HW_showRegs(regs);

    if (HW_breakpointReinstall(regs))
    {
        return DBG_HOOK_ERROR;
    }
#ifdef KGDB_ENABLE
    kgdb_handle_exception(0, SIGTRAP, 0, regs);
#endif

    return DBG_HOOK_HANDLED;
}
NOKPROBE_SYMBOL(HW_stepBrkFn);

static struct step_hook gHwStepHook = {.fn = HW_stepBrkFn};

/*根据名字找函数地址*/
unsigned long kaddr_lookup_name(const char *fname_raw)
{
    int           i;
    unsigned long kaddr;
    char         *fname_lookup, *fname;

    fname_lookup = kzalloc(NAME_MAX, GFP_KERNEL);
    if (!fname_lookup)
        return 0;

    fname = kzalloc(strlen(fname_raw) + 4, GFP_KERNEL);
    if (!fname)
        return 0;

    /*
   * We have to add "+0x0" to the end of our function name
   * because that's the format that sprint_symbol() returns
   * to us. If we don't do this, then our search can stop
   * prematurely and give us the wrong function address!
   */
    strcpy(fname, fname_raw);
    strcat(fname, "+0x0");

    /*获取内核代码段基地址*/
    kaddr = (unsigned long)&sprint_symbol;
    kaddr &= 0xffffffffff000000;

    /*内核符号不会超过0x100000*16的大小，所以按4字节偏移，挨个找*/
    for (i = 0x0; i < 0x400000; i++)
    {
        /*寻找地址对应的符号名称*/
        sprint_symbol(fname_lookup, kaddr);
        /*对比寻找的符号名字*/
        if (strncmp(fname_lookup, fname, strlen(fname)) == 0)
        {
            /*找到了就返回地址*/
            kfree(fname_lookup);
            kfree(fname);
            return kaddr;
        }
        /*偏移4字节*/
        kaddr += 0x04;
    }
    /*没找到地址就返回0*/
    kfree(fname_lookup);
    kfree(fname);
    return 0;
}

/*获取驱动必须的内核接口*/
static int HW_getKallsymsLookupName(void)
{
    kernelApi.fun.kallsyms_lookup_name = (void *)kaddr_lookup_name("kallsyms_lookup_name");
    if (!kernelApi.fun.kallsyms_lookup_name)
    {
        printk("get kallsyms_lookup_name fail \n");
        return -1;
    }
    return 0;
}

/*获取驱动必须的内核接口*/
static int HW_getKernelApi(void)
{
    memset(&kernelApi, 0, sizeof(kernelApi));
    if (HW_getKallsymsLookupName())
    {
        return -1;
    }
    kernelApi.val.debug_fault_info = (void *)kernelApi.fun.kallsyms_lookup_name("debug_fault_info");
    if (!kernelApi.val.debug_fault_info)
    {
        printk("get debug_fault_info fail\n");
        return -1;
    }
    // printk("debug_fault_info = %llx,name = %s\n", &kernelApi.val.debug_fault_info[0],
    //        kernelApi.val.debug_fault_info[0].name);
    // printk("debug_fault_info = %llx,name = %s\n", &kernelApi.val.debug_fault_info[2],
    //        kernelApi.val.debug_fault_info[2].name);
#ifdef CONFIG_CPU_PM
    kernelApi.val.hw_breakpoint_restore = (void *)kernelApi.fun.kallsyms_lookup_name("hw_breakpoint_restore");
    if (!kernelApi.val.hw_breakpoint_restore)
    {
        printk("get hw_breakpoint_restore fail\n");
        return -1;
    }
    // printk("hw_breakpoint_restore = %llx,%llx\n", kernelApi.val.hw_breakpoint_restore,
    //        *kernelApi.val.hw_breakpoint_restore);
#endif
    kernelApi.fun.kernel_active_single_step = (void *)kernelApi.fun.kallsyms_lookup_name("kernel_active_single_step");
    if (!kernelApi.fun.kernel_active_single_step)
    {
        printk("get kernel_active_single_step fail\n");
        return -1;
    }
    kernelApi.fun.kernel_disable_single_step = (void *)kernelApi.fun.kallsyms_lookup_name("kernel_disable_single_step");
    if (!kernelApi.fun.kernel_disable_single_step)
    {
        printk("get kernel_disable_single_step fail\n");
        return -1;
    }
    kernelApi.fun.kernel_enable_single_step = (void *)kernelApi.fun.kallsyms_lookup_name("kernel_enable_single_step");
    if (!kernelApi.fun.kernel_enable_single_step)
    {
        printk("get kernel_enable_single_step fail\n");
        return -1;
    }
    kernelApi.fun.disable_debug_monitors = (void *)kernelApi.fun.kallsyms_lookup_name("disable_debug_monitors");
    if (!kernelApi.fun.disable_debug_monitors)
    {
        printk("get disable_debug_monitors fail\n");
        return -1;
    }
    kernelApi.fun.do_bad = (void *)kernelApi.fun.kallsyms_lookup_name("do_bad");
    if (!kernelApi.fun.do_bad)
    {
        printk("get do_bad fail\n");
        return -1;
    }
    kernelApi.fun.enable_debug_monitors = (void *)kernelApi.fun.kallsyms_lookup_name("enable_debug_monitors");
    if (!kernelApi.fun.enable_debug_monitors)
    {
        printk("get enable_debug_monitors fail\n");
        return -1;
    }
    kernelApi.fun.read_sanitised_ftr_reg = (void *)kernelApi.fun.kallsyms_lookup_name("read_sanitised_ftr_reg");
    if (!kernelApi.fun.read_sanitised_ftr_reg)
    {
        printk("get read_sanitised_ftr_reg fail\n");
        return -1;
    }
    kernelApi.fun.show_regs = (void *)kernelApi.fun.kallsyms_lookup_name("show_regs");
    if (!kernelApi.fun.show_regs)
    {
        printk("get show_regs fail\n");
        return -1;
    }
    kernelApi.fun.dump_backtrace = (void *)kernelApi.fun.kallsyms_lookup_name("dump_backtrace");
    if (!kernelApi.fun.dump_backtrace)
    {
        printk("get dump_backtrace fail\n");
        return -1;
    }
    /*5.0以下内核用的是register_step_hook*/
    kernelApi.fun.register_step_hook = (void *)kernelApi.fun.kallsyms_lookup_name("register_step_hook");
    if (!kernelApi.fun.register_step_hook)
    {
        /*5.0以上内核用的是register_kernel_step_hook*/
        kernelApi.fun.register_step_hook = (void *)kernelApi.fun.kallsyms_lookup_name("register_kernel_step_hook");
        if (!kernelApi.fun.register_step_hook)
        {
            printk("get register_step_hook fail\n");
            return -1;
        }
    }
    kernelApi.fun.unregister_step_hook = (void *)kernelApi.fun.kallsyms_lookup_name("unregister_step_hook");
    if (!kernelApi.fun.unregister_step_hook)
    {
        kernelApi.fun.unregister_step_hook = (void *)kernelApi.fun.kallsyms_lookup_name("unregister_kernel_step_hook");
        if (!kernelApi.fun.unregister_step_hook)
        {
            printk("get unregister_step_hook fail\n");
            return -1;
        }
    }

    /*以下不影响驱动使用，只影响根据io地址查询虚拟地址功能*/
    kernelApi.val.vmap_area_lock = (void *)kernelApi.fun.kallsyms_lookup_name("vmap_area_lock");
    kernelApi.val.vmap_area_list = (void *)kernelApi.fun.kallsyms_lookup_name("vmap_area_list");


    return 0;
}

/*驱动初始化*/
static int __init HW_breakpointInit(void)
{
    int ret = 0;

    if (HW_getKernelApi())
    {
        return -1;
    }
    /*计算断点数量*/

    core_num_brps = HW_getNumBrps();
    core_num_wrps = HW_getNumWrps();

    printk("found %d breakpoint and %d watchpoint registers.\n", core_num_brps, core_num_wrps);

    /* 注册调试异常回调函数 */
    /*执行断点*/
    /*保存原先的变量*/
    kernelApi.val.default_fault_info[0].fn   = kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWBP].fn;
    kernelApi.val.default_fault_info[0].sig  = kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWBP].sig;
    kernelApi.val.default_fault_info[0].code = kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWBP].code;
    kernelApi.val.default_fault_info[0].name = kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWBP].name;
    /*注册新的内容*/
    kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWBP].fn   = HW_breakpointHandler;
    kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWBP].sig  = SIGTRAP;
    kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWBP].code = TRAP_HWBKPT;
    kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWBP].name = "hw-breakpoint handler";
    /*内存断点*/
    /*保存原先的变量*/
    kernelApi.val.default_fault_info[1].fn   = kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWWP].fn;
    kernelApi.val.default_fault_info[1].sig  = kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWWP].sig;
    kernelApi.val.default_fault_info[1].code = kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWWP].code;
    kernelApi.val.default_fault_info[1].name = kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWWP].name;
    /*注册新的内容*/
    kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWWP].fn   = HW_watchpointHandler;
    kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWWP].sig  = SIGTRAP;
    kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWWP].code = TRAP_HWBKPT;
    kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWWP].name = "hw-watchpoint handler";
    kernelApi.fun.register_step_hook(&gHwStepHook);
#ifdef CONFIG_CPU_PM
    /*注册cpu暂停后恢复断点的回调函数*/
    /*保存原先的变量*/
    kernelApi.val.default_hw_breakpoint_restore = *kernelApi.val.hw_breakpoint_restore;
    *kernelApi.val.hw_breakpoint_restore        = (u64)HW_breakpointReset;
#endif
    HW_bpManageInit();
    hw_proc_init();

    printk("HW_breakpointInit\n");
    return 0;
}

static void __exit HW_breakpointExit(void)
{
    hw_proc_exit();
    HW_bpManageDeInit();
#ifdef CONFIG_CPU_PM
    *kernelApi.val.hw_breakpoint_restore = kernelApi.val.default_hw_breakpoint_restore;
#endif
    kernelApi.fun.unregister_step_hook(&gHwStepHook);
    /*内存断点*/
    kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWWP].fn   = kernelApi.val.default_fault_info[1].fn;
    kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWWP].sig  = kernelApi.val.default_fault_info[1].sig;
    kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWWP].code = kernelApi.val.default_fault_info[1].code;
    kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWWP].name = kernelApi.val.default_fault_info[1].name;
    /*执行断点*/
    kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWBP].fn   = kernelApi.val.default_fault_info[0].fn;
    kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWBP].sig  = kernelApi.val.default_fault_info[0].sig;
    kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWBP].code = kernelApi.val.default_fault_info[0].code;
    kernelApi.val.debug_fault_info[DBG_ESR_EVT_HWBP].name = kernelApi.val.default_fault_info[0].name;
    printk(" HW_breakpointExit\n");
}

module_init(HW_breakpointInit);
module_exit(HW_breakpointExit);

MODULE_AUTHOR("zwf");
MODULE_DESCRIPTION("hw break point test");
MODULE_LICENSE("Dual BSD/GPL");
