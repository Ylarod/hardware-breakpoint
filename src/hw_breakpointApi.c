#include "hw_breakpointApi.h"
#include <linux/slab.h>
#include "hw_breakpoint.h"
#include "linux/capability.h"
#include "linux/cpu.h"

typedef int (*HW_remoteFunctionF)(void *);

struct HW_remoteFunctionCall {
	struct HW_breakpointInfo *p;
	HW_remoteFunctionF func;
	void *info;
	int ret;
};

static void HW_remoteFunction(void *data)
{
	struct HW_remoteFunctionCall *tfc = data;

	/*回调函数*/
	tfc->ret = tfc->func(tfc->info);
}

static int HW_cpuFunctionCall(int cpu, HW_remoteFunctionF func, void *info)
{
	struct HW_remoteFunctionCall data = {
		.p = NULL,
		.func = func,
		.info = info,
		.ret = -ENXIO, /* No such CPU */
	};

	smp_call_function_single(cpu, HW_remoteFunction, &data, 1);

	return data.ret;
}

static int HW_breakpointParse(struct HW_breakpointInfo *bp,
			      const HW_breakpointAttr *attr,
			      HW_breakpointVC *hw)
{
	int err;

	err = HW_breakpointArchParse(bp, attr, hw);
	if (err)
		return err;

	if (HW_archCheckBpInKernelspace(hw)) {
		/*
     * Don't let unprivileged users set a breakpoint in the trap
     * path to avoid trap recursion attacks.
     */
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
	}

	return 0;
}

static int HW_breakpointInfoDel(void *p)
{
	struct HW_breakpointInfo *bp = (struct HW_breakpointInfo *)p;
	return HW_breakpointUninstall(bp);
}

static int HW_breakpointInfoAdd(void *p)
{
	struct HW_breakpointInfo *bp = (struct HW_breakpointInfo *)p;
	return HW_breakpointInstall(bp);
}

static int HW_breakpointInfoInit(struct HW_breakpointInfo *bp)
{
	int err;
	HW_breakpointVC hw = {};

	err = HW_breakpointParse(bp, &bp->attr, &hw);
	if (err)
		return err;

	bp->info = hw;

	return 0;
}

static struct HW_breakpointInfo *
HW_breakpointInfoAlloc(const HW_breakpointAttr *attr, int cpu)
{
	struct HW_breakpointInfo *bp = NULL;
	int err;

	/*为bp分配内存*/
	bp = kzalloc(sizeof(*bp), GFP_KERNEL);
	if (!bp) {
		printk("bp alloc fail\n");
		return ERR_PTR(-ENOMEM);
	}

	bp->cpu = cpu;
	bp->attr = *attr;

	/*初始化bp*/
	err = HW_breakpointInfoInit(bp);
	if (err) {
		printk("HW_breakpointInfo_init fail\n");
		return ERR_PTR(err);
	}
	/*这个CPU同步函数不能在KGDB状态下调用*/
	err = HW_cpuFunctionCall(cpu, HW_breakpointInfoAdd, bp);
	if (err) {
		printk("HW_breakpointInfo_add fail\n");
		return ERR_PTR(err);
	}

	return bp;
}

static void HW_breakpointInfoFree(struct HW_breakpointInfo *bp, int cpu)
{
	HW_cpuFunctionCall(cpu, HW_breakpointInfoDel, bp);
	kfree(bp);
}

void HW_breakpointUnregister(struct HW_breakpointInfo *__percpu *bp, int state)
{
	int cpu;

	if (bp == NULL) {
		return;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	cpus_read_lock();
#else
	get_online_cpus();
#endif
	for_each_possible_cpu(cpu) {
		if (state & 1 << cpu) {
			HW_breakpointInfoFree(per_cpu(*bp, cpu), cpu);
		}
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	cpus_read_unlock();
#else
	put_online_cpus();
#endif
}

int HW_breakpointRegister(struct HW_breakpointInfo *__percpu *cpu_events,
			  HW_breakpointAttr *attr, int *state)
{
	struct HW_breakpointInfo *bp;
	int cpu;

	if (cpu_events == NULL || attr == NULL || state == NULL) {
		printk("HW_breakpointRegister para is NULL\n");
		return -1;
	}

	*state = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	cpus_read_lock();
#else
	get_online_cpus();
#endif
	for_each_online_cpu(cpu) {
		bp = HW_breakpointInfoAlloc(attr, cpu);
		if (IS_ERR(bp)) {
			printk("HW_breakpointInfo_alloc error at CPU[%d]\n",
			       cpu);
		}
		/*代表第几个CPU设置断点成功*/
		*state |= 1 << cpu;
		/*为每个CPU保存设置的断点*/
		per_cpu(*cpu_events, cpu) = bp;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	cpus_read_unlock();
#else
	put_online_cpus();
#endif

	return 0;
}
