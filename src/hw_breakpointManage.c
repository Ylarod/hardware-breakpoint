#include "hw_breakpointManage.h"
#include "hw_breakpoint.h"
#include "linux/kallsyms.h"
#include <linux/kgdb.h>
#include <linux/module.h>

struct HW_bpManageInfo {
	struct HW_breakpointInfo **info; /*存储申请到的percpu变量*/
	HW_breakpointAttr attr; /*断点属性*/
	int mask; /*断点应用成功的CPU掩码*/
	char symbolName[KSYM_SYMBOL_LEN]; /*符号名字*/
};
struct HW_bpManage {
	struct HW_bpManageInfo wp[ARM_MAX_WRP]; /*存储观察断点*/
	struct HW_bpManageInfo bp[ARM_MAX_BRP]; /*存储执行断点*/
	int maxWpNum; /*芯片支持的最大观察断点数量*/
	int maxBpNum; /*芯片支持的最大执行断点数量*/
	int cpuMask; /*cpu掩码，代表有几个CPU可用*/
};

static struct HW_bpManage gHwManage;
extern u32 zwf_test_value;
extern u32 zwf_test_value1;

/*显示一个断点的信息*/
static void HW_breakpointShowOne(struct HW_bpManageInfo *bpInfo, int index)
{
	char type[4][30] = { "HW_BREAKPOINT_R", "HW_BREAKPOINT_W",
			     "HW_BREAKPOINT_RW", "HW_BREAKPOINT_X" };

	printk("--------------------------------------------------\n");
	/*打印第几个断点*/
	switch (bpInfo->attr.type) {
	case HW_BREAKPOINT_R:
	case HW_BREAKPOINT_W:
	case HW_BREAKPOINT_RW:
	case HW_BREAKPOINT_X: {
		printk("breakpoint[%d]:\n", index);
		break;
	}
	default: {
		printk("breakpoint[%d] type is error!\n", index);
		return;
	}
	}

	/*打印断点类型*/
	printk("\ttype: \t%s\n", type[bpInfo->attr.type - 1]);
	/*打印监控的符号名称*/
	printk("\tname: \t%s\n", bpInfo->symbolName);
	/*打印想监控的地址范围*/
	printk("\tmonit: \t0x%llx--->0x%llx\n", bpInfo->attr.addr,
	       bpInfo->attr.addr + bpInfo->attr.len - 1);
	/*打印监控的字节长度*/
	printk("\tlen: \t%d\n", bpInfo->attr.len);
	/*打印监控的地址掩码*/
	printk("\tmask: \t0x%x\n", bpInfo->attr.mask);
	/*打印实际监控的地址范围*/
	printk("\trange: \t0x%llx--->0x%llx\n", bpInfo->attr.startAddr,
	       bpInfo->attr.endAddr);
	printk("\tsize: \t%d\n", bpInfo->attr.endAddr - bpInfo->attr.startAddr);
}

/*显示所有断点*/
void HW_breakpointShowAll(void)
{
	struct HW_bpManageInfo *bpInfo = NULL;
	int i = 0;

	for (i = 0; i < gHwManage.maxBpNum; i++) {
		bpInfo = &gHwManage.bp[i];
		if (bpInfo->mask & gHwManage.cpuMask) {
			HW_breakpointShowOne(bpInfo, i);
		}
	}

	for (i = 0; i < gHwManage.maxWpNum; i++) {
		bpInfo = &gHwManage.wp[i];
		if (bpInfo->mask & gHwManage.cpuMask) {
			HW_breakpointShowOne(bpInfo, i + gHwManage.maxBpNum);
		}
	}
}

#ifdef KGDB_ENABLE
/*kgdb的操作函数*/
static int HW_breakpointInstallFromKgdb(unsigned long addr, int len,
					enum kgdb_bptype type)
{
	int bpLen = len, bpType = 0, res;

	printk("111111111111111\n");

	bpLen = max(bpLen, HW_BREAKPOINT_LEN_8);
	bpLen = min(bpLen, HW_BREAKPOINT_LEN_1);

	switch (type) {
	case BP_HARDWARE_BREAKPOINT: {
		bpType = HW_BREAKPOINT_X;
		break;
	}
	case BP_WRITE_WATCHPOINT: {
		bpType = HW_BREAKPOINT_W;
		break;
	}
	case BP_READ_WATCHPOINT: {
		bpType = HW_BREAKPOINT_R;
		break;
	}
	case BP_ACCESS_WATCHPOINT: {
		bpType = HW_BREAKPOINT_W | HW_BREAKPOINT_R;
		break;
	}
	default: {
		return -1;
	}
	}

	res = HW_breakpointInstallFromAddr(addr, bpLen, bpType);

	return res;
}

static int HW_breakpointUnInstallFromKgdb(unsigned long addr, int len,
					  enum kgdb_bptype type)
{
	HW_breakpointUnInstallFromAddr(addr);
	return 0;
}
#endif

static void HW_breakpointUninstallAll(void)
{
	struct HW_bpManageInfo *bpInfo = NULL;
	int i = 0;

	for (i = 0; i < gHwManage.maxBpNum; i++) {
		bpInfo = &gHwManage.bp[i];
		if (bpInfo->mask & gHwManage.cpuMask) {
			HW_breakpointUnregister(bpInfo->info, bpInfo->mask);
			/*清空该断点信息*/
			memset(bpInfo->symbolName, 0,
			       sizeof(bpInfo->symbolName));
			memset(&bpInfo->attr, 0, sizeof(bpInfo->attr));
			bpInfo->mask = 0;
		}
	}

	for (i = 0; i < gHwManage.maxWpNum; i++) {
		bpInfo = &gHwManage.wp[i];
		if (bpInfo->mask & gHwManage.cpuMask) {
			HW_breakpointUnregister(bpInfo->info, bpInfo->mask);
			/*清空该断点信息*/
			memset(bpInfo->symbolName, 0,
			       sizeof(bpInfo->symbolName));
			memset(&bpInfo->attr, 0, sizeof(bpInfo->attr));
			bpInfo->mask = 0;
		}
	}
}

#ifdef KGDB_ENABLE
static void HW_bpKgdbOpsRegister(void)
{
	arch_kgdb_ops.flags = 0;
	arch_kgdb_ops.set_hw_breakpoint = NULL;
	arch_kgdb_ops.remove_hw_breakpoint = NULL;
	arch_kgdb_ops.remove_all_hw_break = NULL;
}

static void HW_bpKgdbOpsUnRegister(void)
{
	arch_kgdb_ops.flags = 0;
	arch_kgdb_ops.set_hw_breakpoint = NULL;
	arch_kgdb_ops.remove_hw_breakpoint = NULL;
	arch_kgdb_ops.remove_all_hw_break = NULL;
}
#endif

static int HW_getAddrMask(u64 addr, int len)
{
	/*期望检测地址的结束地址*/
	u64 addrTmp = addr + len;
	u64 alignment_mask = 0;
	int mask, i = 0;

	/*获取基础mask*/
	mask = (int)__ilog2_u64(len);
	if ((1 << mask) < len) {
		mask = mask + 1;
	}
	for (i = 0; i < mask; i++) {
		alignment_mask |= (1 << i);
	}

	while (1) {
		if ((addr | alignment_mask) >= addrTmp) {
			break;
		}
		mask = mask + 1;
		alignment_mask |= (1 << i);
		i++;
	}

	if (mask > 31) {
		/*arm64的mask最大为0b11111*/
		mask = 31;
	}
	return mask;
}

/*从地址设置一个断点*/
int HW_breakpointInstallFromAddr(u64 addr, int len, int type)
{
	int state, i, maxNum, ret, mask = 0;
	struct HW_bpManageInfo *bpInfo;
	u64 startAddr, endAddr;
	u64 alignment_mask = 0, realLen = len, offset;

	if ((0 == addr) || (addr < TASK_SIZE)) {
		printk("HW_breakpointInstallFromAddr para is error\n");
		return -1;
	}

	switch (type) {
	case HW_BREAKPOINT_R:
	case HW_BREAKPOINT_W:
	case HW_BREAKPOINT_RW: {
		/*内存断点*/
		bpInfo = gHwManage.wp;
		maxNum = gHwManage.maxWpNum;
		if (len > 8) {
			/*要监控的字节大于8个时就要使用掩码来控制了*/
			mask = HW_getAddrMask(addr, len);
			realLen = 4;
		}
		if (mask != 0) {
			/*掩码模式监控*/
			for (i = 0; i < mask; i++) {
				alignment_mask |= (1 << i);
			}
			startAddr = addr & ~(alignment_mask);
			endAddr = addr | alignment_mask;
		} else {
			/*按长度监控*/
			alignment_mask = 0x7;
			offset = addr & alignment_mask;
			realLen = len << offset;
			if (realLen > 8) {
				realLen = 8;
			}
			startAddr = addr & ~(alignment_mask);
			endAddr = startAddr + realLen;
		}
		break;
	}
	case HW_BREAKPOINT_X: {
		/*执行断点*/
		realLen = 4;
		bpInfo = gHwManage.bp;
		maxNum = gHwManage.maxBpNum;
		alignment_mask = 0x3;
		offset = addr & alignment_mask;
		realLen = len << offset;
		if (realLen > 8) {
			realLen = 8;
		}
		startAddr = addr & ~(alignment_mask);
		endAddr = startAddr + realLen;
		break;
	}
	default: {
		/*断点类型错误*/
		printk("breakpoint type error\n");
		return -1;
	}
	}

	for (i = 0; i < maxNum; i++) {
		if ((bpInfo[i].mask & gHwManage.cpuMask) != 0) {
			/*代表断点已经设置*/
			if (bpInfo[i].attr.addr == addr) {
				printk("[install] The addr [%lx] is already set at index %d\n",
				       addr, i);
				return -1;
			}
		}
	}

	for (i = 0; i < maxNum; i++) {
		if ((bpInfo[i].mask & gHwManage.cpuMask) != 0) {
			continue;
		}
		bpInfo[i].attr.len = len;
		bpInfo[i].attr.realLen = realLen;
		bpInfo[i].attr.mask = mask;
		bpInfo[i].attr.type = type;
		bpInfo[i].attr.addr = addr;
		bpInfo[i].attr.startAddr = startAddr;
		bpInfo[i].attr.endAddr = endAddr;
		break;
	}
	if (i == maxNum) {
		printk("[install] breakpoint is full type = %x\n", type);
		return -1;
	}

	// printk("gHwManage.wp[%d].info = %lx\n", i, gHwManage.wp[i].info);
	// printk("info = %lx,attr=%lx,state=%lx\n", bpInfo[i].info, &bpInfo[i].attr,
	//        &state);
	ret = HW_breakpointRegister(bpInfo[i].info, &bpInfo[i].attr, &state);
	if (ret) {
		goto clear;
	}
	/*代表有多少CPU注册成了该断点*/
	bpInfo[i].mask = state;
	memset(bpInfo[i].symbolName, 0, sizeof(bpInfo[i].symbolName));
	sprint_symbol(bpInfo[i].symbolName, addr);
	HW_breakpointShowOne(&bpInfo[i], i);
	return 0;
clear:
	printk("HW_breakpointInstallFromAddr [%lx] error\n", addr);
	/*清除attr信息*/
	memset(&bpInfo[i].attr, 0, sizeof(bpInfo[i].attr));
	memset(bpInfo[i].symbolName, 0, sizeof(bpInfo[i].symbolName));
	bpInfo[i].mask = 0;
	return -1;
}
EXPORT_SYMBOL(HW_breakpointInstallFromAddr);

/*从符号设置一个断点*/
int HW_breakpointInstallFromSymbol(char *name, int len, int type)
{
	int ret = 0;
	u64 addr = 0;

	if ((NULL == name) || (HW_BREAKPOINT_INVALID == type)) {
		printk("HW_breakpointInstallFromSymbol para is error\n");
		return -1;
	}

	addr = kernelApi.fun.kallsyms_lookup_name(name);
	if (0 == addr) {
		/*无法找到该符号的地址*/
		printk("Can not find the symbol, name: %s\n", name);
		return -1;
	}

	ret = HW_breakpointInstallFromAddr(addr, len, type);
	if (ret) {
		printk("HW_breakpointInstallFromSymbol error [%s]\n", name);
		return -1;
	}

	return 0;
}
EXPORT_SYMBOL(HW_breakpointInstallFromSymbol);

void HW_breakpointUnInstallFromAddr(u64 addr)
{
	int i = 0;
	struct HW_bpManageInfo *bpInfo = NULL;

	/*遍历查找和addr相同的断点地址*/
	/*查找breakpoint*/
	for (i = 0; i < gHwManage.maxBpNum; i++) {
		if (gHwManage.bp[i].mask & gHwManage.cpuMask) {
			if (gHwManage.bp[i].attr.addr == addr) {
				bpInfo = &gHwManage.bp[i];
				printk("[uninstall] find addr: bp[%d]\n", i);
				break;
			}
		}
	}
	/*查找watchpoint*/
	for (i = 0; (i < gHwManage.maxWpNum) && (bpInfo == NULL); i++) {
		if (gHwManage.wp[i].mask & gHwManage.cpuMask) {
			if (gHwManage.wp[i].attr.addr == addr) {
				bpInfo = &gHwManage.wp[i];
				printk("[uninstall] find addr: wp[%d]\n", i);
				break;
			}
		}
	}
	if (NULL == bpInfo) {
		printk("HW_breakpointUnInstallFromAddr fail,can not find addr:0x%lx\n",
		       addr);
		return;
	}
	HW_breakpointUnregister(bpInfo->info, bpInfo->mask);
	/*清空该断点信息*/
	memset(bpInfo->symbolName, 0, sizeof(bpInfo->symbolName));
	memset(&bpInfo->attr, 0, sizeof(bpInfo->attr));
	bpInfo->mask = 0;
}
EXPORT_SYMBOL(HW_breakpointUnInstallFromAddr);

void HW_breakpointUnInstallFromSymbol(char *name)
{
	u64 addr = 0;

	if (NULL == name) {
		printk("HW_breakpointUnInstallFromSymbol para is error\n");
		return;
	}

	addr = kernelApi.fun.kallsyms_lookup_name(name);
	if (0 == addr) {
		/*无法找到该符号的地址*/
		printk("[uninstall] Can not find the symbol, name: %s\n", name);
		return;
	}
	HW_breakpointUnInstallFromAddr(addr);
}
EXPORT_SYMBOL(HW_breakpointUnInstallFromSymbol);

/*断点管理去初始化*/
void HW_bpManageDeInit(void)
{
	int i = 0;

	HW_breakpointUninstallAll();

#ifdef KGDB_ENABLE
	HW_bpKgdbOpsUnRegister();
#endif
	for (i = 0; i < gHwManage.maxWpNum; i++) {
		free_percpu(gHwManage.wp[i].info);
	}

	for (i = 0; i < gHwManage.maxBpNum; i++) {
		free_percpu(gHwManage.bp[i].info);
	}
}

/*断点管理初始化*/
int HW_bpManageInit(void)
{
	int cpu = -1, i = 0;
	struct HW_breakpointInfo *__percpu *bp = NULL;

	/*获取断点的数量*/
	gHwManage.maxBpNum = HW_getBreakpointNum(TYPE_INST);
	gHwManage.maxWpNum = HW_getBreakpointNum(TYPE_DATA);

	/*获取CPU数量*/
	for_each_online_cpu(cpu) {
		gHwManage.cpuMask |= 1 << cpu;
	}
	printk("CPU MASK =  %x\n", gHwManage.cpuMask);

	/*为每个断点申请percpu内存*/
	for (i = 0; i < gHwManage.maxWpNum; i++) {
		bp = alloc_percpu(typeof(*bp));
		if (!bp) {
			printk("wp alloc_percpu fail\n");
			goto free;
		}
		gHwManage.wp[i].info = bp;
		bp = NULL;
	}
	for (i = 0; i < gHwManage.maxBpNum; i++) {
		bp = alloc_percpu(typeof(*bp));
		if (!bp) {
			printk("wp alloc_percpu fail\n");
			goto free;
		}
		gHwManage.bp[i].info = bp;
		bp = NULL;
	}

#ifdef KGDB_ENABLE
	HW_bpKgdbOpsRegister();
#endif

	return 0;

free:
	HW_bpManageDeInit();
	return -1;
}
