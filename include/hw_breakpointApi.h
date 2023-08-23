#ifndef _MY_HW_BREAKPOINT_H
#define _MY_HW_BREAKPOINT_H

#include "hw_breakpoint.h"

struct HW_breakpointInfo
{
    int               cpu;
    HW_breakpointAttr attr;
    HW_breakpointVC   info;
};

static inline HW_breakpointVC *HW_counterArchbp(struct HW_breakpointInfo *bp)
{
    return &bp->info;
}


int  HW_getBreakpointNum(int type);
int  HW_breakpointArchParse(struct HW_breakpointInfo *bp, const HW_breakpointAttr *attr, HW_breakpointVC *hw);
int  HW_breakpointInstall(struct HW_breakpointInfo *bp);
int  HW_breakpointUninstall(struct HW_breakpointInfo *bp);
int  HW_breakpointReinstall(struct pt_regs *regs);
int  HW_archCheckBpInKernelspace(HW_breakpointVC *hw);
int  HW_breakpointRegister(struct HW_breakpointInfo *__percpu *cpu_events, HW_breakpointAttr *attr, int *state);
void HW_breakpointUnregister(struct HW_breakpointInfo *__percpu *bp, int state);

#endif
