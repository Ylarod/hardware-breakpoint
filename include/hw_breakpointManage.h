#ifndef _HW_BREAKPOINT_MANAGE_H
#define _HW_BREAKPOINT_MANAGE_H

// #define KGDB_ENABLE

#include "hw_breakpointApi.h"

int HW_bpManageInit(void);
void HW_bpManageDeInit(void);
void HW_breakpointShowAll(void);
int HW_breakpointInstallFromAddr(u64 addr, int len, int type);
void HW_breakpointUnInstallFromAddr(u64 addr);
int HW_breakpointInstallFromSymbol(char *name, int len, int type);
void HW_breakpointUnInstallFromSymbol(char *name);

#endif
