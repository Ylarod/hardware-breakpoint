#include "hw_breakpointApi.h"
#include <linux/version.h>
#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/mii.h>
#include <linux/mdio.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>
#include "asm/string.h"
#include "linux/printk.h"
#include "linux/slab.h"
#include "linux/stddef.h"
#include "hw_breakpoint.h"
#include <linux/random.h>
#include "hw_breakpointManage.h"

#define PROC_FILE_DEBUG "breakpoint"
#define VM_LAZY_FREE    0x02
#define VM_VM_AREA      0x04

static struct proc_dir_entry *proc_file = NULL;

//帮助
char *test_proc_write_usag    = {"Usage:\n"
                                    "\thw_break support cmd type: \n"
                                    "\t\t1: echo add <type> <len> <symbol>/<addr> > /proc/breakpoint, add a breakpoint\n"
                                    "\t\t\t[type]:\n"
                                    "\t\t\t\t[wp1]: HW_BREAKPOINT_R\n"
                                    "\t\t\t\t[wp2]: HW_BREAKPOINT_W\n"
                                    "\t\t\t\t[wp3]: HW_BREAKPOINT_R|HW_BREAKPOINT_W\n"
                                    "\t\t\t\t[bp]:  HW_BREAKPOINT_X\n"
                                    "\t\t\t[len]:[0,8] (2^3,2^31]\n"
                                    "\t\t2: echo del <symbol> > /proc/breakpoint, del a breakpoint\n"
                                    "\t\t3: echo get ptr/val <symbol> > /proc/breakpoint, search &symbol/*(&symbol)\n"
                                    "\t\t4: echo iophy <ioaddr> > /proc/breakpoint, search all of ioaddr map virt\n"};
char *test_proc_write_example = {"Example:\n"
                                 "\tThe first step:\n"
                                 "\t\techo add wp3 4 zwf_test_value0 > /proc/breakpoint, add a watchpoint at "
                                 "&zwf_test_value0\n"
                                 "\tThe second step:\n"
                                 "\t\techo write 0 0 > /proc/breakpoint, write zwf_test_value0\n"
                                 "\tThe third step:\n"
                                 "\t\techo read 0 0 > /proc/breakpoint, read zwf_test_value0\n"
                                 "\tThe forth step:\n"
                                 "\t\techo del zwf_test_value0 > /proc/breakpoint, del wawtchpoint at "
                                 "&zwf_test_value0\n"};
/*******************************************************************************
* 函数名  : print_cmd_params
* 描  述  : 打印cmd的一些参数信息
* 输  入  : - argc  :
*         : - argv[]:
* 输  出  : 无
* 返回值  : OSA_SOK  : 成功
*           OSA_EFAIL: 失败
*******************************************************************************/
void print_cmd_params(int argc, char *argv[])
{
    int loop = 0;

    for (loop = 0; loop < argc; loop++)
    {
        printk("loop:%d, %s\n", loop, argv[loop]);
    }
}

/*******************************************************************************
* 函数名  : processCmdString
* 描  述  : 处理cmd的字符串信息
* 输  入  : - pBuf   :
*         : - pArgc  :
*         : - pArgv[]:
* 输  出  : 无
* 返回值  : OSA_SOK  : 成功
*           OSA_EFAIL: 失败
*******************************************************************************/
void processCmdString(char *pBuf, int *pArgc, char *pArgv[])
{
    int   iArgc;
    char *pTmp = pBuf;

    pArgv[0]   = pBuf;
    iArgc      = 1;

    while (*pTmp)
    {
        if (' ' == *pTmp)
        {
            *pTmp          = '\0';
            pArgv[iArgc++] = pTmp + 1;
        }

        pTmp++;
    }
    *pArgc = iArgc;
    // print_cmd_params(*pArgc, pArgv);
}

static ssize_t hw_proc_read(struct file *file, char __user *pBuf, size_t count, loff_t *pPos)
{
    printk("hw_proc_read\n");

    return 0;
}

u32 zwf_test_value3[32] = {0};
u32 zwf_test_value2[32] = {0};
u32 zwf_test_value1[32] = {0};
u32 zwf_test_value0[32] = {0};

/*显示一块vm struct，以及物理地址对应的虚拟地址*/
static void HW_testShowVm(struct vm_struct *area, u64 phyAddr)
{
    printk("--------------------------------------------------\n");
    if (area->phys_addr)
    {
        printk("\tphy addr:\t0x%llx\n", area->phys_addr);
    }
    if (area->addr)
    {
        printk("\tvirt addr:\t0x%llx\n", area->addr);
    }
    if (area->size)
    {
        printk("\tsize:\t\t0x%llx\n", area->size);
    }
    if (area->addr && area->phys_addr)
    {
        printk("0x%llx to virt: 0x%llx\n", phyAddr, area->addr + phyAddr - area->phys_addr);
    }
    printk("\n");
}

/*proc 通过IO地址查询所有映射过的虚拟地址*/
static void HW_testIOPhyToVirt(char *addrB)
{
    u64 ioAddr = 0;

    if (!kernelApi.val.vmap_area_list || !kernelApi.val.vmap_area_lock)
    {
        printk("vmap_area_list or vmap_area_lock is NULL, can not get virt");
        return;
    }

    /*buf转IO地址*/
    ioAddr = simple_strtol(addrB, NULL, 0);

    /*查询所有虚拟地址*/
    struct vmap_area *va = NULL;
    spin_lock(kernelApi.val.vmap_area_lock);
    list_for_each_entry(va, kernelApi.val.vmap_area_list, list)
    {
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
        if (!(va->flags & VM_VM_AREA))
        {
            continue;
        }
#endif
        struct vm_struct *area = va->vm;
        if (!area)
        {
            continue;
        }
        if (!(area->flags & VM_IOREMAP) || area->flags & VM_UNINITIALIZED)
        {
            continue;
        }
        /*在invalid queue的数据被刷完之后再执行屏障后的读操作*/
        smp_rmb();
        /*找到了IO地址，检查要查询的IO地址是否在该IO地址范围内*/
        struct vm_struct *next = area;
        while (next)
        {
            if (next->phys_addr && next->size)
            {
                /*要查询的IO地址在其范围内*/
                if (ioAddr >= next->phys_addr && ioAddr < next->phys_addr + next->size)
                {
                    HW_testShowVm(next, ioAddr);
                }
            }
            next = next->next;
            if (next == area)
            {
                break;
            }
        }
    }
    spin_unlock(kernelApi.val.vmap_area_lock);
}

/*proc get查询*/
static int HW_testGet(char *typeB, char *nameB)
{
    u64 addr = 0;

    /*查询符号地址*/
    addr = kernelApi.fun.kallsyms_lookup_name(nameB);
    if (!addr || addr < TASK_SIZE)
    {
        printk("can not find symbol %s\n", nameB);
        return -1;
    }
    if (strcmp("ptr", typeB) == 0)
    {
        printk("&%s = 0x%llx\n", nameB, addr);
    }
    else if (strcmp("val", typeB) == 0)
    {
        printk("*(%s) = 0x%llx\n", nameB, *((u64 *)addr));
    }
    else
    {
        return -1;
    }
    return 0;
}

/*proc删除断点*/
static void HW_testDel(char *nameB)
{
    u64 uninstallAddr = 0;

    if (nameB[0] == '0' && nameB[1] == 'x')
    {
        uninstallAddr = simple_strtol(nameB, 0, 0);
    }
    if (uninstallAddr)
    {
        printk("will uninstall at 0x%llx\n", uninstallAddr);
        HW_breakpointUnInstallFromAddr(uninstallAddr);
    }
    else
    {
        printk("will uninstall at &%s\n", nameB);
        HW_breakpointUnInstallFromSymbol(nameB);
    }
}

/*proc添加断点*/
static int HW_testAdd(char *tybeB, char *lenB, char *nameB)
{
    char *name = NULL;
    int   len = HW_BREAKPOINT_LEN_4, type = 0;
    u64   installAddr = 0;

    /*判断断点类型*/
    switch (strlen(tybeB))
    {
        /*长度是2代表执行断点*/
        case 2:
        {
            type = HW_BREAKPOINT_X;
            name = nameB;
            break;
        }
        /*长度是3代表内存断点，第三个字符是断点类型*/
        case 3:
        {
            type = tybeB[2] - '0';
            len  = (int)simple_strtoul(lenB, NULL, 0);
            name = nameB;
            break;
        }
        default:
        {
            return -1;
        }
    }
    /*检查断点类型是否合法*/
    if (type < 1 || type > 4)
    {
        return -1;
    }

    if (nameB[0] == '0' && nameB[1] == 'x')
    {
        installAddr = simple_strtol(nameB, 0, 0);
    }
    if (installAddr)
    {
        printk("will install at 0x%llx\n", installAddr);
        HW_breakpointInstallFromAddr(installAddr, len, type);
    }
    else
    {
        printk("will install at &%s\n", name);
        HW_breakpointInstallFromSymbol(name, len, type);
    }
    return 0;
}

/*测试写入*/
static void HW_testReadWrite(char *cmd, char *testIndexB, char *indexB)
{
    int  index  = simple_strtol(testIndexB, NULL, 0);
    int  index1 = simple_strtol(indexB, NULL, 0);
    u32 *tmpbuf;
    switch (index)
    {
        case 0:
        {
            tmpbuf = zwf_test_value0;
            break;
        }
        case 1:
        {
            tmpbuf = zwf_test_value1;
            break;
        }
        case 2:
        {
            tmpbuf = zwf_test_value2;
            break;
        }
        case 3:
        default:
        {
            tmpbuf = zwf_test_value3;
            break;
        }
    }
    if (strcmp("write", cmd) == 0)
    {
        printk("will write zwf_test_value%d[%d], addr = %lx\n", index, index1, &tmpbuf[index1]);
        tmpbuf[index1] = get_random_u32();
    }
    else if (strcmp("read", cmd) == 0)
    {
        printk("will read zwf_test_value%d[%d], addr = %lx\n", index, index1, &tmpbuf[index1]);
        printk("zwf_test_value%d[%d] = %d\n", index, index1, tmpbuf[index1]);
    }
}

static ssize_t hw_proc_write(struct file *file, const char __user *pBuf, size_t count, loff_t *pPos)
{
    size_t ret;
    char   cmdBuf[128] = {0};
    int    argc        = 0;
    char  *argv[10]    = {NULL};

    // printk("hw_proc_write\n");

    if ((count > sizeof(cmdBuf)) || (count == 0))
    {
        printk("test proc write, count is error!\n");
        return count;
    }

    memset(cmdBuf, 0, sizeof(cmdBuf));
    ret = copy_from_user(cmdBuf, pBuf, count);
    if (0 != ret)
    {
        printk("fail to copy data from user!\n");
        return count;
    }

    //将数据的最后一个换行符改为0
    cmdBuf[count - 1] = '\0';
    memset(argv, 0, sizeof(argv));
    processCmdString(cmdBuf, &argc, argv);

    // printk("CPU = %d\n", raw_smp_processor_id());

    if (strcmp("write", argv[0]) == 0 || strcmp("read", argv[0]) == 0)
    {
        if (argc != 3)
        {
            goto cmdErr;
        }
        HW_testReadWrite(argv[0], argv[1], argv[2]);
        return count;
    }
    else if (strcmp("show", argv[0]) == 0)
    {
        HW_breakpointShowAll();
        return count;
    }
    else if (strcmp("help", argv[0]) == 0)
    {
        printk(test_proc_write_usag);
        printk(test_proc_write_example);
        return count;
    }

    if (strcmp("add", argv[0]) == 0)
    {
        if (argc != 4)
        {
            // printk("argc = %d\n",argc);
            goto cmdErr;
        }
        if (HW_testAdd(argv[1], argv[2], argv[3]))
        {
            goto cmdErr;
        }
    }
    else if (strcmp("del", argv[0]) == 0)
    {
        if (argc != 2)
        {
            // printk("argc = %d\n",argc);
            goto cmdErr;
        }
        HW_testDel(argv[1]);
    }
    else if (strcmp("get", argv[0]) == 0)
    {
        if (argc != 3)
        {
            // printk("argc = %d\n",argc);
            goto cmdErr;
        }
        if (HW_testGet(argv[1], argv[2]))
        {
            goto cmdErr;
        }
    }
    else if (strcmp("iophy", argv[0]) == 0)
    {
        if (argc != 2)
        {
            // printk("argc = %d\n",argc);
            goto cmdErr;
        }
        HW_testIOPhyToVirt(argv[1]);
    }
    else
    {
        goto cmdErr;
    }

    return count;
cmdErr:
    printk("cmd error, echo help > /proc/breakpoint\n");
    return count;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 1, 10)
static const struct proc_ops hw_proc_fops = {
    .proc_read  = hw_proc_read,
    .proc_write = hw_proc_write,
};
#else
static const struct file_operations hw_proc_fops = {
    .open  = NULL,
    .read  = hw_proc_read,
    .write = hw_proc_write,
};
#endif

int hw_proc_init(void)
{

    proc_file = proc_create(PROC_FILE_DEBUG, S_IRUGO | S_IWUGO, NULL, &hw_proc_fops);
    if (NULL == proc_file)
    {
        printk("hw proc init, Create %s proc file failed!\n", PROC_FILE_DEBUG);
        return -ENOMEM;
    }
    printk(test_proc_write_usag);
    printk(test_proc_write_example);
    return 0;
}

void hw_proc_exit(void)
{
    if (NULL != proc_file)
    {
        remove_proc_entry(PROC_FILE_DEBUG, NULL);
    }
}