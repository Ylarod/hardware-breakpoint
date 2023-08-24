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

static struct proc_dir_entry *proc_file = NULL;

//帮助
char *test_proc_write_usag    = {"Usage:\n"
                                    "\thw_break support cmd type: \n"
                                    "\t\t1: echo add <type> <len> <symbol> > /proc/breakpoint, add a breakpoint\n"
                                    "\t\t\t[type]:\n"
                                    "\t\t\t\t[wp1]: HW_BREAKPOINT_R\n"
                                    "\t\t\t\t[wp2]: HW_BREAKPOINT_W\n"
                                    "\t\t\t\t[wp3]: HW_BREAKPOINT_R|HW_BREAKPOINT_W\n"
                                    "\t\t\t\t[bp]:  HW_BREAKPOINT_X\n"
                                    "t\t\t[len]:[0,8] (2^3,2^31]\n"
                                    "\t\t2: echo del <symbol> > /proc/breakpoint, del a breakpoint\n"};
char *test_proc_write_example = {"Example:\n"
                                 "\tThe first step:\n"
                                 "\t\techo add wp3 4 zwf_test_value > /proc/breakpoint, add a watchpoint at "
                                 "&zwf_test_value\n"
                                 "\tThe second step:\n"
                                 "\t\techo write > /proc/breakpoint, write zwf_test_value\n"
                                 "\tThe third step:\n"
                                 "\t\techo read > /proc/breakpoint, read zwf_test_value\n"
                                 "\tThe forth step:\n"
                                 "\t\techo del zwf_test_value > /proc/breakpoint, del wawtchpoint at "
                                 "&zwf_test_value\n"};
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

u32            zwf_test_value3[32] = {0};
u32            zwf_test_value2[32] = {0};
u32            zwf_test_value1[32] = {0};
u32            zwf_test_value0[32] = {0};

static ssize_t hw_proc_write(struct file *file, const char __user *pBuf, size_t count, loff_t *pPos)
{
    char   cmdBuf[128] = {0};
    size_t ret;
    int    argc = 0, type = 0;
    char  *argv[10] = {NULL};

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

    if (strcmp("write", argv[0]) == 0)
    {
        char *end;
        int   index  = simple_strtol(argv[1], &end, 0);
        int   index1 = simple_strtol(argv[2], &end, 0);
        u32  *tmpbuf;
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
                break;
            }
        }
        printk("will write zwf_test_value%d[%d], addr = %lx\n", index, index1, &tmpbuf[index1]);
        tmpbuf[index1] = get_random_u32();
        return count;
    }
    else if (strcmp("read", argv[0]) == 0)
    {
        char *end;
        int   index  = simple_strtol(argv[1], &end, 0);
        int   index1 = simple_strtol(argv[2], &end, 0);
        u32  *tmpbuf;
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
        printk("will read zwf_test_value%d[%d], addr = %lx\n", index, index1, &tmpbuf[index1]);
        printk("zwf_test_value%d[%d] = %d\n", index, index1, tmpbuf[index1]);
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
        char *name = NULL;
        int   len  = HW_BREAKPOINT_LEN_4;
        if (argc < 3)
        {
            // printk("argc = %d\n",argc);
            goto cmdErr;
        }
        /*判断断点类型*/
        switch (strlen(argv[1]))
        {
            /*长度是2代表执行断点*/
            case 2:
            {
                type = HW_BREAKPOINT_X;
                name = argv[3];
                break;
            }
            /*长度是3代表内存断点，第三个字符是断点类型*/
            case 3:
            {
                type = argv[1][2] - '0';
                len  = (int)simple_strtoul(argv[2], NULL, 0);
                name = argv[3];
                break;
            }
            default:
            {
                goto cmdErr;
                break;
            }
        }
        /*检查断点类型是否合法*/
        if (type < 1 || type > 4)
        {
            goto cmdErr;
        }
        HW_breakpointInstallFromSymbol(name, len, type);
    }
    else if (strcmp("del", argv[0]) == 0)
    {
        if (argc != 2)
        {
            // printk("argc = %d\n",argc);
            goto cmdErr;
        }
        HW_breakpointUnInstallFromSymbol(argv[1]);
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