## 已实现功能
- [x] proc通过IO物理地址查询所有ioremap的虚拟地址   
- [x] proc通过符号查询符号里的内容，常用于指针变量
- [x] proc通过符号查询符号地址
- [x] proc列出所有已经插入的断点 
- [x] 通过导出的函数使用符号或地址添加删除断点
- [x] proc通过符号和地址添加删除断点


## 使用方法

这里只介绍proc接口的使用方法，代码里使用直接调对应的函数即可，接口均已导出。具体实现见[原理解析](./doc/硬件断点驱动解析.md)。

### 添加断点

```
echo add <type> <len> <symbol>/<addr> > /proc/breakpoint, add a breakpoint
	[type]:
		[wp1]: HW_BREAKPOINT_R
		[wp2]: HW_BREAKPOINT_W
		[wp3]: HW_BREAKPOINT_R|HW_BREAKPOINT_W
		 [bp]:  HW_BREAKPOINT_X
	[len]:[0,8] (2^3,2^31]
```

使用add指令可添加一个断点，长度可以是1~2^31的任意值，驱动会自动解析入参，设置一个大于期望监控地址范围的断点。触发时会根据期望监控的地址范围，选择是否打印堆栈。重复插入相同地址的断点会失败

### 删除断点

`echo del <symbol>/<addr> > /proc/breakpoint, del a breakpoint `

删除一个断点。

### 查询符号地址或数据

`echo get ptr/val <symbol> > /proc/breakpoint, search &symbol/*(&symbol)`

有些时候想监控的地址是一个指针变量的地址的话，直接输入该符号名字，就无法监控了。所以提供了一个可以查询符号里内容的操作，可以查询指针变量里的指针。然后使用`echo add <type> <len> <addr> > /proc/breakpoint`打断点。也可以查询函数地址，然后在函数地址+N的地方设置执行断点。

### 列出所有已设置的断点

`echo show > /proc/breakpoint`

该命令用于查询所有已设置的断点，信息示例如下所示：

```
--------------------------------------------------
breakpoint[6]:														/*观察断点是6~9，执行断点是0~5*/
        type:   HW_BREAKPOINT_RW									/*断点类型*/
        name:   zwf_test_value0+0x0/0xffffffffffffda78 [hw_break]	/*断点的符号名称*/
        monit:  0xffffff8000843588--->0xffffff800084358b			/*断点期望监控的地址范围*/
        len:    4													/*断点期望监控的长度*/
        mask:   0x0													/*断点的mask掩码*/
        range:  0xffffff8000843588--->0xffffff800084358c			/*断点实际监控的地址范围*/
        size:   4													/*断点实际监控的大小*/
--------------------------------------------------
breakpoint[7]:
        type:   HW_BREAKPOINT_RW
        name:   zwf_test_value1+0x0/0xffffffffffffd9f8 [hw_break]
        monit:  0xffffff8000843608--->0xffffff8000843610
        len:    9
        mask:   0x5
        range:  0xffffff8000843600--->0xffffff800084361f
        size:   31
--------------------------------------------------
breakpoint[8]:
        type:   HW_BREAKPOINT_RW
        name:   zwf_test_value2+0x0/0xffffffffffffd978 [hw_break]
        monit:  0xffffff8000843688--->0xffffff80008436d4
        len:    77
        mask:   0x7
        range:  0xffffff8000843680--->0xffffff80008436ff
        size:   127
--------------------------------------------------
breakpoint[9]:
        type:   HW_BREAKPOINT_RW
        name:   zwf_test_value3+0x0/0xffffffffffffdb00 [hw_break]
        monit:  0xffffff8000843500--->0xffffff800084357f
        len:    128
        mask:   0x8
        range:  0xffffff8000843500--->0xffffff80008435ff
        size:   255

```

### 根据IO地址查询所有映射的虚拟地址

`echo iophy <ioaddr> > /proc/breakpoint`
该功能用于监测IO地址的更改，因为同一个IO地址可能被多个地方ioremap过，所以要监测IO地址的话就先找到该IO地址对应的所有虚拟地址。
示例：
```
/home # echo iophy 0x11030000 > /proc/breakpoint
--------------------------------------------------
VM STRUCT:
     phy addr:       0x11030000              /*该vm_struct映射的物理起始地址*/
     virt addr:      0xffffff800a135000      /*物理地址对应的虚拟地址起始地址*/
     size:           0x2000                  /*vm_struct映射的内存大小*/
0x11030000 to virt: 0xffffff800a135000          /*要查询的IO地址对应的虚拟地址*/

--------------------------------------------------
VM STRUCT:
        phy addr:       0x11020000
        virt addr:      0xffffff800c780000
        size:           0x11000
0x11030000 to virt: 0xffffff800c790000

--------------------------------------------------
VM STRUCT:
        phy addr:       0x10280000
        virt addr:      0xffffff8010000000
        size:           0x79d1000
0x11030000 to virt: 0xffffff8010db0000

```

