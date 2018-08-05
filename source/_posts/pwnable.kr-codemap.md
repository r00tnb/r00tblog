---
title: pwnable.kr-codemap
date: 2018-02-07 12:53:12
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
# 前言
这道题当时理解了逻辑，但是不知道怎么编写调试用的自动化脚本还是参考了别人的写的代码。
# 分析
ssh连上去后无法读源码，需要逆向`codemap.exe`。读取`readme`文件
```bash
codemap@ubuntu:~$ cat readme
reverse engineer the 'codemap.exe' binary, then connect to codemap daemon(nc 0 9021),
the daemon will ask you some question, provide the correct answer to get flag.

```
nc连上去后要求输入第二和第三大堆块里面的字符串，开始以为问题是随机的，试了几次确定只问了这两个堆块。那么getflag关键就是逆向`codemap.exe`，下面给出ida反编译的代码
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // esi@3
  int (***v4)(void); // eax@3
  int (***v5)(void); // edi@3
  int v6; // esi@4
  int (**v7)(void); // eax@4
  int (***v8)(void); // ecx@5
  unsigned int v9; // eax@8
  unsigned int v10; // esi@8
  char *v11; // ebx@8
  unsigned int v12; // esi@9
  char *v14; // [sp+10h] [bp-60h]@0
  unsigned int v15; // [sp+14h] [bp-5Ch]@8
  unsigned int v16; // [sp+18h] [bp-58h]@1
  unsigned int v17; // [sp+1Ch] [bp-54h]@1
  char v18; // [sp+20h] [bp-50h]@9
  int v19; // [sp+6Ch] [bp-4h]@3

  printf("I will make 1000 heap chunks with random size\n");
  printf("each heap chunk has a random string\n");
  printf("press enter to start the memory allocation\n");
  sub_4040B1();
  v17 = 0;
  v16 = 0;
  srand(0);
  while ( 1 )
  {
    v3 = 10000 * rand() % 1337;
    v4 = (int (***)(void))operator new(8u);
    v5 = v4;
    v19 = 0;
    if ( v4 )
    {
      *v4 = (int (**)(void))&off_40F2EC;
      v6 = (10000 * v3 >> 1) + 123;
      v7 = (int (**)(void))operator new(8u);
      if ( v7 )
      {
        v7[1] = (int (*)(void))v6;
        v5[1] = v7;
        v8 = v5;
      }
      else
      {
        v5[1] = 0;
        v8 = v5;
      }
    }
    else
    {
      v8 = 0;
    }
    v19 = -1;
    v9 = (**v8)();
    v10 = v9 % 0x186A0;
    v15 = v9 % 0x186A0;
    v11 = (char *)malloc(v9 % 0x186A0);
    if ( v10 >= 0x10 )
    {
      qmemcpy(&v18, "abcdefghijklmnopqrstubwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", 0x3Fu);
      v12 = 0;
      do
        v11[++v12 - 1] = *(&v18 + rand() % 62);
      while ( v12 < 0xF );
      v11[15] = 0;
      if ( v15 > v17 )
      {
        v17 = v15;
        v14 = v11;
      }
    }
    if ( ++v16 >= 0x3E8 )
      break;
    srand(v16);
  }
  printf("the allcated memory size of biggest chunk is %d byte\n", v17);
  printf("the string inside that chunk is %s\n", v14);
  printf("log in to pwnable.kr and anwer some question to get flag.\n");
  sub_4040B1();
  return 0;
}
```
程序大致逻辑是随机生成`1000`个堆块，并且每个堆块中会存放随机的字符串，最后输出最大的堆块大小和里面的字符串。可以发现程序使用的`srand`函数的种子都是固定值，那么在使用`rand`函数的时候就不是真正的随机，所以堆块的大小和字符串都是固定的。
按照题目要求，需要给1000个堆块排序找到第二和第三大堆块，这里需要知道每次循环中堆块的大小和字符串存在哪。根据题目提示在`0x403E65`处下断点并观察`ebx,eax`可以发现ebx存储的是该堆块的字符串，eax存储的是堆块的大小。
但是要获取题目所要的字符串在1000个堆块中找，手找是不可能的，只能用自动化代码。
以前看过《Python灰帽子》里面讲的有，但是没好好读现在也没啥印象了，参考[这篇writeup的代码](http://blog.csdn.net/pwd_3/article/details/75635647)用`idapython`写的
```python
#coding:utf-8
import idc
from idaapi import *

max_eax = 0
second_eax = 0
third_eax = 0
max_ebx = 0
second_ebx = 0
third_ebx = 0
ft=0
sd=0
td=0
#AddBpt(0x263E65).text:00403E65（在这一句下断点）jbe     short loc_403E6D
#在题目提示的地方前下一个断点。
StartDebugger("","","")#启动具有默认参数的调试器

for count in xrange(999): 
    code = GetDebuggerEvent(WFNE_SUSP|WFNE_CONT, -1) # 恢复执行，等待断点
    eax = GetRegValue("EAX")
    ebx = GetRegValue("EBX")

    if max_eax < eax :
        td=sd
        sd=ft
        ft=count
        third_eax = second_eax
        third_ebx = second_ebx
        second_eax = max_eax
        second_ebx = max_ebx
        max_eax = eax;  
        max_ebx = ebx;  
    elif second_eax < eax :
        td=sd
        sd=count
        third_eax = second_eax
        third_ebx = second_ebx
        second_eax = eax
        second_ebx = ebx
    elif third_eax < eax:
        td=count
        third_eax = eax
        third_ebx = ebx
Message("max eax: %d, ebx: %x, count %d, second eax: %d, ebx: %x, count %d, third eax: %d, ebx: %x, count %d\n" % (max_eax, max_ebx, ft, second_eax, second_ebx, sd, third_eax, third_ebx, td))
```
最后输出
```python
max eax: 99879, ebx: 2aa3108, str: X12nM7yCJcu0x5u, count 546,
second eax: 99679, ebx: 1e22658, str: roKBkoIZGMUKrMb, count 290, 
third eax: 99662, ebx: 2ec5b40, str: 2ckbnDUabcsMA2s, count 629
```
回答问题成功getflag
```bash
codemap@ubuntu:~$ nc 0 9021
What is the string inside 2nd biggest chunk? :
roKBkoIZGMUKrMb
Wait for 10 seconds to prevent brute-forcing...
What is the string inside 3rd biggest chunk? :
2ckbnDUabcsMA2s
Wait for 10 seconds to prevent brute-forcing...
Congratz! flag : select_eax_from_trace_order_by_eax_desc_limit_20
codemap@ubuntu:~$
```
# 总结
做了这道题我准备去好好在读一遍《Python灰帽子》。