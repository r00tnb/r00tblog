---
title: pwnable.kr-collision
date: 2017-12-08 12:55:00
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
## 分析
查看源码`col.c`
```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
}

int main(int argc, char* argv[]){
        if(argc<2){
                printf("usage : %s [passcode]\n", argv[0]);
                return 0;
        }
        if(strlen(argv[1]) != 20){
                printf("passcode length should be 20 bytes\n");
                return 0;
        }

        if(hashcode == check_password( argv[1] )){
                system("/bin/cat flag");
                return 0;
        }
        else
                printf("wrong passcode.\n");
        return 0;
}

```
`check_password`函数对传入的字符串指针强制转换为`int`类型，然后将前5个整数相加返回。
最后判断`hashcode`是否与返回结果相等。
源码还是比较简单的，只要构造好程序的传入参数就行了，payload有很多，但要注意一些会影响传入和运算的特殊字符如`\x00,\x09`等。
我的做法是将前16个字节置为1最后算出一个整数，payload为
```
./col `python -c "print '\x01'*16+'\xE8\x05\xD9\x1D'"`
```
```
col@ubuntu:~$ ./col `python -c "print '\x01'*16+'\xE8\x05\xD9\x1D'"`
daddy! I just managed to create a hash collision :)
col@ubuntu:~$ 

```