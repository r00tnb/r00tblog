---
title: pwnable.kr-coin1
date: 2018-01-24 12:07:00
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
## 前言
这道题考察算法，很简单，用二分发即可。
## 分析
题目大致的意思是：
有一堆硬币，其中只有一个假硬币，真硬币重10，假硬币重9。服务端会给出硬币数目（N）和询问重量的次数（C），每次询问给出要询问重量的硬币的索引，多个用空格隔开。然后服务端会返回询问的总重量。你必须在所有次数用完之后给出假硬币的索引，正确继续答题，错误则直接结束。当找出100个假硬币后会给出flag，限时30秒。

由于网络较差，根据题目建议可以直接在他的服务器上运行代码。直接找一个原来题目的ssh地址，连上去就行了。然后把代码传到/tmp目录下运行即可。
最后贴出exp
```python
#!/usr/bin/env python
# coding=utf-8

from socket import *

def getNC(s):
    tmp = s.split(' ')
    N = int(tmp[0][2:])
    C = int(tmp[1][2:].strip('\n'))
    return N,C

def work():
    sock = socket(AF_INET,SOCK_STREAM)
    sock.connect(('127.0.0.1',9007))
    print sock.recv(2048)
    for i in xrange(100):
        s = sock.recv(100)
        print '{}. {}'.format(i,s)
        N,C = getNC(s)
        left = 0
        right = N-1
        mid = (right+left)/2
        for j in xrange(C):
            coins = [str(n) for n in xrange(left,mid+1)]
            coins = ' '.join(coins)
            #print coins
            sock.send(coins+'\n')
            weit = int(sock.recv(100))
            #print weit
            if weit != (mid-left+1)*10:
                right = mid
                left = left
                mid = (right+left)/2
            else:
                left = mid+1
                right = right
                mid = (right+left)/2
        print '   answer is {}!'.format(left)
        sock.send(str(left)+'\n')
        print '   '+sock.recv(100)
    print sock.recv(1024)
    
work()
```
```
98. N=734 C=10

   answer is 220!
   Correct! (98)

99. N=93 C=7

   answer is 7!
   Correct! (99)

Congrats! get your flag
b1NaRy_S34rch1nG_1s_3asy_p3asy

shellshock@ubuntu:/tmp$ 
```
## 总结
这提考察的算法虽然很简单，但是当时还是写了半天，抽时间好好加强一下算法功底，比如多做做ACM的题目。