---
title: pwnable.kr-crypto1
date: 2018-04-24 13:21:27
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
# 前言
这虽然不是一道二进制的题目，但是也有足够的pwn味道。
# 分析
题目是用了python写的b/s结构，代码逻辑简单。
**client.py**
```python
#!/usr/bin/python
from Crypto.Cipher import AES
import base64
import os, sys
import xmlrpclib
rpc = xmlrpclib.ServerProxy("http://localhost:9100/")

BLOCK_SIZE = 16
PADDING = '\x00'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: c.encrypt(pad(s)).encode('hex')
DecodeAES = lambda c, e: c.decrypt(e.decode('hex'))

# server's secrets
key = 'erased. but there is something on the real source code'
iv = 'erased. but there is something on the real source code'
cookie = 'erased. but there is something on the real source code'

# guest / 8b465d23cb778d3636bf6c4c5e30d031675fd95cec7afea497d36146783fd3a1
def sanitize(arg):
	for c in arg:
		if c not in '1234567890abcdefghijklmnopqrstuvwxyz-_':
			return False
	return True

def AES128_CBC(msg):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return EncodeAES(cipher, msg)

def request_auth(id, pw):
	packet = '{0}-{1}-{2}'.format(id, pw, cookie)
	e_packet = AES128_CBC(packet)
	print 'sending encrypted data ({0})'.format(e_packet)
	sys.stdout.flush()
	return rpc.authenticate(e_packet)

if __name__ == '__main__':
	print '---------------------------------------------------'
	print '-       PWNABLE.KR secure RPC login system        -'
	print '---------------------------------------------------'
	print ''
	print 'Input your ID'
	sys.stdout.flush()
	id = raw_input()
	print 'Input your PW'
	sys.stdout.flush()
	pw = raw_input()

	if sanitize(id) == False or sanitize(pw) == False:
		print 'format error'
		sys.stdout.flush()
		os._exit(0)

	cred = request_auth(id, pw)

	if cred==0 :
		print 'you are not authenticated user'
		sys.stdout.flush()
		os._exit(0)
	if cred==1 :
		print 'hi guest, login as admin'
		sys.stdout.flush()
		os._exit(0)

	print 'hi admin, here is your flag'
	print open('flag').read()
	sys.stdout.flush()
```
**server.py**
```python
#!/usr/bin/python
import xmlrpclib, hashlib
from SimpleXMLRPCServer import SimpleXMLRPCServer
from Crypto.Cipher import AES
import os, sys

BLOCK_SIZE = 16
PADDING = '\x00'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: c.encrypt(pad(s)).encode('hex')
DecodeAES = lambda c, e: c.decrypt(e.decode('hex'))

# server's secrets
key = 'erased. but there is something on the real source code'
iv = 'erased. but there is something on the real source code'
cookie = 'erased. but there is something on the real source code'

def AES128_CBC(msg):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return DecodeAES(cipher, msg).rstrip(PADDING)

def authenticate(e_packet):
	packet = AES128_CBC(e_packet)

	id = packet.split('-')[0]
	pw = packet.split('-')[1]

	if packet.split('-')[2] != cookie:
		return 0	# request is not originated from expected server
	
	if hashlib.sha256(id+cookie).hexdigest() == pw and id == 'guest':
		return 1
        if hashlib.sha256(id+cookie).hexdigest() == pw and id == 'admin':
                return 2
	return 0

server = SimpleXMLRPCServer(("localhost", 9100))
print "Listening on port 9100..."
server.register_function(authenticate, "authenticate")
server.serve_forever()

```
分析代码可以知道，只有当`id=admin,pw=sha256(id+cookie)`时才能获得flag。然而我们不知道`cookie`的值，所以就无法计算出正确的`pw`。
从代码中可以看到，程序使用`aes128_cbc`的加密模式。做web的都知道，这种加密方式容易受到字节反转攻击，但是这里却无法使用，因为字节反转攻击需要响应中有解密出来的明文。但是这里，由于这种加密模式明文和密文的字节是一一对应的，并且在这道题目中`cookie`前面的字符数量可控制，所以可以找到一种方法来爆破出`cookie`的值。
具体方法是，控制要加密的明文中`cookie`前面的字符数量，使要爆破的字节刚好位于分组中的最后一组的最后一个字节。接下来爆破方法是，每次改变最后一个字节，并把客户端返回的对应分组的加密密文与没有改变时的加密密文对比，当相等时说明该字节就是对应的`cookie`字节。如此爆破下去直到找到完整的`cookie`。随后就计算正确的ID和PW即可。
下面是poc，但是要传到题目平台上去，不然会很慢。
```python
#!/usr/bin/python
from pwn import *

context(log_level='error')
cookie = ''

def getRealEPack(ID,PW):
	r = remote('127.0.0.1',9006)
	r.recvuntil('ID\n')
	r.sendline(ID)
	r.recvuntil('PW\n')
	r.sendline(PW)
	s = r.recvline()
	e_pack = s[s.find('(')+1:-2]
	r.close()
	return e_pack

#get cookie
for i in xrange(2,100):
	pack = '-'*(15-i%16)+'--'+cookie
	for j in '1234567890abcdefghijklmnopqrstuvwxyz-_!':
		e_pack0 = getRealEPack(pack+j,'')
		e_pack1 = getRealEPack('-'*(15-i%16),'')
		if e_pack0[:len(pack+j)*2] == e_pack1[:len(pack+j)*2]:
			cookie += j
			print cookie
			break
		if j == '!':
			ID = 'admin'
			PW = hashlib.sha256(ID+cookie).hexdigest()
			print 'ID: {}\nPW: {}'.format(ID,PW)
			exit(0)


```
运行后
```bash
fix@ubuntu:/tmp$ python 1.py
y
yo
you
you_
you_w
you_wi
you_wil
you_will
you_will_
you_will_n
you_will_ne
you_will_nev
you_will_neve
you_will_never
you_will_never_
you_will_never_g
you_will_never_gu
you_will_never_gue
you_will_never_gues
you_will_never_guess
you_will_never_guess_
you_will_never_guess_t
you_will_never_guess_th
you_will_never_guess_thi
you_will_never_guess_this
you_will_never_guess_this_
you_will_never_guess_this_s
you_will_never_guess_this_su
you_will_never_guess_this_sug
you_will_never_guess_this_suga
you_will_never_guess_this_sugar
you_will_never_guess_this_sugar_
you_will_never_guess_this_sugar_h
you_will_never_guess_this_sugar_ho
you_will_never_guess_this_sugar_hon
you_will_never_guess_this_sugar_hone
you_will_never_guess_this_sugar_honey
you_will_never_guess_this_sugar_honey_
you_will_never_guess_this_sugar_honey_s
you_will_never_guess_this_sugar_honey_sa
you_will_never_guess_this_sugar_honey_sal
you_will_never_guess_this_sugar_honey_salt
you_will_never_guess_this_sugar_honey_salt_
you_will_never_guess_this_sugar_honey_salt_c
you_will_never_guess_this_sugar_honey_salt_co
you_will_never_guess_this_sugar_honey_salt_coo
you_will_never_guess_this_sugar_honey_salt_cook
you_will_never_guess_this_sugar_honey_salt_cooki
you_will_never_guess_this_sugar_honey_salt_cookie
ID: admin
PW: fcf00f6fc7f66ffcfec02eaf69d30398b773fa9b2bc398f960784d60048cc503
fix@ubuntu:/tmp$ 

```
```bash
root@kali:~/Desktop/test# nc pwnable.kr 9006
---------------------------------------------------
-       PWNABLE.KR secure RPC login system        -
---------------------------------------------------

Input your ID
admin
Input your PW
fcf00f6fc7f66ffcfec02eaf69d30398b773fa9b2bc398f960784d60048cc503
sending encrypted data (05c4ccfd4880c92339b995c7754ec2e6567f2ed91d955cb7144c1b6037855db1b3a8525e74d30fd4505bb38c975b86f23d0e5aa23eed44b9beaa7e2195da93ba53cb08758a261ada5612245f49d25b81aa5a297aa5d555886073b17e2ed719b3607da6fbfe40b260a45485910404d69c818a2faedac7bb3a727cfbb53eab8406)
hi admin, here is your flag
byte to byte leaking against block cipher plaintext is fun!!

root@kali:~/Desktop/test# 

```
# 总结
很有意思的一次pwn。