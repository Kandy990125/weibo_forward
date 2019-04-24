# -*- coding: utf-8 -*-

import urllib
import urllib2
import requests
import cookielib
import base64
import re
import json
import rsa
import binascii
import function
import datetime
import time
def get_timestramp():
    datetime_object = datetime.datetime.now()
    now_timetuple = datetime_object.timetuple()
    now_second = time.mktime(now_timetuple)
    mow_millisecond = long(now_second * 1000 + datetime_object.microsecond / 1000)
    return str(mow_millisecond)


# 新浪微博的模拟登陆
class weiboLogin():

    def __init__(self, username, password, proxy=-1):
        self.username = username
        self.password = password
        self.proxy = proxy

    def run(self):
        global isFinal
        username = self.username
        password = self.password
        self.login(username, password)

    def enableCookies(self):
        # 获取一个保存cookies的对象
        cj = cookielib.CookieJar()
        # 将一个保存cookies对象和一个HTTP的cookie的处理器绑定
        cookie_support = urllib2.HTTPCookieProcessor(cj)
        # 创建一个opener,设置一个handler用于处理http的url打开
        opener = urllib2.build_opener(cookie_support, urllib2.HTTPHandler)
        # 安装opener，此后调用urlopen()时会使用安装过的opener对象
        urllib2.install_opener(opener)

        # 预登陆获得 servertime, nonce, pubkey, rsakv

    def getServerData(self):
        url = 'http://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&su=ZW5nbGFuZHNldSU0MDE2My5jb20%3D&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.18)&_=1442991685270'
        data = urllib2.urlopen(url).read()
        p = re.compile('\((.*)\)')
        try:
            json_data = p.search(data).group(1)
            data = json.loads(json_data)
            servertime = str(data['servertime'])
            nonce = data['nonce']
            pubkey = data['pubkey']
            rsakv = data['rsakv']
            return servertime, nonce, pubkey, rsakv
        except:
            print 'Get severtime error!'
            return None

    # 获取加密的密码
    def getPassword(self, password, servertime, nonce, pubkey):
        rsaPublickey = int(pubkey, 16)
        key = rsa.PublicKey(rsaPublickey, 65537)  # 创建公钥
        message = str(servertime) + '\t' + str(nonce) + '\n' + str(password)  # 拼接明文js加密文件中得到
        passwd = rsa.encrypt(message, key)  # 加密
        passwd = binascii.b2a_hex(passwd)  # 将加密信息转换为16进制。
        return passwd

        # 获取加密的用户名

    def getUsername(self, username):
        username_ = urllib.quote(username)
        username = base64.encodestring(username_)[:-1]
        return username

        # 获取需要提交的表单数据

    def getFormData(self, userName, password, servertime, nonce, pubkey, rsakv, door=0):
        userName = self.getUsername(userName)
        psw = self.getPassword(password, servertime, nonce, pubkey)

        form_data = {
            'entry': 'weibo',
            'gateway': '1',
            'from': '',
            'savestate': '7',
            'useticket': '1',
            'pagerefer': '',
            'vsnf': '1',
            'su': userName,
            'service': 'miniblog',
            'servertime': servertime,
            'nonce': nonce,
            'pwencode': 'rsa2',
            'rsakv': rsakv,
            'sp': psw,
            'sr': '1366*768',
            'encoding': 'UTF-8',
            'cdult': '2',
            'prelt': '263',
            'domain': 'weibo.com',
            'returntype': 'TEXT'
        }
        if door != 0:
            form_data['door'] = door

        formData = urllib.urlencode(form_data)
        return formData

    # 登陆函数
    def login(self, username, psw, door=0):
        door = function.verifi()
        self.enableCookies()
        url = 'http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.18)'
        servertime, nonce, pubkey, rsakv = self.getServerData()
        if door != 0:
            formData = self.getFormData(username, psw, servertime, nonce, pubkey, rsakv, door['code'])
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0',
                "Cookie": door['cookie'],
                'x-forwarded-for': '127.0.0.1'
            }
        else:
            formData = self.getFormData(username, psw, servertime, nonce, pubkey, rsakv)
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0'}
        proxy = self.proxy
        if proxy != -1:
            proxy_s = urllib2.ProxyHandler(proxy)
            opener = urllib2.build_opener(proxy_s)
            urllib2.install_opener(opener)

        req = urllib2.Request(
            url=url,
            data=formData,
            headers=headers
        )
        result = urllib2.urlopen(req)
        text = result.read()
        text = json.loads(text)

        # print text  #html contents
        # 还没完！！！这边有一个重定位网址，包含在脚本中，获取到之后才能真正地登陆
        if 'ticket' in text:
            ticket = text['ticket']
            login_url = "http://passport.weibo.com/wbsso/login?callback=sinaSSOController.callbackLoginStatus&ticket=" + urllib.quote(
                ticket)
            headers = {
                "Cookie": "login_sid_t=4d11ea0e55541792dd04b186c7bcede6;",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.73",
                'x-forwarded-for': '127.0.0.1'
            }
            r = requests.get(login_url, headers=headers, allow_redirects=False)
            res = r.headers
            print(res)
            acookie = res['Set-Cookie']
            print(acookie)
            p = re.compile('SUB=.*?;')
            acookie = p.search(acookie).group(0)
            print(acookie + '******' + username + ',' + psw + '\n')
            # fp.write(acookie + '******' + username + ',' + psw + '\n')
            # fp.flush()
            print "Login success!"
            return 1
        else:
            if self.flag > 2:
                exit()
            self.flag = self.flag + 1
            print 'Login error!'
            res = function.verifi()
            self.login(username, psw, door=res)
            return 0
username = ""
password = ""
proxy = ""
weibo = weiboLogin(username, password, proxy=-1)
weibo.run()

cookie = ""
url = "https://weibo.com/5630416067/Hr0iqEDxy?type=repost"
headers = {
    'accept': 'application/json, text/plain, */*',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'zh-CN,zh;q=0.9',
    'content-type': 'application/x-www-form-urlencoded',
    'cookie': cookie,
    'origin': 'https://m.weibo.cn',
    'referer': url,
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.170 Safari/537.36',
    'x-requested-with': 'XMLHttpRequest',
}
time_stramp = get_timestramp()
# https://weibo.com/aj/v6/mblog/forward?ajwvr=6&domain=5630416067&__rnd=1556112080798
forward_url = "https://weibo.com/aj/v6/mblog/forward?ajwvr=6&domain=100406&__rnd=" + time_stramp
form_data = {
    'pic_src':'',
    'pic_id':'',
    'appkey':'',
    'mid': 4364699384893924,
    'style_type': '1',
    'mark':',' ,
    'reason':"麦不辣鸡腿堡的转发机器*3**login",
    'module':'',
    'page_module_id': '',
    'refer_sort': '',
    'rank': '0',
    'rankid':'',
    'isReEdit':'',
    '_t': '0'
}
response = requests.post(url=forward_url, data=form_data, headers=headers, allow_redirects=False)
print response.text