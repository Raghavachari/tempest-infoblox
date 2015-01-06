#!/usr/bin/env python
import pexpect

ssh_newkey = 'Are you sure you want to continue connecting'
# my ssh command line
p=pexpect.spawn('ssh jenkins@10.39.18.25')

i=p.expect([ssh_newkey,'password:',pexpect.EOF])
if i==0:
    p.sendline('yes')
    i=p.expect([ssh_newkey,'password:',pexpect.EOF])
if i==1:
    print "I give password",
    p.sendline("infoblox")
    p.expect(pexpect.EOF)
    #p.sendline("/home/jenkins/./test.sh")
    print p.before
elif i==2:
    print "I either got key or connection timeout"
    pass
print p.before # print out the result
