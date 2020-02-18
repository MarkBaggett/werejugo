#!/usr/bin/env python
#Quick and Dirty Python Interface to Powershell from Python
#Requires pexpect module.  Try "pip install pexpect"
import pexpect
from pexpect.popen_spawn import PopenSpawn
import re
import time

class pxpowershell(object):
    def __init__(self, *args, **kwargs):
        self.cmd = "powershell.exe"
        self.unique_prompt = "XYZPYEXPECTZYX"
        self.orig_prompt = ""
        self.process = ""
    def start_process(self):
        self.process =  pexpect.popen_spawn.PopenSpawn(self.cmd)
        time.sleep(2)
        init_banner = self.process.read_nonblocking(4096, 2)
        try:
            prompt = re.findall(b'PS [A-Z]:', init_banner, re.MULTILINE)[0]
        except Exception as e:
            raise(Exception("Unable to determine powershell prompt. {0}".format(e)))
        self.process.sendline("Get-Content function:\prompt")
        self.process.expect(prompt)
        #The first 32 characters will be the command we sent in
        self.orig_prompt = self.process.before[32:]
        self.process.sendline('Function prompt{{"{0}"}}'.format(self.unique_prompt))
        self.process.expect(self.unique_prompt)
        self.process.expect(self.unique_prompt)
    def restore_prompt(self):
        self.process.sendline('Function prompt{{"{0}"}}'.format(self.orig_prompt))
    def run(self,pscommand):
        self.process.sendline(pscommand)
        self.process.expect(self.unique_prompt)
        return self.process.before[len(pscommand)+2:]
    def stop_process(self):
        self.process.kill(9)

def powershell_output(powershell_cmd):
    pshell = pxpowershell()
    pshell.start_process()
    result = pshell.run(powershell_cmd)
    pshell.stop_process()
    return result

if __name__ == "__main__":
    #Quick demo
    x = pxpowershell()
    x.start_process()
    x.run("$a = 10000")
    print(x.run("$a + 1"))
    result = x.run("get-process")
    print(result)
    x.stop_process()

