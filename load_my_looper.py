#conding:utf-8
'''
Created on 2015年10月8日

@author: Mr.li
'''
from ctypes import  *
from my_debugger_defines import *
kernel32 = windll.kernel32
path = raw_input("输入路径：")
create_flags = DEBUG_PROCESS
startupinfo = STARTUPINFO()
process_information = PROCESS_INFORMATION()

startupinfo.dwFlags =0x1
startupinfo.wShowWindow = 0x0

startupinfo.cd = sizeof(startupinfo)

kernel32.CreateProcessA(path,None,None,None,None,create_flags,None,None,byref(startupinfo),byref(process_information))
print(process_information.dwProcessId)