#coding:utf-8

import my_debugger
from my_debugger_defines import HW_EXECUTE
debugger = my_debugger.debugger()
#debugger.load(b"c:\\WINDOWS\\system32\\calc.exe")
"""
在传入的路径值前面加上b ，成功运行
"""

pid = input("Enter the PID of the process to attach to:  ")
debugger.attach(int(pid))
print_address = debugger.func_resolve("msvcrt.dll","printf")
print("[*] Address of print: 0x%0xx" % print_address)
debugger.bp_set_hw(print_address,1,HW_EXECUTE)

debugger.run()
debugger.detach()