#coding:utf-8

import my_debugger

debugger = my_debugger.debugger()
debugger.load(b"c:\\WINDOWS\\system32\\calc.exe")
"""
在传入的路径值前面加上b ，成功运行
"""