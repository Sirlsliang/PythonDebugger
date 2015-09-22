#coding:utf-8
"""
利用了函数
BOOL WINAPI CreateProcessA(
    LPCSTR lpApplicationName,#设置可执行文件的路径
    LPTSTR lpCommandLine,#命令参数，或者上一个参数为空时，设置可执行文件的路径
    LPSECURITE_ATTRIBUTES lpProcessAttributes,
    #指向一个SECURITY_ATTRIBUTES结构体，这个结构体决定是否返回的句柄可以被子进程继承
    LPSECURITE_ATTRIBUTES lpThreadAttributes,
    #指向一个SECURITY_ATTRIBUTES结构体，这个结构体决定是否返回的句柄可以被子进程继承
    BOOL blnheritHandles,
    #指示新进程是否从调用进程处继承句柄
    DWORD dwCreationFlags,
    #指定附加的、用来控制优先类和进程的创建的标志。一下的标志可以“组合后指定”。
    #常用标志：CREATE_DEFAULT_ERROR_MODE：新的进程不继承调用继承的错误模式
    #CREATE_NEW_CONSOLE:新的进程将使用一个新的控制台,而不是继承父进程的控制台
    #CREATE_NEW_PROCESS_GROUP：新的进程将是一个进程树的根进程。
    #CREATE_SEPARATE_WOW_VDM:当运行于一个16位的windows应用程序时有效
    #CREATE_SHARED_WOW_VDM:这个标志只有当运行一个16为的windows应用程序时才有效
    #CREATE_SUSPENDED:新进程的主线程会议暂停的状态被创建
    #CREATE_UNICODE_ENVIRONMENT:被设置，由lpEnvironment参数指定的环境使用Unicode，空则环境块使用ANSI字符
    #DEBUG_PROCESS:这个标志被设置，调用程序将被当作一个调试程序，并且新进程会被当作被调试的进程。
    #DEBUG_ONLY_THIS_PROCESS:此标志没有被设置且调用进程正在被调试，新进程将成为调试调用进程的调试器的另一个调试对象
    #DETACHED_PROCESS:对于控制台进程，新进程没有访问父进程控制台的权限
    该参数也可以用来控制新进程的优先类，优先类来决定此进程的线程调度的优先级。
        HIGH_PRIRITY_CLASS:必须立即运行
        NORMAL_PRIORITY_CLASS:这个进程没有特殊的任务调度要求
        IDLE_PRIORITY_CLASS:这个进程的线程只有在系统空闲时才会运行起来
        REALTIME_PRIORITY_CLASS:这个进程拥有可用的最高优先级
    #DETACHED_PROCESS:
    LPVOID IpEnvironment,
    #指向一个新进程的环境块，如果此参数为空，新进程使用调用进程的环境。
    LPCTSTR lpCurrentDirectory,
    #指向一个以NULL结尾的字符串，这个字符串用来指定子进程的工作路径
    LPSTARTUPINFO IPStartupInfo,
    #指向一个用于决定新进程的主窗体如何显示STARTUPINFO结构
    LPPROCESS_INFORMATION lpProcessInformation
    #指向一个用来接收新进程的识别信息的PROCESS_INFOMATION结构体
);
"""
from ctypes import *
from my_debugger_defines import *

kernel32 = windll.kernel32

class debugger(object):
    def __init__(self):
        self.h_process = None
        self.pid = None
        self.debugger_active = False
    
    
    def load(self, path_to_exe):
        creation_flags = CREATE_NEW_CONSOLE
        #实例化之前定义的结构体
        startupinfo     = STARTUPINFO()
        process_information = PROCESS_INFORMATION()
        #在以下两个成员变量的共同作用下，新建进程将在一个单独的窗体被显示，
        #可以通过改变结构体STARTUPINFO中的各个成员变量的值来控制debugee进程的行为
        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0

        #设置结构体STARTUPINFO中的成员变量cb的值，用以表示结构体本身的大小
        startupinfo.cb = sizeof(startupinfo)
        
        if kernel32.CreateProcessA(path_to_exe,
                                   None,
                                   None,
                                   None,
                                   None,
                                   creation_flags,
                                   None,
                                   None,
                                   byref(startupinfo),
                                   byref(process_information)):
        
            print("[*] We have successfully launched the process")
            print("[*] PID:%d" % process_information.dwProcessId)
            #保存一个指向新建进程的一个有效句柄以供后续的进程访问所使用
            self.h_process = self.open_process(process_information.dwProcessId)
        else:
            print("[*] Error: 0x%08." % kernel32.GetLastError())

    def open_process(self,pid):
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,pid)

    def attach(self,pid):
        self.h_process = self.open_process(pid)
        #试图附加到目标进程，如附加失败，则输出提示信息并返回
        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid = int(pid)
            self.run()
        else:
            print("[*] Unable to attach to the process.")

    def run(self):
        #现在我们等待发生在debugee进程中的调试事件
        while self.debugger_active == True:
            self.get_debug_event()

    def get_debug_event(self):
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE

        if kernel32.WaitForDebugEvent(byref(debug_event),INFINITE):
            #目前我们还未构建任何与事件处理相关的功能逻辑，我们先简单的恢复目标进程
            input("press a key to continue....")
            self.debugger_active = True
            kernel32.ContinueDebugEvent(debug_event.dwProcessId,debug_event.dwThreaId,continue_status)

    def detach(self):
        if kernel32.DebugActiveProcessStop(self.pid):
            print("[*] Finished debugging. Exiting....")
            return True
        else:
            print("There was an error")
            return False
    



















