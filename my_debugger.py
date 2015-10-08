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
        self.h_thread = None
        self.context  = None
        self.exception = None
        self.exception_address = None
        self.breakpoints = {}
        self.first_breakpoint = None
        self.hardware_breakpoints = {}
    
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
        return h_process

    def attach(self,pid):
        self.h_process = self.open_process(pid)
        #试图附加到目标进程，如附加失败，则输出提示信息并返回
        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid = int(pid)
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
            self.h_thread = self.open_thread(debug_event.dwThreadId)
            self.context = self.get_thread_context(self.h_thread)
            print("Event code: %d Thread ID %d" %(debug_event.dwDebugEventCode,debug_event.dwThreadId))
            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                self.exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress
            if self.exception == EXCEPTION_ACCESS_VIOLATION:
                print("Access Violation Detected.")
            elif self.exception == EXCEPTION_BREAKPOINT:
                continue_status == self.exception_handler_breakpoint()

            elif self.exception == EXCEPTION_GUARD_PAGE:
                print("Guard Page Access Detected")

            elif self.exception == EXCEPTION_SINGLE_STEP:
                print("single Stepping")

            kernel32.ContinueDebugEvent(debug_event.dwProcessId,debug_event.dwThreadId,continue_status)

    def exception_handler_breakpoint(self):
        print("[*] Inside the breakpoint handler.")
        print("Exception address 0x%08x" %self.exception_address)
        return DBG_CONTINUE


    def detach(self):
        if kernel32.DebugActiveProcessStop(self.pid):
            print("[*] Finished debugging. Exiting....")
            return True
        else:
            print("There was an error")
            return False
    
    def open_thread(self,thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS,None,thread_id)
        if h_thread is not None:
            return h_thread
        else:
            print ("[*] Counld not obtain a valid thread handle.")
            return False


    def enumerate_threads(self):
        
        thread_entry =THREADENTRY32()
        thread_list = []
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,self.pid)
        
        if snapshot is not None:
            #设置结构体的大小，否则会调用失败
            thread_entry.dwSize = sizeof(thread_entry)
            success = kernel32.Thread32First(snapshot,byref(thread_entry))
            while success:
                if thread_entry.th32OwnerProcessID == self.pid:
                    print("th32ThreadID: %s " % thread_entry.th32ThreadID)
                    thread_list.append(thread_entry.th32ThreadID)
                success = kernel32.Thread32Next(snapshot,byref(thread_entry))
            kernel32.CloseHandle(snapshot)
            return thread_list
        else:
            return False

    def get_thread_context(self,thread_id = None,h_thread= None):
        context = CONTEXT()
        context.ContextFlags= CONTEXT_FULL|CONTEXT_DEBUG_REGISTERS
        #获取线程句柄

        if h_thread is None:
            self.h_thread = self.open_thread(thread_id)
        if kernel32.GetThreadContext(self.h_thread,byref(context)):
            
            return context
        else:
            return False

    def read_process_memory(self,address,length):
        data = ""
        read_buf = create_string_buffer(length)
        count = c_ulong(0)
        if not kernel32.ReadProcessMemory(self.h_process,address,read_buf,length,byref(count)):
            return False

        else:
            data += read_buf.raw
            return data

    def write_process_memory(self,address,data):
        count = c_ulong(0)
        length = len(data)
        c_data = c_char_p(data[count.value:])
        if not kernel32.WriteProcessMemory(self.h_process,address,c_data,length,byref(count)):
            return False
        else:
            return True

    def bp_set(self,address):
        try:
            if not self.breakpoints.has_key(address):
                original_byte = self.read_process_memory(address,1)
                self.write_process_memory(address,"\xCC")
                print("raw",original_byte)
                self.breakpoints[address] = (address,original_byte)
        except:
            return False
        return True

    def bp_set_hw(self, address, length, condition):
        
        #检测硬件断点的长度是否有效
        if length not in (1, 2, 4):
            return False
        else:
            length -= 1
            
        #检测硬件断点的触发条件是否有效
        if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
            return False
        
        #检测是否存在空置的调试器寄存器槽
        if not self.hardware_breakpoints.has_key(0):
            avaliable = 0
        
        elif not self.hardware_breakpoints.has_key(1):
            avaliable = 1
            
        elif not self.hardware_breakpoints.has_key(2):
            avaliable = 2
        
        elif not self.hardware_breakpoints.has_key(3):
            avaliable = 3
        
        else:
            return False
        
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)
            
            if not context:
                context.Dr7 |= 1 << (avaliable * 2)
        
            if avaliable == 0 :
                context.Dr0 = address
            elif avaliable == 1: 
                context.Dr1 = address
            elif avaliable == 2:
                context.Dr2 = address
            elif avaliable == 3:
                context.Dr3 = address
        
            context.Dr7 |= condition << ((avaliable * 4)+ 16)
            
            context.Dr7 |= length << ((avaliable * 4) + 18)
            
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread,byref(context))
        
        self.hardware_breakpoints[avaliable] = (address,length,condition)
        
        return True                                                                                              
        
        
        
        
        
        
    def func_resolve(self,dll,function):
        handle = kernel32.GetModuleHandleA(dll)
        address = kernel32.GetProcAddress(handle,function)

        kernel32.CloseHandle(handle)
        return address

    def contine(self,address):
        data =self.breakpoints[address][1]
        count = c_ulong(0)
        length = len(data)
        c_data = data
        if not kernel32.WriteProcessMemory(self.h_process,address,c_data,length,byref(count)):
            return False
        else:
            return True



    def exception_handler_single_step(self):
        
        if self.context.Dr6 & 0x1 and self.hardware_breakpoints.has_key(0):
            slot = 0
        
        elif self.context.Dr6 & 0x2 and self.hardware_breakpoints.has_key(1):
            slot =1
        
        elif self.context.Dr6 & 0x4 and self.hardware_breakpoints.has_key(2):
            slot = 2
        
        elif self.context.Dr6 & 0x8 and self.hardware_breakpoints.has_key(3):
            slot = 3
            
        else:
            continue_status = DBG_EXCEPTION_NOT_HANDLED
            
        
        if self.bp_del_hw(slot):
            continue_status = DBG_CONTINUE
        print("[*] Hardware breakpoint removed")
        
        
    def bp_del_hw(self,slot):
        
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id = thread_id)
            
            context.Dr7 &= ~(1<< (slot*2))
            
            if slot == 0:
                context.Dr0 = 0x00000000
            
            elif slot == 1:
                context.Dr1 = 0x00000000
                
            elif slot == 2:
                context.Dr2 = 0x00000000
                
            elif slot == 3:
                context.Dr3 = 0x00000000
                
            context.Dr7 &= ~(3<<((slot * 4) + 16))
                
            context.Dr7 &= ~(3<<((slot * 4) + 18))
            
            h_thread = self.open_thread(thread_id)
            
            kernel32.SetThreadContext(h_thread,byref(context))
            
        del self.hardware_breakpoints[slot]
        return True 
            













