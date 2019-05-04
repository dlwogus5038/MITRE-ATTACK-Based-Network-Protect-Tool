import win32evtlog # requires pywin32 pre-installed
import datetime
import sys
import os, traceback, types

def isUserAdmin():

    if os.name == 'nt':
        import ctypes
        # WARNING: requires Windows XP SP2 or higher!
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            traceback.print_exc()
            print ("Admin check failed, assuming not an admin.")
            return False
    elif os.name == 'posix':
        # Check for root on Posix
        return os.getuid() == 0
    else:
        raise (RuntimeError, "Unsupported operating system for this module: %s" % (os.name,))

def runAsAdmin(cmdLine=None, wait=True):

    if os.name != 'nt':
        raise (RuntimeError, "This function is only implemented on Windows.")

    import win32api, win32con, win32event, win32process
    from win32com.shell.shell import ShellExecuteEx
    from win32com.shell import shellcon

    python_exe = sys.executable

    if cmdLine is None:
        cmdLine = [python_exe] + sys.argv
    elif type(cmdLine) not in (types.TupleType,types.ListType):
        raise (ValueError, "cmdLine is not a sequence.")
    cmd = '"%s"' % (cmdLine[0],)
    # XXX TODO: isn't there a function or something we can call to massage command line params?
    params = " ".join(['"%s"' % (x,) for x in cmdLine[1:]])
    cmdDir = ''
    #showCmd = win32con.SW_SHOWNORMAL
    showCmd = win32con.SW_HIDE
    lpVerb = 'runas'  # causes UAC elevation prompt.

    # print "Running", cmd, params

    # ShellExecute() doesn't seem to allow us to fetch the PID or handle
    # of the process, so we can't get anything useful from it. Therefore
    # the more complex ShellExecuteEx() must be used.

    # procHandle = win32api.ShellExecute(0, lpVerb, cmd, params, cmdDir, showCmd)

    procInfo = ShellExecuteEx(nShow=showCmd,
                              fMask=shellcon.SEE_MASK_NOCLOSEPROCESS,
                              lpVerb=lpVerb,
                              lpFile=cmd,
                              lpParameters=params)

    if wait:
        procHandle = procInfo['hProcess']    
        obj = win32event.WaitForSingleObject(procHandle, win32event.INFINITE)
        rc = win32process.GetExitCodeProcess(procHandle)
        #print "Process handle %s returned code %s" % (procHandle, rc)
    else:
        rc = None

    return rc

def get_evt():
    
    rc = 0
    if not isUserAdmin():
        print ("You're not an admin.", os.getpid(), "params: ", sys.argv)
        #rc = runAsAdmin(["c:\\Windows\\notepad.exe"])
        rc = runAsAdmin()
    else:
        print ("You are an admin!", os.getpid(), "params: ", sys.argv)

        #*********************************************************************#

        # 당일로그만 출력.(전일 날짜와 매칭되는 순간부터 강제종료 - 불필요한 로그 파싱 방지)

        today = datetime.datetime.now().date()
        day_ago = today - datetime.timedelta(days=1)

        server = 'localhost' # name of the target computer to get event logs
        logtype = 'Security' # 'Application' # 'Security' #'System' # Security를 사용할떄는 관리자 권한이 필요함!!
        hand = win32evtlog.OpenEventLog(server,logtype)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
        total = win32evtlog.GetNumberOfEventLogRecords(hand)

        while True:
            events = win32evtlog.ReadEventLog(hand, flags,0)
            if events:
                for event in events:
                    if str(event.TimeGenerated)[:10] == str(today):
                        print ('Event Category:', event.EventCategory)
                        print ('Time Generated:', event.TimeGenerated)
                        print ('Source Name:', event.SourceName)
                        print ('Event ID:', event.EventID)
                        print ('Event Type:', event.EventType)
                        data = event.StringInserts

                        if data:
                            print ('Event Data:')
                            for msg in data:
                                print (msg)

                        print('*' * 100)

                    elif str(event.TimeGenerated)[:10] == str(day_ago):
                        sys.exit(0) #input() 으로 바로 안꺼지게 하고 멈출수있음.

        #*********************************************************************#

        rc = 0

    return rc

if __name__ == "__main__":
    sys.exit(get_evt())