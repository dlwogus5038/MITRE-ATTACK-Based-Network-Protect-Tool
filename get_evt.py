import win32evtlog # requires pywin32 pre-installed
import datetime
import sys
import xmltodict
import threading
import time
import subprocess
import re
import json
import os
from dateutil import tz

# EvtQuery -> EvtNext -> EvtRender

# CAR-2013-04-002: Quick execution of a series of suspicious commands
# TODO 각각의 exe가 어떤 ATT&CK 기법인지 판단이 잘 안됨...
# TODO MITRE ATT&CK 홈페이지에서 Software 에 있는것들 확인후 채워넣기!
# TODO str.split() 을 이용해서 - 이 특수문자로 나눠서 테크닉과 전술 구별하기!
commands_of_interest = {
    'arp.exe'       : (0, ['System Network Configuration Discovery-Discovery']),
    'at.exe'        : (1, ['Scheduled Task-Persistence-Privilege Escalation-Execution']),
    'attrib.exe'    : (2, ['']),
    'cscript.exe'   : (3, ['']),
    'dsquery.exe'   : (4, ['Account Discovery-Discovery', 'Permission Groups Discovery-Discovery']),
    'hostname.exe'  : (5, ['System Network Configuration Discovery-Discovery']),
    'ipconfig.exe'  : (6, ['System Network Configuration Discovery-Discovery']),
    'mimikatz.exe'  : (7, ['Credential Dumping-Credential Access', 'Account Manipulation-Credential Access']),
    'nbtstat.exe'   : (8, ['System Network Configuration Discovery-Discovery', 'System Network Connections Discovery-Discovery']),
    'net.exe'       : (9, ['Account Discovery-Discovery', 'Permission Groups Discovery-Discovery', 'Remote System Discovery-Discovery', 'Service Execution-Persistence-Privilege Escalation', 'System Network Connections Discovery-Discovery', 'System Service Discovery-Discovery', 'Windows Admin Shares-Lateral Movement']),
    'netsh.exe'     : (10, ['Disabling Security Tools-Defense Evasion', 'Security Software Discovery-Discovery']),
    'nslookup.exe'  : (11, ['']),
    'ping.exe'      : (12, ['Remote System Discovery-Discovery', 'Network Service Scanning-Discovery']),
    'quser.exe'     : (13, ['System Network Connections Discovery-Discovery']),
    'qwinsta.exe'   : (14, ['']),
    'reg.exe'       : (15, ['Modify Registry-Defense Evasion', 'Query Registry-Discovery', 'Service Registry Permissions Weakness-Persistence-Privilege Escalation']),
    'runas.exe'     : (16, ['']),
    'sc.exe'        : (17, ['Modify Existing Service-Persistence-Privilege Escalation', 'Service Registry Permissions Weakness-Persistence-Privilege Escalation']),
    'schtasks.exe'  : (18, ['Scheduled Task-Persistence-Privilege Escalation-Execution']),
    'ssh.exe'       : (19, ['']),
    'systeminfo.exe': (20, ['System Information Discovery-Discovery', 'System Owner/User Discovery-Discovery']),
    'taskkill.exe'  : (21, ['Disabling Security Tools-Defense Evasion']),
    'telnet.exe'    : (22, ['']),
    'tracert.exe'   : (23, ['Remote System Discovery-Discovery']),
    'wscript.exe'   : (24, ['Scripting-Defense Evasion-Execution']),
    'xcopy.exe'     : (25, [''])
}

# CAR-2013-05-002: Suspicious Run Locations
# cmd 에서 명령어 입력하고 출력값 받아오는 코드
windir = subprocess.getstatusoutput("echo %windir%")[1]
systemroot = subprocess.getstatusoutput("echo %systemroot%")[1]

# 로그 리스트

log_list = ["Microsoft-Windows-Sysmon/Operational", "System", "Security"]

# Detected Events

tactics = {}
techniques = {}

# 读取Tactics字典
with open('Tactics.json', 'r', encoding='utf-8') as json_file:
    tactics = json.load(json_file)

# 读取Techniques字典
with open('Techniques.json', 'r', encoding='utf-8') as json_file:
    techniques = json.load(json_file)

tac_tech_events = {}
for elem in tactics['Enterprise']:
    tac_tech_events[elem] = {}
    tac_tech_events[elem]['Events'] = []
    for elem2 in tactics['Enterprise'][elem]['Techniques']:
        tac_tech_events[elem][elem2['Name']] = {}
        tac_tech_events[elem][elem2['Name']]['Events'] = []

# =============================================================== #

def Utc_to_local(evt_utc_time):
    from_zone = tz.tzutc()
    to_zone = tz.tzlocal()

    utc = datetime.datetime.strptime(evt_utc_time[:10] + ' ' + evt_utc_time[11:26], '%Y-%m-%d %H:%M:%S.%f')
    utc = utc.replace(tzinfo=from_zone)

    evt_local_time = utc.astimezone(to_zone)

    return evt_local_time

# ===================================================================================================== #
# ===================================================================================================== #

class Sysmon_evt (threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.min_time = datetime.datetime.now(tz.tzlocal())
        self.max_time = datetime.datetime.now(tz.tzlocal())
        self.tmp_time = None

    def run(self):
        while 1:
            self.get_evt_log()
            time.sleep(1) # 이렇게 안해주면 CPU를 너무 많이먹음...

    def get_evt_log(self): # 매번 지역변수로 새로 설정해서 매번 갱신을 시켜줘야지만 새로운 이벤트 로그를 받아옴.
        path = "Microsoft-Windows-Sysmon/Operational"
        handle = win32evtlog.EvtQuery( # Get event log
                        path,
                        win32evtlog.EvtQueryReverseDirection,
                        #"Event/System[EventID=5]",
                        #None
                    )

        while 1:
            events = win32evtlog.EvtNext(handle, 10)
            if len(events) == 0:
                return
            for event in events:
                record = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)

                # xml to dict
                record_dict = xmltodict.parse(record)

                # UTC to Local Time
                evt_local_time = Utc_to_local(record_dict['Event']['System']['TimeCreated']['@SystemTime'])
                record_dict['Event']['System']['TimeCreated']['@SystemTime'] = evt_local_time
                # print(evt_local_time , self.max_time)

                if evt_local_time <= self.min_time:
                    self.min_time = self.max_time
                    return
                else:
                    # print("==============Sysmon================")
                    # print(evt_local_time)
                    if evt_local_time > self.max_time:
                        self.max_time = evt_local_time

                    # record_dict 의 EventData 의 value 값 수정하기... Data - name - text 이런식으로 돼있어서 인덱스하기 힘듦...!
                    temp_data = {}
                    for data in record_dict['Event']['EventData']['Data']:
                        if '#text' in data:
                            temp_data[data['@Name']] = data['#text']
                        elif data == None or data == 'None':
                            temp_data = {}
                        else:
                            temp_data[data['@Name']] = None
                    record_dict['Event']['EventData'] = temp_data
                    # print(temp_data)

                    # 변수 설정
                    evt_id = int(record_dict['Event']['System']['EventID'])


                    # CAR analytics

                    # TODO 나중에 eventid = 1이랑 eventid = 3이랑 따로 묶어서 if..elif..elif..else 이런식으로 만들기! 그래야 더 빠를것같음!
                    # TODO 그리고 record_dict['Event']['EventData']['CommandLine'] 처럼 자주 이용되는것들은 com_line 이런식으로 변수 하나 만들어서 저장하는게 더 보기도 편할듯!
                    # TODO 그리고 record_dict의 모든 value가 어떤 자료형으로 저장되는지 확인해보기! str으로 저장되면 여태까지 쓴 str(~) 이런거 다 지우기!
                    # TODO re.search 해가지고 예를들어 cmd.exe$ 이런식으로 正则表达式 만들면 'cmd.exe' in ~~ 이런식으로 하는것보다 훨씬 속도 빠를듯!

                    # TODO 나중에 CAR에 나와있는 설명들 가져다 쓸때 영어, 한국어, 중국어 번역해서 각 언어 버전 만들기! 해당 의심 이벤트 발견시 띄울때 이러한 설명 필요함!

                    # TODO takeown.exe 같은건 CAR 에 안나와있음! 그래서 CALDERA로 공격 돌려보고 의심할만한 image_exe가 보인다! 싶으면 takeown ATT&CK 이렇게 구글에 검색해서 확인해보기!

                    # TODO MITRE EVALUATIONS 꼭 확인하면서 각각 조직들마다 어떤식으로 탐지했는지 확인하기!

                    # TODO 의심 이벤트 발견시 그 이벤트의 부모 프로세스를 따라가면서 어디서부터 어떻게 시작됬고 만약 의심할만한 프로그램으로부터 시작된거면 그 프로그램이 어디서 어떻게 들어왔는지까지 EVENT로 다 파악하기!

                    # TODO 의심 이벤트 발견시 ATT&CK CAR 에 정리되어있는 관련 테크닉이라고 나와있다고 전부다 네트워크 툴에서 보여주지말고, 상세하게 어떤거일때 어떤 테크닉이다 라고 정해서 보여주기! 예를들어 net을 봤을때 net use / net stop 이런거 등등이 있음!
                    ############################################################################################

                    # 의심가는 이벤트 발견시 이벤트 정보 담는 변수
                    event_set = {}

                    if evt_id == 1:

                        image = str(record_dict['Event']['EventData']['Image'])
                        image_exe = image.split('\\')
                        image_exe = (image_exe[-1]).lower()
                        parent_image = str(record_dict['Event']['EventData']['ParentImage'])
                        parent_image_exe = parent_image.split('\\')
                        parent_image_exe = (parent_image_exe[-1]).lower()
                        com_line = str(record_dict['Event']['EventData']['CommandLine'])
                        
                        # CAR-2013-04-002: Quick execution of a series of suspicious commands
                        # 너무 많음...
                        # https://car.mitre.org/analytics/CAR-2013-04-002

                        # TODO 각각의 exe가 어떤 ATT&CK 기법인지 판단이 잘 안됨...
                        for exe_name in commands_of_interest:
                            if exe_name == image_exe:
                                com_check = self.Quick_execution_of_a_series_of_suspicious_commands(record_dict)
                                if com_check[0] == True:
                                    # TODO 이렇게 2개 표시하는 방법 말고... 이런식으로 하면 겹쳐서 나오게 됨.. 나중에 한꺼번에 다 몰아서 검사한다음 한꺼번에 출력시키게 바꿔야됨!
                                    print('Quick execution of a series of suspicious commands \"' + com_check[1][0] + '\", \"' + com_check[1][1] + '\" // Detected')
                                    # TODO 각 이벤트마다 해당되는 Tactics랑 Techniques 에다가 넣어야함!

                        # CAR-2016-03-002: Create Remote Process via WMIC
                        # Windows Management Instrumentation - Execution
                        # https://car.mitre.org/analytics/CAR-2016-03-002

                        if (
                            'wmic.exe' == image_exe and
                            ' process call create ' in com_line and
                            ' /node:' in com_line
                            ):

                            print('Create Remote Process via WMIC // Detected')
                            event_set['ID'] = 'CAR-2016-03-002'
                            event_set['Name'] = 'Create Remote Process via WMIC'
                            event_set['Event'] = [record_dict]
                            tac_tech_events['Execution']['Events'].append(event_set)
                            tac_tech_events['Execution']['Windows Management Instrumentation']['Events'].append(event_set)

                        # CAR-2014-07-001: Service Search Path Interception
                        # Path Interception - Privilege Escalation, Persistence
                        # https://car.mitre.org/analytics/CAR-2014-07-001

                        if (
                            'services.exe' == parent_image_exe and
                            ' ' in com_line and
                            com_line[0] != '\"' and
                            ' ' not in image and
                            'exe' not in com_line
                            ):

                            print('Service Search Path Interception // Detected')
                            event_set['ID'] = 'CAR-2014-07-001'
                            event_set['Name'] = 'Service Search Path Interception'
                            event_set['Event'] = [record_dict]

                            tac_tech_events['Privilege Escalation']['Events'].append(event_set)
                            tac_tech_events['Persistence']['Events'].append(event_set)

                            tac_tech_events['Privilege Escalation']['Path Interception']['Events'].append(event_set)
                            tac_tech_events['Persistence']['Path Interception']['Events'].append(event_set)

                        # CAR-2014-03-005: Remotely Launched Executables via Services
                        # New Service - Execution
                        # Modify Existing Service - Execution
                        # Service Execution - Execution
                        # https://car.mitre.org/analytics/CAR-2014-03-005

                        if 'services.exe' == parent_image_exe:
                            flow = self.Remotely_Launched_Executables_via_Services(record_dict)
                            if flow[0] == True:
                                print('Remotely Launched Executables via Services // Detected')
                                event_set['ID'] = 'CAR-2014-03-005'
                                event_set['Name'] = 'Remotely Launched Executables via Services'
                                event_set['Event'] = [record_dict, flow[1]]

                                tac_tech_events['Execution']['Events'].append(event_set)

                                tac_tech_events['Execution']['New Service']['Events'].append(event_set)
                                tac_tech_events['Execution']['Modify Existing Service']['Events'].append(event_set)
                                tac_tech_events['Execution']['Service Execution']['Events'].append(event_set)

                        # CAR-2013-07-005: Command Line Usage of Archiving Software
                        # Data Compressed - Exfiltration
                        # https://car.mitre.org/analytics/CAR-2013-07-005

                        # TODO 테스트 : 7z.exe a test.zip test.txt

                        if ' a ' in com_line:

                            print('Command Line Usage of Archiving Software // Detected')
                            event_set['ID'] = 'CAR-2013-07-005'
                            event_set['Name'] = 'Command Line Usage of Archiving Software'
                            event_set['Event'] = [record_dict]

                            tac_tech_events['Exfiltration']['Events'].append(event_set)

                            tac_tech_events['Exfiltration']['Data Compressed']['Events'].append(event_set)

                        # CAR-2014-04-003: Powershell Execution
                        # PowerShell - Defense Evasion
                        # Scripting - Defense Evasion
                        # https://car.mitre.org/analytics/CAR-2014-04-003

                        # TODO 이러한 정보들 뿐만 아니라, 내가 저장시킨 Powershell 로그에 Mimikatz라던가 그런게 없는지 확인해보기!
                        # TODO 또 ParentImage도 어떤놈인지 확인하기!

                        if (
                            'powershell.exe' == image_exe and
                            'explorer.exe' != parent_image_exe
                            ):

                            print('Powershell Execution // Detected')
                            event_set['ID'] = 'CAR-2014-04-003'
                            event_set['Name'] = 'Powershell Execution'
                            event_set['Event'] = [record_dict]

                            tac_tech_events['Defense Evasion']['Events'].append(event_set)

                            tac_tech_events['Defense Evasion']['PowerShell']['Events'].append(event_set)
                            tac_tech_events['Defense Evasion']['Scripting']['Events'].append(event_set)

                        # CAR-2013-05-004: Execution with AT
                        # Scheduled Task - Execution,Persistence, Privilege Escalation
                        # https://car.mitre.org/analytics/CAR-2013-05-004

                        # TODO 테스트 : at 10:00 calc.exe // returns a job number X 
                        # TODO 테스트 : at X /delete

                        if 'at.exe' == image_exe:

                            print('Execution with AT // Detected')
                            event_set['ID'] = 'CAR-2013-05-004'
                            event_set['Name'] = 'Execution with AT'
                            event_set['Event'] = [record_dict]

                            tac_tech_events['Execution']['Events'].append(event_set)
                            tac_tech_events['Persistence']['Events'].append(event_set)
                            tac_tech_events['Privilege Escalation']['Events'].append(event_set)

                            tac_tech_events['Execution']['Scheduled Task']['Events'].append(event_set)
                            tac_tech_events['Persistence']['Scheduled Task']['Events'].append(event_set)
                            tac_tech_events['Privilege Escalation']['Scheduled Task']['Events'].append(event_set)

                        # CAR-2013-07-001: Suspicious Arguments
                        # Credential Dumping - Credential Access
                        # Masquerading - Defense Evasion
                        # Remote Services - Lateral Movement
                        # Remote File Copy - Command and Control, Lateral Movement
                        # https://car.mitre.org/analytics/CAR-2013-07-001

                        # TODO 테스트 : putty.exe -pw <password> -R <port>:<host> <user>@<host>
                        # TODO 테스트 : 7z.exe a test.zip test.txt

                        putty = re.search( r'-pw .* -R .*:.* .*@.*', com_line, re.M|re.I)
                        port_fwd = re.search(r'-R .* -pw', com_line, re.M|re.I)
                        scp = re.search(r'-pw .* .* .*@.*', com_line, re.M|re.I)
                        # TODO mimikatz는 powershell으로 자주 실행되기때문에 사실 cmd가 아니라 powershell 내가 저장시킨 로그에서 판단해야됨!
                        # TODO mimikatz 뿐만 아니라 다른 스크립트들도 똑같음!! 그리고 caldera 공격은 sysmon 이벤트에서 commandLine에 안찍힘! 그래서 sysmon 이벤트에서는 판단 불가능!
                        # TODO 그래서 결국 내가 저장시킨 powershell 스크립트를 확인해야될듯!
                        # TODO caldera 공격에서는 commander.exe -f 뭐 이런식으로밖에 안나옴!!
                        mimikatz = re.search(r'sekurlsa', com_line, re.M|re.I)
                        rar = re.search(r'.* -hp .*', com_line, re.M|re.I)
                        archive = re.search(r'.* a .*', com_line, re.M|re.I)
                        # TODO ip_addr 이거는 정상적인 프로세스도 감지해냄... 확인해봤는데 ~~.2.0.0.68.dll 이런게 있었는데 dll인데도 검출했음.. 원하던 IP가 아님..
                        ip_addr = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', com_line, re.M|re.I)

                        check_detected = False
                        if putty:
                            print('Suspicious Arguments : putty // Detected')
                            check_detected = True
                        elif port_fwd:
                            print('Suspicious Arguments : port_fwd // Detected')
                            check_detected = True
                        elif scp:
                            print('Suspicious Arguments : scp // Detected')
                            check_detected = True
                        elif mimikatz:
                            print('Suspicious Arguments : mimikatz // Detected')
                            check_detected = True
                        elif rar:
                            print('Suspicious Arguments : rar // Detected')
                            check_detected = True
                        elif archive:
                            print('Suspicious Arguments : archive // Detected')
                            check_detected = True
                        elif ip_addr:
                            print('Suspicious Arguments : ip_addr // Detected')
                            print('CommandLine : ' + com_line)
                            check_detected = True

                        if check_detected == True:
                            event_set['ID'] = 'CAR-2013-07-001'
                            event_set['Name'] = 'Suspicious Arguments'
                            event_set['Event'] = [record_dict]
                            
                            # TODO 전술이랑 테크닉을 어떻게 나눌지 고민해봐야함..

                        # CAR-2014-11-004: Remote PowerShell Sessions
                        # PowerShell - Execution
                        # Windows Remote Management - Lateral Movement
                        # https://car.mitre.org/analytics/CAR-2014-11-004

                        if (
                            'svchost.exe' == parent_image_exe and
                            'wsmprovhost.exe' == image_exe
                            ):

                            print('Remote PowerShell Sessions // Detected') 
                            event_set['ID'] = 'CAR-2014-11-004'
                            event_set['Name'] = 'Remote PowerShell Sessions'
                            event_set['Event'] = [record_dict]

                            tac_tech_events['Execution']['Events'].append(event_set)
                            tac_tech_events['Lateral Movement']['Events'].append(event_set)

                            tac_tech_events['Execution']['PowerShell']['Events'].append(event_set)
                            tac_tech_events['Lateral Movement']['Windows Remote Management']['Events'].append(event_set)

                        # CAR-2013-05-002: Suspicious Run Locations
                        # Masquerading - Defense Evasion
                        # https://car.mitre.org/analytics/CAR-2013-05-002

                        # TODO 테스트 : copy C:\windows\system32\notepad.exe C:\windows\tasks
                        # TODO 테스트 : start C:\windows\tasks\notepad.exe
                        # TODO 테스트 : del C:\windows\tasks\notepad.exe

                        if (
                            re.search( r'.*:\\RECYCLER\\.*', image, re.M|re.I) != None or
                            re.search( r'.*:\\SystemVolumeInformation\\.*', image, re.M|re.I) != None or
                            re.search( windir + r'\\Tasks\\.*', image, re.M|re.I) != None or
                            re.search( systemroot + r'\\debug\\.*', image, re.M|re.I) != None
                            ):

                            print('Suspicious Run Locations // Detected') 
                            event_set['ID'] = 'CAR-2013-05-002'
                            event_set['Name'] = 'Suspicious Run Locations'
                            event_set['Event'] = [record_dict]

                            tac_tech_events['Defense Evasion']['Events'].append(event_set)

                            tac_tech_events['Defense Evasion']['Masquerading']['Events'].append(event_set)

                        # CAR-2014-11-003: Debuggers for Accessibility Applications
                        # Accessibility Features - Privilege Escalation, Execution, Persistence
                        # https://car.mitre.org/analytics/CAR-2014-11-003

                        # TODO Document에서 Pseudocode는 (command_line match "$.* .*(sethcutilmanosknarratormagnify)\.exe") 이런식으로 표시했는데
                        # TODO 여기서 $ 이게 뭘뜻하는건지 모르겠음... 뒤에서부터 匹配하는거라는데... 어법이 안맞는것같은데..
                        # TODO 일단 그래서 $ 빼고 했음

                        # TODO 테스트 : cmd.exe Magnify.exe

                        if ( 
                            re.search( r'.* .*sethc\.exe*', com_line, re.M|re.I) != None or
                            re.search( r'.* .*utilman\.exe*', com_line, re.M|re.I) != None or
                            re.search( r'.* .*osk\.exe*', com_line, re.M|re.I) != None or
                            re.search( r'.* .*narrator\.exe*', com_line, re.M|re.I) != None or
                            re.search( r'.* .*Magnify\.exe*', com_line, re.M|re.I) != None
                            ):

                            print('Debuggers for Accessibility Applications // Detected') 
                            event_set['ID'] = 'CAR-2014-11-003'
                            event_set['Name'] = 'Debuggers for Accessibility Applications'
                            event_set['Event'] = [record_dict]

                            tac_tech_events['Privilege Escalation']['Events'].append(event_set)
                            tac_tech_events['Execution']['Events'].append(event_set)
                            tac_tech_events['Persistence']['Events'].append(event_set)

                            tac_tech_events['Privilege Escalation']['Accessibility Features']['Events'].append(event_set)
                            tac_tech_events['Execution']['Accessibility Features']['Events'].append(event_set)
                            tac_tech_events['Persistence']['Accessibility Features']['Events'].append(event_set)

                        # CAR-2014-03-006: RunDLL32.exe monitoring
                        # Rundll32 - Defense Evasion
                        # https://car.mitre.org/analytics/CAR-2014-03-006

                        # TODO 이게 바로 위에서 말한 $ 사용법의 올바른 예! 위에있는 ~ in ~ 이런식의 코드들도 다 밑에 방식으로 바꾸는게 좋음!

                        # TODO 테스트 : c:\windows\syswow64\rundll32.exe
                        # TODO 테스트 : RUNDLL32.EXE SHELL32.DLL,Control_RunDLL desk.cpl,,0

                        if 'rundll32.exe' == image_exe:

                            print('RunDLL32.exe monitoring // Detected') 
                            event_set['ID'] = 'CAR-2014-03-006'
                            event_set['Name'] = 'RunDLL32.exe monitoring'
                            event_set['Event'] = [record_dict]
                            # TODO 여기서 주의해야할점!! Rundll32은 Execution 에도 있고 Defense Evasion 에도 있음! 그러므로 지금처럼
                            # TODO tac_events 랑 tech_events로 나누면 안되고 나중에는 tac_events['Defense Evasion']['Rundll32'].append(~) 이런식으로 바꿔야함!
                            # TODO 이렇게 바꾸지 않으면 심각한 오류임!
                            tac_tech_events['Defense Evasion']['Events'].append(event_set)
                            tac_tech_events['Defense Evasion']['Rundll32']['Events'].append(event_set)

                        # CAR-2016-03-001: Host Discovery Commands
                        # Account Discovery - Discovery
                        # Permission Groups Discovery - Discovery
                        # System Network Configuration Discovery - Discovery
                        # System Information Discovery - Discovery
                        # System Owner/User Discovery - Discovery
                        # Process Discovery - Discovery
                        # System Service Discovery - Discovery
                        # https://car.mitre.org/analytics/CAR-2016-03-001

                        # TODO 아래처럼 괄호 저렇게 나누는거 보기 편한것같음!

                        if (
                            'hostname.exe' == image_exe or
                            'ipconfig.exe' == image_exe or
                            'net.exe' == image_exe or
                            'quser.exe' == image_exe or
                            'qwinsta.exe' == image_exe or
                            (
                                'sc.exe' == image_exe and 
                                (' query' in com_line or 
                                    ' qc' in com_line
                                )
                            ) or
                            'systeminfo.exe' == image_exe or
                            'tasklist.exe' == image_exe or
                            'whoami.exe' == image_exe
                            ):

                            # TODO (내가한거) whoami 이런거 발견했을때 만약에 parentProcess가 powershell이면 명령어 확인해보기!

                            print('Host Discovery Commands // Detected') 
                            event_set['ID'] = 'CAR-2016-03-001'
                            event_set['Name'] = 'Host Discovery Commands'
                            event_set['Event'] = [record_dict]
                            # TODO 각각 어떤 전술과 테크닉 으로 나눌지는 생각해봐야함!

                        # CAR-2014-05-002: Services launching Cmd
                        # New Service - Persistence, Privilege Escalation
                        # https://car.mitre.org/analytics/CAR-2014-05-002

                        if (
                            'cmd.exe' == image_exe and
                            'services.exe' == parent_image_exe
                            ):

                            print("Services launching Cmd // Detected")
                            event_set['ID'] = 'CAR-2014-05-002'
                            event_set['Name'] = 'Services launching Cmd'
                            event_set['Event'] = [record_dict]

                            tac_tech_events['Persistence']['Events'].append(event_set)
                            tac_tech_events['Privilege Escalation']['Events'].append(event_set)

                            tac_tech_events['Persistence']['New Service']['Events'].append(event_set)
                            tac_tech_events['Privilege Escalation']['New Service']['Events'].append(event_set)

                        # CAR-2013-08-001: Execution with schtasks
                        # Scheduled Task - Persistence
                        # https://car.mitre.org/analytics/CAR-2013-08-001

                        # TODO 테스트 : schtasks /Create /SC ONCE /ST 19:00 /TR C:\Windows\System32\calc.exe /TN calctask
                        # TODO 테스트 : schtasks /Delete /TN calctask

                        if 'schtasks.exe' == image_exe:
                            print("Execution with schtasks // Detected")
                            event_set['ID'] = 'CAR-2013-08-001'
                            event_set['Name'] = 'Execution with schtasks'
                            event_set['Event'] = [record_dict]

                            tac_tech_events['Persistence']['Events'].append(event_set)

                            tac_tech_events['Persistence']['Scheduled Task']['Events'].append(event_set)

                        # CAR-2014-11-008: Command Launched from WinLogon
                        # Accessibility Features - Privilege Escalation, Execution, Persistence
                        # https://car.mitre.org/analytics/CAR-2014-11-008

                        if (
                            'cmd.exe' == image_exe and
                            'winlogon.exe' == parent_image_exe
                            ):

                            print("Command Launched from WinLogon // Detected")
                            event_set['ID'] = 'CAR-2014-11-008'
                            event_set['Name'] = 'Command Launched from WinLogon'
                            event_set['Event'] = [record_dict]

                            tac_tech_events['Privilege Escalation']['Events'].append(event_set)
                            tac_tech_events['Execution']['Events'].append(event_set)
                            tac_tech_events['Persistence']['Events'].append(event_set)

                            tac_tech_events['Privilege Escalation']['Accessibility Features']['Events'].append(event_set)
                            tac_tech_events['Execution']['Accessibility Features']['Events'].append(event_set)
                            tac_tech_events['Persistence']['Accessibility Features']['Events'].append(event_set)


                    elif evt_id == 3:

                        # CAR-2014-05-001: RPC Activity
                        # Lateral Movement - Valid Accounts
                        # Lateral Movement - Remote Services
                        # https://car.mitre.org/analytics/CAR-2014-05-001

                        if (
                            int(record_dict['Event']['EventData']['DestinationPort']) >= 49152 and
                            int(record_dict['Event']['EventData']['SourcePort']) >= 49152
                            ):

                            rpc_mapper = self.RPC_Activity(record_dict)

                            if rpc_mapper[0] == True:
                                print('RPC Activity // Detected')
                                event_set['ID'] = 'CAR-2014-05-001'
                                event_set['Name'] = 'RPC Activity'
                                event_set['Event'] = [record_dict, rpc_mapper[1]]

                                tac_tech_events['Lateral Movement']['Events'].append(event_set)

                                tac_tech_events['Lateral Movement']['Valid Accounts']['Events'].append(event_set)
                                tac_tech_events['Lateral Movement']['Remote Services']['Events'].append(event_set)

                        # CAR-2014-11-006: Windows Remote Management (WinRM)
                        # Windows Remote Management - Lateral Movement
                        # https://car.mitre.org/analytics/CAR-2014-11-006

                        if (
                            int(record_dict['Event']['EventData']['DestinationPort']) == 5985 or
                            int(record_dict['Event']['EventData']['DestinationPort']) == 5986
                            ):

                            print('Windows Remote Management (WinRM) // Detected')
                            event_set['ID'] = 'CAR-2014-11-006'
                            event_set['Name'] = 'Windows Remote Management (WinRM)'
                            event_set['Event'] = [record_dict, rpc_mapper[1]]

                            tac_tech_events['Lateral Movement']['Events'].append(event_set)

                            tac_tech_events['Lateral Movement']['Windows Remote Management']['Events'].append(event_set)


                    ###########################################################################################

                    # CAR-2013-03-001: Reg.exe called from Command Shell
                    # Query Registry - Defense Evasion
                    # Modify Registry - Persistence, Privilege Escalation
                    # Registry Run Keys / Startup Folder - Persistence, Privilege Escalation
                    # Service Registry Permissions Weakness - Persistence, Privilege Escalation
                    # https://car.mitre.org/analytics/CAR-2013-03-001

                    # TODO 실시간으로 어떤식으로 분석을 진행해야하는지 아직 잘 모르겠음.
                    # TODO Pseudocode를 봤는데... 아마 이건 실시간으로 분석할수 있는게 아닌것같음..
                    # TODO 로그인한 시간부터 분석을 테스트한 시간까지 쭉 쿼리해야됨

                    # TODO 테스트 : reg.exe QUERY HKLM\Software\Microsoft


                    # CAR-2015-04-002: Remotely Scheduled Tasks via Schtasks
                    # Scheduled Task - Execution
                    # https://car.mitre.org/analytics/CAR-2015-04-002

                    # TODO Pseudocode를 이해를 못하겠음.. proto_info.rpc_interface가 뭘 뜻하는거지..?

                    # CAR-2013-10-002: DLL Injection via Load Library
                    # Process Injection - Defense Evasion
                    # Bypass User Account Control - Privilege Escalation
                    # https://car.mitre.org/analytics/CAR-2013-10-002

                    # TODO Thread 에 관한 예제가 없어서 어떻게 만들어야할지 모르겠음.
                    #if str(record_dict['Event']['System']['EventID']) == str(8) and
                    #    (str(record_dict['Event']['EventData']['StartFunction']) == "LoadLibraryA" or
                    #        str(record_dict['Event']['EventData']['StartFunction']) == "LoadLibraryW") and
                    #    str(record_dict['Event']['EventData']['SourceImage']) == "C:\\Path\\To\\TrustedProgram.exe":

                    #    print("DLL Injection via Load Library // Detected")
                    # TODO Thread 에 관한 예제는 찾았지만 Path To TrustedProgram 을 구별 불가능!!

                    # CAR-2014-11-005: Remote Registry
                    # Modify Registry - Lateral Movement, Defense Evasion
                    # https://car.mitre.org/analytics/CAR-2014-11-005

                    # proto_info를 sysmon은 탐지 못함... CAR에 나와있는 내용 봤는데 아직 탐지가능한 툴이 없는듯.. (https://car.mitre.org/data_model/flow#proto_info)

                    

                    # CAR-2014-03-001: SMB Write Request - NamedPipes
                    # https://car.mitre.org/analytics/CAR-2014-03-001

                    # TODO 이것도 proto_info 를 어디서 어떻게 받아오는지 모르겠음...

                    # CAR-2013-09-005: Service Outlier Executables
                    # Modify Existing Service - Persistence, Privilege Escalation
                    # New Service - Persistence, Privilege Escalation
                    # https://car.mitre.org/analytics/CAR-2013-09-005

                    #if str(record_dict['Event']['System']['EventID']) == str(1) and
                    #    str(record_dict['Event']['EventData']['ParentImage']) == "C:\\Windows\\System32\\services.exe"

                    # TODO 이건 실시간이 아니라 어느정도 텀을 둔 분석인듯!
                    # TODO 그리고 Pseudocode 에서 "historic_services = filter services (where timestamp < now - 1 day AND timestamp > now - 1 day)" 이게 무슨뜻인지 못알아듣겠음...
                    # Create a baseline of services seen over the last 30 days and a list of services seen today. Remove services in the baseline from services seen today, leaving a list of new services.
                    # 지난 30일 동안 표시된 서비스의 기준선과 현재 표시된 서비스 목록을 생성하십시오. 현재 표시된 서비스에서 기준선에 있는 서비스를 제거하고 새 서비스 목록을 남긴다.
                    # TODO 실시간 검사를 실행하기전에 30일동안의 historic_services 목록을 생성해놔야 할것 같음... (실시간 검사인것 같기도 하고...?)
                    # TODO 아마 services.exe가 부모프로세스일때의 process created를 검사하는듯! 그리고 지난 30일동안의 historic_services 목록에 있는지 확인하는것일듯!
                    # TODO 만약 저 목록에 없으면 출력!
                    # TODO 생각해보니 1시간마다 검사해보는것도 나쁘진 않은것같고... 또 1시간은 너무 길어서 효과를 못볼것같기도하고..
                    # TODO 아무튼 나중에 생각해보기!!


                    # CAR-2013-05-005: SMB Copy and Execution
                    # Windows Admin Shares - Lateral Movement
                    # Valid Accounts - Defense Evasion, Lateral Movement
                    # Remote File Copy - Lateral Movement
                    # https://car.mitre.org/analytics/CAR-2013-05-005

                    # TODO 이 분석을 진행하려면 "CAR-2013-05-003" 이 분석 내용이 필요한데, "CAR-2013-05-003"분석은 proto_info를 필요로함.. sysmon으로는 얻을수 없는 정보..

                    # CAR-2013-02-003: Processes Spawning cmd.exe
                    # Command-Line Interface - Execution
                    # https://car.mitre.org/analytics/CAR-2013-02-003

                    #if str(record_dict['Event']['System']['EventID']) == str(1) and
                    #    'cmd.exe' in str(record_dict['Event']['EventData']['Image']):

                    #    print('Processes Spawning cmd.exe // Detected') 
                    # TODO 이건 너무 광범위한것같음... 그냥 cmd만 나오면 바로 출력을시켜버리니...
                    # TODO Document에는 abnormal parent process가 cmd를 실행시키면, 이라고 나와있는데 abnormal parent가 뭔지 모르겠음..


                    # CAR-2014-11-007: Remote Windows Management Instrumentation (WMI) over RPC
                    # Windows Management Instrumentation - Lateral Movement
                    # https://car.mitre.org/analytics/CAR-2014-11-007

                    # TODO proto_info....


                    # CAR-2013-07-002: RDP Connection Detection
                    # Remote Desktop Protocol - Lateral Movement
                    # https://car.mitre.org/analytics/CAR-2013-07-002

                    # TODO network connection start는 sysmon 이벤트 로그에 남는데 end는 안남는것같음...

                    # CAR-2013-09-003: SMB Session Setups
                    # https://car.mitre.org/analytics/CAR-2013-09-003

                    # TODO proto_info를 어디서 찾을수 있을까나...

                    # CAR-2013-05-003: SMB Write Request
                    # Remote File Copy - Lateral Movement
                    # Windows Admin Shares - Lateral Movement
                    # Valid Accounts - Defense Evasion, Lateral Movement

                    # TODO proto_info...... 어떻게 찾지..

                    # CAR-2014-11-002: Outlier Parents of Cmd
                    # Command-Line Interface - Execution
                    # https://car.mitre.org/analytics/CAR-2014-11-002

                    # TODO 여기도 Pseudocode가 이상한것같음... (where timestamp < now - 1 day AND timestamp > now - 1 day) 이게 무슨뜻인지..
                    # TODO 어떤말을 하고싶어하는지는 알겠음. 지난 30일동안 cmd의 parent_exe 목록을 만들고, 실시간검색으로 만약 지난 30일동안 나타나지 않았던 parent_exe가 나타나면 경고를 띄우는것.

                    # CAR-2014-02-001: Service Binary Modifications
                    # New Service - Persistence, Privilege Escalation   Moderate
                    # Modify Existing Service - Persistence  
                    # File System Permissions Weakness - Persistence, Privilege Escalation   Moderate
                    # Service Execution - Execution, Privilege Escalation Moderate
                    # https://car.mitre.org/analytics/CAR-2014-02-001

                    # TODO Autoruns가 있어야 가능함..

                    # CAR-2013-01-003: SMB Events Monitoring
                    # Valid Accounts - Lateral Movement
                    # Data from Network Shared Drive - Exfiltration
                    # Windows Admin Shares - Lateral Movement
                    # https://car.mitre.org/analytics/CAR-2013-01-003

                    # TODO proto_info....

                    # CAR-2015-04-001: Remotely Scheduled Tasks via AT
                    # Scheduled Task - Execution
                    # https://car.mitre.org/analytics/CAR-2015-04-001

                    # TODO proto_info....

                    # CAR-2013-01-002: Autorun Differences
                    # https://car.mitre.org/analytics/CAR-2013-01-002

                    # TODO Autorun에 대한 설명인가..?


                    # CAR-2014-12-001: Remotely Launched Executables via WMI
                    # Windows Management Instrumentation - Execution
                    # https://car.mitre.org/analytics/CAR-2014-12-001

                    # TODO proto_info....

                    # CAR-2013-05-009: Running executables with same hash and different names
                    # Masquerading - Defense Evasion
                    # https://car.mitre.org/analytics/CAR-2013-05-009

                    # Output Description : A list of hashes and the different executables associated with each one


    def RPC_Activity(self, rpc_endpoint):

        path = "Microsoft-Windows-Sysmon/Operational"
        handle = win32evtlog.EvtQuery( # Get event log
                        path,
                        win32evtlog.EvtQueryReverseDirection,
                        #"Event/System[EventID=5]",
                        #None
                    )

        while 1:
            events = win32evtlog.EvtNext(handle, 10)
            if len(events) == 0:
                return (False, None)
            for event in events:
                record = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)

                # xml to dict
                rpc_mapper = xmltodict.parse(record)

                # 변수 설정
                evt_id = int(rpc_mapper['Event']['System']['EventID'])

                # UTC to Local Time
                evt_local_time = Utc_to_local(rpc_mapper['Event']['System']['TimeCreated']['@SystemTime'])
                rpc_mapper['Event']['System']['TimeCreated']['@SystemTime'] = evt_local_time

                # rpc_mapper 의 EventData 의 value 값 수정하기... Data - name - text 이런식으로 돼있어서 인덱스하기 힘듦...!
                temp_data = {}
                for data in rpc_mapper['Event']['EventData']['Data']:
                    if '#text' in data:
                        temp_data[data['@Name']] = data['#text']
                    elif data == None or data == 'None':
                        temp_data = {}
                    else:
                        temp_data[data['@Name']] = None
                rpc_mapper['Event']['EventData'] = temp_data
                # print(temp_data)

                if (
                    evt_id == 3 and 
                    int(rpc_mapper['Event']['EventData']['DestinationPort']) == 135 and
                    rpc_mapper['Event']['EventData']['SourceIp'] == rpc_endpoint['Event']['EventData']['SourceIp'] and
                    rpc_mapper['Event']['EventData']['DestinationIp'] == rpc_endpoint['Event']['EventData']['DestinationIp'] and
                    rpc_endpoint['Event']['System']['TimeCreated']['@SystemTime'] - datetime.timedelta(seconds=2) <= rpc_mapper['Event']['System']['TimeCreated']['@SystemTime'] and
                    rpc_endpoint['Event']['System']['TimeCreated']['@SystemTime'] >= rpc_mapper['Event']['System']['TimeCreated']['@SystemTime'] and
                    rpc_endpoint['Event']['System']['EventRecordID'] != rpc_mapper['Event']['System']['EventRecordID']
                    ):
                    return (True, rpc_mapper)

                elif rpc_endpoint['Event']['System']['TimeCreated']['@SystemTime'] - datetime.timedelta(seconds=2) > rpc_mapper['Event']['System']['TimeCreated']['@SystemTime']:
                    return (False, None)

    def Quick_execution_of_a_series_of_suspicious_commands(self, reg_processes):

        # TODO 각각의 exe가 어떤 ATT&CK 기법인지 판단이 잘 안됨...

        path = "Microsoft-Windows-Sysmon/Operational"
        handle = win32evtlog.EvtQuery( # Get event log
                        path,
                        win32evtlog.EvtQueryReverseDirection,
                        #"Event/System[EventID=5]",
                        #None
                    )

        while 1:
            events = win32evtlog.EvtNext(handle, 10)
            if len(events) == 0:
                return (False, ['', ''])
            for event in events:
                record = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)

                # xml to dict
                reg = xmltodict.parse(record)

                # 변수 설정
                evt_id = 0
                try:
                    evt_id = int(reg['Event']['System']['EventID'])
                except:
                    evt_id = int(reg['Event']['System']['EventID']['#text'])

                # UTC to Local Time
                evt_local_time = Utc_to_local(reg['Event']['System']['TimeCreated']['@SystemTime'])
                reg['Event']['System']['TimeCreated']['@SystemTime'] = evt_local_time

                # reg 의 EventData 의 value 값 수정하기... Data - name - text 이런식으로 돼있어서 인덱스하기 힘듦...!
                temp_data = {}
                for data in reg['Event']['EventData']['Data']:
                    if '#text' in data:
                        temp_data[data['@Name']] = data['#text']
                    elif data == None or data == 'None':
                        temp_data = {}
                    else:
                        temp_data[data['@Name']] = None
                reg['Event']['EventData'] = temp_data
                # print(temp_data)


                if (
                    evt_id == 1 and 
                    reg_processes['Event']['System']['TimeCreated']['@SystemTime'] - datetime.timedelta(minutes=30) <= reg['Event']['System']['TimeCreated']['@SystemTime'] and
                    reg['Event']['System']['TimeCreated']['@SystemTime'] <= reg_processes['Event']['System']['TimeCreated']['@SystemTime'] and
                    reg_processes['Event']['EventData']['User'] == reg['Event']['EventData']['User'] and
                    reg_processes['Event']['EventData']['ParentProcessId'] == reg['Event']['EventData']['ParentProcessId'] and
                    reg_processes['Event']['System']['EventRecordID'] != reg['Event']['System']['EventRecordID']
                    ):
                    rp_exe = str(reg_processes['Event']['EventData']['Image']).split('\\')
                    rp_exe = (rp_exe[-1]).lower()
                    r_exe = str(reg['Event']['EventData']['Image']).split('\\')
                    r_exe = (r_exe[-1]).lower()

                    # (내가한거)TODO 여기서 parentImage가 powershell 인 경우가 많은데! 이럴때 powershell의 명령어도 함께 꼭 검사해봐야됨!!

                    for exe_name in commands_of_interest:
                        if exe_name == r_exe:
                            return (True, [rp_exe, r_exe])
                elif reg_processes['Event']['System']['TimeCreated']['@SystemTime'] - datetime.timedelta(minutes=30) > reg['Event']['System']['TimeCreated']['@SystemTime']:
                    return (False, ['', ''])

                

    def Remotely_Launched_Executables_via_Services(self, service):
        # TODO 나중에 handle에 있는 #"Event/System[EventID=5]" 이부분의 Query도 고치면 더 빠르게 찾을수 있지 않을까 싶음. (다른함수들의 handle도 포함)

        path = "Microsoft-Windows-Sysmon/Operational"
        handle = win32evtlog.EvtQuery( # Get event log
                        path,
                        win32evtlog.EvtQueryReverseDirection,
                        #"Event/System[EventID=5]",
                        #None
                    )

        while 1:
            events = win32evtlog.EvtNext(handle, 10)
            if len(events) == 0:
                return (False, None)
            for event in events:
                record = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)

                # xml to dict
                flow  = xmltodict.parse(record)

                # 변수 설정
                evt_id = 0
                try:
                    evt_id = int(flow['Event']['System']['EventID'])
                except:
                    evt_id = int(flow['Event']['System']['EventID']['#text'])


                # UTC to Local Time
                evt_local_time = Utc_to_local(flow ['Event']['System']['TimeCreated']['@SystemTime'])
                flow ['Event']['System']['TimeCreated']['@SystemTime'] = evt_local_time

                # flow 의 EventData 의 value 값 수정하기... Data - name - text 이런식으로 돼있어서 인덱스하기 힘듦...!
                temp_data = {}
                for data in flow['Event']['EventData']['Data']:
                    if '#text' in data:
                        temp_data[data['@Name']] = data['#text']
                    elif data == None or data == 'None':
                        temp_data = {}
                    else:
                        temp_data[data['@Name']] = None
                flow['Event']['EventData'] = temp_data
                # print(temp_data)


                if (
                    evt_id == 3 and 
                    service['Event']['System']['TimeCreated']['@SystemTime'] - datetime.timedelta(seconds=1) <= flow ['Event']['System']['TimeCreated']['@SystemTime'] and
                    service['Event']['System']['TimeCreated']['@SystemTime'] >= flow ['Event']['System']['TimeCreated']['@SystemTime'] and
                    service['Event']['EventData']['User'] == flow['Event']['EventData']['User'] and
                    service['Event']['EventData']['ProcessId'] == flow['Event']['EventData']['ProcessId'] and
                    service['Event']['System']['EventRecordID'] != flow['Event']['System']['EventRecordID']
                    ):

                    return (True, flow)

                elif service['Event']['System']['TimeCreated']['@SystemTime'] - datetime.timedelta(seconds=1) > flow ['Event']['System']['TimeCreated']['@SystemTime']:
                    return (False, None)



# ===================================================================================================== #
# ===================================================================================================== #

class System_evt (threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.min_time = datetime.datetime.now(tz.tzlocal())
        self.max_time = datetime.datetime.now(tz.tzlocal())

    def run(self):
        while 1:
            self.get_evt_log()
            time.sleep(1) # 이렇게 안해주면 CPU를 너무 많이먹음...

    def get_evt_log(self): # 매번 지역변수로 새로 설정해서 매번 갱신을 시켜줘야지만 새로운 이벤트 로그를 받아옴.
        path = "System"
        handle = win32evtlog.EvtQuery( # Get event log
                        path,
                        win32evtlog.EvtQueryReverseDirection,
                        #"Event/System[EventID=5]",
                        #None
                    )

        while 1:
            events = win32evtlog.EvtNext(handle, 10)
            if len(events) == 0:
                return
            for event in events:
                record = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)

                # xml to dict
                record_dict = xmltodict.parse(record)

                # 변수 설정
                evt_id = 0
                try:
                    evt_id = int(record_dict['Event']['System']['EventID'])
                except:
                    evt_id = int(record_dict['Event']['System']['EventID']['#text'])

                # UTC to Local Time
                evt_local_time = Utc_to_local(record_dict['Event']['System']['TimeCreated']['@SystemTime'])
                record_dict['Event']['System']['TimeCreated']['@SystemTime'] = evt_local_time

                if evt_local_time <= self.min_time:
                    self.min_time = self.max_time
                    return
                else:
                    # print("==============System================")
                    # print(evt_local_time)
                    if evt_local_time > self.max_time:
                        self.max_time = evt_local_time

                    # record_dict 의 EventData 의 value 값 수정하기... Data - name - text 이런식으로 돼있어서 인덱스하기 힘듦...!
                    temp_data = {}
                    for data in record_dict['Event']['EventData']['Data']:
                        if '#text' in data:
                            temp_data[data['@Name']] = data['#text']
                        elif data == None or data == 'None':
                            temp_data = {}
                        else:
                            temp_data[data['@Name']] = None
                    record_dict['Event']['EventData'] = temp_data
                    # print(temp_data)

                    # CAR analytics

                    # 의심가는 이벤트 발견시 이벤트 정보 담는 변수
                    event_set = {}

                    # CAR-2016-04-003: User Activity from Stopping Windows Defensive Services
                    # Indicator Blocking - Defense Evasion
                    # https://car.mitre.org/analytics/CAR-2016-04-003

                    # 테스트 : 관리자권한으로 powershell 에서 Stop-Service -displayname "Windows Firewall" 나 Stop-Service -displayname "Windows Defender" 실행.

                    if (
                        evt_id == 7036 and
                        str(record_dict['Event']['EventData']['param1']) in ["Windows Defender", "Windows Firewall"] and
                        str(record_dict['Event']['EventData']['param2']) == "stopped"
                        ):

                        print("User Activity from Stopping Windows Defensive Services // Detected")
                        event_set['ID'] = 'CAR-2016-04-003'
                        event_set['Name'] = 'User Activity from Stopping Windows Defensive Services'
                        event_set['Event'] = [record_dict]

                        tac_tech_events['Defense Evasion']['Events'].append(event_set)

                        tac_tech_events['Defense Evasion']['Indicator Blocking']['Events'].append(event_set)

                    # CAR-2016-04-002: User Activity from Clearing Event Logs
                    # Indicator Blocking - Defense Evasion
                    # https://car.mitre.org/analytics/CAR-2016-04-002

                    # 확인 방법 : Clear-Eventlog Security 또는 Clear-Eventlog System

                    if (
                        evt_id == 1100 or
                        evt_id == 1102
                        ):

                        print('User Activity from Clearing Event Logs // Detected')
                        event_set['ID'] = 'CAR-2016-04-002'
                        event_set['Name'] = 'User Activity from Clearing Event Logs'
                        event_set['Event'] = [record_dict]

                        tac_tech_events['Defense Evasion']['Events'].append(event_set)

                        tac_tech_events['Defense Evasion']['Indicator Blocking']['Events'].append(event_set)

# ===================================================================================================== #
# ===================================================================================================== #

class Security_evt (threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.min_time = datetime.datetime.now(tz.tzlocal())
        self.max_time = datetime.datetime.now(tz.tzlocal())

    def run(self):
        while 1:
            self.get_evt_log()
            time.sleep(1) # 이렇게 안해주면 CPU를 너무 많이먹음...

    def get_evt_log(self): # 매번 지역변수로 새로 설정해서 매번 갱신을 시켜줘야지만 새로운 이벤트 로그를 받아옴.
        path = "Security"
        handle = win32evtlog.EvtQuery( # Get event log
                        path,
                        win32evtlog.EvtQueryReverseDirection,
                        #"Event/System[EventID=5]",
                        #None
                    )

        while 1:
            events = win32evtlog.EvtNext(handle, 10)
            if len(events) == 0:
                return
            for event in events:
                record = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)

                # xml to dict
                record_dict = xmltodict.parse(record)

                # 변수 설정
                evt_id = 0
                try:
                    evt_id = int(record_dict['Event']['System']['EventID'])
                except:
                    evt_id = int(record_dict['Event']['System']['EventID']['#text'])

                # UTC to Local Time
                evt_local_time = Utc_to_local(record_dict['Event']['System']['TimeCreated']['@SystemTime'])
                record_dict['Event']['System']['TimeCreated']['@SystemTime'] = evt_local_time

                if evt_local_time <= self.min_time:
                    self.min_time = self.max_time
                    return
                else:
                    # print("==============Security================")
                    # print(evt_local_time)
                    if evt_local_time > self.max_time:
                        self.max_time = evt_local_time

                    # record_dict 의 EventData 의 value 값 수정하기... Data - name - text 이런식으로 돼있어서 인덱스하기 힘듦...!
                    temp_data = {}
                    for data in record_dict['Event']['EventData']['Data']:
                        if '#text' in data:
                            temp_data[data['@Name']] = data['#text']
                        elif data == None or data == 'None':
                            temp_data = {}
                        else:
                            temp_data[data['@Name']] = None
                    record_dict['Event']['EventData'] = temp_data
                    # print(temp_data)

                    # CAR analytics

                    # 의심가는 이벤트 발견시 이벤트 정보 담는 변수
                    event_set = {}

                    # CAR-2016-04-005: Remote Desktop Logon
                    # Lateral Movement - Valid Accounts
                    # https://car.mitre.org/analytics/CAR-2016-04-005

                    if (
                        evt_id == 4624 and
                        str(record_dict['Event']['EventData']['AuthenticationPackageName']) == 'Negotiate' and
                        str(record_dict['Event']['EventData']['LogonType']) == str(10)
                        ):

                        #TODO Severity라는 항목을 찾을수가 없음... 이 항목의 값이 Information 이어야 함..
                        print('Remote Desktop Logon // Detected')
                        event_set['ID'] = 'CAR-2016-04-005'
                        event_set['Name'] = 'Remote Desktop Logon'
                        event_set['Event'] = [record_dict]

                        tac_tech_events['Lateral Movement']['Events'].append(event_set)

                        tac_tech_events['Lateral Movement']['Valid Accounts']['Events'].append(event_set)

                    # CAR-2013-02-008: Simultaneous Logins on a Host
                    # Lateral Movement - Valid Accounts
                    # https://car.mitre.org/analytics/CAR-2013-02-008

                    #TODO 지금까지의 로그인 내역을 다 받아온다음, 호스트 네임별로 유저 리스트를 그룹 지음.
                    # 그리고 각 그룹마다 제일 처음 로그인 한 시간, 그리고 제일 나중에 로그인 한 시간을 저장하고
                    # 로그인 시도 횟수도 같이 저장함.
                    # 그 다음 그 정보들을 통해서 latest_time - earliest_time <= 1 hour and user_count > 1 조건을 찾음
                    # 찾으면 그게 바로 Simultaneous Logins on a Host 임!

                    # TODO 아니면 매번 Logon 이벤트를 발견 할떄마다 1시간 안에 똑같은 로그인 활동이 발생했는지 알아보면 될듯!
                    # ㄴ 너무 시간이 오래 걸릴듯...
                    # ㄴ 차라리 데이터베이스에다가 하나하나씩 저장하면서 확인하는게 빠를듯... 이렇게 하면 나중에는 결국 많이 확인 안해도 될듯.

                    # TODO 나중에 데이터베이스 설정하고 구현하기!

                    # CAR-2016-04-004: Successful Local Account Login
                    # Pass the Hash - Lateral Movement
                    # https://car.mitre.org/analytics/CAR-2016-04-004

                    # TODO 테스트 : net user 'test' 'test' /add # Creates the user

                    if (
                        evt_id == 4624 and
                        str(record_dict['Event']['EventData']['TargetUserName']) != 'ANONYMOUS LOGON' and
                        str(record_dict['Event']['EventData']['AuthenticationPackageName']) == 'NTLM'
                        ):

                        print('Successful Local Account Login // Detected')
                        event_set['ID'] = 'CAR-2016-04-004'
                        event_set['Name'] = 'Successful Local Account Login'
                        event_set['Event'] = [record_dict]

                        tac_tech_events['Lateral Movement']['Events'].append(event_set)

                        tac_tech_events['Lateral Movement']['Pass the Hash']['Events'].append(event_set)

                    # CAR-2015-07-001: All Logins Since Last Boot
                    # https://car.mitre.org/analytics/CAR-2015-07-001

                    # TODO 이건 아마 mimikatz가 실행된걸 발견하고 난 다음에 target_host랑 event_time을 입력해서
                    # TODO 해당 mimikatz를 발견한 호스트 외에 lateral movement에 의해 피해를 입었을수도 있는 유저들에 대해 조사하는듯!
                    # TODO Security 이벤트 로그중에 EventID 가 4648인 Logon 로그 유의하기!! mimikatz와 연관있는것같음!

                    # CAR-2013-10-001: User Login Activity Monitoring
                    # Remote Desktop Protocol - Lateral Movement
                    # Valid Accounts - Defense Evasion
                    # https://car.mitre.org/analytics/CAR-2013-10-001

                    # Output Description : The time of login events for distinct users on individual systems

                    # CAR-2016-04-002: User Activity from Clearing Event Logs
                    # Indicator Blocking - Defense Evasion
                    # https://car.mitre.org/analytics/CAR-2016-04-002

                    # 확인 방법 : Clear-Eventlog Security 또는 Clear-Eventlog System

                    if evt_id == 104:

                        print('User Activity from Clearing Event Logs // Detected')
                        event_set['ID'] = 'CAR-2016-04-002'
                        event_set['Name'] = 'User Activity from Clearing Event Logs'
                        event_set['Event'] = [record_dict]

                        tac_tech_events['Defense Evasion']['Events'].append(event_set)

                        tac_tech_events['Defense Evasion']['Indicator Blocking']['Events'].append(event_set)


# TODO 아무래도 실시간으로 분석하는 기능 말고도 몇시간 또는 몇십분마다 분석하는 기능도 필요할듯...?
# 실시간으로만 가능한 분석이 있는가 하면, 시간을 좀 두어야 분석이 가능한것들도 있는 것 같음.

if __name__ == "__main__":
    sm_evt = Sysmon_evt()
    sm_evt.start()

    sys_evt = System_evt()
    sys_evt.start()

    sec_evt = Security_evt()
    sec_evt.start()

    print("Quit \'q\' :")
    q = input()
    if q == 'q':
        os._exit(0)

# 내가 추가한것 1 : powershell 명령어 log에 저장시킨거 / quick_~~ 어쩌구 에서 powershell을 이용해서 Invoke-Mimikatz를 사용하면 mimikatz는 안떠서 이 분석결과가 안뜰수있음
# -> 그래서 powershell 명령어 log 확인해서 Invoke-Mimikatz 이런게 있는걸 발견하면 Quick ~ 어쩌구에서 연관시켜서 탐지 가능!
# 내가 추가한것 2 : whoami 같은건 Quick~ 에서 의심가는 리스트에 안들어있음. 그래서 이런게 발생했을때 parentProcess가 Powershell이면 똑같이 명령어 log 확인해보기!
# -> 만약에 정말로 Invoke-Mimikatz 같은게 있으면 확실하게 저런 명령을 썼다는걸 알수있음!
# 내가 추가한것 3 : psexec.exe 같은것에 대해서도 모니터링 추가해야함!