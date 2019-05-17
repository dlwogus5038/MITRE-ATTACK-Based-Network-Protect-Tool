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
import codecs
from dateutil import tz
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

# EvtQuery -> EvtNext -> EvtRender

# CAR-2013-04-002: Quick execution of a series of suspicious commands
# TODO 각각의 exe가 어떤 ATT&CK 기법인지 판단이 잘 안됨...
# TODO MITRE ATT&CK 홈페이지에서 Software 에 있는것들 확인후 채워넣기!
# TODO str.split() 을 이용해서 _ 이 특수문자로 나눠서 테크닉과 전술 구별하기!

commands_of_interest = {
    'arp.exe'       : ['System Network Configuration Discovery_Discovery'],
    'at.exe'        : ['Scheduled Task_Persistence_Privilege Escalation_Execution'],
    'attrib.exe'    : [],
    'cscript.exe'   : [],
    'dsquery.exe'   : ['Account Discovery_Discovery', 'Permission Groups Discovery_Discovery'],
    'hostname.exe'  : ['System Network Configuration Discovery_Discovery'],
    'ipconfig.exe'  : ['System Network Configuration Discovery_Discovery'],
    'mimikatz.exe'  : ['Credential Dumping_Credential Access', 'Account Manipulation_Credential Access'],
    'nbtstat.exe'   : ['System Network Configuration Discovery_Discovery', 'System Network Connections Discovery_Discovery'],
    'net.exe'       : ['Account Discovery_Discovery', 'Permission Groups Discovery_Discovery', 'Remote System Discovery_Discovery', 'Service Execution_Execution', 'System Network Connections Discovery_Discovery', 'System Service Discovery_Discovery', 'Windows Admin Shares_Lateral Movement'],
    'netsh.exe'     : ['Disabling Security Tools_Defense Evasion', 'Security Software Discovery_Discovery'],
    'nslookup.exe'  : [],
    'ping.exe'      : ['Remote System Discovery_Discovery', 'Network Service Scanning_Discovery'],
    'quser.exe'     : ['System Network Connections Discovery_Discovery'],
    'qwinsta.exe'   : [],
    'reg.exe'       : ['Modify Registry_Defense Evasion', 'Query Registry_Discovery', 'Service Registry Permissions Weakness_Persistence_Privilege Escalation'],
    'runas.exe'     : [],
    'sc.exe'        : ['Modify Existing Service_Persistence', 'Service Registry Permissions Weakness_Persistence_Privilege Escalation'],
    'schtasks.exe'  : ['Scheduled Task_Persistence_Privilege Escalation_Execution'],
    'ssh.exe'       : [],
    'systeminfo.exe': ['System Information Discovery_Discovery', 'System Owner/User Discovery_Discovery'],
    'taskkill.exe'  : ['Disabling Security Tools_Defense Evasion'],
    'telnet.exe'    : [],
    'tracert.exe'   : ['Remote System Discovery_Discovery'],
    'wscript.exe'   : ['Scripting_Defense Evasion_Execution'],
    'xcopy.exe'     : []
}

host_discovery_commands  = {
    'hostname.exe'  : ['System Network Configuration Discovery'],
    'ipconfig.exe'  : ['System Network Configuration Discovery'],
    'net.exe'       : ['Account Discovery', 'Permission Groups Discovery', 'System Service Discovery'],
    'quser.exe'     : ['System Network Connections Discovery'],
    'qwinsta.exe'   : [],
    'sc.exe'        : ['System Service Discovery'],
    'systeminfo.exe': ['System Information Discovery', 'System Owner/User Discovery'],
    'tasklist.exe'  : ['System Service Discovery', 'Process Discovery'],
    'whoami.exe'    : ['System Owner/User Discovery']
}

service_outlier_executables_history = {}

outlier_parents_of_cmd_history = {}

# CAR-2013-05-002: Suspicious Run Locations
# cmd 에서 명령어 입력하고 출력값 받아오는 코드
windir = subprocess.getstatusoutput("echo %windir%")[1]
systemroot = subprocess.getstatusoutput("echo %systemroot%")[1]
desktop_path = subprocess.getstatusoutput("echo %HOMEPATH%")[1] + "\\Desktop"

# 로그 리스트

log_list = ["Microsoft-Windows-Sysmon/Operational", "System", "Security"]

# =============================================================== #

def Utc_to_local(evt_utc_time):
    from_zone = tz.tzutc()
    to_zone = tz.tzlocal()

    utc = datetime.datetime.strptime(evt_utc_time[:10] + ' ' + evt_utc_time[11:26], '%Y-%m-%d %H:%M:%S.%f')
    utc = utc.replace(tzinfo=from_zone)

    evt_local_time = utc.astimezone(to_zone)

    return evt_local_time

def get_last_30_days_history():

    count = 0

    print("Get last 30 days history...")

    today_time = datetime.datetime.now(tz.tzlocal())

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
            # remove parsed events
            # win32evtlog.ClearEventLog(handle, None): Access Violation (0xC0000005)
            break
        for event in events:
            count += 1

            if count % 1000 == 0:
                print(count)


            record = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
            ##print(event)

            # xml to dict
            record_dict = xmltodict.parse(record)
            # print(record_dict)

            # UTC to Local Time
            evt_local_time = Utc_to_local(record_dict['Event']['System']['TimeCreated']['@SystemTime'])
            record_dict['Event']['System']['TimeCreated']['@SystemTime'] = evt_local_time

            temp_data = {}
            for data in record_dict['Event']['EventData']['Data']:
                if '#text' in data:
                    temp_data[data['@Name']] = data['#text']
                elif data == None or data == 'None':
                    temp_data = {}
                else:
                    temp_data[data['@Name']] = None
            record_dict['Event']['EventData'] = temp_data

            evt_id = int(record_dict['Event']['System']['EventID'])

            if evt_local_time < today_time - datetime.timedelta(days=30):
                return

            if evt_id == 1:
                image = str(record_dict['Event']['EventData']['Image'])
                parent_image = str(record_dict['Event']['EventData']['ParentImage'])

                if parent_image == "C:\\Windows\\System32\\services.exe":
                    service_outlier_executables_history[image] = 0

                if 'cmd.exe' in image:
                    outlier_parents_of_cmd_history[parent_image] = 0


def add_table_row(table, time, id, car_id, car_name):

    # Matrix Table

    table_row = table.rowCount()
    table.setRowCount(table_row + 1)

    # Time

    new_item=QTableWidgetItem(str(time))
    new_item.setFont(QFont('Times New Roman',13))
    new_item.setTextAlignment(Qt.AlignCenter)

    table.setItem(table_row, 0, new_item)

    # ID

    new_item=QTableWidgetItem(id)
    new_item.setFont(QFont('Times New Roman',13))
    new_item.setTextAlignment(Qt.AlignCenter)

    table.setItem(table_row, 1, new_item)

    # CAR-ID

    new_item=QTableWidgetItem(car_id)
    new_item.setFont(QFont('Times New Roman',13))
    new_item.setTextAlignment(Qt.AlignCenter)

    table.setItem(table_row, 2, new_item)

    # CAR-NAME

    new_item=QTableWidgetItem(car_name)
    new_item.setFont(QFont('Times New Roman',13))
    new_item.setTextAlignment(Qt.AlignCenter)

    table.setItem(table_row, 3, new_item)

def home_add_table_row(mainwindow, time, id, event_set):

    # Home Table

    car_id = event_set['ID']
    car_name = event_set['Name']

    home_table = mainwindow.home_detected_table

    table_row = home_table.rowCount()
    home_table.setRowCount(table_row + 1)

    # Time

    new_item=QTableWidgetItem(str(time))
    new_item.setFont(QFont('Times New Roman',13))
    new_item.setTextAlignment(Qt.AlignCenter)

    home_table.setItem(table_row, 0, new_item)

    # ID

    new_item=QTableWidgetItem(id)
    new_item.setFont(QFont('Times New Roman',13))
    new_item.setTextAlignment(Qt.AlignCenter)

    home_table.setItem(table_row, 1, new_item)

    # CAR-ID

    new_item=QTableWidgetItem(car_id)
    new_item.setFont(QFont('Times New Roman',13))
    new_item.setTextAlignment(Qt.AlignCenter)

    home_table.setItem(table_row, 2, new_item)

    # CAR-NAME

    new_item=QTableWidgetItem(car_name)
    new_item.setFont(QFont('Times New Roman',13))
    new_item.setTextAlignment(Qt.AlignCenter)

    home_table.setItem(table_row, 3, new_item)

    QTableWidget.resizeColumnsToContents(home_table)
    QTableWidget.resizeRowsToContents(home_table)

def append_to_event_dict(evt_dict, event_id, event_set):
    if event_id not in evt_dict:
        evt_dict[event_id] = {}
    evt_dict[event_id][event_set['ID']] = event_set

def predict_group_or_sw(mainwindow, tech_list):
    group_or_sw_list = []
    for tech_name in tech_list:
        group_or_sw_list = []
        for elem in mainwindow.techniques['Enterprise'][tech_name]['Examples']:
            group_or_sw_list.append(elem['Name'])

    group_or_sw_list = list(set(group_or_sw_list))

    for elem in group_or_sw_list:
        if elem in mainwindow.predict_attacker:
            mainwindow.predict_attacker[elem] += 1
        else:
            mainwindow.predict_attacker[elem] = 1

    # Sort by dict value
    sorted_tuple = sorted(mainwindow.predict_attacker.items(), key=lambda d:d[1], reverse = True)

    count = 0
    for elem in sorted_tuple:

        # Home Predict Table

        # Group or Software Name

        new_item=QTableWidgetItem(str(elem[0]))
        new_item.setFont(QFont('Times New Roman',13))
        new_item.setTextAlignment(Qt.AlignCenter)

        mainwindow.home_predict_table.setItem(count, 0, new_item)

        # Weight

        new_item=QTableWidgetItem(str(elem[1]))
        new_item.setFont(QFont('Times New Roman',13))
        new_item.setTextAlignment(Qt.AlignCenter)

        mainwindow.home_predict_table.setItem(count, 1, new_item)

        count += 1

        if count == 10:
            break

def change_interface(mainwindow, event_set, event_id, evt_local_time, tac_tech_list):
    tac_list = []
    tech_list = []

    for elem in tac_tech_list:
        tech_tac_split = elem.split('_')

        tech_name = tech_tac_split[0]
        tac_name = tech_tac_split[1]

        tac_list.append(tac_name)
        tech_list.append(tech_name)

        mainwindow.tac_tech_events[tac_name][tech_name]['Events'][event_id] = event_set
        append_to_event_dict(mainwindow.tac_tech_events[tac_name][tech_name]['Events'], event_id, event_set)
        add_table_row(mainwindow.tac_tech_events[tac_name][tech_name]['Table'], evt_local_time, event_id, event_set['ID'], event_set['Name'])
        mainwindow.tac_tech_events[tac_name][tech_name]['Button'].setStyleSheet(mainwindow.detect_tech_button_style)

    tac_list = list(set(tac_list))
    tech_list = list(set(tech_list))

    for elem in tac_list:
    	mainwindow.tac_tech_events[elem]['Events'][event_id] = event_set
    	append_to_event_dict(mainwindow.tac_tech_events[elem]['Events'], event_id, event_set)
    	add_table_row(mainwindow.tac_tech_events[elem]['Table'], evt_local_time, event_id, event_set['ID'], event_set['Name'])
    	mainwindow.tac_tech_events[elem]['Button'].setStyleSheet(mainwindow.detect_tech_button_style)

    # Detected Num Label (Home)
    mainwindow.detected_num += 1
    mainwindow.detected_num_label.setText('Detected Event Num : ' + str(mainwindow.detected_num))

    # Home Detected Events
    append_to_event_dict(mainwindow.home_detected_events, event_id, event_set)
    home_add_table_row(mainwindow, evt_local_time, event_id, event_set)

    # Predict Attacker
    predict_group_or_sw(mainwindow, tech_list)

# ===================================================================================================== #
# ===================================================================================================== #

class Sysmon_evt (threading.Thread):
    def __init__(self, mainwindow):
        threading.Thread.__init__(self)
        self.mainwindow = mainwindow
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

                    # Checked Event Number
                    self.mainwindow.check_num += 1
                    self.mainwindow.check_num_label.setText('Checked Event Num : ' + str(self.mainwindow.check_num))

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

                    # Event-ID
                    event_id = record_dict['Event']['System']['EventRecordID']

                    if evt_id == 5:
                        # Powershell 관련 이벤트들은 Powershell이 끝나고 나서야 모든 CommandLine을 얻을 수 있기때문에 5로 확인해야됨.

                        # TODO 내가한것! : CALDERA를 통한 공격에는 CommandLine이 제대로 남지 않음! 그래서 스크립트 어떤걸 사용했는지 파악 불가!
                        # TODO 그래서 powershell-log 를 바탕화면에 남겨서 거기서 확인할꺼임!
                        # TODO 원래 evt_id가 1일때 판단하는거였지만 내가 5로 바꿔서 판단했음!

                        # TODO Powershell "Get-NetLocalGroupMember" 같은거 다 채워넣어야함... 어떤 tactic 이랑 technique 인지랑, 어떤 분석이랑 연관돼있는지 확인 필요!!!

                        image = str(record_dict['Event']['EventData']['Image'])
                        image_exe = image.split('\\')
                        image_exe = (image_exe[-1]).lower()

                        proc_id = record_dict['Event']['EventData']['ProcessId']

                        # CAR-2014-04-003: Powershell Execution
                        # PowerShell - Execution
                        # Scripting - Defense Evasion
                        # https://car.mitre.org/analytics/CAR-2014-04-003

                        # TODO 이러한 정보들 뿐만 아니라, 내가 저장시킨 Powershell 로그에 Mimikatz라던가 그런게 없는지 확인해보기!
                        # TODO 또 ParentImage도 어떤놈인지 확인하기!

                        # Defense Evasion 에는 PowerShell이 없음!
                        # PowerShell은 Execution 에 밖에 없음!

                        # TODO 여기에서 Powershell log 파일 확인 후에! 만약에 뭐 Invoke-Mimikatz 같은게 있으면 그떄 뒤에 
                        # TODO Quick_execution_of_a_series_of_suspicious_commands 같은 곳에서 사용 가능할ㄷㅅ!


                        if 'powershell.exe' == image_exe:

                            ps_dict = self.get_ps_info(proc_id)

                            if ps_dict != {}:

                                print('Powershell Execution // Detected')
                                event_set = {}
                                event_set['ID'] = 'CAR-2014-04-003'
                                event_set['Name'] = 'Powershell Execution'
                                event_set['Event'] = [ps_dict['ps_start']]
                                # TODO event_set['ps_command_line'] = ps_dict['ps_command_line']

                                tac_tech_list = ['PowerShell_Execution', 'Scripting_Defense Evasion']
                                change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                                """

                                self.mainwindow.tac_tech_events['Defense Evasion']['Events'][event_id] = event_set
                                self.mainwindow.tac_tech_events['Execution']['Events'][event_id] = event_set

                                self.mainwindow.tac_tech_events['Execution']['PowerShell']['Events'][event_id] = event_set
                                self.mainwindow.tac_tech_events['Defense Evasion']['Scripting']['Events'][event_id] = event_set

                                append_to_event_dict(self.mainwindow.tac_tech_events['Defense Evasion']['Events'], event_id, event_set)
                                append_to_event_dict(self.mainwindow.tac_tech_events['Execution']['Events'], event_id, event_set)
                                append_to_event_dict(self.mainwindow.tac_tech_events['Execution']['PowerShell']['Events'], event_id, event_set)
                                append_to_event_dict(self.mainwindow.tac_tech_events['Defense Evasion']['Scripting']['Events'], event_id, event_set)

                                add_table_row(self.mainwindow.tac_tech_events['Defense Evasion']['Table'], evt_local_time, event_id, 'CAR-2014-04-003', 'Powershell Execution')
                                add_table_row(self.mainwindow.tac_tech_events['Execution']['Table'], evt_local_time, event_id, 'CAR-2014-04-003', 'Powershell Execution')
                                add_table_row(self.mainwindow.tac_tech_events['Execution']['PowerShell']['Table'], evt_local_time, event_id, 'CAR-2014-04-003', 'Powershell Execution')
                                add_table_row(self.mainwindow.tac_tech_events['Defense Evasion']['Scripting']['Table'], evt_local_time, event_id, 'CAR-2014-04-003', 'Powershell Execution')

                                self.mainwindow.tac_tech_events['Execution']['PowerShell']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                                self.mainwindow.tac_tech_events['Defense Evasion']['Scripting']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)

                                self.mainwindow.tac_tech_events['Defense Evasion']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)
                                self.mainwindow.tac_tech_events['Execution']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                                # Detected Num Label (Home)
                                self.mainwindow.detected_num += 1
                                self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                                # Home Detected Events
                                append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                                home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                                # Predict Attacker
                                predict_group_or_sw(self.mainwindow, ['PowerShell', 'Scripting'])

                                """

                                # return_dict['mimikatz'] = 0
                                # return_dict['get-netLlocalgroupmember'] = 0
                                # return_dict['get-domaincomputer'] = 0
                                # return_dict['ps_start'] = ps_start
                                # return_dict['ps_command_line'] = ''.join(lines)

                                # TODO 밑에 Quick 어쩌구 그거랑, Mimikatz 관련된거 여기서 실행시켜야함!
                                if ps_dict['mimikatz'] == 1:

                                    #############################################################################################

                                    # CAR-2013-04-002: Quick execution of a series of suspicious commands
                                    # 너무 많음...
                                    # https://car.mitre.org/analytics/CAR-2013-04-002

                                    com_check = self.Quick_execution_of_a_series_of_suspicious_commands(record_dict)
                                    if com_check[0] == True:
                                        print('Quick execution of a series of suspicious commands \"' + com_check[1][0] + '\", \"' + com_check[1][1] + '\" // Detected')

                                        event_set = {}
                                        event_set['ID'] = 'CAR-2013-04-002'
                                        event_set['Name'] = 'Quick execution of a series of suspicious commands'
                                        event_set['Event'] = [ps_dict['ps_start'], com_check[2]]

                                        all_tac_list = []
                                        all_tech_tac_list = []
                                        for elem in commands_of_interest['mimikatz.exe']:
                                            elem_split = elem.split('_')
                                            tmp_tech_name = elem_split[0]
                                            tmp_tac_list = elem_split[1:]
                                            for elem2 in tmp_tac_list:
                                                all_tech_tac_list.append(elem + '_' + elem2)
                                                all_tac_list.append(elem2)

                                        for elem in commands_of_interest[com_check[1][1]]:
                                            elem_split = elem.split('_')
                                            tmp_tech_name = elem_split[0]
                                            tmp_tac_list = elem_split[1:]
                                            for elem2 in tmp_tac_list:
                                                all_tech_tac_list.append(elem + '_' + elem2)
                                                all_tac_list.append(elem2)

                                        all_tac_list=list(set(all_tac_list))
                                        for elem in all_tac_list:
                                            append_to_event_dict(self.mainwindow.tac_tech_events[elem]['Events'], event_id, event_set)
                                            add_table_row(self.mainwindow.tac_tech_events[elem]['Table'], evt_local_time, event_id, 'CAR-2013-04-002', 'Quick execution of a series of suspicious commands')
                                            self.mainwindow.tac_tech_events[elem]['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                                        tmp_tech_list = []
                                        all_tech_tac_list=list(set(all_tech_tac_list))
                                        for elem in all_tech_tac_list:
                                            tmp_list = elem.split('_')
                                            append_to_event_dict(self.mainwindow.tac_tech_events[tmp_list[1]][tmp_list[0]]['Events'], event_id, event_set)
                                            add_table_row(self.mainwindow.tac_tech_events[tmp_list[1]][tmp_list[0]]['Table'], evt_local_time, event_id, 'CAR-2013-04-002', 'Quick execution of a series of suspicious commands')
                                            self.mainwindow.tac_tech_events[tmp_list[1]][tmp_list[0]]['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                                            tmp_tech_list.append(tmp_list[0])

                                        # Detected Num Label (Home)
                                        self.mainwindow.detected_num += 1
                                        self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                                        # Home Detected Events
                                        append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                                        home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                                        # Predict Attacker
                                        predict_group_or_sw(self.mainwindow, tmp_tech_list)
                                        

                                    ###############################################################################################

                                    # CAR-2013-07-001: Suspicious Arguments
                                    # Credential Dumping - Credential Access
                                    # https://car.mitre.org/analytics/CAR-2013-07-001

                                    print('Suspicious Arguments : mimikatz // Detected')
                                    check_detected = True

                                    if check_detected == True:
                                        event_set = {}
                                        event_set['ID'] = 'CAR-2013-07-001'
                                        event_set['Name'] = 'Suspicious Arguments'
                                        event_set['Event'] = [ps_dict['ps_start']]

                                        tac_tech_list = ['Credential Dumping_Credential Access']
                                        change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                                        """

                                        append_to_event_dict(self.mainwindow.tac_tech_events['Credential Access']['Events'], event_id, event_set)
                                        append_to_event_dict(self.mainwindow.tac_tech_events['Credential Access']['Credential Dumping']['Events'], event_id, event_set)

                                        add_table_row(self.mainwindow.tac_tech_events['Credential Access']['Table'], evt_local_time, event_id, 'CAR-2013-07-001', 'Suspicious Arguments')
                                        add_table_row(self.mainwindow.tac_tech_events['Credential Access']['Credential Dumping']['Table'], evt_local_time, event_id, 'CAR-2013-07-001', 'Suspicious Arguments')

                                        self.mainwindow.tac_tech_events['Credential Access']['Credential Dumping']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                                        self.mainwindow.tac_tech_events['Credential Access']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                                        # Detected Num Label (Home)
                                        self.mainwindow.detected_num += 1
                                        self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                                        # Home Detected Events
                                        append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                                        home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                                        # Predict Attacker
                                        predict_group_or_sw(self.mainwindow, ['Credential Dumping'])
                                        """

                                if ps_dict['get-netLlocalgroupmember'] == 1:
                                    print('get-netLlocalgroupmember')
                                if ps_dict['get-domaincomputer'] == 1:
                                    print('get-domaincomputer')



                    elif evt_id == 1:
                        image = str(record_dict['Event']['EventData']['Image'])
                        image_exe = image.split('\\')
                        image_exe = (image_exe[-1]).lower()
                        parent_image = str(record_dict['Event']['EventData']['ParentImage'])
                        parent_image_exe = parent_image.split('\\')
                        parent_image_exe = (parent_image_exe[-1]).lower()
                        com_line = str(record_dict['Event']['EventData']['CommandLine'])

                        ##########################################################################################
                        
                        # CAR-2013-04-002: Quick execution of a series of suspicious commands
                        # 각각의 exe가 어떤 ATT&CK 기법인지 판단이 잘 안되지만 판단되는건 다 적어 넣었음!
                        # https://car.mitre.org/analytics/CAR-2013-04-002

                        # TODO 각각의 exe가 어떤 ATT&CK 기법인지 판단이 잘 안됨...
                        for exe_name in commands_of_interest:
                            if exe_name == image_exe:
                                com_check = self.Quick_execution_of_a_series_of_suspicious_commands(record_dict)
                                if com_check[0] == True:
                                    # TODO 이렇게 2개 표시하는 방법 말고... 이런식으로 하면 겹쳐서 나오게 됨.. 나중에 한꺼번에 다 몰아서 검사한다음 한꺼번에 출력시키게 바꿔야됨!
                                    print('Quick execution of a series of suspicious commands \"' + com_check[1][0] + '\", \"' + com_check[1][1] + '\" // Detected')

                                    event_set = {}
                                    event_set['ID'] = 'CAR-2013-04-002'
                                    event_set['Name'] = 'Quick execution of a series of suspicious commands'
                                    event_set['Event'] = [record_dict, com_check[2]]

                                    all_tac_list = []
                                    all_tech_tac_list = []
                                    for elem in commands_of_interest[com_check[1][0]]:
                                        elem_split = elem.split('_')
                                        tmp_tech_name = elem_split[0]
                                        tmp_tac_list = elem_split[1:]
                                        for elem2 in tmp_tac_list:
                                            all_tech_tac_list.append(elem + '_' + elem2)
                                            all_tac_list.append(elem2)

                                    for elem in commands_of_interest[com_check[1][1]]:
                                        elem_split = elem.split('_')
                                        tmp_tech_name = elem_split[0]
                                        tmp_tac_list = elem_split[1:]
                                        for elem2 in tmp_tac_list:
                                            all_tech_tac_list.append(elem + '_' + elem2)
                                            all_tac_list.append(elem2)

                                    all_tac_list=list(set(all_tac_list))
                                    for elem in all_tac_list:
                                        append_to_event_dict(self.mainwindow.tac_tech_events[elem]['Events'], event_id, event_set)
                                        add_table_row(self.mainwindow.tac_tech_events[elem]['Table'], evt_local_time, event_id, 'CAR-2013-04-002', 'Quick execution of a series of suspicious commands')
                                        self.mainwindow.tac_tech_events[elem]['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                                    tmp_tech_list = []
                                    all_tech_tac_list=list(set(all_tech_tac_list))
                                    for elem in all_tech_tac_list:
                                        tmp_list = elem.split('_')
                                        append_to_event_dict(self.mainwindow.tac_tech_events[tmp_list[1]][tmp_list[0]]['Events'], event_id, event_set)
                                        add_table_row(self.mainwindow.tac_tech_events[tmp_list[1]][tmp_list[0]]['Table'], evt_local_time, event_id, 'CAR-2013-04-002', 'Quick execution of a series of suspicious commands')
                                        self.mainwindow.tac_tech_events[tmp_list[1]][tmp_list[0]]['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                                        tmp_tech_list.append(tmp_list[0])

                                    # Detected Num Label (Home)
                                    self.mainwindow.detected_num += 1
                                    self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                                    # Home Detected Events
                                    append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                                    home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                                    # Predict Attacker
                                    predict_group_or_sw(self.mainwindow, tmp_tech_list)

                        ##########################################################################################

                        # CAR-2016-03-002: Create Remote Process via WMIC
                        # Windows Management Instrumentation - Execution
                        # https://car.mitre.org/analytics/CAR-2016-03-002

                        if (
                            'wmic.exe' == image_exe and
                            ' process call create ' in com_line and
                            ' /node:' in com_line
                            ):

                            print('Create Remote Process via WMIC // Detected')
                            event_set = {}
                            event_set['ID'] = 'CAR-2016-03-002'
                            event_set['Name'] = 'Create Remote Process via WMIC'
                            event_set['Event'] = [record_dict]

                            tac_tech_list = ['Windows Management Instrumentation_Execution']
                            change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                            """

                            append_to_event_dict(self.mainwindow.tac_tech_events['Execution']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Execution']['Windows Management Instrumentation']['Events'], event_id, event_set)

                            add_table_row(self.mainwindow.tac_tech_events['Execution']['Table'], evt_local_time, event_id, 'CAR-2016-03-002', 'Create Remote Process via WMIC')
                            add_table_row(self.mainwindow.tac_tech_events['Execution']['Windows Management Instrumentation']['Table'], evt_local_time, event_id, 'CAR-2016-03-002', 'Create Remote Process via WMIC')

                            self.mainwindow.tac_tech_events['Execution']['Windows Management Instrumentation']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Execution']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                            # Detected Num Label (Home)
                            self.mainwindow.detected_num += 1
                            self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                            # Home Detected Events
                            append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                            home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                            # Predict Attacker
                            predict_group_or_sw(self.mainwindow, ['Windows Management Instrumentation'])

                            """

                        ##########################################################################################

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
                            event_set = {}
                            event_set['ID'] = 'CAR-2014-07-001'
                            event_set['Name'] = 'Service Search Path Interception'
                            event_set['Event'] = [record_dict]

                            tac_tech_list = ['Path Interception_Privilege Escalation', 'Path Interception_Persistence']
                            change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                            """

                            append_to_event_dict(self.mainwindow.tac_tech_events['Privilege Escalation']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Privilege Escalation']['Path Interception']['Events'], event_id, event_set)

                            append_to_event_dict(self.mainwindow.tac_tech_events['Persistence']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Persistence']['Path Interception']['Events'], event_id, event_set)

                            add_table_row(self.mainwindow.tac_tech_events['Privilege Escalation']['Table'], evt_local_time, event_id, 'CAR-2014-07-001', 'Service Search Path Interception')
                            add_table_row(self.mainwindow.tac_tech_events['Privilege Escalation']['Path Interception']['Table'], evt_local_time, event_id, 'CAR-2014-07-001', 'Service Search Path Interception')
                            add_table_row(self.mainwindow.tac_tech_events['Persistence']['Table'], evt_local_time, event_id, 'CAR-2014-07-001', 'Service Search Path Interception')
                            add_table_row(self.mainwindow.tac_tech_events['Persistence']['Path Interception']['Table'], evt_local_time, event_id, 'CAR-2014-07-001', 'Service Search Path Interception')

                            self.mainwindow.tac_tech_events['Privilege Escalation']['Path Interception']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Persistence']['Path Interception']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Persistence']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)
                            self.mainwindow.tac_tech_events['Privilege Escalation']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                            # Detected Num Label (Home)
                            self.mainwindow.detected_num += 1
                            self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                            # Home Detected Events
                            append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                            home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                            # Predict Attacker
                            predict_group_or_sw(self.mainwindow, ['Path Interception'])

                            """

                        ##########################################################################################

                        # CAR-2014-03-005: Remotely Launched Executables via Services
                        # New Service - Execution
                        # Service Execution - Execution
                        # https://car.mitre.org/analytics/CAR-2014-03-005

                        if 'services.exe' == parent_image_exe:
                            flow = self.Remotely_Launched_Executables_via_Services(record_dict)
                            if flow[0] == True:

                                print('Remotely Launched Executables via Services // Detected')
                                event_set = {}
                                event_set['ID'] = 'CAR-2014-03-005'
                                event_set['Name'] = 'Remotely Launched Executables via Services'
                                event_set['Event'] = [record_dict, flow[1]]

                                tac_tech_list = ['New Service_Execution', 'Service Execution_Execution']
                                change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                                """

                                append_to_event_dict(self.mainwindow.tac_tech_events['Execution']['Events'], event_id, event_set)

                                append_to_event_dict(self.mainwindow.tac_tech_events['Execution']['New Service']['Events'], event_id, event_set)
                                append_to_event_dict(self.mainwindow.tac_tech_events['Execution']['Service Execution']['Events'], event_id, event_set)

                                add_table_row(self.mainwindow.tac_tech_events['Execution']['Table'], evt_local_time, event_id, 'CAR-2014-03-005', 'Remotely Launched Executables via Services')
                                add_table_row(self.mainwindow.tac_tech_events['Execution']['New Service']['Table'], evt_local_time, event_id, 'CAR-2014-03-005', 'Remotely Launched Executables via Services')
                                add_table_row(self.mainwindow.tac_tech_events['Execution']['Service Execution']['Table'], evt_local_time, event_id, 'CAR-2014-03-005', 'Remotely Launched Executables via Services')

                                self.mainwindow.tac_tech_events['Execution']['New Service']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                                self.mainwindow.tac_tech_events['Execution']['Service Execution']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)

                                self.mainwindow.tac_tech_events['Execution']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                                # Detected Num Label (Home)
                                self.mainwindow.detected_num += 1
                                self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                                # Home Detected Events
                                append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                                home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                                # Predict Attacker
                                predict_group_or_sw(self.mainwindow, ['New Service', 'Service Execution'])

                                """

                        ##########################################################################################

                        # CAR-2013-07-005: Command Line Usage of Archiving Software
                        # Data Compressed - Exfiltration
                        # https://car.mitre.org/analytics/CAR-2013-07-005

                        # TODO 테스트 : 7z.exe a test.zip test.txt

                        if ' a ' in com_line:

                            print('Command Line Usage of Archiving Software // Detected')
                            event_set = {}
                            event_set['ID'] = 'CAR-2013-07-005'
                            event_set['Name'] = 'Command Line Usage of Archiving Software'
                            event_set['Event'] = [record_dict]

                            tac_tech_list = ['Data Compressed_Exfiltration']
                            change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                            """

                            append_to_event_dict(self.mainwindow.tac_tech_events['Exfiltration']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Exfiltration']['Data Compressed']['Events'], event_id, event_set)

                            add_table_row(self.mainwindow.tac_tech_events['Exfiltration']['Table'], evt_local_time, event_id, 'CAR-2013-07-005', 'Command Line Usage of Archiving Software')
                            add_table_row(self.mainwindow.tac_tech_events['Exfiltration']['Data Compressed']['Table'], evt_local_time, event_id, 'CAR-2013-07-005', 'Command Line Usage of Archiving Software')

                            self.mainwindow.tac_tech_events['Exfiltration']['Data Compressed']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Exfiltration']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                            # Detected Num Label (Home)
                            self.mainwindow.detected_num += 1
                            self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                            # Home Detected Events
                            append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                            home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                            # Predict Attacker
                            predict_group_or_sw(self.mainwindow, ['Data Compressed'])

                            """

                        ##########################################################################################

                        # CAR-2013-05-004: Execution with AT
                        # Scheduled Task - Execution,Persistence, Privilege Escalation
                        # https://car.mitre.org/analytics/CAR-2013-05-004

                        # TODO 테스트 : at 10:00 calc.exe // returns a job number X 
                        # TODO 테스트 : at X /delete

                        if 'at.exe' == image_exe:

                            print('Execution with AT // Detected')
                            event_set = {}
                            event_set['ID'] = 'CAR-2013-05-004'
                            event_set['Name'] = 'Execution with AT'
                            event_set['Event'] = [record_dict]

                            tac_tech_list = ['Scheduled Task_Execution', 'Scheduled Task_Persistence', 'Scheduled Task_Privilege Escalation']
                            change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                            """

                            append_to_event_dict(self.mainwindow.tac_tech_events['Execution']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Execution']['Scheduled Task']['Events'], event_id, event_set)

                            append_to_event_dict(self.mainwindow.tac_tech_events['Persistence']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Persistence']['Scheduled Task']['Events'], event_id, event_set)

                            append_to_event_dict(self.mainwindow.tac_tech_events['Privilege Escalation']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Privilege Escalation']['Scheduled Task']['Events'], event_id, event_set)

                            add_table_row(self.mainwindow.tac_tech_events['Execution']['Table'], evt_local_time, event_id, 'CAR-2013-05-004', 'Execution with AT')
                            add_table_row(self.mainwindow.tac_tech_events['Execution']['Scheduled Task']['Table'], evt_local_time, event_id, 'CAR-2013-05-004', 'Execution with AT')

                            add_table_row(self.mainwindow.tac_tech_events['Persistence']['Table'], evt_local_time, event_id, 'CAR-2013-05-004', 'Execution with AT')
                            add_table_row(self.mainwindow.tac_tech_events['Persistence']['Scheduled Task']['Table'], evt_local_time, event_id, 'CAR-2013-05-004', 'Execution with AT')

                            add_table_row(self.mainwindow.tac_tech_events['Privilege Escalation']['Table'], evt_local_time, event_id, 'CAR-2013-05-004', 'Execution with AT')
                            add_table_row(self.mainwindow.tac_tech_events['Privilege Escalation']['Scheduled Task']['Table'], evt_local_time, event_id, 'CAR-2013-05-004', 'Execution with AT')

                            self.mainwindow.tac_tech_events['Execution']['Scheduled Task']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Persistence']['Scheduled Task']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Privilege Escalation']['Scheduled Task']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)

                            self.mainwindow.tac_tech_events['Execution']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)
                            self.mainwindow.tac_tech_events['Persistence']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)
                            self.mainwindow.tac_tech_events['Privilege Escalation']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                            # Detected Num Label (Home)
                            self.mainwindow.detected_num += 1
                            self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                            # Home Detected Events
                            append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                            home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                            # Predict Attacker
                            predict_group_or_sw(self.mainwindow, ['Scheduled Task'])

                            """

                        ##########################################################################################

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

                        event_set = {}

                        if putty or port_fwd or scp or mimikatz or rar or archive or ip_addr:
                            event_set['ID'] = 'CAR-2013-07-001'
                            event_set['Name'] = 'Suspicious Arguments'
                            event_set['Event'] = [record_dict]

                            check_detected = True

                        tac_tech_list = []

                        if putty:
                            print('Suspicious Arguments : putty // Detected')

                            tac_tech_list.append('Remote Services_Lateral Movement')
                            """

                            append_to_event_dict(self.mainwindow.tac_tech_events['Lateral Movement']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Lateral Movement']['Remote Services']['Events'], event_id, event_set)

                            add_table_row(self.mainwindow.tac_tech_events['Lateral Movement']['Table'], evt_local_time, event_id, 'CAR-2013-07-001', 'Suspicious Arguments')
                            add_table_row(self.mainwindow.tac_tech_events['Lateral Movement']['Remote Services']['Table'], evt_local_time, event_id, 'CAR-2013-07-001', 'Suspicious Arguments')

                            self.mainwindow.tac_tech_events['Lateral Movement']['Remote Services']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Lateral Movement']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                            # Predict Attacker
                            predict_group_or_sw(self.mainwindow, ['Remote Services'])

                            """

                        elif port_fwd:
                            print('Suspicious Arguments : port_fwd // Detected')

                            # TODO 어떤 Tactics 와 Techniques 인지 파악해야함!

                        elif scp:
                            print('Suspicious Arguments : scp // Detected')

                            tac_tech_list.append('Remote File Copy_Lateral Movement')
                            tac_tech_list.append('Remote File Copy_Command and Control')

                            """

                            append_to_event_dict(self.mainwindow.tac_tech_events['Lateral Movement']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Lateral Movement']['Remote File Copy']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Command and Control']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Command and Control']['Remote File Copy']['Events'], event_id, event_set)

                            add_table_row(self.mainwindow.tac_tech_events['Lateral Movement']['Table'], evt_local_time, event_id, 'CAR-2013-07-001', 'Suspicious Arguments')
                            add_table_row(self.mainwindow.tac_tech_events['Lateral Movement']['Remote File Copy']['Table'], evt_local_time, event_id, 'CAR-2013-07-001', 'Suspicious Arguments')
                            add_table_row(self.mainwindow.tac_tech_events['Command and Control']['Table'], evt_local_time, event_id, 'CAR-2013-07-001', 'Suspicious Arguments')
                            add_table_row(self.mainwindow.tac_tech_events['Command and Control']['Remote File Copy']['Table'], evt_local_time, event_id, 'CAR-2013-07-001', 'Suspicious Arguments')

                            self.mainwindow.tac_tech_events['Lateral Movement']['Remote File Copy']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Lateral Movement']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)
                            self.mainwindow.tac_tech_events['Command and Control']['Remote File Copy']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Command and Control']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                            # Predict Attacker
                            predict_group_or_sw(self.mainwindow, ['Remote File Copy'])

                            """

                        elif mimikatz:
                            print('Suspicious Arguments : mimikatz // Detected')

                            tac_tech_list.append('Credential Dumping_Credential Access')

                            """

                            append_to_event_dict(self.mainwindow.tac_tech_events['Credential Access']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Credential Access']['Credential Dumping']['Events'], event_id, event_set)

                            add_table_row(self.mainwindow.tac_tech_events['Credential Access']['Table'], evt_local_time, event_id, 'CAR-2013-07-001', 'Suspicious Arguments')
                            add_table_row(self.mainwindow.tac_tech_events['Credential Access']['Credential Dumping']['Table'], evt_local_time, event_id, 'CAR-2013-07-001', 'Suspicious Arguments')

                            self.mainwindow.tac_tech_events['Credential Access']['Credential Dumping']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Credential Access']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                            # Predict Attacker
                            predict_group_or_sw(self.mainwindow, ['Credential Dumping'])

                            """

                        elif rar:
                            print('Suspicious Arguments : rar // Detected')

                            # TODO 어떤 Tactics 와 Techniques 인지 파악해야함!
                            
                        elif archive:
                            print('Suspicious Arguments : archive // Detected')

                            # TODO 어떤 Tactics 와 Techniques 인지 파악해야함!
                            
                        elif ip_addr:
                            print('Suspicious Arguments : ip_addr // Detected')
                            print('CommandLine : ' + com_line)

                            tac_tech_list.append('Remote Services_Lateral Movement')

                            """

                            append_to_event_dict(self.mainwindow.tac_tech_events['Lateral Movement']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Lateral Movement']['Remote Services']['Events'], event_id, event_set)

                            add_table_row(self.mainwindow.tac_tech_events['Lateral Movement']['Table'], evt_local_time, event_id, 'CAR-2013-07-001', 'Suspicious Arguments')
                            add_table_row(self.mainwindow.tac_tech_events['Lateral Movement']['Remote Services']['Table'], evt_local_time, event_id, 'CAR-2013-07-001', 'Suspicious Arguments')

                            self.mainwindow.tac_tech_events['Lateral Movement']['Remote Services']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Lateral Movement']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                            # Predict Attacker
                            predict_group_or_sw(self.mainwindow, ['Remote Services'])

                            """


                        if check_detected == True:
                        	
                        	if len(tac_tech_list) != 0:
                        		change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                        	"""

                            # Detected Num Label (Home)
                            self.mainwindow.detected_num += 1
                            self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                            # Home Detected Events
                            append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                            home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                            """
                            
                            
                            # TODO 전술이랑 테크닉을 어떻게 나눌지 고민해봐야함..

                        ##########################################################################################

                        # CAR-2014-11-004: Remote PowerShell Sessions
                        # PowerShell - Execution
                        # Windows Remote Management - Lateral Movement
                        # https://car.mitre.org/analytics/CAR-2014-11-004

                        if (
                            'svchost.exe' == parent_image_exe and
                            'wsmprovhost.exe' == image_exe
                            ):

                            print('Remote PowerShell Sessions // Detected') 
                            event_set = {}
                            event_set['ID'] = 'CAR-2014-11-004'
                            event_set['Name'] = 'Remote PowerShell Sessions'
                            event_set['Event'] = [record_dict]

                            tac_tech_list = ['PowerShell_Execution', 'Windows Remote Management_Lateral Movement']
                            change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                            """

                            append_to_event_dict(self.mainwindow.tac_tech_events['Execution']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Execution']['PowerShell']['Events'], event_id, event_set)

                            append_to_event_dict(self.mainwindow.tac_tech_events['Lateral Movement']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Lateral Movement']['Windows Remote Management']['Events'], event_id, event_set)

                            add_table_row(self.mainwindow.tac_tech_events['Execution']['Table'], evt_local_time, event_id, 'CAR-2014-11-004', 'Remote PowerShell Sessions')
                            add_table_row(self.mainwindow.tac_tech_events['Execution']['PowerShell']['Table'], evt_local_time, event_id, 'CAR-2014-11-004', 'Remote PowerShell Sessions')

                            add_table_row(self.mainwindow.tac_tech_events['Lateral Movement']['Table'], evt_local_time, event_id, 'CAR-2014-11-004', 'Remote PowerShell Sessions')
                            add_table_row(self.mainwindow.tac_tech_events['Lateral Movement']['Windows Remote Management']['Table'], evt_local_time, event_id, 'CAR-2014-11-004', 'Remote PowerShell Sessions')

                            self.mainwindow.tac_tech_events['Execution']['PowerShell']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Lateral Movement']['Windows Remote Management']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)

                            self.mainwindow.tac_tech_events['Execution']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)
                            self.mainwindow.tac_tech_events['Lateral Movement']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                            # Detected Num Label (Home)
                            self.mainwindow.detected_num += 1
                            self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                            # Home Detected Events
                            append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                            home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                            # Predict Attacker
                            predict_group_or_sw(self.mainwindow, ['PowerShell', 'Windows Remote Management'])

                            """

                        ##########################################################################################

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
                            event_set = {}
                            event_set['ID'] = 'CAR-2013-05-002'
                            event_set['Name'] = 'Suspicious Run Locations'
                            event_set['Event'] = [record_dict]

                            tac_tech_list = ['Masquerading_Defense Evasion']
                            change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                            """
                            append_to_event_dict(self.mainwindow.tac_tech_events['Defense Evasion']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Defense Evasion']['Masquerading']['Events'], event_id, event_set)

                            add_table_row(self.mainwindow.tac_tech_events['Defense Evasion']['Table'], evt_local_time, event_id, 'CAR-2013-05-002', 'Suspicious Run Locations')
                            add_table_row(self.mainwindow.tac_tech_events['Defense Evasion']['Masquerading']['Table'], evt_local_time, event_id, 'CAR-2013-05-002', 'Suspicious Run Locations')

                            self.mainwindow.tac_tech_events['Defense Evasion']['Masquerading']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Defense Evasion']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                            # Detected Num Label (Home)
                            self.mainwindow.detected_num += 1
                            self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                            # Home Detected Events
                            append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                            home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                            # Predict Attacker
                            predict_group_or_sw(self.mainwindow, ['Masquerading'])
                            """

                        ##########################################################################################

                        # CAR-2014-11-003: Debuggers for Accessibility Applications
                        # Accessibility Features - Privilege Escalation, Persistence
                        # https://car.mitre.org/analytics/CAR-2014-11-003

                        # TODO Document에서 Pseudocode는 (command_line match "$.* .*(sethcutilmanosknarratormagnify)\.exe") 이런식으로 표시했는데
                        # TODO 여기서 $ 이게 뭘뜻하는건지 모르겠음... 뒤에서부터 匹配하는거라는데... 어법이 안맞는것같은데..
                        # TODO 일단 그래서 $ 빼고 했음

                        # TODO 테스트 : cmd.exe Magnify.exe

                        if ( 
                            re.search( r'.* .*sethc\.exe.*', com_line, re.M|re.I) != None or
                            re.search( r'.* .*utilman\.exe.*', com_line, re.M|re.I) != None or
                            re.search( r'.* .*osk\.exe.*', com_line, re.M|re.I) != None or
                            re.search( r'.* .*narrator\.exe.*', com_line, re.M|re.I) != None or
                            re.search( r'.* .*Magnify\.exe.*', com_line, re.M|re.I) != None
                            ):

                            print('Debuggers for Accessibility Applications // Detected') 
                            event_set = {}
                            event_set['ID'] = 'CAR-2014-11-003'
                            event_set['Name'] = 'Debuggers for Accessibility Applications'
                            event_set['Event'] = [record_dict]

                            tac_tech_list = ['Accessibility Features_Privilege Escalation', 'Accessibility Features_Persistence']
                            change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                            # TODO 각각 어느 전술이랑 어느 테크닉에 저장할지 다시 생각해보기!
                            # TODO Execution 에는 Accessibility Features 가 없는데 CAR에는 왜 Tactics에 Execution이 포함돼있지...?

                            """

                            append_to_event_dict(self.mainwindow.tac_tech_events['Privilege Escalation']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Privilege Escalation']['Accessibility Features']['Events'], event_id, event_set)

                            append_to_event_dict(self.mainwindow.tac_tech_events['Persistence']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Persistence']['Accessibility Features']['Events'], event_id, event_set)

                            add_table_row(self.mainwindow.tac_tech_events['Privilege Escalation']['Table'], evt_local_time, event_id, 'CAR-2014-11-003', 'Debuggers for Accessibility Applications')
                            add_table_row(self.mainwindow.tac_tech_events['Privilege Escalation']['Accessibility Features']['Table'], evt_local_time, event_id, 'CAR-2014-11-003', 'Debuggers for Accessibility Applications')

                            add_table_row(self.mainwindow.tac_tech_events['Persistence']['Table'], evt_local_time, event_id, 'CAR-2014-11-003', 'Debuggers for Accessibility Applications')
                            add_table_row(self.mainwindow.tac_tech_events['Persistence']['Accessibility Features']['Table'], evt_local_time, event_id, 'CAR-2014-11-003', 'Debuggers for Accessibility Applications')

                            self.mainwindow.tac_tech_events['Privilege Escalation']['Accessibility Features']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Persistence']['Accessibility Features']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)

                            self.mainwindow.tac_tech_events['Persistence']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)
                            self.mainwindow.tac_tech_events['Privilege Escalation']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                            # Detected Num Label (Home)
                            self.mainwindow.detected_num += 1
                            self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                            # Home Detected Events
                            append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                            home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                            # Predict Attacker
                            predict_group_or_sw(self.mainwindow, ['Accessibility Features'])

                            """

                        ##########################################################################################

                        # CAR-2014-03-006: RunDLL32.exe monitoring
                        # Rundll32 - Defense Evasion
                        # https://car.mitre.org/analytics/CAR-2014-03-006

                        # TODO 이게 바로 위에서 말한 $ 사용법의 올바른 예! 위에있는 ~ in ~ 이런식의 코드들도 다 밑에 방식으로 바꾸는게 좋음!

                        # TODO 테스트 : c:\windows\syswow64\rundll32.exe
                        # TODO 테스트 : RUNDLL32.EXE SHELL32.DLL,Control_RunDLL desk.cpl,,0

                        if 'rundll32.exe' == image_exe:

                            print('RunDLL32.exe monitoring // Detected') 
                            event_set = {}
                            event_set['ID'] = 'CAR-2014-03-006'
                            event_set['Name'] = 'RunDLL32.exe monitoring'
                            event_set['Event'] = [record_dict]
                            # TODO 여기서 주의해야할점!! Rundll32은 Execution 에도 있고 Defense Evasion 에도 있음! 그러므로 지금처럼
                            # TODO tac_events 랑 tech_events로 나누면 안되고 나중에는 tac_events['Defense Evasion']['Rundll32'].append(~) 이런식으로 바꿔야함!
                            # TODO 이렇게 바꾸지 않으면 심각한 오류임!

                            tac_tech_list = ['Rundll32_Defense Evasion']
                            change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                            """

                            append_to_event_dict(self.mainwindow.tac_tech_events['Defense Evasion']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Defense Evasion']['Rundll32']['Events'], event_id, event_set)

                            add_table_row(self.mainwindow.tac_tech_events['Defense Evasion']['Table'], evt_local_time, event_id, 'CAR-2014-03-006', 'RunDLL32.exe monitoring')
                            add_table_row(self.mainwindow.tac_tech_events['Defense Evasion']['Rundll32']['Table'], evt_local_time, event_id, 'CAR-2014-03-006', 'RunDLL32.exe monitoring')

                            self.mainwindow.tac_tech_events['Defense Evasion']['Rundll32']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Defense Evasion']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                            # Detected Num Label (Home)
                            self.mainwindow.detected_num += 1
                            self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                            # Home Detected Events
                            append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                            home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                            # Predict Attacker
                            predict_group_or_sw(self.mainwindow, ['Rundll32'])

                            """

                        ##########################################################################################

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
                            event_set = {}
                            event_set['ID'] = 'CAR-2016-03-001'
                            event_set['Name'] = 'Host Discovery Commands'
                            event_set['Event'] = [record_dict]

                            tmp_tech_list = host_discovery_commands[image_exe]

                            tac_tech_list = []

                            for tech_elem in tmp_tech_list:
                            	tac_tech_list.append(tech_elem + '_Discovery')

                            change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                            """

                            append_to_event_dict(self.mainwindow.tac_tech_events['Discovery']['Events'], event_id, event_set)
                            add_table_row(self.mainwindow.tac_tech_events['Discovery']['Table'], evt_local_time, event_id, 'CAR-2016-03-001', 'Host Discovery Commands')
                            self.mainwindow.tac_tech_events['Discovery']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                            for tech_elem in tmp_tech_list:
                                append_to_event_dict(self.mainwindow.tac_tech_events['Discovery'][tech_elem]['Events'], event_id, event_set)
                                add_table_row(self.mainwindow.tac_tech_events['Discovery'][tech_elem]['Table'], evt_local_time, event_id, 'CAR-2016-03-001', 'Host Discovery Commands')
                                self.mainwindow.tac_tech_events['Discovery'][tech_elem]['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)

                                # Predict Attacker
                                predict_group_or_sw(self.mainwindow, [tech_elem])

                            # Detected Num Label (Home)
                            self.mainwindow.detected_num += 1
                            self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                            # Home Detected Events

                            append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                            home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                            """

                        ##########################################################################################

                        # CAR-2014-05-002: Services launching Cmd
                        # New Service - Persistence, Privilege Escalation
                        # https://car.mitre.org/analytics/CAR-2014-05-002

                        if (
                            'cmd.exe' == image_exe and
                            'services.exe' == parent_image_exe
                            ):

                            print("Services launching Cmd // Detected")
                            event_set = {}
                            event_set['ID'] = 'CAR-2014-05-002'
                            event_set['Name'] = 'Services launching Cmd'
                            event_set['Event'] = [record_dict]

                            tac_tech_list = ['New Service_Persistence', 'New Service_Privilege Escalation']
                            change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                            """

                            self.mainwindow.tac_tech_events['Persistence']['Events'][event_id] = event_set
                            self.mainwindow.tac_tech_events['Privilege Escalation']['Events'][event_id] = event_set

                            self.mainwindow.tac_tech_events['Persistence']['New Service']['Events'][event_id] = event_set
                            self.mainwindow.tac_tech_events['Privilege Escalation']['New Service']['Events'][event_id] = event_set

                            append_to_event_dict(self.mainwindow.tac_tech_events['Persistence']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Persistence']['New Service']['Events'], event_id, event_set)

                            append_to_event_dict(self.mainwindow.tac_tech_events['Privilege Escalation']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Privilege Escalation']['New Service']['Events'], event_id, event_set)

                            add_table_row(self.mainwindow.tac_tech_events['Persistence']['Table'], evt_local_time, event_id, 'CAR-2014-05-002', 'Services launching Cmd')
                            add_table_row(self.mainwindow.tac_tech_events['Persistence']['New Service']['Table'], evt_local_time, event_id, 'CAR-2014-05-002', 'Services launching Cmd')

                            add_table_row(self.mainwindow.tac_tech_events['Privilege Escalation']['Table'], evt_local_time, event_id, 'CAR-2014-05-002', 'Services launching Cmd')
                            add_table_row(self.mainwindow.tac_tech_events['Privilege Escalation']['New Service']['Table'], evt_local_time, event_id, 'CAR-2014-05-002', 'Services launching Cmd')

                            self.mainwindow.tac_tech_events['Persistence']['New Service']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Privilege Escalation']['New Service']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)

                            self.mainwindow.tac_tech_events['Persistence']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)
                            self.mainwindow.tac_tech_events['Privilege Escalation']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                            # Detected Num Label (Home)
                            self.mainwindow.detected_num += 1
                            self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                            # Home Detected Events
                            append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                            home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                            # Predict Attacker
                            predict_group_or_sw(self.mainwindow, ['New Service'])

                            """

                        ##########################################################################################

                        # CAR-2013-08-001: Execution with schtasks
                        # Scheduled Task - Persistence
                        # https://car.mitre.org/analytics/CAR-2013-08-001

                        # TODO 테스트 : schtasks /Create /SC ONCE /ST 19:00 /TR C:\Windows\System32\calc.exe /TN calctask
                        # TODO 테스트 : schtasks /Delete /TN calctask

                        if 'schtasks.exe' == image_exe:
                            print("Execution with schtasks // Detected")
                            event_set = {}
                            event_set['ID'] = 'CAR-2013-08-001'
                            event_set['Name'] = 'Execution with schtasks'
                            event_set['Event'] = [record_dict]

                            tac_tech_list = ['Scheduled Task_Persistence']
                            change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                            """

                            append_to_event_dict(self.mainwindow.tac_tech_events['Persistence']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Persistence']['Scheduled Task']['Events'], event_id, event_set)


                            add_table_row(self.mainwindow.tac_tech_events['Persistence']['Table'], evt_local_time, event_id, 'CAR-2013-08-001', 'Execution with schtasks')
                            add_table_row(self.mainwindow.tac_tech_events['Persistence']['Scheduled Task']['Table'], evt_local_time, event_id, 'CAR-2013-08-001', 'Execution with schtasks')

                            self.mainwindow.tac_tech_events['Persistence']['Scheduled Task']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)

                            self.mainwindow.tac_tech_events['Persistence']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                            # Detected Num Label (Home)
                            self.mainwindow.detected_num += 1
                            self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                            # Home Detected Events
                            append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                            home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                            # Predict Attacker
                            predict_group_or_sw(self.mainwindow, ['Scheduled Task'])

                            """

                        ##########################################################################################

                        # CAR-2014-11-008: Command Launched from WinLogon
                        # Accessibility Features - Privilege Escalation, Execution, Persistence
                        # https://car.mitre.org/analytics/CAR-2014-11-008

                        if (
                            'cmd.exe' == image_exe and
                            'winlogon.exe' == parent_image_exe
                            ):

                            # TODO Execution 에는 Accessibility Features 가 없음!!!!

                            print("Command Launched from WinLogon // Detected")
                            event_set = {}
                            event_set['ID'] = 'CAR-2014-11-008'
                            event_set['Name'] = 'Command Launched from WinLogon'
                            event_set['Event'] = [record_dict]

                            tac_tech_list = ['Accessibility Features_Privilege Escalation', 'Accessibility Features_Persistence']
                            change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                            """

                            self.mainwindow.tac_tech_events['Privilege Escalation']['Events'][event_id] = event_set
                            self.mainwindow.tac_tech_events['Persistence']['Events'][event_id] = event_set

                            self.mainwindow.tac_tech_events['Privilege Escalation']['Accessibility Features']['Events'][event_id] = event_set
                            self.mainwindow.tac_tech_events['Persistence']['Accessibility Features']['Events'][event_id] = event_set

                            append_to_event_dict(self.mainwindow.tac_tech_events['Privilege Escalation']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Privilege Escalation']['Accessibility Features']['Events'], event_id, event_set)

                            append_to_event_dict(self.mainwindow.tac_tech_events['Persistence']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Persistence']['Accessibility Features']['Events'], event_id, event_set)

                            add_table_row(self.mainwindow.tac_tech_events['Privilege Escalation']['Table'], evt_local_time, event_id, 'CAR-2014-11-008', 'Command Launched from WinLogon')
                            add_table_row(self.mainwindow.tac_tech_events['Privilege Escalation']['Accessibility Features']['Table'], evt_local_time, event_id, 'CAR-2014-11-008', 'Command Launched from WinLogon')

                            add_table_row(self.mainwindow.tac_tech_events['Persistence']['Table'], evt_local_time, event_id, 'CAR-2014-11-008', 'Command Launched from WinLogon')
                            add_table_row(self.mainwindow.tac_tech_events['Persistence']['Accessibility Features']['Table'], evt_local_time, event_id, 'CAR-2014-11-008', 'Command Launched from WinLogon')

                            self.mainwindow.tac_tech_events['Privilege Escalation']['Accessibility Features']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Persistence']['Accessibility Features']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)

                            self.mainwindow.tac_tech_events['Persistence']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)
                            self.mainwindow.tac_tech_events['Privilege Escalation']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                            # Detected Num Label (Home)
                            self.mainwindow.detected_num += 1
                            self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                            # Home Detected Events
                            append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                            home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                            # Predict Attacker
                            predict_group_or_sw(self.mainwindow, ['Accessibility Features'])

                            """

                        ##########################################################################################

                        # CAR-2013-03-001: Reg.exe called from Command Shell
                        # Query Registry - Defense Evasion
                        # Modify Registry - Persistence, Privilege Escalation
                        # Registry Run Keys / Startup Folder - Persistence, Privilege Escalation
                        # Service Registry Permissions Weakness - Persistence, Privilege Escalation
                        # https://car.mitre.org/analytics/CAR-2013-03-001

                        # TODO 실시간으로 어떤식으로 분석을 진행해야하는지 아직 잘 모르겠음.
                        # TODO Pseudocode를 봤는데... 아마 이건 실시간으로 분석할수 있는게 아닌것같음..
                        # TODO 로그인한 시간부터 분석을 테스트한 시간까지 쭉 쿼리해야됨

                        # TODO 그렇게 안하고, 이 프로그램을 실행시키고 나서부터 해당 이벤트를 발견할때마다 list에 담는것임.
                        # TODO 그다음 list 안에서 group이나 그런것 count(hostname) 이런거 파악해서 계산한다음에 展示 하면 됨!

                        # 이 프로그램이 컴퓨터를 키면 바로 실행되는 시작프로그램으로 설정되어 있다고 가정하에 코딩하고있는 분석임!

                        # TODO 테스트 : reg.exe QUERY HKLM\Software\Microsoft

                        if (
                            'reg.exe' == image_exe and
                            'cmd.exe' == parent_image_exe
                            ):

                            cmd_proc = self.reg_called_from_command_shell(record_dict['Event']['EventData']['ParentProcessId'])

                            print('Reg.exe called from Command Shell // Detected') 
                            event_set = {}
                            event_set['ID'] = 'CAR-2013-03-001'
                            event_set['Name'] = 'Reg.exe called from Command Shell'
                            event_set['Event'] = [record_dict, cmd_proc]

                            tac_tech_list = ['Query Registry_Defense Evasion', 'Modify Registry_Persistence', 'Modify Registry_Privilege Escalation',
                            'Registry Run Keys / Startup Folder_Persistence', 'Registry Run Keys / Startup Folder_Privilege Escalation',
                            'Service Registry Permissions Weakness_Persistence', 'Service Registry Permissions Weakness_Privilege Escalation']
                            change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                            """

                            append_to_event_dict(self.mainwindow.tac_tech_events['Defense Evasion']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Defense Evasion']['Query Registry']['Events'], event_id, event_set)

                            append_to_event_dict(self.mainwindow.tac_tech_events['Persistence']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Persistence']['Modify Registry']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Persistence']['Registry Run Keys / Startup Folder']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Persistence']['Service Registry Permissions Weakness']['Events'], event_id, event_set)

                            append_to_event_dict(self.mainwindow.tac_tech_events['Privilege Escalation']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Privilege Escalation']['Modify Registry']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Privilege Escalation']['Registry Run Keys / Startup Folder']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Privilege Escalation']['Service Registry Permissions Weakness']['Events'], event_id, event_set)
                            

                            add_table_row(self.mainwindow.tac_tech_events['Defense Evasion']['Table'], evt_local_time, event_id, 'CAR-2013-03-001', 'Reg.exe called from Command Shell')
                            add_table_row(self.mainwindow.tac_tech_events['Defense Evasion']['Query Registry']['Table'], evt_local_time, event_id, 'CAR-2013-03-001', 'Reg.exe called from Command Shell')

                            add_table_row(self.mainwindow.tac_tech_events['Persistence']['Table'], evt_local_time, event_id, 'CAR-2013-03-001', 'Reg.exe called from Command Shell')
                            add_table_row(self.mainwindow.tac_tech_events['Persistence']['Modify Registry']['Table'], evt_local_time, event_id, 'CAR-2013-03-001', 'Reg.exe called from Command Shell')
                            add_table_row(self.mainwindow.tac_tech_events['Persistence']['Registry Run Keys / Startup Folder']['Table'], evt_local_time, event_id, 'CAR-2013-03-001', 'Reg.exe called from Command Shell')
                            add_table_row(self.mainwindow.tac_tech_events['Persistence']['Service Registry Permissions Weakness']['Table'], evt_local_time, event_id, 'CAR-2013-03-001', 'Reg.exe called from Command Shell')
                            
                            add_table_row(self.mainwindow.tac_tech_events['Privilege Escalation']['Table'], evt_local_time, event_id, 'CAR-2013-03-001', 'Reg.exe called from Command Shell')
                            add_table_row(self.mainwindow.tac_tech_events['Privilege Escalation']['Modify Registry']['Table'], evt_local_time, event_id, 'CAR-2013-03-001', 'Reg.exe called from Command Shell')
                            add_table_row(self.mainwindow.tac_tech_events['Privilege Escalation']['Registry Run Keys / Startup Folder']['Table'], evt_local_time, event_id, 'CAR-2013-03-001', 'Reg.exe called from Command Shell')
                            add_table_row(self.mainwindow.tac_tech_events['Privilege Escalation']['Service Registry Permissions Weakness']['Table'], evt_local_time, event_id, 'CAR-2013-03-001', 'Reg.exe called from Command Shell')

                            self.mainwindow.tac_tech_events['Defense Evasion']['Query Registry']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Defense Evasion']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                            self.mainwindow.tac_tech_events['Persistence']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)
                            self.mainwindow.tac_tech_events['Persistence']['Modify Registry']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Persistence']['Registry Run Keys / Startup Folder']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Persistence']['Service Registry Permissions Weakness']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            
                            self.mainwindow.tac_tech_events['Privilege Escalation']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)
                            self.mainwindow.tac_tech_events['Privilege Escalation']['Modify Registry']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Privilege Escalation']['Registry Run Keys / Startup Folder']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Privilege Escalation']['Service Registry Permissions Weakness']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)

                            # Detected Num Label (Home)
                            self.mainwindow.detected_num += 1
                            self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                            # Home Detected Events
                            append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                            home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                            # Predict Attacker
                            predict_group_or_sw(self.mainwindow, ['Query Registry', 'Modify Registry', 'Registry Run Keys / Startup Folder', 'Service Registry Permissions Weakness'])

                            """
                        ###########################################################################################

                        # CAR-2013-09-005: Service Outlier Executables
                        # Modify Existing Service - Persistence, Privilege Escalation
                        # New Service - Persistence, Privilege Escalation
                        # https://car.mitre.org/analytics/CAR-2013-09-005

                        # TODO 이건 실시간이 아니라 어느정도 텀을 둔 분석인듯!
                        # TODO 그리고 Pseudocode 에서 "historic_services = filter services (where timestamp < now - 1 day AND timestamp > now - 1 day)" 이게 무슨뜻인지 못알아듣겠음...
                        # Create a baseline of services seen over the last 30 days and a list of services seen today. Remove services in the baseline from services seen today, leaving a list of new services.
                        # 지난 30일 동안 표시된 서비스의 기준선과 현재 표시된 서비스 목록을 생성하십시오. 현재 표시된 서비스에서 기준선에 있는 서비스를 제거하고 새 서비스 목록을 남긴다.
                        # TODO 실시간 검사를 실행하기전에 30일동안의 historic_services 목록을 생성해놔야 할것 같음... (실시간 검사인것 같기도 하고...?)
                        # TODO 아마 services.exe가 부모프로세스일때의 process created를 검사하는듯! 그리고 지난 30일동안의 historic_services 목록에 있는지 확인하는것일듯!
                        # TODO 만약 저 목록에 없으면 출력!
                        # TODO 생각해보니 1시간마다 검사해보는것도 나쁘진 않은것같고... 또 1시간은 너무 길어서 효과를 못볼것같기도하고..
                        # TODO 아무튼 나중에 생각해보기!!

                        # TODO 생각을바꿔서! parent_image_path 가 C:\\Windows\\System32\\services.exe 인 경우마다 검사를 하는것임!
                        # TODO 그리고 지난 30일간의 그 리스트는 데이터베이스에 저장해놓고 필요할때마다 거기서 빼서 확인하고, 삽입하고, 삭제하고 하면 되듯!

                        # TODO 매번 이 이벤트가 발생할때마다 30일 지난 history 삭제하기!

                        # TODO 이거는... 미리 30일동안의 history를 만들어놔야할듯...?
                        # TODO 그렇게 안하면 구현하기가 좀 복잡함..

                        if parent_image == "C:\\Windows\\System32\\services.exe" and (image not in service_outlier_executables_history):

                            # 이미 get_last_30_days_history 함수를 이용해서 지난 30일동안의 history를 다 받아왔음!

                            print('Service Outlier Executables // Detected') 
                            event_set = {}
                            event_set['ID'] = 'CAR-2013-09-005'
                            event_set['Name'] = 'Service Outlier Executables'
                            event_set['Event'] = [record_dict]

                            tac_tech_list = ['Modify Existing Service_Persistence', 'Modify Existing Service_Privilege Escalation', 'New Service_Persistence', 'New Service_Privilege Escalation']
                            change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                            """

                            append_to_event_dict(self.mainwindow.tac_tech_events['Persistence']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Persistence']['Modify Existing Service']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Persistence']['New Service']['Events'], event_id, event_set)

                            append_to_event_dict(self.mainwindow.tac_tech_events['Privilege Escalation']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Privilege Escalation']['New Service']['Events'], event_id, event_set)
                            
                            add_table_row(self.mainwindow.tac_tech_events['Persistence']['Table'], evt_local_time, event_id, event_set['ID'], event_set['Name'])
                            add_table_row(self.mainwindow.tac_tech_events['Persistence']['Modify Existing Service']['Table'], evt_local_time, event_id, event_set['ID'], event_set['Name'])
                            add_table_row(self.mainwindow.tac_tech_events['Persistence']['New Service']['Table'], evt_local_time, event_id, event_set['ID'], event_set['Name'])
                            
                            add_table_row(self.mainwindow.tac_tech_events['Privilege Escalation']['Table'], evt_local_time, event_id, event_set['ID'], event_set['Name'])
                            add_table_row(self.mainwindow.tac_tech_events['Privilege Escalation']['New Service']['Table'], evt_local_time, event_id, event_set['ID'], event_set['Name'])

                            self.mainwindow.tac_tech_events['Persistence']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)
                            self.mainwindow.tac_tech_events['Persistence']['Modify Existing Service']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Persistence']['New Service']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                          
                            self.mainwindow.tac_tech_events['Privilege Escalation']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)
                            self.mainwindow.tac_tech_events['Privilege Escalation']['New Service']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)

                            # Detected Num Label (Home)
                            self.mainwindow.detected_num += 1
                            self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                            # Home Detected Events
                            append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                            home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                            # Predict Attacker
                            predict_group_or_sw(self.mainwindow, ['Modify Existing Service', 'New Service'])

                            """

                        

                        ###########################################################################################

                        # CAR-2014-11-002: Outlier Parents of Cmd
                        # Command-Line Interface - Execution
                        # https://car.mitre.org/analytics/CAR-2014-11-002

                        # TODO 여기도 Pseudocode가 이상한것같음... (where timestamp < now - 1 day AND timestamp > now - 1 day) 이게 무슨뜻인지..
                        # TODO 어떤말을 하고싶어하는지는 알겠음. 지난 30일동안 cmd의 parent_exe 목록을 만들고, 실시간검색으로 만약 지난 30일동안 나타나지 않았던 parent_exe가 나타나면 경고를 띄우는것.

                        # 여기도 지난 30일동안의 history를 준비해놔야됨...

                        if parent_image == "C:\\Windows\\System32\\services.exe" and (image not in service_outlier_executables_history):

                            # 이미 get_last_30_days_history 함수를 이용해서 지난 30일동안의 history를 다 받아왔음!

                            print('Outlier Parents of Cmd // Detected') 
                            event_set = {}
                            event_set['ID'] = 'CAR-2014-11-002'
                            event_set['Name'] = 'Outlier Parents of Cmd'
                            event_set['Event'] = [record_dict]

                            tac_tech_list = ['Command-Line Interface_Execution']
                            change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                            """

                            append_to_event_dict(self.mainwindow.tac_tech_events['Execution']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Execution']['Command-Line Interface']['Events'], event_id, event_set)

                            add_table_row(self.mainwindow.tac_tech_events['Execution']['Table'], evt_local_time, event_id, event_set['ID'], event_set['Name'])
                            add_table_row(self.mainwindow.tac_tech_events['Execution']['Command-Line Interface']['Table'], evt_local_time, event_id, event_set['ID'], event_set['Name'])

                            self.mainwindow.tac_tech_events['Execution']['Command-Line Interface']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                            self.mainwindow.tac_tech_events['Execution']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                            # Detected Num Label (Home)
                            self.mainwindow.detected_num += 1
                            self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                            # Home Detected Events
                            append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                            home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                            # Predict Attacker
                            predict_group_or_sw(self.mainwindow, ['Command-Line Interface'])

                            """

                        ###########################################################################################


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
                                event_set = {}
                                event_set['ID'] = 'CAR-2014-05-001'
                                event_set['Name'] = 'RPC Activity'
                                event_set['Event'] = [record_dict, rpc_mapper[1]]

                                tac_tech_list = ['Valid Accounts_Lateral Movement', 'Remote Services_Lateral Movement']
                                change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                                """

                                append_to_event_dict(self.mainwindow.tac_tech_events['Lateral Movement']['Events'], event_id, event_set)
                                append_to_event_dict(self.mainwindow.tac_tech_events['Lateral Movement']['Valid Accounts']['Events'], event_id, event_set)
                                append_to_event_dict(self.mainwindow.tac_tech_events['Lateral Movement']['Remote Services']['Events'], event_id, event_set)

                                add_table_row(self.mainwindow.tac_tech_events['Lateral Movement']['Table'], evt_local_time, event_id, 'CAR-2014-05-001', 'RPC Activity')
                                add_table_row(self.mainwindow.tac_tech_events['Lateral Movement']['Valid Accounts']['Table'], evt_local_time, event_id, 'CAR-2014-05-001', 'RPC Activity')
                                add_table_row(self.mainwindow.tac_tech_events['Lateral Movement']['Remote Services']['Table'], evt_local_time, event_id, 'CAR-2014-05-001', 'RPC Activity')

                                self.mainwindow.tac_tech_events['Lateral Movement']['Valid Accounts']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)
                                self.mainwindow.tac_tech_events['Lateral Movement']['Remote Services']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)

                                self.mainwindow.tac_tech_events['Lateral Movement']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                                # Detected Num Label (Home)
                                self.mainwindow.detected_num += 1
                                self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                                # Home Detected Events
                                append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                                home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                                # Predict Attacker
                                predict_group_or_sw(self.mainwindow, ['Valid Accounts', 'Remote Services'])

                                """

                        ##########################################################################################

                        # CAR-2014-11-006: Windows Remote Management (WinRM)
                        # Windows Remote Management - Lateral Movement
                        # https://car.mitre.org/analytics/CAR-2014-11-006

                        if (
                            int(record_dict['Event']['EventData']['DestinationPort']) == 5985 or
                            int(record_dict['Event']['EventData']['DestinationPort']) == 5986
                            ):

                            print('Windows Remote Management (WinRM) // Detected')
                            event_set = {}
                            event_set['ID'] = 'CAR-2014-11-006'
                            event_set['Name'] = 'Windows Remote Management (WinRM)'
                            event_set['Event'] = [record_dict, rpc_mapper[1]]

                            tac_tech_list = ['Windows Remote Management_Lateral Movement']
                            change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                            """

                            append_to_event_dict(self.mainwindow.tac_tech_events['Lateral Movement']['Events'], event_id, event_set)
                            append_to_event_dict(self.mainwindow.tac_tech_events['Lateral Movement']['Windows Remote Management']['Events'], event_id, event_set)

                            add_table_row(self.mainwindow.tac_tech_events['Lateral Movement']['Table'], evt_local_time, event_id, 'CAR-2014-11-006', 'Windows Remote Management (WinRM)')
                            add_table_row(self.mainwindow.tac_tech_events['Lateral Movement']['Windows Remote Management']['Table'], evt_local_time, event_id, 'CAR-2014-11-006', 'Windows Remote Management (WinRM)')

                            self.mainwindow.tac_tech_events['Lateral Movement']['Windows Remote Management']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)

                            self.mainwindow.tac_tech_events['Lateral Movement']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                            # Detected Num Label (Home)
                            self.mainwindow.detected_num += 1
                            self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                            # Home Detected Events
                            append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                            home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                            # Predict Attacker
                            predict_group_or_sw(self.mainwindow, ['Windows Remote Management'])

                            """
                            


                    ###########################################################################################

                    # CAR-2015-04-002: Remotely Scheduled Tasks via Schtasks
                    # Scheduled Task - Execution
                    # https://car.mitre.org/analytics/CAR-2015-04-002

                    # TODO Pseudocode를 이해를 못하겠음.. proto_info.rpc_interface가 뭘 뜻하는거지..?
                    # TODO ㄴ proto_info.rpc_interface는 지금 상황에선 모니터링 기능을 충족시켜주는 모니터링 툴이 없어서 탐지 불가...

                    ###########################################################################################

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

                    ###########################################################################################

                    # CAR-2014-11-005: Remote Registry
                    # Modify Registry - Lateral Movement, Defense Evasion
                    # https://car.mitre.org/analytics/CAR-2014-11-005

                    # proto_info를 sysmon은 탐지 못함... CAR에 나와있는 내용 봤는데 아직 탐지가능한 툴이 없는듯.. (https://car.mitre.org/data_model/flow#proto_info)

                    ###########################################################################################

                    # CAR-2014-03-001: SMB Write Request - NamedPipes
                    # https://car.mitre.org/analytics/CAR-2014-03-001

                    # TODO 이것도 proto_info 를 어디서 어떻게 받아오는지 모르겠음...

                    ###########################################################################################

                    # CAR-2013-05-005: SMB Copy and Execution
                    # Windows Admin Shares - Lateral Movement
                    # Valid Accounts - Defense Evasion, Lateral Movement
                    # Remote File Copy - Lateral Movement
                    # https://car.mitre.org/analytics/CAR-2013-05-005

                    # TODO 이 분석을 진행하려면 "CAR-2013-05-003" 이 분석 내용이 필요한데, "CAR-2013-05-003"분석은 proto_info를 필요로함.. sysmon으로는 얻을수 없는 정보..

                    ###########################################################################################

                    # CAR-2013-02-003: Processes Spawning cmd.exe
                    # Command-Line Interface - Execution
                    # https://car.mitre.org/analytics/CAR-2013-02-003

                    #if str(record_dict['Event']['System']['EventID']) == str(1) and
                    #    'cmd.exe' in str(record_dict['Event']['EventData']['Image']):

                    #    print('Processes Spawning cmd.exe // Detected') 
                    # TODO 이건 너무 광범위한것같음... 그냥 cmd만 나오면 바로 출력을시켜버리니...
                    # TODO Document에는 abnormal parent process가 cmd를 실행시키면, 이라고 나와있는데 abnormal parent가 뭔지 모르겠음..

                    ###########################################################################################

                    # CAR-2014-11-007: Remote Windows Management Instrumentation (WMI) over RPC
                    # Windows Management Instrumentation - Lateral Movement
                    # https://car.mitre.org/analytics/CAR-2014-11-007

                    # TODO proto_info....

                    ###########################################################################################

                    # CAR-2013-07-002: RDP Connection Detection
                    # Remote Desktop Protocol - Lateral Movement
                    # https://car.mitre.org/analytics/CAR-2013-07-002

                    # TODO network connection start는 sysmon 이벤트 로그에 남는데 end는 안남는것같음...

                    ###########################################################################################

                    # CAR-2013-09-003: SMB Session Setups
                    # https://car.mitre.org/analytics/CAR-2013-09-003

                    # TODO proto_info를 어디서 찾을수 있을까나...

                    ###########################################################################################

                    # CAR-2013-05-003: SMB Write Request
                    # Remote File Copy - Lateral Movement
                    # Windows Admin Shares - Lateral Movement
                    # Valid Accounts - Defense Evasion, Lateral Movement

                    # TODO proto_info...... 어떻게 찾지..

                    ###########################################################################################

                    # CAR-2014-02-001: Service Binary Modifications
                    # New Service - Persistence, Privilege Escalation   Moderate
                    # Modify Existing Service - Persistence  
                    # File System Permissions Weakness - Persistence, Privilege Escalation   Moderate
                    # Service Execution - Execution, Privilege Escalation Moderate
                    # https://car.mitre.org/analytics/CAR-2014-02-001

                    # TODO Autoruns가 있어야 가능함..

                    ###########################################################################################

                    # CAR-2013-01-003: SMB Events Monitoring
                    # Valid Accounts - Lateral Movement
                    # Data from Network Shared Drive - Exfiltration
                    # Windows Admin Shares - Lateral Movement
                    # https://car.mitre.org/analytics/CAR-2013-01-003

                    # TODO proto_info....

                    ###########################################################################################

                    # CAR-2015-04-001: Remotely Scheduled Tasks via AT
                    # Scheduled Task - Execution
                    # https://car.mitre.org/analytics/CAR-2015-04-001

                    # TODO proto_info....

                    ###########################################################################################

                    # CAR-2013-01-002: Autorun Differences
                    # https://car.mitre.org/analytics/CAR-2013-01-002

                    # TODO Autorun에 대한 설명인가..?

                    ###########################################################################################

                    # CAR-2014-12-001: Remotely Launched Executables via WMI
                    # Windows Management Instrumentation - Execution
                    # https://car.mitre.org/analytics/CAR-2014-12-001

                    # TODO proto_info....

                    ###########################################################################################

                    # CAR-2013-05-009: Running executables with same hash and different names
                    # Masquerading - Defense Evasion
                    # https://car.mitre.org/analytics/CAR-2013-05-009

                    # Output Description : A list of hashes and the different executables associated with each one

                    ###########################################################################################

    def reg_called_from_command_shell(self, ppid):

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
                cmd_proc = xmltodict.parse(record)

                # 변수 설정
                evt_id = int(cmd_proc['Event']['System']['EventID'])

                # UTC to Local Time
                evt_local_time = Utc_to_local(cmd_proc['Event']['System']['TimeCreated']['@SystemTime'])
                cmd_proc['Event']['System']['TimeCreated']['@SystemTime'] = evt_local_time

                # cmd_proc 의 EventData 의 value 값 수정하기... Data - name - text 이런식으로 돼있어서 인덱스하기 힘듦...!
                temp_data = {}
                for data in cmd_proc['Event']['EventData']['Data']:
                    if '#text' in data:
                        temp_data[data['@Name']] = data['#text']
                    elif data == None or data == 'None':
                        temp_data = {}
                    else:
                        temp_data[data['@Name']] = None
                cmd_proc['Event']['EventData'] = temp_data
                # print(temp_data)

                if (
                    evt_id == 1 and 
                    ppid == cmd_proc['Event']['EventData']['ProcessId']
                    ):
                    return cmd_proc
    

    def get_ps_info(self, proc_id):

        # TODO PowerShell 찾아야함

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
                return (False, ['', ''], None)
            for event in events:
                record = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)

                # xml to dict
                ps_start = xmltodict.parse(record)

                # 변수 설정
                evt_id = 0
                try:
                    evt_id = int(ps_start['Event']['System']['EventID'])
                except:
                    evt_id = int(ps_start['Event']['System']['EventID']['#text'])

                # UTC to Local Time
                evt_local_time = Utc_to_local(ps_start['Event']['System']['TimeCreated']['@SystemTime'])
                ps_start['Event']['System']['TimeCreated']['@SystemTime'] = evt_local_time

                # ps_start 의 EventData 의 value 값 수정하기... Data - name - text 이런식으로 돼있어서 인덱스하기 힘듦...!
                temp_data = {}
                for data in ps_start['Event']['EventData']['Data']:
                    if '#text' in data:
                        temp_data[data['@Name']] = data['#text']
                    elif data == None or data == 'None':
                        temp_data = {}
                    else:
                        temp_data[data['@Name']] = None
                ps_start['Event']['EventData'] = temp_data
                # print(temp_data)


                if (
                    evt_id == 1 and 
                    ps_start['Event']['EventData']['ProcessId'] == str(proc_id)
                    ):

                    # Powershell Start 이벤트일때 parentImage 판단!

                    parent_image = str(ps_start['Event']['EventData']['ParentImage'])
                    parent_image_exe = parent_image.split('\\')
                    parent_image_exe = (parent_image_exe[-1]).lower()

                    if parent_image_exe != 'explorer.exe':
                    
                        # 현재 날짜에 생성된 powershell 로그 디렉토리 이름 찾기
                        now_time = time.localtime()
                        ps_dir_name = "%04d%02d%02d" % (now_time.tm_year, now_time.tm_mon, now_time.tm_mday)

                        ps_log_path = desktop_path + '\\powershell-log\\' + ps_dir_name + '\\'

                        # 해당 디렉토리 내의 파일 리스트 찾기

                        filenames = os.listdir(ps_log_path)
                        for filename in filenames:
                            full_filename = ps_log_path + filename

                            f = codecs.open(full_filename, 'r', 'utf-8')
                            lines = f.readlines()
                            proc_id_line = lines[7]
                            ps_log_proc_id = re.sub('[^0-9]', '', proc_id_line)

                            # 해당 powershell 이벤트와 상응하는 powershell start 이벤트 찾기

                            if ps_log_proc_id == proc_id:

                                return_dict = {}
                                return_dict['mimikatz'] = 0
                                return_dict['get-netLlocalgroupmember'] = 0
                                return_dict['get-domaincomputer'] = 0
                                return_dict['ps_command_line'] = ''.join(lines)

                                # 의심스러운 powershell 명령어 실행됬는지 확인

                                check_suspicious = False
                                suspicious_command_line = ''

                                for line in lines:
                                    if line[0:3] == "PS>":
                                        pre_100_str = (line[0:100]).lower()
                                        if "mimikatz" in pre_100_str:
                                            return_dict['mimikatz'] = 1
                                            suspicious_command_line += line
                                            check_suspicious = True
                                        if "get-netLlocalgroupmember" in pre_100_str:
                                            return_dict['get-netLlocalgroupmember'] = 1
                                            suspicious_command_line += line
                                            check_suspicious = True
                                        if "get-domaincomputer" in pre_100_str:
                                            return_dict['get-domaincomputer'] = 1
                                            suspicious_command_line += line
                                            check_suspicious = True

                                if check_suspicious == True:
                                    f.close()
                                    ps_start['Event']['EventData']['CommandLine'] = suspicious_command_line
                                    return_dict['ps_start'] = ps_start
                                    return return_dict

                            f.close()
                return {}


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
                return (False, ['', ''], None)
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
                            return (True, [rp_exe, r_exe], reg)
                elif reg_processes['Event']['System']['TimeCreated']['@SystemTime'] - datetime.timedelta(minutes=30) > reg['Event']['System']['TimeCreated']['@SystemTime']:
                    return (False, ['', ''], None)

                

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
    def __init__(self, mainwindow):
        threading.Thread.__init__(self)
        self.mainwindow = mainwindow
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
                        if data == None or data == 'None':
                            temp_data = {}
                        elif '#text' in data:
                            temp_data[data['@Name']] = data['#text']
                        elif '@Name' in data:
                            temp_data[data['@Name']] = None
                        else:
                            temp_data = {}
                    record_dict['Event']['EventData'] = temp_data
                    # print(temp_data)

                    # Checked Event Number
                    self.mainwindow.check_num += 1
                    self.mainwindow.check_num_label.setText('Checked Event Num : ' + str(self.mainwindow.check_num))

                    # CAR analytics

                    # 의심가는 이벤트 발견시 이벤트 정보 담는 변수
                    event_set = {}

                    # Event-ID
                    event_id = record_dict['Event']['System']['EventRecordID']

                    ##########################################################################################

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
                        event_set = {}
                        event_set['ID'] = 'CAR-2016-04-003'
                        event_set['Name'] = 'User Activity from Stopping Windows Defensive Services'
                        event_set['Event'] = [record_dict]

                        tac_tech_list = ['Indicator Blocking_Defense Evasion']
                        change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                        """

                        append_to_event_dict(self.mainwindow.tac_tech_events['Defense Evasion']['Events'], event_id, event_set)
                        append_to_event_dict(self.mainwindow.tac_tech_events['Defense Evasion']['Indicator Blocking']['Events'], event_id, event_set)

                        add_table_row(self.mainwindow.tac_tech_events['Defense Evasion']['Table'], evt_local_time, event_id, 'CAR-2016-04-003', 'User Activity from Stopping Windows Defensive Services')
                        add_table_row(self.mainwindow.tac_tech_events['Defense Evasion']['Indicator Blocking']['Table'], evt_local_time, event_id, 'CAR-2016-04-003', 'User Activity from Stopping Windows Defensive Services')

                        self.mainwindow.tac_tech_events['Defense Evasion']['Indicator Blocking']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)

                        self.mainwindow.tac_tech_events['Defense Evasion']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                        # Detected Num Label (Home)
                        self.mainwindow.detected_num += 1
                        self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                        # Home Detected Events
                        append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                        home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                        # Predict Attacker
                        predict_group_or_sw(self.mainwindow, ['Indicator Blocking'])

                        """
                        
                    ##########################################################################################

                    # CAR-2016-04-002: User Activity from Clearing Event Logs
                    # Indicator Blocking - Defense Evasion
                    # https://car.mitre.org/analytics/CAR-2016-04-002

                    # 확인 방법 : Clear-Eventlog Security 또는 Clear-Eventlog System

                    if (
                        evt_id == 1100 or
                        evt_id == 1102
                        ):

                        print('User Activity from Clearing Event Logs // Detected')
                        event_set = {}
                        event_set['ID'] = 'CAR-2016-04-002'
                        event_set['Name'] = 'User Activity from Clearing Event Logs'
                        event_set['Event'] = [record_dict]

                        tac_tech_list = ['Indicator Blocking_Defense Evasion']
                        change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                        """

                        append_to_event_dict(self.mainwindow.tac_tech_events['Defense Evasion']['Events'], event_id, event_set)
                        append_to_event_dict(self.mainwindow.tac_tech_events['Defense Evasion']['Indicator Blocking']['Events'], event_id, event_set)


                        add_table_row(self.mainwindow.tac_tech_events['Defense Evasion']['Table'], evt_local_time, event_id, 'CAR-2016-04-002', 'User Activity from Clearing Event Logs')
                        add_table_row(self.mainwindow.tac_tech_events['Defense Evasion']['Indicator Blocking']['Table'], evt_local_time, event_id, 'CAR-2016-04-002', 'User Activity from Clearing Event Logs')

                        self.mainwindow.tac_tech_events['Defense Evasion']['Indicator Blocking']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)

                        self.mainwindow.tac_tech_events['Defense Evasion']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                        # Detected Num Label (Home)
                        self.mainwindow.detected_num += 1
                        self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                        # Home Detected Events
                        append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                        home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                        # Predict Attacker
                        predict_group_or_sw(self.mainwindow, ['Indicator Blocking'])

                        """

# ===================================================================================================== #
# ===================================================================================================== #

class Security_evt (threading.Thread):
    def __init__(self, mainwindow):
        threading.Thread.__init__(self)
        self.mainwindow = mainwindow
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
                        if data == None or data == 'None':
                            temp_data = {}
                        if '#text' in data:
                            temp_data[data['@Name']] = data['#text']
                        elif '@Name' in data:
                            temp_data[data['@Name']] = None
                        else:
                            temp_data = {}
                    record_dict['Event']['EventData'] = temp_data
                    # print(temp_data)

                    # Checked Event Number
                    self.mainwindow.check_num += 1
                    self.mainwindow.check_num_label.setText('Checked Event Num : ' + str(self.mainwindow.check_num))

                    # CAR analytics

                    # 의심가는 이벤트 발견시 이벤트 정보 담는 변수
                    event_set = {}

                    # Event-ID
                    event_id = record_dict['Event']['System']['EventRecordID']

                    ##########################################################################################

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
                        event_set = {}
                        event_set['ID'] = 'CAR-2016-04-005'
                        event_set['Name'] = 'Remote Desktop Logon'
                        event_set['Event'] = [record_dict]

                        tac_tech_list = ['Valid Accounts_Lateral Movement']
                        change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                        """

                        append_to_event_dict(self.mainwindow.tac_tech_events['Lateral Movement']['Events'], event_id, event_set)
                        append_to_event_dict(self.mainwindow.tac_tech_events['Lateral Movement']['Valid Accounts']['Events'], event_id, event_set)


                        add_table_row(self.mainwindow.tac_tech_events['Lateral Movement']['Table'], evt_local_time, event_id, 'CAR-2016-04-005', 'Remote Desktop Logon')
                        add_table_row(self.mainwindow.tac_tech_events['Lateral Movement']['Valid Accounts']['Table'], evt_local_time, event_id, 'CAR-2016-04-005', 'Remote Desktop Logon')

                        self.mainwindow.tac_tech_events['Lateral Movement']['Valid Accounts']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)

                        self.mainwindow.tac_tech_events['Lateral Movement']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                        # Detected Num Label (Home)
                        self.mainwindow.detected_num += 1
                        self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                        # Home Detected Events
                        append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                        home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                        # Predict Attacker
                        predict_group_or_sw(self.mainwindow, ['Valid Accounts'])

                        """

                    ##########################################################################################

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
                        event_set = {}
                        event_set['ID'] = 'CAR-2016-04-004'
                        event_set['Name'] = 'Successful Local Account Login'
                        event_set['Event'] = [record_dict]

                        tac_tech_list = ['Pass the Hash_Lateral Movement']
                        change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                        """

                        append_to_event_dict(self.mainwindow.tac_tech_events['Lateral Movement']['Events'], event_id, event_set)
                        append_to_event_dict(self.mainwindow.tac_tech_events['Lateral Movement']['Pass the Hash']['Events'], event_id, event_set)

                        add_table_row(self.mainwindow.tac_tech_events['Lateral Movement']['Table'], evt_local_time, event_id, 'CAR-2016-04-004', 'Successful Local Account Login')
                        add_table_row(self.mainwindow.tac_tech_events['Lateral Movement']['Pass the Hash']['Table'], evt_local_time, event_id, 'CAR-2016-04-004', 'Successful Local Account Login')

                        self.mainwindow.tac_tech_events['Lateral Movement']['Pass the Hash']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)

                        self.mainwindow.tac_tech_events['Lateral Movement']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                        # Detected Num Label (Home)
                        self.mainwindow.detected_num += 1
                        self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                        # Home Detected Events
                        append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                        home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                        # Predict Attacker
                        predict_group_or_sw(self.mainwindow, ['Pass the Hash'])

                        """

                    ##########################################################################################

                    # CAR-2016-04-002: User Activity from Clearing Event Logs
                    # Indicator Blocking - Defense Evasion
                    # https://car.mitre.org/analytics/CAR-2016-04-002

                    # 확인 방법 : Clear-Eventlog Security 또는 Clear-Eventlog System

                    if evt_id == 104:

                        print('User Activity from Clearing Event Logs // Detected')
                        event_set = {}
                        event_set['ID'] = 'CAR-2016-04-002'
                        event_set['Name'] = 'User Activity from Clearing Event Logs'
                        event_set['Event'] = [record_dict]

                        tac_tech_list = ['Indicator Blocking_Defense Evasion']
                        change_interface(self.mainwindow, event_set, event_id, evt_local_time, tac_tech_list)

                        """

                        append_to_event_dict(self.mainwindow.tac_tech_events['Defense Evasion']['Events'], event_id, event_set)
                        append_to_event_dict(self.mainwindow.tac_tech_events['Defense Evasion']['Indicator Blocking']['Events'], event_id, event_set)

                        add_table_row(self.mainwindow.tac_tech_events['Defense Evasion']['Table'], evt_local_time, event_id, 'CAR-2016-04-002', 'User Activity from Clearing Event Logs')
                        add_table_row(self.mainwindow.tac_tech_events['Defense Evasion']['Indicator Blocking']['Table'], evt_local_time, event_id, 'CAR-2016-04-002', 'User Activity from Clearing Event Logs')

                        self.mainwindow.tac_tech_events['Defense Evasion']['Indicator Blocking']['Button'].setStyleSheet(self.mainwindow.detect_tech_button_style)

                        self.mainwindow.tac_tech_events['Defense Evasion']['Button'].setStyleSheet(self.mainwindow.detect_tac_button_style)

                        # Detected Num Label (Home)
                        self.mainwindow.detected_num += 1
                        self.mainwindow.detected_num_label.setText('Detected Event Num : ' + str(self.mainwindow.detected_num))

                        # Home Detected Events
                        append_to_event_dict(self.mainwindow.home_detected_events, event_id, event_set)
                        home_add_table_row(self.mainwindow, evt_local_time, event_id, event_set)

                        # Predict Attacker
                        predict_group_or_sw(self.mainwindow, ['Remote Desktop Protocol', 'Valid Accounts'])

                        """

                    ##########################################################################################

                    # CAR-2015-07-001: All Logins Since Last Boot
                    # https://car.mitre.org/analytics/CAR-2015-07-001

                    # TODO 이건 아마 mimikatz가 실행된걸 발견하고 난 다음에 target_host랑 event_time을 입력해서
                    # TODO 해당 mimikatz를 발견한 호스트 외에 lateral movement에 의해 피해를 입었을수도 있는 유저들에 대해 조사하는듯!
                    # TODO Security 이벤트 로그중에 EventID 가 4648인 Logon 로그 유의하기!! mimikatz와 연관있는것같음!

                    # TODO 이것도 login Action에 대해 파악할 수 있는 모니터링 툴이 부족함...

                    ##########################################################################################

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

                    # TODO 실시간으로 할수 있을것같음!
                    # TODO 이것도 시작 프로그램으로 설정됬다고 치고!
                    # TODO 매번 interest 한 Login 이 생겼을때마다 dict 에 넣음! 이때 key는 hostname 이고! value는 이벤트 list!
                    # TODO 그리고 매번 실시간으로 로그인이 생길때마다 확인하는것임! 그리고 이때 1시간 차이가 넘어가는 이벤트는 다 삭제해야됨!
                    # TODO User_count는 len(list)로 해결하면 될것같음!

                    # TODO 보니까 이것도 coverage map이 텅텅 비어있음... 모니터링 툴이 부족한듯!
                    
                    ##########################################################################################

                    # CAR-2013-10-001: User Login Activity Monitoring
                    # Remote Desktop Protocol - Lateral Movement
                    # Valid Accounts - Defense Evasion
                    # https://car.mitre.org/analytics/CAR-2013-10-001

                    # Output Description : The time of login events for distinct users on individual systems
                        


# TODO 아무래도 실시간으로 분석하는 기능 말고도 몇시간 또는 몇십분마다 분석하는 기능도 필요할듯...?
# 실시간으로만 가능한 분석이 있는가 하면, 시간을 좀 두어야 분석이 가능한것들도 있는 것 같음.

# ============================================================================================================= #
 
def init_matrix():
    tactics = {}

    # 读取Tactics字典
    with open('Tactics.json', 'r', encoding='utf-8') as json_file:
        tactics = json.load(json_file)

    tmp_tac_tech = []
    max_tech_num = 0
    tact_num = 0

    for tact in tactics['Enterprise']:
        tact_num += 1

        tmp = []
        tmp.append(tact)

        if len(tactics['Enterprise'][tact]['Techniques']) > max_tech_num:
            max_tech_num = len(tactics['Enterprise'][tact]['Techniques'])

        for tech in tactics['Enterprise'][tact]['Techniques']:
            tmp.append(tech['Name'])

        tmp_tac_tech.append(tmp)

    tac_tech = [''] * ((max_tech_num + 1) * tact_num)

    for i in range(0, len(tmp_tac_tech)):
        for j in range(0, len(tmp_tac_tech[i])):
            tac_tech[(j * tact_num) + i] = tmp_tac_tech[i][j]

    return tac_tech


class MatrixButton(QPushButton):
    def __init__(self, parent=None, main_window=None):
        QPushButton.__init__(self, parent)
        self.name = ""
        self.tac_name = ""
        self.tac0_tech1 = None
        self.main_window = main_window
        self.clicked.connect(self.click_action)

    def click_action(self):
        if self.tac0_tech1 == 0:
            # print(self.name)
            self.main_window.create_tac_tab(self.name)
        else:
            # print(self.name)
            self.main_window.create_tech_tab(self.name, self.tac_name)
        # self.main_window.setWindowTitle("ATT&CK 2")


class MainWindow(QTabWidget):
    def __init__(self,parent=None):
        super(MainWindow, self).__init__(parent)

        self.tactics = []
        self.techniques = []
        self.softwares = []
        self.groups = []

        self.default_tech_button_style = 'font:10px;text-align : center;padding: 0px;background-color: rgb(252, 252, 252);border-style: outset;border-width: 1px;border-color: rgb(220, 220, 220);'
        self.default_tac_button_style = 'font:11px;text-align : center;padding: 0px;background-color: rgb(80, 80, 80);color: rgb(252, 252, 252);font-weight: bold;'
        
        self.detect_tech_button_style = 'font:10px;text-align : center;padding: 0px;background-color: rgb(255, 0, 0);border-style: outset;border-width: 1px;border-color: rgb(220, 220, 220);'
        self.detect_tac_button_style = 'font:11px;text-align : center;padding: 0px;background-color: rgb(80, 80, 80);color: rgb(255, 0, 0);font-weight: bold;'
        
        # 读取Tactics字典
        with open('Tactics.json', 'r', encoding='utf-8') as json_file:
            self.tactics = json.load(json_file)

        # 读取Techniques字典
        with open('Techniques.json', 'r', encoding='utf-8') as json_file:
            self.techniques = json.load(json_file)

        # 读取Software字典
        with open('Software.json', 'r', encoding='utf-8') as json_file:
            self.softwares = json.load(json_file)

        # 读取Groups字典
        with open('Groups.json', 'r', encoding='utf-8') as json_file:
            self.groups = json.load(json_file)

        # Tactics-Techniques Detected Events, MapButtons, Detected Table

        self.tac_tech_events = {}
        for elem in self.tactics['Enterprise']:
            self.tac_tech_events[elem] = {}
            self.tac_tech_events[elem]['Table'] = self.make_detected_table()
            self.tac_tech_events[elem]['Events'] = {}
            for elem2 in self.tactics['Enterprise'][elem]['Techniques']:
                self.tac_tech_events[elem][elem2['Name']] = {}
                self.tac_tech_events[elem][elem2['Name']]['Events'] = {}
                self.tac_tech_events[elem][elem2['Name']]['Table'] = self.make_detected_table()

        # Home Detected Table
        self.home_detected_table = self.make_detected_table()
        QTableWidget.resizeColumnsToContents(self.home_detected_table)
        self.home_detected_table.setMinimumSize(1400, 400)#######设置滚动条的尺寸
        self.home_detected_table.tac_name = ""
        self.home_detected_table.tech_name = ""

        # Home Detected Events
        self.home_detected_events = {}

        self.setMinimumSize(1530,900)
        self.setMaximumSize(1530,900)

        # Checked Event Number
        self.check_num = 0
        self.check_num_label = QLabel('Checked Event Num : 0')

        # Predict Attacker
        self.predict_attacker = {}

        # Home Predict Table
        self.home_predict_table = self.make_predict_table()
        QTableWidget.resizeColumnsToContents(self.home_predict_table)
        self.home_predict_table.setMinimumSize(1400, 400)#######设置滚动条的尺寸


        # Detected Event Number
        self.detected_num = 0
        self.detected_num_label = QLabel('Detected Event Num : 0')

        # 添加关闭Tab功能
        self.setTabsClosable(True)
        self.tabCloseRequested.connect(self.close_tab)

        self.tab1=QWidget()
        self.tab2=QWidget()

        self.make_matrix()

        self.addTab(self.tab1, "Tab 1")
        self.addTab(self.tab2, "ATT&CK Matrix")

        self.make_home()

        self.setWindowTitle("ATT&CK")

    def make_predict_table(self):
        table = QTableWidget(10,2)
        # 点击事件
        #self.tac_detected.itemClicked.connect(self.tac_item_clicked)
        # 去掉边框线
        table.setFrameShape(QFrame.NoFrame);
        # 设置表格整行选中
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        # 设置垂直方向的表头标签
        table.setHorizontalHeaderLabels(['Group or Software Name', 'Weight'])
        # 设置水平方向表格为自适应的伸缩模式
        #self.tac_detected.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        # 将表格变为禁止编辑
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # 表格头的显示与隐藏
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setStyleSheet('font-family : Times New Roman;font:20px;')

        return table

    def make_detected_table(self):
        table = QTableWidget(0,4)
        # 点击事件
        #self.tac_detected.itemClicked.connect(self.tac_item_clicked)
        # 去掉边框线
        table.setFrameShape(QFrame.NoFrame);
        # 设置表格整行选中
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        # 设置垂直方向的表头标签
        table.setHorizontalHeaderLabels(['Time', 'ID', 'CAR-ID', 'CAR-NAME'])
        # 设置水平方向表格为自适应的伸缩模式
        #self.tac_detected.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        # 将表格变为禁止编辑
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # 表格头的显示与隐藏
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setStyleSheet('font-family : Times New Roman;font:20px;')

        return table

    def make_matrix(self):
        topFiller = QWidget()
        topFiller.setMinimumSize(1530, 3200)#######设置滚动条的尺寸

        tac_tech = init_matrix()
        tac_tech_width = 11
        tac_tech_height = 64

        count = 0
        button_width = 135
        button_height = 50

        # ATT&CK 매트리스 버튼 만들기

        for tactech in tac_tech:
            if tactech == '':
                count += 1
                continue

            MapButton = MatrixButton(topFiller, self)
            MapButton.name = tactech
            MapButton.resize(button_width, button_height)

            # 띄어쓰기... 텍스트가 너무 길면 버튼 밖으로 나가서 안보임..
            enter_count = 0
            newstr = ""
            for ch in tactech:
                if ch == ' ':
                    if enter_count % 2 == 1:
                        newstr += '\n'
                    else:
                        newstr += ' '
                    enter_count += 1
                else:
                    newstr += ch

            MapButton.setText(newstr)
            MapButton.move(button_width * (count%11),button_height * int(count/11))

            # Tactics 매트릭스 원소 색깔 바꿔서 차이점 주기!
            if int(count/11) > 0:
                # Technique
                MapButton.setStyleSheet(self.default_tech_button_style)
                # MapButton.setToolTip("Description")
                MapButton.tac0_tech1 = 1
                MapButton.tac_name = tac_tech[count % 11]
                self.tac_tech_events[tac_tech[count % 11]][tactech]['Button'] = MapButton
            else:
                #Tactics
                MapButton.setStyleSheet(self.default_tac_button_style)
                MapButton.tac0_tech1 = 0
                self.tac_tech_events[tactech]['Button'] = MapButton

            count += 1

            # MapButton.clicked.connect(lambda:self.tech_clicked(MapButton.text()))

        ##创建一个滚动条
        scroll = QScrollArea()
        scroll.setStyleSheet('background-color: rgb(252, 252, 252);')
        scroll.setWidget(topFiller)
 
        vbox = QVBoxLayout()
        vbox.addWidget(scroll)
        self.tab2.setLayout(vbox)


    def make_home(self):
        #表单布局
        layout=QFormLayout()
        
        # Checked Event Num

        self.check_num_label.setText('Checked Event Num : ' + str(self.check_num))
        self.check_num_label.setStyleSheet('font:25px;'
            #'font-family : Times New Roman'
            'text-align : center;' 
            'padding: 0px;'
            'color: rgb(0,255,0);'
            'font-weight: bold;')
        layout.addRow(self.check_num_label, QLabel())

        # Detected Event Num
        
        self.detected_num_label.setStyleSheet('font:25px;'
            #'font-family : Times New Roman'
            'text-align : center;' 
            'padding: 0px;'
            'color: rgb(255,0,0);'
            'font-weight: bold;')
        layout.addRow(self.detected_num_label, QLabel())

        # Predict Attacker Table

        key_label = QLabel('Predict Attacker Table')
        key_label.setStyleSheet('font:30px;'
            #'font-family : Times New Roman'
            'padding: 0px;'
            'font-weight: bold;')

        layout.addRow(key_label,QLabel())

        layout.addRow(self.home_predict_table, QLabel())
        self.home_predict_table.itemClicked.connect(self.predict_item_clicked)

        # Detected Event Table

        key_label = QLabel('Detected Event Table')
        key_label.setStyleSheet('font:30px;'
            #'font-family : Times New Roman'
            'padding: 0px;'
            'font-weight: bold;')

        layout.addRow(key_label,QLabel())

        layout.addRow(self.home_detected_table, QLabel())
        self.home_detected_table.itemClicked.connect(self.event_item_clicked)
        #设置选项卡的小标题与布局方式
        self.setTabText(0,'Home')
        self.tab1.setLayout(layout)


    #关闭tab
    def close_tab(self, index):
        if self.count()>1 and index != 0 and index != 1:
            self.removeTab(index)
        elif index == 0 or index == 1:
            # TODO
            print('No')
        else:
            # TODO
            self.close()   # 当只有1个tab时，关闭主窗口

    #创建tactics tab
    def create_tac_tab(self, name):
        tab = QWidget()
        #####

        topFiller = QWidget()

        scroll = QScrollArea()
        scroll.setStyleSheet('background-color: rgb(252, 252, 252);')
        scroll.setWidget(topFiller)

        layout = QFormLayout()

        row_count = 0

        for key in self.tactics['Enterprise'][name]:
            if type(self.tactics['Enterprise'][name][key]) != type([]):
                key_label = QLabel(key)
                key_label.setStyleSheet('font:30px;'
                    #'font-family : Times New Roman'
                    'padding: 0px;'
                    'font-weight: bold;')

                # newstr = key + ' : ' + self.tactics['Enterprise'][name][key]
                # print(newstr)
                layout.addRow(key_label,QLabel())
                row_count += 3

                descript_str = self.tactics['Enterprise'][name][key]

                while 1:
                    if len(descript_str) > 150:
                        tmp_str = descript_str[:150]
                        while 1:
                            if tmp_str[-1] == ' ':
                                break
                            else:
                                tmp_str = tmp_str[:-1]

                        descript_str = descript_str[len(tmp_str):]

                        descript_label = QLabel('   ' + tmp_str)
                        descript_label.setStyleSheet('font:20px;padding: 0px;font-family : Times New Roman;')
                        layout.addRow(descript_label,QLabel())
                        row_count += 2
                    else:
                        descript_label = QLabel('   ' + descript_str + '\n')
                        descript_label.setStyleSheet('font:20px;padding: 0px;font-family : Times New Roman;')
                        layout.addRow(descript_label,QLabel())
                        row_count += 2
                        break

            else:
                
                key_label = QLabel(key)
                key_label.setStyleSheet('font:30px;'
                    #'font-family : Times New Roman'
                    'text-align : center;' 
                    'padding: 0px;'
                    'font-weight: bold;')
                layout.addRow(key_label,QLabel())

                column_count = 0
                column_list = []
                for list_elem in self.tactics['Enterprise'][name][key]:
                    for list_key in list_elem:
                        column_list.append(list_key)
                        column_count += 1
                    break

                table_widget = QTableWidget(10,column_count)
                table_widget.name = name
                table_widget.itemClicked.connect(self.tac_item_clicked)
                # 设置表头不可点击
                # table_widget.horizontalHeader().setClickable(False);
                # 去掉边框线
                table_widget.setFrameShape(QFrame.NoFrame);
                # 设置表格整行选中
                table_widget.setSelectionBehavior(QAbstractItemView.SelectRows)
                # 设置垂直方向的表头标签
                table_widget.setHorizontalHeaderLabels(column_list)
                # 设置水平方向表格为自适应的伸缩模式
                #table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
                # 将表格变为禁止编辑
                table_widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
                # 表格头的显示与隐藏
                table_widget.verticalHeader().setVisible(False)
                table_widget.horizontalHeader().setStyleSheet('font-family : Times New Roman;font:20px;')

                row_num = 0
                row_index = 0
                for list_elem in self.tactics['Enterprise'][name][key]:
                    column_index = 0
                    row_index += 1
                    for list_key in list_elem:
                        table_widget.setRowCount(row_index)

                        item_text = list_elem[list_key]
                        tmp_text_list = []
                        while 1:
                            if len(item_text) > 130:
                                tmp_str = item_text[:130]
                                while 1:
                                    if tmp_str[-1] == ' ':
                                        break
                                    else:
                                        tmp_str = tmp_str[:-1]

                                item_text = item_text[len(tmp_str):]

                                tmp_text_list.append(tmp_str + '\n')
                                row_count += 1.3
                            else:
                                tmp_text_list.append(item_text)
                                row_count += 1.3
                                break

                        item_text = ""
                        for elem in tmp_text_list:
                            item_text += elem

                        new_item=QTableWidgetItem(item_text)
                        new_item.setFont(QFont('Times New Roman',13))
                        # new_item.setTextAlignment(Qt.AlignCenter)
                        table_widget.setItem(row_index - 1, column_index, new_item)

                        column_index += 1
                        row_num += 1


                QTableWidget.resizeColumnsToContents(table_widget)
                QTableWidget.resizeRowsToContents(table_widget)
                row_num += 2 # HorisonHeader
                table_widget.setMinimumSize(1400,row_num * 13)
                layout.addRow(table_widget,QLabel())

        # Detected Event
        key_label = QLabel('\nDetected Event')
        key_label.setStyleSheet('font:30px;'
            #'font-family : Times New Roman'
            'text-align : center;' 
            'padding: 0px;'
            'font-weight: bold;')
        layout.addRow(key_label,QLabel())

        self.tac_tech_events[name]['Table'].tac_name = name
        self.tac_tech_events[name]['Table'].tech_name = ""
        self.tac_tech_events[name]['Table'].itemClicked.connect(self.event_item_clicked)
        QTableWidget.resizeColumnsToContents(self.tac_tech_events[name]['Table'])
        QTableWidget.resizeRowsToContents(self.tac_tech_events[name]['Table'])
        self.tac_tech_events[name]['Table'].setMinimumSize(1400, (self.tac_tech_events[name]['Table'].rowCount() + 2) * 13)
        layout.addRow(self.tac_tech_events[name]['Table'],QLabel())

        row_count += self.tac_tech_events[name]['Table'].rowCount()
                
        topFiller.setLayout(layout)
        topFiller.setMinimumSize(1530, row_count * 20)#######设置滚动条的尺寸


        self.addTab(tab, 'Tactics - ' + name)
        self.setCurrentWidget(tab)

        vbox = QVBoxLayout()
        vbox.addWidget(scroll)
        tab.setLayout(vbox)

    #创建techniques tab
    def create_tech_tab(self, name, tact=None, domain_name=None):
        tab = QWidget()
        #####

        topFiller = QWidget()

        scroll = QScrollArea()
        scroll.setStyleSheet('background-color: rgb(252, 252, 252);')
        scroll.setWidget(topFiller)

        layout = QFormLayout()

        row_count = 0

        domain = None
        if domain_name == None:
            domain = 'Enterprise'
        else:
            domain = domain_name

        for key in self.techniques[domain][name]:
            if type(self.techniques[domain][name][key]) != type([]):
                key_label = QLabel(key)
                key_label.setStyleSheet('font:30px;'
                    #'font-family : Times New Roman'
                    'padding: 0px;'
                    'font-weight: bold;')

                layout.addRow(key_label,QLabel())
                row_count += 3

                descript_str = self.techniques[domain][name][key]

                while 1:
                    if len(descript_str) > 150:
                        tmp_str = descript_str[:150]
                        while 1:
                            if tmp_str[-1] == ' ':
                                break
                            else:
                                tmp_str = tmp_str[:-1]

                        descript_str = descript_str[len(tmp_str):]

                        descript_label = QLabel('   ' + tmp_str)
                        descript_label.setStyleSheet('font:20px;padding: 0px;font-family : Times New Roman;')
                        layout.addRow(descript_label,QLabel())
                        row_count += 2
                    else:
                        descript_label = QLabel('   ' + descript_str + '\n')
                        descript_label.setStyleSheet('font:20px;padding: 0px;font-family : Times New Roman;')
                        layout.addRow(descript_label,QLabel())
                        row_count += 2
                        break

            else:
                
                key_label = QLabel(key)
                key_label.setStyleSheet('font:30px;'
                    #'font-family : Times New Roman'
                    'text-align : center;' 
                    'padding: 0px;'
                    'font-weight: bold;')
                layout.addRow(key_label,QLabel())

                column_count = 0
                column_list = []
                for list_elem in self.techniques[domain][name][key]:
                    for list_key in list_elem:
                        column_list.append(list_key)
                        column_count += 1
                    break

                table_widget = QTableWidget(10,column_count)
                table_widget.itemClicked.connect(self.tech_item_clicked)
                # 去掉边框线
                table_widget.setFrameShape(QFrame.NoFrame);
                # 设置表格整行选中
                table_widget.setSelectionBehavior(QAbstractItemView.SelectRows)
                # 设置垂直方向的表头标签
                table_widget.setHorizontalHeaderLabels(column_list)
                # 设置水平方向表格为自适应的伸缩模式
                #table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
                # 将表格变为禁止编辑
                table_widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
                # 表格头的显示与隐藏
                table_widget.verticalHeader().setVisible(False)
                table_widget.horizontalHeader().setStyleSheet('font-family : Times New Roman;font:20px;')

                row_num = 0
                row_index = 0
                for list_elem in self.techniques[domain][name][key]:
                    column_index = 0
                    row_index += 1
                    for list_key in list_elem:
                        table_widget.setRowCount(row_index)

                        item_text = list_elem[list_key]
                        tmp_text_list = []
                        while 1:
                            if len(item_text) > 130:
                                tmp_str = item_text[:130]
                                while 1:
                                    if tmp_str[-1] == ' ':
                                        break
                                    else:
                                        tmp_str = tmp_str[:-1]

                                item_text = item_text[len(tmp_str):]

                                tmp_text_list.append(tmp_str + '\n')
                                row_count += 1.3
                            else:
                                tmp_text_list.append(item_text)
                                row_count += 1.3
                                break

                        item_text = ""
                        for elem in tmp_text_list:
                            item_text += elem

                        new_item=QTableWidgetItem(item_text)
                        new_item.setFont(QFont('Times New Roman',13))
                        # new_item.setTextAlignment(Qt.AlignCenter)
                        table_widget.setItem(row_index - 1, column_index, new_item)

                        column_index += 1
                        row_num += 1


                QTableWidget.resizeColumnsToContents(table_widget)
                QTableWidget.resizeRowsToContents(table_widget)
                row_num += 2 # HorisonHeader
                table_widget.setMinimumSize(1400,row_num * 13)
                layout.addRow(table_widget,QLabel())

        if domain == 'Enterprise':
            # Detected Event
            key_label = QLabel('\nDetected Event')
            key_label.setStyleSheet('font:30px;'
                #'font-family : Times New Roman'
                'text-align : center;' 
                'padding: 0px;'
                'font-weight: bold;')
            layout.addRow(key_label,QLabel())

            tac_name = ''
            if tact != None:
                tac_name = tact
            else:
                tac_name = self.techniques[domain][name]['Tactic']
                if ',' in tac_name:
                    tac_name = tac_name.split(',')[0]

            if tac_name == 'Command And Control':
                tac_name = 'Command and Control'

            self.tac_tech_events[tac_name][name]['Table'].tac_name = tac_name
            self.tac_tech_events[tac_name][name]['Table'].tech_name = name
            self.tac_tech_events[tac_name][name]['Table'].itemClicked.connect(self.event_item_clicked)

            QTableWidget.resizeColumnsToContents(self.tac_tech_events[tac_name][name]['Table'])
            QTableWidget.resizeRowsToContents(self.tac_tech_events[tac_name][name]['Table'])
            self.tac_tech_events[tac_name][name]['Table'].setMinimumSize(1400,(self.tac_tech_events[tac_name][name]['Table'].rowCount() + 2) * 13)
            layout.addRow(self.tac_tech_events[tac_name][name]['Table'],QLabel())

            row_count += self.tac_tech_events[tac_name][name]['Table'].rowCount()
                
        topFiller.setLayout(layout)
        topFiller.setMinimumSize(1530, row_count * 20)#######设置滚动条的尺寸


        self.addTab(tab, 'Techniques - ' + name)
        self.setCurrentWidget(tab)

        vbox = QVBoxLayout()
        vbox.addWidget(scroll)
        tab.setLayout(vbox)

    #创建Groups tab
    def create_group_tab(self, name):
        tab = QWidget()
        #####

        topFiller = QWidget()

        scroll = QScrollArea()
        scroll.setStyleSheet('background-color: rgb(252, 252, 252);')
        scroll.setWidget(topFiller)

        layout = QFormLayout()

        row_count = 0

        for key in self.groups[name]:
            if type(self.groups[name][key]) != type([]):
                key_label = QLabel(key)
                key_label.setStyleSheet('font:30px;'
                    #'font-family : Times New Roman'
                    'padding: 0px;'
                    'font-weight: bold;')

                layout.addRow(key_label,QLabel())
                row_count += 3

                descript_str = self.groups[name][key]

                while 1:
                    if len(descript_str) > 150:
                        tmp_str = descript_str[:150]
                        while 1:
                            if tmp_str[-1] == ' ':
                                break
                            else:
                                tmp_str = tmp_str[:-1]

                        descript_str = descript_str[len(tmp_str):]

                        descript_label = QLabel('   ' + tmp_str)
                        descript_label.setStyleSheet('font:20px;padding: 0px;font-family : Times New Roman;')
                        layout.addRow(descript_label,QLabel())
                        row_count += 2
                    else:
                        descript_label = QLabel('   ' + descript_str + '\n')
                        descript_label.setStyleSheet('font:20px;padding: 0px;font-family : Times New Roman;')
                        layout.addRow(descript_label,QLabel())
                        row_count += 2
                        break

            else:
                
                key_label = QLabel(key)
                key_label.setStyleSheet('font:30px;'
                    #'font-family : Times New Roman'
                    'text-align : center;' 
                    'padding: 0px;'
                    'font-weight: bold;')
                layout.addRow(key_label,QLabel())

                column_count = 0
                column_list = []
                for list_elem in self.groups[name][key]:
                    for list_key in list_elem:
                        column_list.append(list_key)
                        column_count += 1
                    break

                table_widget = QTableWidget(10,column_count)
                table_widget.itemClicked.connect(self.group_item_clicked)
                # 去掉边框线
                table_widget.setFrameShape(QFrame.NoFrame);
                # 设置表格整行选中
                table_widget.setSelectionBehavior(QAbstractItemView.SelectRows)
                # 设置垂直方向的表头标签
                table_widget.setHorizontalHeaderLabels(column_list)
                # 设置水平方向表格为自适应的伸缩模式
                #table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
                # 将表格变为禁止编辑
                table_widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
                # 表格头的显示与隐藏
                table_widget.verticalHeader().setVisible(False)
                table_widget.horizontalHeader().setStyleSheet('font-family : Times New Roman;font:20px;')

                row_num = 0
                row_index = 0
                for list_elem in self.groups[name][key]:
                    column_index = 0
                    row_index += 1
                    for list_key in list_elem:
                        table_widget.setRowCount(row_index)

                        item_text = list_elem[list_key]
                        tmp_text_list = []
                        while 1:
                            if len(item_text) > 130:
                                tmp_str = item_text[:130]
                                while 1:
                                    if tmp_str[-1] == ' ':
                                        break
                                    else:
                                        tmp_str = tmp_str[:-1]

                                item_text = item_text[len(tmp_str):]

                                tmp_text_list.append(tmp_str + '\n')
                                row_count += 1.3
                            else:
                                tmp_text_list.append(item_text)
                                row_count += 1.3
                                break

                        item_text = ""
                        for elem in tmp_text_list:
                            item_text += elem

                        new_item=QTableWidgetItem(item_text)
                        new_item.setFont(QFont('Times New Roman',13))
                        # new_item.setTextAlignment(Qt.AlignCenter)
                        table_widget.setItem(row_index - 1, column_index, new_item)

                        column_index += 1
                        row_num += 1


                QTableWidget.resizeColumnsToContents(table_widget)
                QTableWidget.resizeRowsToContents(table_widget)
                row_num += 2 # HorisonHeader
                table_widget.setMinimumSize(1400,row_num * 13)
                layout.addRow(table_widget,QLabel())

        '''

        # Detected Event
        key_label = QLabel('\nDetected Event')
        key_label.setStyleSheet('font:30px;'
            #'font-family : Times New Roman'
            'text-align : center;' 
            'padding: 0px;'
            'font-weight: bold;')
        layout.addRow(key_label,QLabel())

        QTableWidget.resizeColumnsToContents(table_widget)
        QTableWidget.resizeRowsToContents(table_widget)
        # self.group_detected.setMinimumSize(1400,200)
        # layout.addRow(self.group_detected,QLabel())

        '''
                
        topFiller.setLayout(layout)
        topFiller.setMinimumSize(1530, row_count * 20)#######设置滚动条的尺寸


        self.addTab(tab, 'Groups - ' + name)
        self.setCurrentWidget(tab)

        vbox = QVBoxLayout()
        vbox.addWidget(scroll)
        tab.setLayout(vbox)

    #创建Softwares tab
    def create_sw_tab(self, name):
        tab = QWidget()
        #####

        topFiller = QWidget()

        scroll = QScrollArea()
        scroll.setStyleSheet('background-color: rgb(252, 252, 252);')
        scroll.setWidget(topFiller)

        layout = QFormLayout()

        row_count = 0

        for key in self.softwares[name]:
            if type(self.softwares[name][key]) != type([]):
                key_label = QLabel(key)
                key_label.setStyleSheet('font:30px;'
                    #'font-family : Times New Roman'
                    'padding: 0px;'
                    'font-weight: bold;')

                layout.addRow(key_label,QLabel())
                row_count += 3

                descript_str = self.softwares[name][key]

                while 1:
                    if len(descript_str) > 150:
                        tmp_str = descript_str[:150]
                        while 1:
                            if tmp_str[-1] == ' ':
                                break
                            else:
                                tmp_str = tmp_str[:-1]

                        descript_str = descript_str[len(tmp_str):]

                        descript_label = QLabel('   ' + tmp_str)
                        descript_label.setStyleSheet('font:20px;padding: 0px;font-family : Times New Roman;')
                        layout.addRow(descript_label,QLabel())
                        row_count += 2
                    else:
                        descript_label = QLabel('   ' + descript_str + '\n')
                        descript_label.setStyleSheet('font:20px;padding: 0px;font-family : Times New Roman;')
                        layout.addRow(descript_label,QLabel())
                        row_count += 2
                        break

            else:
                
                key_label = QLabel(key)
                key_label.setStyleSheet('font:30px;'
                    #'font-family : Times New Roman'
                    'text-align : center;' 
                    'padding: 0px;'
                    'font-weight: bold;')
                layout.addRow(key_label,QLabel())

                column_count = 0
                column_list = []
                for list_elem in self.softwares[name][key]:
                    if type(list_elem) == type(""):
                        column_count = 1
                        column_list = ['Name']
                    else:
                        for list_key in list_elem:
                            column_list.append(list_key)
                            column_count += 1
                    break

                table_widget = QTableWidget(1,column_count)
                table_widget.itemClicked.connect(self.sw_item_clicked)
                # 去掉边框线
                table_widget.setFrameShape(QFrame.NoFrame);
                # 设置表格整行选中
                table_widget.setSelectionBehavior(QAbstractItemView.SelectRows)
                # 设置垂直方向的表头标签
                table_widget.setHorizontalHeaderLabels(column_list)
                # 设置水平方向表格为自适应的伸缩模式
                #table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
                # 将表格变为禁止编辑
                table_widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
                # 表格头的显示与隐藏
                table_widget.verticalHeader().setVisible(False)
                table_widget.horizontalHeader().setStyleSheet('font-family : Times New Roman;font:20px;')

                row_num = 0
                row_index = 0
                for list_elem in self.softwares[name][key]:
                    column_index = 0
                    row_index += 1
                    if type(list_elem) == type(""):
                        new_item=QTableWidgetItem(list_elem)
                        new_item.setFont(QFont('Times New Roman',13))
                        new_item.setTextAlignment(Qt.AlignCenter)
                        table_widget.setItem(row_index - 1, column_index, new_item)
                        row_count += 1.3
                    else:
                        for list_key in list_elem:
                            table_widget.setRowCount(row_index)

                            item_text = list_elem[list_key]
                            tmp_text_list = []
                            while 1:
                                if len(item_text) > 130:
                                    tmp_str = item_text[:130]
                                    while 1:
                                        if tmp_str[-1] == ' ':
                                            break
                                        else:
                                            tmp_str = tmp_str[:-1]

                                    item_text = item_text[len(tmp_str):]

                                    tmp_text_list.append(tmp_str + '\n')
                                    row_count += 1.3
                                else:
                                    tmp_text_list.append(item_text)
                                    row_count += 1.3
                                    break

                            item_text = ""
                            for elem in tmp_text_list:
                                item_text += elem

                            new_item=QTableWidgetItem(item_text)
                            new_item.setFont(QFont('Times New Roman',13))
                            table_widget.setItem(row_index - 1, column_index, new_item)

                            column_index += 1
                            row_num += 1


                QTableWidget.resizeColumnsToContents(table_widget)
                QTableWidget.resizeRowsToContents(table_widget)
                row_num += 2 # HorisonHeader
                table_widget.setMinimumSize(1400,row_num * 13)
                layout.addRow(table_widget,QLabel())
                
        topFiller.setLayout(layout)
        topFiller.setMinimumSize(1530, row_count * 20)#######设置滚动条的尺寸


        self.addTab(tab, 'softwares - ' + name)
        self.setCurrentWidget(tab)

        vbox = QVBoxLayout()
        vbox.addWidget(scroll)
        tab.setLayout(vbox)

    #创建Event tab
    def create_event_tab(self, event_id, tac_name, tech_name, car_id, car_name):
        tab = QWidget()
        #####

        topFiller = QWidget()

        scroll = QScrollArea()
        scroll.setStyleSheet('background-color: rgb(252, 252, 252);')
        scroll.setWidget(topFiller)

        layout = QFormLayout()

        row_count = 0

        # TODO ######################################################################
        # TODO ######################################################################

        key_label = QLabel('CAR-ID')
        key_label.setStyleSheet('font:30px;'
                    #'font-family : Times New Roman'
                    'text-align : center;' 
                    'padding: 0px;'
                    'font-weight: bold;')
        layout.addRow(key_label,QLabel())

        row_count += 3

        descript_label = QLabel('   ' + car_id + '\n')
        descript_label.setStyleSheet('font:20px;padding: 0px;font-family : Times New Roman;')
        layout.addRow(descript_label,QLabel())

        row_count += 2

        key_label = QLabel('CAR-NAME')
        key_label.setStyleSheet('font:30px;'
                    #'font-family : Times New Roman'
                    'text-align : center;' 
                    'padding: 0px;'
                    'font-weight: bold;')
        layout.addRow(key_label,QLabel())

        row_count += 3

        descript_label = QLabel('   ' + car_name + '\n')
        descript_label.setStyleSheet('font:20px;padding: 0px;font-family : Times New Roman;')
        layout.addRow(descript_label,QLabel())

        row_count += 2

        event_list = []
        if tac_name == "":
            # Home Detected Events
            event_list = self.home_detected_events[event_id][car_id]['Event']
        elif tech_name == "":
            # Tactics Detected Events
            event_list = self.tac_tech_events[tac_name]['Events'][event_id][car_id]['Event']
        else:
            # Techniques Detected Events
            event_list = self.tac_tech_events[tac_name][tech_name]['Events'][event_id][car_id]['Event']

        # Create Table

        for evt in event_list:

            # Event Label

            key_label = QLabel('Event - ' + evt['Event']['System']['EventRecordID'])
            key_label.setStyleSheet('font:30px;'
                        #'font-family : Times New Roman'
                        'text-align : center;' 
                        'padding: 0px;'
                        'font-weight: bold;')
            layout.addRow(key_label,QLabel())
            row_count += 3

            # Table

            table_widget = QTableWidget(0, 2)
            # 去掉边框线
            table_widget.setFrameShape(QFrame.NoFrame);
            # 设置表格整行选中
            table_widget.setSelectionBehavior(QAbstractItemView.SelectRows)
            # 设置垂直方向的表头标签
            table_widget.setHorizontalHeaderLabels(['Name', 'Value'])
            # 设置水平方向表格为自适应的伸缩模式
            #table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
            # 将表格变为禁止编辑
            table_widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
            # 表格头的显示与隐藏
            table_widget.verticalHeader().setVisible(False)
            table_widget.horizontalHeader().setStyleSheet('font-family : Times New Roman;font:20px;')


            system_dict = evt['Event']['System']
            data_dict = evt['Event']['EventData']

            row_index = 0

            table_widget.setRowCount(row_index + 1)
            new_item=QTableWidgetItem('System')
            new_item.setFont(QFont('Times New Roman',20))
            table_widget.setItem(row_index, 0, new_item)

            # System Attribute

            for key_name in system_dict:
                row_index += 1
                table_widget.setRowCount(row_index + 1)

                # Key
                new_item=QTableWidgetItem(key_name)
                new_item.setFont(QFont('Times New Roman',13))
                table_widget.setItem(row_index, 0, new_item)

                if type(system_dict[key_name]) == type(""):

                    # Value
                    value_text = self.arrange_string(str(system_dict[key_name]), 100)
                    row_count += (value_text[1] - 1) * 1.3
                    new_item=QTableWidgetItem(value_text[0])
                    new_item.setFont(QFont('Times New Roman',13))
                    new_item.setTextAlignment(Qt.AlignCenter)
                    table_widget.setItem(row_index, 1, new_item)

                elif system_dict[key_name] == None:
                    # Value
                    new_item=QTableWidgetItem("")
                    new_item.setFont(QFont('Times New Roman',13))
                    new_item.setTextAlignment(Qt.AlignCenter)
                    table_widget.setItem(row_index, 1, new_item)
                else:

                    for key_name2 in system_dict[key_name]:

                        row_index += 1
                        table_widget.setRowCount(row_index + 1)

                        # Key
                        new_item=QTableWidgetItem('ㄴ' + key_name2)
                        new_item.setFont(QFont('Times New Roman',13))
                        table_widget.setItem(row_index, 0, new_item)

                        # Value
                        value_text = self.arrange_string(str(system_dict[key_name][key_name2]), 100)
                        row_count += (value_text[1] - 1) * 1.3
                        new_item=QTableWidgetItem(value_text[0])
                        new_item.setFont(QFont('Times New Roman',13))
                        new_item.setTextAlignment(Qt.AlignCenter)
                        table_widget.setItem(row_index, 1, new_item)

            # EventData Attributec

            row_index += 1
            table_widget.setRowCount(row_index + 1)
            new_item=QTableWidgetItem('Data')
            new_item.setFont(QFont('Times New Roman',20))
            table_widget.setItem(row_index, 0, new_item)

            for key_name in data_dict:

                row_index += 1
                table_widget.setRowCount(row_index + 1)

                # Key
                new_item=QTableWidgetItem(key_name)
                new_item.setFont(QFont('Times New Roman',13))
                table_widget.setItem(row_index, 0, new_item)

                if type(data_dict[key_name]) == type(""):

                    # Value
                    value_text = self.arrange_string(str(data_dict[key_name]), 100)
                    row_count += (value_text[1] - 1) * 1.3
                    new_item=QTableWidgetItem(value_text[0])
                    new_item.setFont(QFont('Times New Roman',13))
                    new_item.setTextAlignment(Qt.AlignCenter)
                    table_widget.setItem(row_index, 1, new_item)
                elif data_dict[key_name] == None:
                    # Value
                    new_item=QTableWidgetItem("")
                    new_item.setFont(QFont('Times New Roman',13))
                    new_item.setTextAlignment(Qt.AlignCenter)
                    table_widget.setItem(row_index, 1, new_item)
                else:
                    print('없을텐데..?')
                    print(data_dict[key_name])
                    '''
                    row_index += 1
                    table_widget.setRowCount(row_index + 1)

                    # Key
                    new_item=QTableWidgetItem('ㄴ' + key_name)
                    new_item.setFont(QFont('Times New Roman',13))
                    new_item.setTextAlignment(Qt.AlignCenter)
                    table_widget.setItem(row_index, 0, new_item)

                    for key_name2 in data_dict[key_name]:

                        row_index += 1
                        table_widget.setRowCount(row_index + 1)

                        # Key
                        new_item=QTableWidgetItem('ㄴㄴ' + key_name2)
                        new_item.setFont(QFont('Times New Roman',13))
                        new_item.setTextAlignment(Qt.AlignCenter)
                        table_widget.setItem(row_index, 0, new_item)

                        # Value
                        new_item=QTableWidgetItem(str(data_dict[key_name][key_name2]))
                        new_item.setFont(QFont('Times New Roman',13))
                        new_item.setTextAlignment(Qt.AlignCenter)
                        table_widget.setItem(row_index, 1, new_item)
                        '''

            QTableWidget.resizeColumnsToContents(table_widget)
            QTableWidget.resizeRowsToContents(table_widget)
            row_index += 2 # HorisonHeader
            table_widget.setMinimumSize(1400,row_index * 25)
            layout.addRow(table_widget,QLabel())

            row_count += row_index * 1.3

            layout.addRow(QLabel(),QLabel())

        # TODO ######################################################################
        # TODO ######################################################################
                
        topFiller.setLayout(layout)
        topFiller.setMinimumSize(1530, row_count * 20)#######设置滚动条的尺寸


        self.addTab(tab, 'Events - ' + event_id)
        self.setCurrentWidget(tab)

        vbox = QVBoxLayout()
        vbox.addWidget(scroll)
        tab.setLayout(vbox)

    def tac_item_clicked(self, item):
        # 获取父类
        parent = item.tableWidget()
        tec_name = parent.item(item.row(), 1).text()
        self.create_tech_tab(tec_name, parent.name)

    def tech_item_clicked(self, item):
        # 获取父类
        parent = item.tableWidget()
        name = parent.item(item.row(), 0).text()
        try:
            self.create_group_tab(name)
        except:
            self.create_sw_tab(name)

    def group_item_clicked(self, item):
        # 获取父类
        parent = item.tableWidget()
        if parent.columnCount() == 4:
            name = parent.item(item.row(), 2).text()
            domain = parent.item(item.row(), 0).text()
            self.create_tech_tab(name, None, domain)
        else:
            name = parent.item(item.row(), 1).text()
            self.create_sw_tab(name)

    def sw_item_clicked(self, item):
        # 获取父类
        parent = item.tableWidget()
        
        if parent.columnCount() == 4:
            name = parent.item(item.row(), 2).text()
            domain = parent.item(item.row(), 0).text()
            self.create_tech_tab(name, None, domain)
        else:
            name = parent.item(item.row(), 0).text()
            self.create_group_tab(name)

    def predict_item_clicked(self, item):
        # 获取父类
        parent = item.tableWidget()
        group_or_sw_name = parent.item(item.row(), 0).text()
        if group_or_sw_name in self.groups:
            self.create_group_tab(group_or_sw_name)
        else:
            self.create_sw_tab(group_or_sw_name)

    def event_item_clicked(self, item):
        # 获取父类
        parent = item.tableWidget()
        event_id = parent.item(item.row(), 1).text()
        car_id = parent.item(item.row(), 2).text()
        car_name= parent.item(item.row(), 3).text()
        tac_name = parent.tac_name
        tech_name = parent.tech_name
        self.create_event_tab(event_id, tac_name, tech_name, car_id, car_name)

    def arrange_string(self, arr, split_len):
        result_str = ""
        row_count = 0
        while 1:
            if len(arr) == 0 or len(arr) <= split_len:
                result_str += arr
                row_count += 1
                break
            else:
                tmp_str = arr[:split_len]
                while 1:
                    if tmp_str == '':
                        tmp_str = arr[:split_len]
                        break
                    elif tmp_str[-1] == ' ':
                        break
                    else:
                        tmp_str = tmp_str[:-1]

                arr = arr[len(tmp_str):]
                result_str += tmp_str + '\n'
                row_count += 1

        return (result_str, row_count)

 
if __name__ == "__main__":
    get_last_30_days_history()

    app = QApplication(sys.argv)
    mainwindow = MainWindow()
    mainwindow.show()

    sm_evt = Sysmon_evt(mainwindow)
    sm_evt.start()

    sys_evt = System_evt(mainwindow)
    sys_evt.start()

    sec_evt = Security_evt(mainwindow)
    sec_evt.start()

    # print("Quit \'q\' :")
    # q = input()
    # if q == 'q':
    #    os._exit(0)

    sys.exit(app.exec_())

# 내가 추가한것 1 : powershell 명령어 log에 저장시킨거 / quick_~~ 어쩌구 에서 powershell을 이용해서 Invoke-Mimikatz를 사용하면 mimikatz는 안떠서 이 분석결과가 안뜰수있음
# -> 그래서 powershell 명령어 log 확인해서 Invoke-Mimikatz 이런게 있는걸 발견하면 Quick ~ 어쩌구에서 연관시켜서 탐지 가능!
# 내가 추가한것 2 : whoami 같은건 Quick~ 에서 의심가는 리스트에 안들어있음. 그래서 이런게 발생했을때 parentProcess가 Powershell이면 똑같이 명령어 log 확인해보기!
# -> 만약에 정말로 Invoke-Mimikatz 같은게 있으면 확실하게 저런 명령을 썼다는걸 알수있음!
# 내가 추가한것 3 : psexec.exe 같은것에 대해서도 모니터링 추가해야함!

# 내가 추가한것 4 : CAR 에 나와있는 테크닉-전술 세트가 맞지 않을때가 있음... Service Execution 이거는 Execution 밖에 없는데 다른 Persistence나 이상한게 같이 세트로 있을때가 있음..
# 내가 추가한것 5 : CALDERA를 통한 공격에는 CommandLine이 제대로 남지 않음! 그래서 스크립트 어떤걸 사용했는지 파악 불가!
                 # 그래서 powershell-log 를 바탕화면에 남겨서 거기서 확인할꺼임!
                 # 원래 evt_id가 1일때 판단하는거였지만 내가 5로 바꿔서 판단했음!
                 # Powershell 관련 이벤트들은 Powershell이 끝나고 나서야 모든 CommandLine을 얻을 수 있기때문에 5로 확인해야됨.