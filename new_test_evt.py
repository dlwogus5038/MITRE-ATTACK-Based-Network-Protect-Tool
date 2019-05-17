import win32evtlog # requires pywin32 pre-installed
import datetime
import sys
import xmltodict
import threading
import datetime
from dateutil import tz

count = 0

service_outlier_executables_history = {}

outlier_parents_of_cmd_history = {}

# EvtQuery -> EvtNext -> EvtRender

log_list = ["Microsoft-Windows-Sysmon/Operational", "System", "Security"]

def Utc_to_local(evt_utc_time):
    from_zone = tz.tzutc()
    to_zone = tz.tzlocal()

    utc = datetime.datetime.strptime(evt_utc_time[:10] + ' ' + evt_utc_time[11:26], '%Y-%m-%d %H:%M:%S.%f')
    utc = utc.replace(tzinfo=from_zone)

    evt_local_time = utc.astimezone(to_zone)

    return evt_local_time

def new_get():

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
            print(service_outlier_executables_history)
            print(outlier_parents_of_cmd_history)
            break
        for event in events:
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
                print(service_outlier_executables_history)
                print(outlier_parents_of_cmd_history)
                return

            if evt_id == 1:
                image = str(record_dict['Event']['EventData']['Image'])
                parent_image = str(record_dict['Event']['EventData']['ParentImage'])

                if parent_image == "C:\\Windows\\System32\\services.exe":
                    print('image : ' + image)
                    service_outlier_executables_history[image] = 0

                if 'cmd.exe' in image:
                    print('parent_image : ' + parent_image)
                    outlier_parents_of_cmd_history[parent_image] = 0

            #if (count % 100 == 0):
            #    print(count)


new_get()