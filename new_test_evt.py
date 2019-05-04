import win32evtlog # requires pywin32 pre-installed
import datetime
import sys
import xmltodict
import threading
from datetime import datetime
from dateutil import tz

count = 0

# EvtQuery -> EvtNext -> EvtRender

log_list = ["Microsoft-Windows-Sysmon/Operational", "System", "Security"]

def Utc_to_local(evt_utc_time):
    from_zone = tz.tzutc()
    to_zone = tz.tzlocal()

    utc = datetime.strptime(evt_utc_time[:10] + ' ' + evt_utc_time[11:26], '%Y-%m-%d %H:%M:%S.%f')
    utc = utc.replace(tzinfo=from_zone)

    evt_local_time = utc.astimezone(to_zone)

    return evt_local_time

def new_get():
    global count

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
            # remove parsed events
            # win32evtlog.ClearEventLog(handle, None): Access Violation (0xC0000005)
            break
        for event in events:
            count += 1
            record = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
            ##print(event)

            # xml to dict
            record_dict = xmltodict.parse(record)
            print(record_dict)

            # UTC to Local Time
            evt_local_time = Utc_to_local(record_dict['Event']['System']['TimeCreated']['@SystemTime'])
            record_dict['Event']['System']['TimeCreated']['@SystemTime'] = evt_local_time

            if (count % 100 == 0):
                print(count)


new_get()
