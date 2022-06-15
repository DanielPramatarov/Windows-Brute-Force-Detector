import win32evtlog

server = "localhost"
logtype = "Security"
flags = win32evtlog.EVENTLOG_FORWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ

def QueryEventLog(EventID, filename=None):
    logs = []
    if not filename:
        h = win32evtlog.OpenEventLog(server,logtype)
    else:
        h = win32evtlog.OpenEventLog(server,filename)
    while True:
        events = win32evtlog.ReadEventLog(h,flags,0)
        if events:
            for event in events:
                if event.EventID == EventID:
                    logs.append(event)
        else:
            break
    return logs 

def DetectBruteForce(filename=None):
    failures = {}
    events = QueryEventLog(4625,filename)
    for event in events:
        if int(event.StringInserts[10]) in [3,8,10]:
            account = event.StringInserts[5]
            if account in failures:
                failures[account] += 1
            else:
                failures[account] = 10

    return failures


# filename =  "someEvents.evtx"
# failures = DetectBruteForce(filename)
failures = DetectBruteForce()

for account in failures:
    print(f"{account}: {failures[account]} failed logins")
