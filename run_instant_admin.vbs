Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "schtasks /run /tn ""PingTesterAdmin""", 0, False
