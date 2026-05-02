# Tips

### ***Return every command starting by Test***
```
Get-Command | select-string test
```

### ***Get command information, i.e: Test-NetConnection***

```
Get-Help Test-NeConnection
```

### ***Returning network domain status***
```
Test-NetConnection www.google.com
```

### ***Tracing route***
```
Test-NetConnection www.google.com -TraceRoute
```

### ***Checking open port***
```
Test-NetConnection www.google.com -Port 80
```

### ***Silence Warning***
```
Test-NetConnection www.google.com -Port 81 -WarningAction SilentlyContinue -InformationLevel Quiet
```
