param($ip)
if(!$ip){
	echo "portscan"
	echo ".\portscan.ps1 192.168.0.1"
} else {
	try{
		foreach ($port in 1..100){
			if (Test-NetConnection $ip -Port $port -WarningAction SilentlyContinue -InformationLevel Quiet) {
				echo "Open Port: $port"
			}
		}
	} catch {
	
	}
}
