$site=Read-Host "Inform website "
$web=Invoke-WebRequest -uri "$site" -Method Options
echo "Server headers "
$web.headers.server
echo ""
echo "HTTP headers allowed "
$web.headers.allow
echo ""
echo "Links "
$web2=Invoke-WebRequest -uri "$site"
$web2.links.href | select-string http://
