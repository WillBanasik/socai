// Web Shell Stage 1 — Web-server process spawning a shell / LOLBin.
// A web server (w3wp/httpd/nginx/tomcat/java/php/node) spawning cmd/powershell/etc is
//   the classic web-shell execution signal — detected here via ProcessRollup2 ancestry.
#event_simpleName=ProcessRollup2
| ComputerName = /{{device_name}}/i
| ParentBaseFileName = /^(w3wp|httpd|nginx|tomcat|tomcat9|java|php-cgi|php|node)\.exe$/i
| FileName = /^(cmd|powershell|pwsh|bash|sh|wscript|cscript|net|whoami|certutil|bitsadmin)\.exe$/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName,
         CommandLine, ParentCommandLine], limit=200)
| sort(@timestamp, order=asc, limit=200)
