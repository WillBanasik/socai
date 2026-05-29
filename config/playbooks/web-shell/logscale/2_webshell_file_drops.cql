// Web Shell Stage 2 — Web-shell file drops in web roots.
#event_simpleName=/^(NewScriptWritten|GenericFileWritten|NewExecutableWritten)$/
| ComputerName = /{{device_name}}/i
| TargetFileName = /(inetpub\\wwwroot|\\wwwroot|webapps|htdocs|httpdocs|\\www\\|tomcat|App_Data).*\.(aspx?|ashx|php|jspx?|war|cfm)$/i
| table([@timestamp, ComputerName, UserName, TargetFileName, SHA256HashData], limit=200)
| sort(@timestamp, order=asc, limit=200)
