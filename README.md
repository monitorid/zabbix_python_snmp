# zabbix_python_snmp

**check_dns_server.py** Script to check the availability of server DNS<br/>
**disk_snmp.py** Script for polling Linux Server by SNMP and adding appropriate disks metrics to the Zabbix server

### Requirements
Python 3.8.2<br/>
asyncio<br/>
py-zabbix<br/>
pysnmp<br/>
dnspython<br/>
```
pip install -r requirements.txt
```

#### Options

# Config example (config.json)
```
{
    "zabbix": {
		"url": "http://10.21.0.1:8080",
        "api_token": "8091bd90f0e0fbbf269b58c8672e74d5daad7486984bda7f66bdf4fa3d52f582"
	},
	"pylld":{
		"filter_fs_names": "^(/dev|/sys|/run|/proc|.+/shm$)",
		"posfix": "PyLLD",
		"hostgrp": "PyLLD Python Script"
    },
	"hosts":[ 
		{
			"type": "dns",
			"ip": "10.0.0.1",
			"hostname": "dns-server.local",
			"port": "161",
			"protocol": {
				"version": 3,
				"auth_key": "temp_password",
				"priv_key": "temp_password"
			}
		}
	]
}
```
