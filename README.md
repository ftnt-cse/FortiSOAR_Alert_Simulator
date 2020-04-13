# FortiSOAR Alert Simulator:
## Introduction:
A tool meant to be used during demos to simulate a SOAR environement by sending a series of alerts with a specific timing according to a template. this creates a scenario to illustrate targeted FortiSOAR capabilities.
it is meant to run on FortiSOAR to simulates an Asset network (Defined in the topology pptx) connected to the internet via FortiGate Firewall (FortiGate-Edge) and a set of alert sources including:
-FortiSIEM
-Qradar
-Others to come
The Environement requires a FortiGate to be used as a response enforcement point.

## Components:

- Main script: The main cli
- Modules Directory: Contain various functions libraries
- Templates Directory: Contains the available templates to be used during the demo, each template file represents a scenario. it is a list of dictionary objects.

### Templates:
A sample template structure:
```json
[
{
"data":[
		{
		"sleep":-1,
		"name": "Traffic to FortiGuard Malware IP List",
		"source":"FSM-INTL-DEMO",
		"sourcedata":{
			 	"incident": {
						"id": 8119518313,
						"xmlId": "Incident@000000000",
						"ruleDesc": "Detects network traffic to FortiGuard Blocked IP List",
						"ruleName": "Traffic to FortiGuard Malware IP List",
						"severity": 9,
						"origDevIp": "{{TR_FG_MGMT_IP}}",
						"srcIpAddr": "{{TR_ASSET_IP}}1",
						"cacheIndex": "<phCustId>2002</phCustId>",
						"destIpAddr": "{{TR_MALICIOUS_IP}}",
						"externalId": 8179,
						"incidentEt": "PH_RULE_TO_FORTIGUARD_MALWARE_IP",
						"origDevName": "{{TR_FG_DEV_NAME}}",
						"severityCat": "HIGH",
						"creationTime": "{{TR_NOW}}",
						"deviceStatus": "Pending",
						"lastModified": "{{TR_NOW}}",
						"lastSeenTime": "{{TR_NOW}}",
						"ticketStatus": "None",
						"firstSeenTime": "{{TR_PAST}}",
						"incidentCount": "{{TR_RANDOM_INTEGER}}",
						"incidentTarget": "destIpAddr:,",
						"incidentCategory": "Security/Command and Control",
						"phIncidentCategory": "Network",
						}
				}
		}
	]
},
{
"data":[
		{
		"sleep":0,
		"name": "Traffic to FortiGuard Malware IP List",
		"source":"FSM-INTL-DEMO",
		"sourcedata":{
			 	"incident": {
						"id": 8119518313,
						"xmlId": "Incident@000000000",
						"ruleDesc": "Detects network traffic to FortiGuard Blocked IP List",
						"ruleName": "Traffic to FortiGuard Malware IP List",
						"severity": 9,
						"origDevIp": "{{TR_FG_MGMT_IP}}",
						"srcIpAddr": "{{TR_ASSET_IP}}2",
						"cacheIndex": "<phCustId>2002</phCustId>",
						"destIpAddr": "{{TR_MALICIOUS_IP}}",
						"externalId": 8179,
						"incidentEt": "PH_RULE_TO_FORTIGUARD_MALWARE_IP",
						"origDevName": "{{TR_FG_DEV_NAME}}",
						"severityCat": "HIGH",
						"creationTime": "{{TR_NOW}}",
						"deviceStatus": "Pending",
						"lastModified": "{{TR_NOW}}",
						"lastSeenTime": "{{TR_NOW}}",
						"ticketStatus": "None",
						"firstSeenTime": "{{TR_PAST}}",
						"incidentCount": "{{TR_RANDOM_INTEGER}}",
						"incidentTarget": "destIpAddr:,",
						"incidentCategory": "Security/Command and Control",
						"phIncidentCategory": "Network",
						}
				}
		}
	]
}
]
```
- __"sleep":__ can take the values : 
- 0 => the alert will be sent immediatly 
- a negative integet => The user will be prompted to press any key to send the alert and continue to the next one
- a positive integer => would indicate the number of seconds to wait before sending the current alert

 Template file contains the static text as sent from the alert source device and a set of variables delimited with {{}}.

All variables will be replaced with their dynamic value at runtime. when a list of alerts is present within the same template you can manipulate variable values by statically concatenating values, example : 

If {{TR_ASSET_IP}} is present in both alerts of the same template it's possible to set the first as: {{TR_ASSET_IP}}1 and {{TR_ASSET_IP}}2 in the second, so the sent alert will have 2 values of {{TR_ASSET_IP}}

The list of available dynamic values (Variables):
|"VARIABLE"|function name|use case|
|:----------|:-------------|:-------------|
|"TR_FG_MGMT_IP"|get_fg_mgmt_ip|get fortigate mgmt IP (according to the topology file)|
|"TR_FG_DEV_NAME"|get_fg_dev_name|get fortigate device name (according to the topology file)|
|"TR_ASSET_IP"|get_asset_ip| get a random local IP|
|"TR_MALICIOUS_IP"|get_malicious_ip| get a malicious IP from CTI|
|"TR_NOW"|get_time_now|get current timestamp|
|"TR_RANDOM_INTEGER"|get_random_integer|get random number between 55555 and 99999|
|"TR_MALICIOUS_DOMAIN"|get_malicious_domains| get a malicious domain name from CTI|
|"TR_MALICIOUS_URL"|get_malicious_url|get a malicious url from CTI|
|"TR_MALICIOUS_HASH"|get_malware_hash|get malicious hash from CTI|
|"TR_PUBLIC_IP"|get_my_public_ip|get your public IP address|
|"TR_PAST"|get_time_past |up to a couple of days ago|
|"TR_T-1"|get_time_minus_one |get timestamp of about one hour ago|
|"TR_T-2"|get_time_minus_two |get timestamp of about two hours ago|
|"TR_T-3"|get_time_minus_tree|get timestamp of about three hours ago|
|"TR_T-4"|get_time_minus_four|get timestamp of about four hours ago|
|"TR_T-5"|get_time_minus_five|get timestamp of about five hours ago|
|"TR_T-6"|get_time_minus_six (get timestamp of about six hours ago)
|"TR_USERNAME"|get_username|a random username|
