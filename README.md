# FortiSOAR Alert Simulator:
## Introduction:
A tool meant to be used during demos to simulate a SOAR environement by sending a series of alerts with a specific timing according to a template. this creates a scenario to illustrate targeted FortiSOAR capabilities.
it is meant to run on FortiSOAR to simulates an Asset network (Defined in the topology pptx) connected to the internet via FortiGate Firewall (FortiGate-Edge) and a set of alert sources including:
-FortiSIEM
-Qradar
-Others to come
The Environement requires a FortiGate to be used as a response enforcement point.

## Components:
-Main script: The main cli

-Modules Directory: Contain various functions libraries

-Templates Directory: Contains the available templates to be used during the demo, each template file represents a scenario. it is a list of dictionary objects.

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
- -1 => the alert will be sent immediatly 
- 0 => The user will be prompted to press any key to send the alert and continue to the next one
- a positive integer would indicate the number of seconds to wait before sending the current alert

- The template must not contain a duplicate of the dynamic variable, if a source IP for example is used as srcIpAddr, 
so IncidentSrc should be empty. this is to maintain alert consitancy
Template file contains the static text as sent from the alert source device and a set of variables delimited with {{}}. 
- All the variables will be replaced with their dynamic value at runtime. when a list of alerts is present within the same template it's possible to have different variable values
by adding a digit at the end of the variable, example : {{TR_ASSET_IP}} is present in both alerts of the same template and we want its value to be different, 
we can write it as : {{TR_ASSET_IP}}1 in the first alert and {{TR_ASSET_IP}}2 in the second, so whatever value will be taken at runtime it will have 1 and 2 
at its end respectively 
