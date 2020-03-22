#!/usr/bin/env python
# FSR-Simulator is a CLI program to generate FSM like incidents for FSR
# Script simulates an Asset server : 192.168.10.10 connected to the internet via FortiGate Firewall : 192.168.10.254
# The template must not contain a duplicate of the dynamic variable, if a source IP for example is used as srcIpAddr, 
# so IncidentSrc should be empty. this is to maintain alert consitancy
# Template file contains the static text as sent from the alert source device and a set of variables delimited with {{}}. all the variables
# will be replaced with their dynamic value at runtime. when a list of alerts is present within the same template it's possible to have different variable values
# by adding a digit at the end of the variable, example : {{TR_ASSET_IP}} is present in both alerts of the same template and we want its value to be different, 
# we can write it as : {{TR_ASSET_IP}}1 in the first alert and {{TR_ASSET_IP}}2 in the second, so whatever value will be taken at runtime it will have 1 and 2 
# at its end respectively 
# FortiSOAR CSE Team
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND
from simulator_files.artifact_factory import *
from simulator_files.fortisoar_lib import *
from pathlib import Path

import requests, json, argparse, textwrap, random, time, os, csv, string, re
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def cook_alert(incident,malware_hashes_file,malicious_urls_file,malicious_ip_file,malicious_domains_file,is_random=True):
	try:
		with open(incident, 'r') as f:
			template_file = f.read()
		f.close()
		tag_list = re.findall('\{\{(.*?)\}\}',template_file)
		for tag in tag_list:
			template_file=template_file.replace('{{'+tag+'}}',str(function_dictionary[tag]()))
	except IOError:
		print(bcolors.FAIL+"Couldn't open template file: "+incident+bcolors.ENDC)
		exit()

	return json.loads(template_file)

def main():
	tenant_iri=None
	parser = argparse.ArgumentParser(
	prog='ProgramName',
	formatter_class=argparse.RawDescriptionHelpFormatter,
	epilog=textwrap.dedent('''\
		 FSR Alert Simulator
		 '''))
	parser.add_argument('-s', '--server',type=str, required=True, help="FortiSOAR IP Address (wihout http://)")
	parser.add_argument('-u', '--username',type=str, required=True, help="FortiSOAR Username")
	parser.add_argument('-p', '--password',type=str, required=False, default='Rotana@1492',help="FortiSOAR Password")
	parser.add_argument('-i', '--incident_template',type=str, required=True, help="Incident Template file (One of the files under ./templates) exp: ./templates/PH_RULE_AO_MALWARE_HASH_MATCH.json")
	parser.add_argument('-r', '--random',type=str, required=False, default='yes', choices=['yes', 'no'],help='if True, the IoC within the alert will be random')
	parser.add_argument('-t', '--tenant',type=str, required=False, help='Tenant IRI')

	args = parser.parse_args()

	headers=fsr_login(args.server,args.username,args.password)

	if args.random.lower() == 'no':
		is_random=False
	else:
		is_random=True

	alerts=cook_alert(args.incident_template,malware_hashes,malicious_urls,malicious_ips,malicious_domains,is_random)

	if args.tenant:
		tenant_iri=lookup_tenant_iri(args.server,headers,args.tenant)['@id']

	for alert in alerts:
		print(alert)
		fsr_send_alert(args.server,headers,alert,tenant_iri)


if __name__ == '__main__':
	main()
