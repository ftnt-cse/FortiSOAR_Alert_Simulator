#!/usr/bin/env python
# Main: CLI
# FortiSOAR CSE Team
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND
from simulator_files.artifact_factory import *
from simulator_files.fortisoar_lib import *


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
