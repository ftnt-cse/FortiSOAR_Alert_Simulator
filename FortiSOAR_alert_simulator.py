#!/bin/python3
# FSR-Simulator is a CLI program to generate FSM like incidents for FSR
# Script simulates an Asset server : 192.168.10.10 connected to the internet via FortiGate Firewall : 192.168.10.254
# FortiSOAR CSE Team
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND

from pathlib import Path
#import glob
import requests, json, argparse, textwrap, random, time, os, csv, string
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

templates_path 		= './'
malware_hashes 		= './threat_intelligence/malware_hashes.txt'
malicious_domains	= './threat_intelligence/malicious_domains.txt'
malicious_ips		= './threat_intelligence/malicious_ips.txt'
malicious_urls		= './threat_intelligence/malicious_urls.txt'
usernames=['Sun.Tzu','Albert.Einstein','Isaac.Newton','Leonardo.Da.Vinci','Aristotle','Galileo.Galilei','Alexander.the.Great','Charles.Darwin','Plato','William.Shakespeare','Martin.Luther.Kin','Socrates','Mahatma.Gandhi','Abraham.Lincoln','George.Washington','Mose','Nikola.Tesla','Gautama.Buddha','Julius.Ceasar','Karl.Marx','Martin.Luther','Napoleon.Bonaparte','Johannes.Gutenberg']

class bcolors:
	OKGREEN = '\033[92m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'

def fsr_login(server,username,password):
	body = {
		'credentials': {
			'loginid': username,
			'password': password
		}
	}
	try:
		response = requests.post(
			url='https://'+server+'/auth/authenticate', json=body,
			verify=False
		)
		if response.status_code != 200:
			print(bcolors.FAIL+'Authentication error'+bcolors.ENDC)
			exit()
		json_response = response.json()
		token = json_response['token']
		headers = {"Authorization": "Bearer " + token}
		return headers

	except requests.ConnectionError:
		print(bcolors.FAIL+"Connection error"+bcolors.ENDC)
		exit()
	except requests.ConnectTimeout:
		print(bcolors.FAIL+"Connection timeout"+bcolors.ENDC)
		exit()

def get_malware_hashes(malware_hashes_file,is_random=True):

	if not os.path.exists(os.path.dirname(malware_hashes_file)):
		os.makedirs(os.path.dirname(malware_hashes_file))

	if not os.path.isfile(malware_hashes_file):
		try:
			response = requests.get(url='https://cybercrime-tracker.net/ccamlist.php')
			if response.status_code != 200:
				print(bcolors.FAIL+'TI Download Failed'+bcolors.ENDC)
				exit()
			with open(malware_hashes_file, 'wb') as f:
				f.write(response.content)

		except requests.ConnectionError:
			print(bcolors.FAIL+"Connection error"+bcolors.ENDC)
			exit()
		except requests.ConnectTimeout:
			print(bcolors.FAIL+"Connection timeout"+bcolors.ENDC)
			exit()

	lines = open(malware_hashes_file).read().splitlines()
	if not is_random:
		return lines[0]
	else:
		return(random.choice(lines))


def get_malicious_urls(malicious_urls_file,is_random=True):

	if not os.path.exists(os.path.dirname(malicious_urls_file)):
		os.makedirs(os.path.dirname(malicious_urls_file))

	if not os.path.isfile(malicious_urls_file):
		try:
			response = requests.get(url='https://openphish.com/feed.txt')
			if response.status_code != 200:
				print(bcolors.FAIL+'TI Download Failed'+bcolors.ENDC)
				exit()
			with open(malicious_urls_file, 'wb') as f:
				f.write(response.content)

		except requests.ConnectionError:
			print(bcolors.FAIL+"Connection error"+bcolors.ENDC)
			exit()
		except requests.ConnectTimeout:
			print(bcolors.FAIL+"Connection timeout"+bcolors.ENDC)
			exit()

	lines = open(malicious_urls_file).read().splitlines()
	if not is_random:
		return lines[0]
	else:
		return(random.choice(lines))


def get_malicious_ip(malicious_ip_file,is_random=True):
	lines=''
	if not os.path.exists(os.path.dirname(malicious_ip_file)):
		os.makedirs(os.path.dirname(malicious_ip_file))

	if not os.path.isfile(malicious_ip_file):
		try:
			response = requests.get(url='https://malsilo.gitlab.io/feeds/dumps/ip_list.txt')
			if response.status_code != 200:
				print(bcolors.FAIL+'TI Download Failed'+bcolors.ENDC)
				exit()
			decoded_content = response.content.decode('utf-8')
			cr = csv.reader(decoded_content.splitlines(), delimiter=',')
			for skip in range(16):
				next(cr)
			bad_ips_list = list(cr)
			for row in bad_ips_list:
				lines+=row[2].split(':')[0]+'\n'
			with open(malicious_ip_file, 'w+') as f:
			 	f.write(lines)

		except requests.ConnectionError:
			print(bcolors.FAIL+"Connection error"+bcolors.ENDC)
			exit()
		except requests.ConnectTimeout:
			print(bcolors.FAIL+"Connection timeout"+bcolors.ENDC)
			exit()


	lines = open(malicious_ip_file).read().splitlines()
	if not is_random:
		return lines[0]
	else:
		return(random.choice(lines))


def get_malicious_domains(malicious_domains_file,is_random=True):
	lines=''
	if not os.path.exists(os.path.dirname(malicious_domains_file)):
		os.makedirs(os.path.dirname(malicious_domains_file))

	if not os.path.isfile(malicious_domains_file):
		try:
			response = requests.get(url='https://osint.bambenekconsulting.com/feeds/c2-dommasterlist-high.txt')
			if response.status_code != 200:
				print(bcolors.FAIL+'TI Download Failed'+bcolors.ENDC)
				exit()
			decoded_content = response.content.decode('utf-8')
			cr = csv.reader(decoded_content.splitlines(), delimiter=',')
			for skip in range(16):
				next(cr)
			bad_ips_list = list(cr)
			for row in bad_ips_list:
				lines+=row[0]+'\n'
			with open(malicious_domains_file, 'w+') as f:
			 	f.write(lines)

		except requests.ConnectionError:
			print(bcolors.FAIL+"Connection error"+bcolors.ENDC)
			exit()
		except requests.ConnectTimeout:
			print(bcolors.FAIL+"Connection timeout"+bcolors.ENDC)
			exit()


	lines = open(malicious_domains_file).read().splitlines()
	if not is_random:
		return lines[0]
	else:
		return(random.choice(lines))


def cook_alert(incident,malware_hashes_file,malicious_urls_file,malicious_ip_file,malicious_domains_file,is_random=True):
	body={
		"data": [
			{
				"name": "",
				"source":"FSM-INTL-DEMO",
				"sourcedata": {}
			}
			]
		}

	#templates_files = [f for f in glob.glob(templates_path + "**/*.json", recursive=True)]
	try:
		with open(incident, 'r') as f:
			incident_json = json.load(f)
	except IOError:
		print(bcolors.FAIL+"Couldn't open template file: "+incident+bcolors.ENDC)
		exit()

	body['data'][0]['sourcedata']=incident_json['sourcedata']


	# Common attributes
	body['data'][0]['name']=body['data'][0]['sourcedata']['incident']['ruleName']
	body['data'][0]['sourcedata']['incident']['id']	= random.randint(1, 9999999999)
	body['data'][0]['sourcedata']['incident']['creationTime']= time.time()
	body['data'][0]['sourcedata']['incident']['devImportance']		= random.randint(1, 4)
	body['data'][0]['sourcedata']['incident']['lastSeenTime']		= time.time()
	body['data'][0]['sourcedata']['incident']['incidentCount']		= random.randint(1, 20)
	body['data'][0]['sourcedata']['incident']['firstSeenTime']		= time.time() - 3600
	body['data'][0]['sourcedata']['incident']['lastModified']		= time.time()
	body['data'][0]['sourcedata']['incident']['incidentId']			= random.randint(1, 999999)
	# Specific attributes
	if body['data'][0]['sourcedata']['incident']['incidentEt'] == 'PH_RULE_AO_MALWARE_HASH_MATCH':
		filename=''.join([random.choice(string.ascii_letters + string.digits) for n in range(16)])
		body['data'][0]['sourcedata']['incident']['incidentDetail'] = "fileName:C:\\\\Windows\\\\System32\\\\"+\
		filename+".exe, hashCode:"+get_malware_hashes(malware_hashes_file,is_random)+","

	elif body['data'][0]['sourcedata']['incident']['incidentEt'] == 'PH_RULE_DNS_FORTIGUARD_MALWARE_DOMAIN':
		bad_domain = get_malicious_domains(malicious_domains_file,is_random)
		body['data'][0]['sourcedata']['incident']['destName'] = bad_domain
		body['data'][0]['sourcedata']['incident']['incidentTarget'] = "destName:"+bad_domain+","

	elif body['data'][0]['sourcedata']['incident']['incidentEt'] == 'PH_RULE_TO_FORTIGUARD_MALWARE_IP':
		bad_ip = get_malicious_ip(malicious_ip_file,is_random)
		body['data'][0]['sourcedata']['incident']['destIpAddr'] = bad_ip
		body['data'][0]['sourcedata']['incident']['incidentTarget'] = "destIpAddr:"+bad_ip+","

	elif body['data'][0]['sourcedata']['incident']['incidentEt'] == 'PH_RULE_VPN_LOGON_SUCCESS_OUTSIDE_COUNTRY':
		foreign_ip = "192.58.142."+str(random.randint(1, 254))
		body['data'][0]['sourcedata']['incident']['sourceUser'] = random.choices(usernames)[0]
		body['data'][0]['sourcedata']['incident']['srcIpAddr'] = foreign_ip
		body['data'][0]['sourcedata']['incident']['incidentSrc'] = "srcIpAddr:"+foreign_ip+","

	elif body['data'][0]['sourcedata']['incident']['incidentEt'] == 'PH_RULE_HIGH_SEV_SEC_IPS_IN_PERMIT':
		bad_ip = get_malicious_ip(malicious_ip_file,is_random)
		#TODO : fetch IPS rules from FG and it it's attack ID, feed CSV to FSR Assets
		body['data'][0]['sourcedata']['incident']['incidentDetail'] = "compEventType:FortiGate-ips-signature-"+str(random.randint(8000, 9000))+", attackName:, incidentCount:6,"
		body['data'][0]['sourcedata']['incident']['srcIpAddr'] = bad_ip
		body['data'][0]['sourcedata']['incident']['incidentSrc'] = "srcIpAddr:"+bad_ip+","

	elif body['data'][0]['sourcedata']['incident']['incidentEt'] == 'PH_RULE_WEB_FORTIGUARD_MALWARE_URL':
		bad_url = get_malicious_urls(malicious_urls,is_random)
		body['data'][0]['sourcedata']['incident']['destName'] = bad_url.split("//")[1]
		body['data'][0]['sourcedata']['incident']['incidentDetail'] = "infoURL:"+bad_url+","
		body['data'][0]['sourcedata']['incident']['incidentTarget'] = "destName:"+bad_url.split("//")[1]+","


	return body

def lookup_tenant_iri(server,headers,tenant_name):
	try:
		response = requests.get(url='https://'+server+'/api/3/tenants',
			headers=headers,verify=False)

		if response.status_code != 200:
			print(bcolors.FAIL+'Error retrieving tenants IRI:'+response.text+bcolors.ENDC)
			exit()
		tenants=response.json()
		for tenant in tenants['hydra:member']:
			if tenant_name in tenant['name']:
				return tenant
		else:
			print(bcolors.FAIL+"Tenant not found"+bcolors.ENDC)
			exit()
	except requests.ConnectionError:
		print(bcolors.FAIL+"Connection error"+bcolors.ENDC)
		exit()
	except requests.ConnectTimeout:
		print(bcolors.FAIL+"Connection timeout"+bcolors.ENDC)
		exit()

def fsr_send_alert(server,headers,body, tenant=None):

	try:
		if tenant:
			body['data'][0]['tenant'] = tenant
		response = requests.post(url='https://'+server+'/api/3/insert/alerts',
			headers=headers,json=body,verify=False)

		if response.status_code != 200:
			print(bcolors.FAIL+'Error Updating :'+response.text+bcolors.ENDC)
			exit()
		else:
			print(bcolors.OKGREEN+'Alert Sent'+bcolors.ENDC)

		return response.json()

	except requests.ConnectionError:
		print(bcolors.FAIL+"Connection error"+bcolors.ENDC)
		exit()
	except requests.ConnectTimeout:
		print(bcolors.FAIL+"Connection timeout"+bcolors.ENDC)
		exit()

def main():
	parser = argparse.ArgumentParser(
	prog='ProgramName',
	formatter_class=argparse.RawDescriptionHelpFormatter,
	epilog=textwrap.dedent('''\
		 FSR Incident Simulator
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
	body=cook_alert(args.incident_template,malware_hashes,malicious_urls,malicious_ips,malicious_domains,is_random)

	# FortiGuard C&C scenario : 2 alerts, same dst IP, different src IP
	if 	body['data'][0]['sourcedata']['incident']['incidentEt'] == 'PH_RULE_TO_FORTIGUARD_MALWARE_IP':
		source_ip='192.168.10.'+str(random.randint(100, 200))
		body['data'][0]['sourcedata']['incident']['srcIpAddr'] = source_ip
		body['data'][0]['sourcedata']['incident']['incidentSrc'] = source_ip
		fsr_send_alert(args.server,headers,body)
		source_ip='192.168.10.'+str(random.randint(100, 200))
		body['data'][0]['sourcedata']['incident']['srcIpAddr'] = source_ip
		body['data'][0]['sourcedata']['incident']['incidentSrc'] = source_ip
		input('Type anykey to continue')
		fsr_send_alert(args.server,headers,body)
		exit()
	if args.tenant:
		fsr_send_alert(args.server,headers,body,lookup_tenant_iri(args.server,headers,args.tenant)['@id'])
	else:
		fsr_send_alert(args.server,headers,body)



if __name__ == '__main__':
	main()
