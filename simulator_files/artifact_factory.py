#!/bin/python3
# function library to generate:
#	-Random artifacts
#	-network related artifact (usernames, network and system devices attributes)
# FortiSOAR CSE Team
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND

import requests, json, random, time, os, csv
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

templates_path 		= './'
malware_hashes 		= './threat_intelligence/malware_hashes.txt'
malicious_domains	= './threat_intelligence/malicious_domains.txt'
malicious_ips		= './threat_intelligence/malicious_ips.txt'
malicious_urls		= './threat_intelligence/malicious_urls.txt'


class bcolors:
	OKGREEN = '\033[92m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'


def get_username():
	usernames=['Sun.Tzu','Albert.Einstein','Isaac.Newton','Leonardo.Da.Vinci','Aristotle','Galileo.Galilei','Alexander.the.Great','Charles.Darwin','Plato','William.Shakespeare','Martin.Luther.Kin','Socrates','Mahatma.Gandhi','Abraham.Lincoln','George.Washington','Mose','Nikola.Tesla','Gautama.Buddha','Julius.Ceasar','Karl.Marx','Martin.Luther','Napoleon.Bonaparte','Johannes.Gutenberg']
	return random.choices(usernames)[0]
def get_fg_mgmt_ip():
	return "10.200.3.1"

def get_fg_dev_name():
	return "FortiGate-Edge"

def get_asset_ip():
	return "10.200.3."+str(random.randint(2, 24))

def get_time_now():
	return int(time.time())

def get_time_past():
	return int(time.time()) - random.randint(3600, 86400)

def get_random_integer(start=55555,end=99999):
	random.randint(start, end)

def get_malware_hash(malware_hashes_file=malware_hashes,is_random=True):

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


def get_malicious_url(malicious_urls_file=malicious_urls,is_random=True):

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


def get_malicious_ip(malicious_ip_file=malicious_ips,is_random=True):
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


def get_malicious_domains(malicious_domains_file=malicious_domains,is_random=True):
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

function_dictionary={
"TR_FG_MGMT_IP":get_fg_mgmt_ip,
"TR_ASSET_IP":get_asset_ip,
"TR_MALICIOUS_IP":get_malicious_ip,
"TR_FG_DEV_NAME":get_fg_dev_name,
"TR_NOW":get_time_now,
"TR_PAST":get_time_past,
"TR_RANDOM_INTEGER":get_random_integer,
"TR_MALICIOUS_DOMAIN":get_malicious_domains,
"TR_MALICIOUS_URL":get_malicious_url,
"TR_MALICIOUS_HASH":get_malware_hash
}

clean_artifact_dictionary={
"TR_FG_MGMT_IP":get_fg_mgmt_ip,
"TR_ASSET_IP":get_asset_ip,
"TR_MALICIOUS_IP":get_malicious_ip,
"TR_FG_DEV_NAME":get_fg_dev_name,
"TR_NOW":get_time_now,
"TR_PAST":get_time_past,
"TR_RANDOM_INTEGER":get_random_integer,
"TR_MALICIOUS_DOMAIN":get_malicious_domains,
"TR_MALICIOUS_URL":get_malicious_url,
"TR_MALICIOUS_HASH":get_malware_hash
}
