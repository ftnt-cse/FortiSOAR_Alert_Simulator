#!/bin/python3
# FSR-Simulator is a CLI program to generate FSM like incidents for FSR
# Function library to handle FortiSOAR communication
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND

from .artifact_factory import *
import requests, json, argparse, textwrap, random, time, os, csv, string
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

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


