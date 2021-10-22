# -*- coding: utf-8 -*-

#!/usr/bin/env python

__sure_version =  "1.0.6"

#Common Imports
import os 
try:
	import json
except ImportError:
	print(" Tool could not find the required libraries, please try running the tool with 'python3 sure.py'.  ")
	exit()
	
import re
from datetime import datetime, timedelta
from argparse import ArgumentParser
import socket	
import subprocess
import logging
import time 
import threading
import sys 
import platform
import getpass

try:
	#python3 Imports
	import requests
	import queue

except ImportError:
	#python2 Imports
	import Queue
try:
	requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
except NameError:
	try:
		from requests.packages import urllib3
		urllib3.disable_warnings()
	except:
		pass #this will only trigger https validation errors. 

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#Argument Parsing anf Validation 

def argumentParser():
	parser = ArgumentParser(description='AURA - SDWAN (SURE) Audit & Upgrade Readiness - v'+ __sure_version )


	parser.add_argument('-q', '--quiet',
						required=False, 
						action='store_true',
						help="Quiet execution of the script"
						)

	parser.add_argument('-v', '--verbose', 
						required=False, 
						action='store_true',
						help="Verbose execution of the script"
						)

	parser.add_argument('-d' , '--debug',
						required=False, 
						action='store_true',
						help="Debug execution of the script"
						)

	parser.add_argument('-u', '--username',
						type=str, 
						required=True, 
						help="vManage Username"
						)

	parser.add_argument('-vp', '--vmanage_port',
						type=str, 
						required=False, 
						help="vManage Password")
	args = parser.parse_args()
	return args

def argValidation(args):
	args = vars(args)
	if args['debug'] == True and args['quiet'] == True and  args['verbose']== True :
		raise Exception('Entered more than 1 flag')
	elif args['debug'] == True and args['quiet'] == True and  args['verbose']== False : 
		raise Exception('Entered more than 1 flag')
	elif args['debug'] == True and args['quiet'] == False and  args['verbose']== True : 
		raise Exception('Entered more than 1 flag')
	elif args['debug'] == False and args['quiet'] == True and  args['verbose']== True : 
		raise Exception('Entered more than 1 flag')

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
def showCommand(exec_mode_command):
	exec_mode_command = exec_mode_command+'\n'
	exec_mode_command = exec_mode_command.encode()
	p = subprocess.Popen('viptela_cli', shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	p.stdin.write(exec_mode_command) #passing command
	stdOutput,stdError = p.communicate()
	p.stdin.close()
	return stdOutput.decode()


def executeCommand(command):
	stream = os.popen(command)
	output = stream.read()
	return output


def match(data , regex):
	match = re.search(regex, str(data))
	matchedData = match.group()
	return matchedData


#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

def generateSessionIDpy3(vManageIP,Username,Password,Port):
	if Port==None:
		login = "https://{}:8443/j_security_check".format(vManageIP)
	else:
		login = "https://{}:{}/j_security_check".format(vManageIP,Port)
		
	payload = 'j_username={}&j_password={}'.format(Username,Password)
	
	headers = {
			  'Content-Type': 'application/x-www-form-urlencoded'
				}

	JsessionID = requests.request("POST", login, headers=headers, data = payload, verify=False)
	if JsessionID.status_code == 200:
		JsessionID = (JsessionID.headers['Set-Cookie']).split(';')
		return JsessionID[0]
	else:
		print(" Error creating JsessionID, verify if  the information provided is correct ")


def CSRFTokenpy3(vManageIP,JSessionID,Port):
	if Port==None:
		token = "https://{}:8443/dataservice/client/token".format(vManageIP)
	else:
		token = "https://{}:{}/dataservice/client/token".format(vManageIP,Port)
		
	headers = {
	  'Cookie': JSessionID
	}

	tokenID = requests.request("GET", token, headers=headers, verify = False)
	if tokenID.status_code==200:
		return tokenID.text
	else:
		print(" Please check if the vManage IP/URL is correct and JSessionID is valid ")


def getRequestpy3(version_tuple, vManageIP,JSessionID, mount_point, Port, tokenID = None):
	if Port==None:
		url = "https://{}:8443/dataservice/{}".format(vManageIP, mount_point)
	else:
		url = "https://{}:{}/dataservice/{}".format(vManageIP, Port, mount_point)

	if version_tuple[0:2] < ('19','2'):
		headers = {
					'Cookie': JSessionID
					}
	else:
		headers = {
					'X-XSRF-TOKEN': tokenID,
					'Cookie': JSessionID
					}
	response = requests.request("GET", url , headers=headers, verify=False)
	data = response.content
	if response.status_code==200:
		return data.decode()
	else:
		print('Please verify if the vManage ip/url is correct and JSessionID/CSRFToken is valid')



def sessionLogoutpy3(vManageIP,JSessionID,Port, tokenID= None):
	if Port==None:
		url = "https://{}:8443/logout".format(vManageIP)
	else:
		url = "https://{}:{}/logout".format(vManageIP,Port)

	if version_tuple[0:2] < ('19','2'):
		headers = {
					'Cookie': JSessionID
					}
	else:
		headers = {
					'X-XSRF-TOKEN': tokenID,
					'Cookie': JSessionID
					}

	response = requests.request("GET", url, headers=headers, verify=False)

	return response.text.encode('utf8')


def generateSessionID(vManageIP,Username,Password,Port):
	if Port==None:
		command = "curl --insecure -i -s -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'j_username={}' --data-urlencode 'j_password={}' https://{}:8443/j_security_check".format(Username, Password,vManageIP)
		login = executeCommand(command)
	else:
		command = "curl --insecure -i -s -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'j_username={}' --data-urlencode 'j_password={}' https://{}:{}/j_security_check".format(Username, Password,vManageIP, Port)
		login = executeCommand(command)  
	 
	login = login.split(' ')
	if int(login[1]) == 200:
		jsessionid = (login[3].split('=')[1][0:-1])
		return jsessionid
	else:
		print('Error creating JsessionID, verify if  the information provided is correct')


def CSRFToken(vManageIP,JSessionID,Port):
	if Port==None:
		command = 'curl --insecure -s https://{}:8443/dataservice/client/token?json=true -H "Cookie: JSESSIONID={}"'.format(vManageIP, JSessionID)
		tokenid= executeCommand(command)

	else:
		command = 'curl --insecure -s https://{}:{}/dataservice/client/token?json=true -H "Cookie: JSESSIONID={}"'.format(vManageIP, Port, JSessionID)
		tokenid= executeCommand(command)
	tokenid = json.loads(tokenid)
	tokenid = tokenid["token"]
	return tokenid


def getRequest(version_tuple, vManageIP,JSessionID, mount_point, Port, tokenID = None):
	if version_tuple[0:2] < ('19','2'):
		if Port==None:
			command = 'curl -s --insecure "https://{}:8443/dataservice/{}" -H "Cookie: JSESSIONID={}" '.format(vManageIP, mount_point,JSessionID )
			data = executeCommand(command)    
		else:
			command = 'curl -s --insecure "https://{}:{}/dataservice/{}" -H "Cookie: JSESSIONID={}"'.format(vManageIP,Port,mount_point,JSessionID )
			data = executeCommand(command)
	else:
		if Port==None:
			command = 'curl -s "https://{}:8443/dataservice/{}" -H "Cookie: JSESSIONID={}" --insecure -H "X-XSRF-TOKEN={}"'.format(vManageIP,mount_point,JSessionID, tokenID)
			data = executeCommand(command)
		else:
			command = 'curl -s "https://{}:{}/dataservice/{}" -H "Cookie: JSESSIONID={}" --insecure -H "X-XSRF-TOKEN={}"'.format(vManageIP,Port, mount_point,JSessionID, tokenID)
			data = executeCommand(command)
	return data

  


def sessionLogout(vManageIP,JSessionID, Port, tokenID= None):
	if version_tuple[0:2] < ('19','2'):
		if Port==None:
			command = 'curl --insecure -s "https://{}:8443/logout" -H "Cookie: JSESSIONID={}'.format(vManageIP,JSessionID )
			executeCommand(command)
		else:
			command = 'curl --insecure -s "https://{}:{}/logout" -H "Cookie: JSESSIONID={}'.format(vManageIP, Port, JSessionID)
			executeCommand(command)   
	else:
		if Port==None:
			command = 'curl -s "https://{}:8443/logout" -H "Cookie: JSESSIONID={}" --insecure -H "X-XSRF-TOKEN={}"'.format(vManageIP, JSessionID, tokenid)
			executeCommand(command) 
		else:
			command = 'curl -s "https://{}:{}/logout" -H "Cookie: JSESSIONID={}" --insecure -H "X-XSRF-TOKEN={}"'.format(vManageIP, Port, JSessionID, tokenid)
			executeCommand(command)


#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#Create Directory, File and Wrtie to the File

def createDir(path):
	if os.path.isdir(path) == False:
		mode = 0o777
		try:
			os.mkdir(path)
		except:
			os.mkdir(path, mode)

def createFile(file_path):
	return (open(file_path, 'w+'))


def writeFile(file_name,text):
	file_name.write(text)

  
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#Setup Multiple Loggers


def setup_logger(logger_name, log_file, level=logging.DEBUG):
	level=logging.DEBUG
	l = logging.getLogger(logger_name)
	formatter = logging.Formatter('%(levelname)s:%(message)s')
	fileHandler = logging.FileHandler(log_file, mode='w')
	fileHandler.setFormatter(formatter)

	l.setLevel(level)
	l.addHandler(fileHandler)

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#Validate if vManage server
def is_vmanage():
	if platform.system() == 'Linux' and os.path.exists("/var/log/nms") and os.path.exists("/etc/viptela"):
		return True
	else:
		return False

#vManage Version
def vManageVersion():
	version = showCommand('show version')
	version_tuple = tuple(version.split('.'))
	return version,version_tuple

#vManage Loopback IP
def getLoip():
	try:
		hostname = socket.gethostname()
		vmanage_lo_ip = socket.gethostbyname(hostname)
		return vmanage_lo_ip
	except:
		raise Exception('Unable to retrieve vManage Loopback IP address')

#Controllers info        
def controllersInfo(controllers):
	controllers_info = {}
	for device in controllers['data']:
		if device['deviceState'] == 'READY':
			controllers_info[(device['host-name'])] = [(device['deviceType']),(device['deviceIP']),(device['version']) ,(device['reachability']),(device['globalState']),(device['timeRemainingForExpiration']), (device['state_vedgeList']) ] 
	return (controllers_info)

#CPU Clock Speed
def cpuSpeed():    
	cpu_speed = executeCommand('lscpu | grep CPU\ MHz\:')
	cpu_speed = match(str(cpu_speed),'\d+')
	cpu_speed = float(cpu_speed)/1000
	return cpu_speed

# CPU Count
def cpuCount():
	cpu_count = executeCommand('lscpu | grep CPU\(\s\)\:')
	cpu_count = match(str(cpu_count),'\d+')
	return int(cpu_count)

#vEdge Count
def vedgeCount(vedges):
	vedge_count = 0
	vedge_count_active = 0
	vedge_info = {}
	for vedge in vedges['data']:
		vedge_count+=1
		if 'version' in vedge.keys():
			vedge_count_active +=1
			vedge_info[(vedge['host-name'])] = [vedge['version'] , 
												vedge['validity'],
												vedge['reachability']
											   ]
	return vedge_count, vedge_count_active, vedge_info 

# Server mode: Single Server/Cluster of 3/Cluster of 6
def serverMode(controllers_info):
	cluster_size = 0
	vmanage_info = {}
	for key in controllers_info:
		if controllers_info[key][0]  == 'vmanage':
			cluster_size += 1 
			vmanage_info[key] = controllers_info[key]
			
	server_mode = ''   
	if cluster_size == 6:
		server_mode = 'Cluster of 6'
	elif cluster_size == 3:
		server_mode = 'Cluster of 3'
	elif cluster_size == 1:
		server_mode = 'Single Server'
	
	return cluster_size, server_mode, vmanage_info

#Disk Controller Type 
def diskController():
	disk_controller = executeCommand('df -kh | grep /opt/data')
	disk_controller = str(disk_controller).split()
	return disk_controller[0]

#DPI data collection enabled/disabled
def  dpiStatus(dpi_stats):
	dpi_status = next((item for item in dpi_stats if item['indexName'] == 'dpistatistics'), None)
	return dpi_status['status']

#Server type: onprem/cloud
def serverType():
	server_type = str(executeCommand('cat /sys/devices/virtual/dmi/id/sys_vendor'))
	if 'VMware' in server_type:
		return 'on-prem'
	elif 'Amazon'in server_type or 'Microsoft' in server_type:
		return 'on-cloud'

#vSmart and vBond info
def vbondvmartInfo(controllers_info):
	vsmart_info = {}
	vbond_info = {}
	for key in controllers_info:
		if controllers_info[key][0]  == 'vsmart':
			vsmart_info[key] = controllers_info[key]
		elif controllers_info[key][0]  == 'vbond':
			vbond_info[key] = controllers_info[key]
	return vbond_info, vsmart_info


#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#Critical Checks

#01:Check:vManage:Validate current version
def criticalCheckone(version):
	#Boot Partition Size
	boot_partition_size = executeCommand('df -kh | grep boot')
	boot_partition_size = re.findall('(\d+.\d+)([G,M,K])', boot_partition_size)
	if boot_partition_size[0][1] == 'G':
		boot_partition_size_Gig = float(boot_partition_size[0][0])
	elif boot_partition_size[0][1] == 'M':
		boot_partition_size_Gig = (float(boot_partition_size[0][0]))/1000
	elif boot_partition_size[0][1] == 'K':
		boot_partition_size_Gig = ((float(boot_partition_size[0][0]))/1000)/1000

	#vmanage version
	vmanage_version = float('.'.join((version.split('.'))[0:2]))
	if vmanage_version == 20.6:
		check_result = 'SUCCESSFUL'
		check_analysis = 'Current vManage version is {}, and matching latest long life release version'.format(version)
		check_action = None
	elif vmanage_version > 20.3 or vmanage_version < 20.6:
		check_result = 'SUCCESSFUL'
		check_analysis = 'Direct Upgrade to next long life release 20.6 is possible and no intermediate upgrade is required'
		check_action = None
	elif vmanage_version == 20.3:
		check_result = 'SUCCESSFUL'
		check_analysis = 'Controller is currently on recommended long life release branch, you can upgrade directly to latest release in 20.3.x'
		check_action = None
	elif vmanage_version >= 20.1 or vmanage_version < 20.3:
		check_result = 'SUCCESSFUL'
		check_analysis = 'Direct Upgrade to next long life release 20.3 is possible and no intermediate upgrade is required'
		check_action = None
	elif vmanage_version >= 18.3 or vmanage_version <= 19.2:
		if boot_partition_size_Gig <= 2.0:
			check_result = 'Failed'
			check_analysis = 'Current Disk Space is {}, it is less than 2GB and Direct Upgrade to next long life release 20.3 is not possible'.format(' '.join(boot_partition_size[0]))
			check_action = 'Upgrade through Version 20.1 is required'
		elif  boot_partition_size_Gig > 2.0:
			check_result = 'SUCCESSFUL'
			check_analysis = 'Current Disk Space is {}, it is more than 2GB and Direct Upgrade to next long life release 20.3 is possible'.format(' '.join(boot_partition_size[0]))
			check_action = None
	elif vmanage_version < 18.3:
		check_result = 'Failed'
		check_analysis = 'Direct Upgrade to Version 20.3 is not possible'
		check_action = 'Step Upgrade to 18.4 is required'
	return (' '.join(boot_partition_size[0])), check_result, check_analysis, check_action

#02:Check:vManage:At minimum 20%  server disk space should be available
def criticalCheckTwo():
	optdata_partition_size_percent = executeCommand('df -kh | grep /opt/data')
	optdata_partition_size_percent = re.findall('(\d+)([%])' , optdata_partition_size_percent)
	optdata_partition_size = int(optdata_partition_size_percent[0][0])
	rootfs_partition_size_percent = executeCommand('df -kh | grep rootfs.rw')
	rootfs_partition_size_percent = re.findall('(\d+)([%])' , rootfs_partition_size_percent)
	rootfs_partition_size = int(rootfs_partition_size_percent[0][0])

	if optdata_partition_size <= 80 and rootfs_partition_size <= 80:
		check_result = 'SUCCESSFUL'
		check_analysis = 'Enough Disk space is available to perform the upgrade. Space available /opt/data:{}%, rootfs.rw:{}%'.format(100-optdata_partition_size, 100-rootfs_partition_size)
		check_action = None
	elif optdata_partition_size >= 80 or rootfs_partition_size >= 80:
		check_result = 'Failed'
		check_analysis = 'Not enough disk space is available for the upgrade. Space available /opt/data:{}%, rootfs.rw:{}%'.format(100-optdata_partition_size, 100-rootfs_partition_size)
		check_action = 'Free the disk space by opening a TAC case depending on where the disk is being used'
	
	return (''.join(optdata_partition_size_percent[0])),(''.join(rootfs_partition_size_percent[0])), check_result, check_analysis, check_action

#03:Check:vManage:Memory size
def criticalCheckthree(vedge_count, dpi_status, server_type, cluster_size, version_tuple):
	if version_tuple[0:2] < ('20','5'):
		memory_size_gb = executeCommand('free -g | grep Mem')
	elif  version_tuple[0:2] >= ('20','5'):
		memory_size_gb = executeCommand('free --giga | grep Mem')

	memory_size_gb = str(memory_size_gb).split()
	memory_size = int(memory_size_gb[1])

	if dpi_status == 'enable' and server_type == 'on-prem':
		if memory_size < 128:
			check_result = 'Failed'
			check_analysis = 'Memory size is below the hardware size recommendations when DPI is enabled. Memory size should be 128 GB.\n For more information please check: https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html'
			check_action = 'Correct the memory available to the server'

	elif dpi_status != 'enable' and server_type == 'on-prem':
		if cluster_size == 1:
			if memory_size < 32:
				check_result = 'Failed'
				check_analysis = '''The current memory size does not meet minimum hardware recommendations.\n 
									Memory size must be 32 GB or higher.'''
				check_action = 'Correct the memory available to the server'
			elif vedge_count > 250 and vedge_count <= 1000 and memory_size < 64:
				check_result = 'Failed'
				check_analysis = '''Because of current xEdge device count, the memory size is insufficient to perform upgrade.\n 
									Memory size should be 64 GB or higher, as per documented hardware recommendations.'''
				check_action = 'Correct the memory available to the server'
			elif vedge_count > 1000 and vedge_count <= 1500 and memory_size < 128:
				check_result = 'Failed'
				check_analysis = '''Because of current xEdge device count, the memory size is insufficient to perform upgrade.\n 
									Memory size should be 128 GB, as per documented hardware recommendations.'''
				check_action = 'Correct the memory available to the server'
			elif vedge_count > 1500:
				check_result = 'Failed'
				check_analysis = 'xEdge device count is more than 1500, it exceeds supported scenarios.'
				check_action = 'Please implement network changes to bring the scale into supported range'
		elif cluster_size>1:
			if vedge_count <= 2000 and memory_size < 64:
				check_result = 'Failed'
				check_analysis = '''Because of current xEdge device count, the memory size is insufficient to perform upgrade.\n 
									Memory size should be 64 GB or higher, as per documented hardware recommendations.'''
				check_action = 'Correct the memory available to the server'
			elif vedge_count > 2000 and vedge_count <= 5000 and memory_size < 128:
				check_result = 'Failed'
				check_analysis = '''Because of current xEdge device count, the memory size is insufficient to perform upgrade.\n
									Memory size should be 128 GB, as per documented hardware recommendations.'''
				check_action = 'Correct the memory available to the server'
			elif vedge_count > 5000:
				check_result = 'Failed'
				check_analysis = 'xEdge device count is more than 5000, it exceeds supported scenarios.'
				check_action = 'Please evaluate current overlay design.'
	else:
		check_result = 'SUCCESSFUL'
		check_analysis = 'Server meets hardware recommendations'
		check_action = None

	return memory_size, memory_size_gb[1], dpi_status, server_type, check_result, check_analysis, check_action


#04:Check:vManage:CPU Count
def criticalCheckfour(cpu_count, vedge_count, dpi_status, server_type):
	if dpi_status == 'enable' and server_type == 'on-prem':
		if cpu_count < 32:
			check_result = 'Failed'
			check_analysis = 'No. of Processors is below minimum supported size when DPI is in use. CPU Count is {}, it should be 32 or higher.'.format(cpu_count)
			check_action = 'Allocate more processors'
	elif dpi_status != 'enable' and server_type == 'on-prem':
		if vedge_count > 250 and  cpu_count < 32:
			check_result = 'Failed'
			check_analysis = 'Based on device count, number of Processors is insufficient for the upgrade. CPU Count is {}, it should be 32 or higher.'.format(cpu_count)
			check_action = 'Allocate more processors'
		elif cpu_count < 16:
			check_result = 'Failed'
			check_analysis = 'Number of Processors is below the minimum supported size. CPU Count is {}, it should be 16 or higher.'.format(cpu_count)
			check_action = 'Allocate more processors'
	elif dpi_status != 'enable' and server_type == 'on-cloud':
		if edge_count > 250 and  cpu_count < 32:
			check_result = 'Failed'
			check_analysis = 'Based on device count, number of Processors is insufficient for the upgrade. CPU Count is {}, it should be 32 or higher.'.format(cpu_count)
			check_action = 'Allocate more processors'
		elif edge_count < 250 and  cpu_count < 16:
			check_result = 'Failed'
			check_analysis = 'Number of Processors is below the minimum supported size. CPU Count is {}, it should be 16 or higher.' .format(cpu_count)
			check_action = 'Allocate more processors'
	else:
		check_result = 'SUCCESSFUL'
		check_analysis = 'No. of Processors is sufficient for the upgrade,  CPU count is {}.'.format(cpu_count)
		check_action = None

	return check_result, check_analysis, check_action

#05:Check:vManage:ElasticSearch Indices status
def criticalCheckfive(es_indexes):
	es_index_red = []
	for index in es_indexes['data']:
		if index['status'] != 'GREEN':
			es_index_red.appened(es_indexes['indexName'])

	if len(es_index_red) != 0:
		check_result = 'Failed'
		check_analysis = 'There are Indices with RED status'
		check_action = 'At least one StatsDB index is exhibiting problems. Please contact TAC  case to investigate and correct the issue'
	elif len(es_index_red) == 0:
		check_result = 'SUCCESSFUL'
		check_analysis = 'All the indices are in GREEN status'
		check_action = None

	return es_index_red, check_result, check_analysis, check_action

#06:Check:vManage:Look for any neo4j exception errors
def criticalChecksix():
	if os.path.isfile('/var/log/nms/neo4j-out.log') == False:
		check_result = 'Failed'
		check_analysis = '/var/log/nms/neo4j-out.log file not found'
		check_action = 'Config DB log file was not found. It is advisable to contact TAC to investigate why the /var/log/nms/neo4j-out.log is missing'

	elif os.path.isfile('/var/log/nms/neo4j-out.log') == True:
		with open ('/var/log/nms/neo4j-out.log') as neo4j_out:
			neo4j_out_data = neo4j_out.readlines()
		count = 0
		for line in neo4j_out_data:
			if 'ERROR' in line:
			    last_14day_date_time = datetime.now() - timedelta(days = 14)
			    match = re.findall(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',  line)
			    date_time = datetime.strptime(match1[0], '%Y-%m-%d %H:%M:%S')
			    if date_time > last_14day_date_time:
			        count +=1

		if count == 0:
			check_result = 'SUCCESSFUL'
			check_analysis = 'No Error messaged found in /var/log/nms/neo4j-out.log'
			check_action = None
		else:
			check_result = 'Failed'
			check_analysis = '{} Error messages found in /var/log/nms/neo4j-out.log'.format(count)
			check_action = 'There are errors reported in configDB log file. It is advisable to contact TAC to investigate any issues before an upgrade'
	
	return check_result, check_analysis, check_action

#07:Check:vManage:Validate all services are up
def criticalCheckseven():
	nms_status1 = showCommand('request nms all status')
	nms_status = nms_status1.split('NMS')
	nms_failed = []
	for nms in nms_status:
		if 'true' in nms  and 'not running' in nms:
			nms_failed.append(nms.split('\t')[0].strip())
			check_result = 'Failed'
			check_analysis = 'Enabled service/s not running'
			check_action = 'It is advisable to investigate why a service is being reported as failed. Please  restart the process or contact TAC for further help'
		else:
			check_result = 'SUCCESSFUL'
			check_analysis = 'All enabled services are running'
			check_action = None
	return nms_status1, nms_failed, check_result,check_analysis,check_action


#08:Check:vManage:Elasticsearch Indices version
def criticalCheckeight(version_tuple):
	if version_tuple[0:2] < ('20','3'):
		try:
			indices_data = executeCommand('curl --connect-timeout 6 --silent -XGET "localhost:9200/*/_settings?pretty"')
			indices_data = json.loads(indices_data)
		except:
			ip_add = (executeCommand("netstat -a -n -o |  grep tcp | awk '{print $4}'| grep :9200")).split()[0]
			pattern = "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):9200"
			match = re.search(pattern, ip_add)
			if match:
				indices_data = executeCommand('curl --connect-timeout 6 --silent -XGET "{}/*/_settings?pretty"'.format(ip_add))
				indices_data = json.loads(indices_data)
	else:
		try:
			indices_data = executeCommand('curl --connect-timeout 6 --silent -XGET "localhost:9200/*/_settings?pretty" -u elasticsearch:s3cureElast1cPass')
			indices_data = json.loads(indices_data)
		except:
			ip_add = (executeCommand("netstat -a -n -o |  grep tcp | awk '{print $4}'| grep :9200")).split()[0]
			pattern = "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):9200"
			match = re.search(pattern, ip_add)
			if match:
				indices_data = executeCommand('curl --connect-timeout 6 --silent -XGET "{}/*/_settings?pretty" -u elasticsearch:s3cureElast1cPass'.format(ip_add))
				indices_data = json.loads(indices_data)

	if indices_data:
		version_list = {}
		for es in indices_data:
			version =  (indices_data[es]['settings']['index']['version']['created'])
			first_digit = int(version[0])
			second_digit = int(version[1:3])
			third_digit = int(version[3:5])
			version = str(first_digit)+'.'+str(second_digit)
			version = float(version)
			if version <= 3.0:
				version_list[es] = version

		if len(version_list) != 0:
			check_result = 'Failed'
			check_analysis = 'StatsDB indices with version 2.0 found'
			check_action = 'All legacy version indices should be deleted before attempting an upgrade. Please contact TAC to review and remove them as needed'
		elif len(version_list) == 0:
			check_result = 'SUCCESSFUL'
			check_analysis = 'Version of all the Elasticsearch Indices is greater than 2.0'
			check_action = None
	else:
		check_result = 'Failed'
		check_analysis = 'Failed to retrieve Elasticsearch Indices version data'
		check_action = 'It was not possible to obtain indices version data. Please check if there is any error on server, before attempting upgrade'
	return version_list, check_result, check_analysis, check_action



#09:Check:vManage:Evaluate incoming DPI data size
def criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count, total_devices, dpi_status):
	if dpi_status != 'enable':
		dpi_estimate_ondeday = 0
		for index in (es_indices_est[1]['Per index disk space ']):  
			if index['index'] == 'Approute' and index['status'] != 'success':
					appr_estimate_ondeday = None
			elif index['index'] == 'Approute' and index['status'] == 'success':
					appr_estimate_ondeday = index['estimation']['1 day   ']
					if 'KB' in appr_estimate_ondeday:
						appr_estimate_ondeday_gb = float(appr_estimate_ondeday.split(' ')[0])/(1024**2)
					elif 'MB' in appr_estimate_ondeday:
						appr_estimate_ondeday_gb = float(appr_estimate_ondeday.split(' ')[0])/(1024)
					elif 'GB' in appr_estimate_ondeday:
						appr_estimate_ondeday_gb = float(appr_estimate_ondeday.split(' ')[0])
					elif 'TB' in appr_estimate_ondeday:
						appr_estimate_ondeday_gb = float(appr_estimate_ondeday.split(' ')[0])*(1024)

		if appr_estimate_ondeday == None:
			check_result = 'Failed'
			check_analysis = 'It was not possible to retrieve index data.'
			check_action = 'Check if there is any server side error, related to API execution'

		elif appr_estimate_ondeday != None:
			if server_type == 'on-cloud' :
				if appr_estimate_ondeday_gb > 500.0:
					check_result = 'Failed'
					check_analysis = '''The rate of incoming Approute data is higher than expected.\n
										DPI is disabled.'''

					check_action = 'Server hardware size may need to be changed according to the rate of daily incoming Approute data.'
				else:
					check_result = 'SUCCESSFUL'
					check_analysis = '''The rate of daily incoming Approute data is within limits.\n
										DPI is disabled.'''
					check_action = None

			elif server_type == 'on-prem':
				if appr_estimate_ondeday_gb <= 50.0:
					if cpu_count < 32 or  memory_size < 128:
						check_result = 'Failed'
						check_analysis = '''The CPU Count/Memory size is insufficient for the daily incoming Approute data.\n
											DPI is disabled.'''
						check_action =  'Server hardware size may need to be changed according to the rate of daily incoming Approute data.'

				elif appr_estimate_ondeday_gb > 50.0 and appr_estimate_ondeday_gb <= 100.0: 
					if cluster_size < 3 or cpu_count < 32 or memory_size < 128:
						check_result = 'Failed'
						check_analysis = '''The CPU Count/Memory size is insufficient for the daily incoming Approute data.\n
											DPI is disabled.'''
						check_action =  'Server hardware size may need to be changed according to the rate of daily incoming Approute data.'

				elif appr_estimate_ondeday_gb > 100.0 and total_devices < 1000: 
					if cluster_size < 3 or cpu_count < 32 or memory_size < 128:
						check_result = 'Failed'
						check_analysis = '''The CPU Count/Memory size is insufficient for the daily incoming Approute data.\n
											DPI is disabled.'''
						check_action =  'Server hardware size may need to be changed according to the rate of daily incoming Approute data.'

				elif appr_estimate_ondeday_gb > 100.0 and total_devices >= 1000: 
					if cluster_size < 6 or cpu_count < 32 or memory_size < 128:
						check_result = 'Failed'
						check_analysis = '''The CPU Count/Memory size is insufficient for the daily incoming Approute data.\n
											DPI is disabled.'''
						check_action =  'Server hardware size may need to be changed according to the rate of daily incoming Approute data.'
				else:
					check_result = 'SUCCESSFUL'
					check_analysis = '''The rate of daily incoming Approute data is within limits.\n
										DPI is disabled.'''
					check_action = None

	elif dpi_status == 'enable':
		for index in (es_indices_est[1]['Per index disk space ']):   
			if index['index'] == 'DPI' and index['status'] != 'success':
				dpi_estimate_ondeday = None

			elif index['index'] == 'Approute' and index['status'] != 'success':
				appr_estimate_ondeday = 0

			elif index['index'] == 'DPI' and index['status'] == 'success':
				dpi_estimate_ondeday = index['estimation']['1 day   ']
				if 'KB' in dpi_estimate_ondeday:
					dpi_estimate_ondeday_gb = float(dpi_estimate_ondeday.split(' ')[0])/(1024**2)
				elif 'MB' in dpi_estimate_ondeday:
					dpi_estimate_ondeday_gb = float(dpi_estimate_ondeday.split(' ')[0])/(1024)
				elif 'GB' in dpi_estimate_ondeday:
					dpi_estimate_ondeday_gb = float(dpi_estimate_ondeday.split(' ')[0])
				elif 'TB' in dpi_estimate_ondeday:
					dpi_estimate_ondeday_gb = float(dpi_estimate_ondeday.split(' ')[0])*(1024)

			elif index['index'] == 'Approute' and index['status'] == 'success':
				appr_estimate_ondeday = index['estimation']['1 day   ']
				if 'KB' in appr_estimate_ondeday:
					appr_estimate_ondeday_gb = float(appr_estimate_ondeday.split(' ')[0])/(1024**2)
				elif 'MB' in appr_estimate_ondeday:
					appr_estimate_ondeday_gb = float(appr_estimate_ondeday.split(' ')[0])/(1024)
				elif 'GB' in appr_estimate_ondeday:
					appr_estimate_ondeday_gb = float(appr_estimate_ondeday.split(' ')[0])
				elif 'TB' in appr_estimate_ondeday:
					appr_estimate_ondeday_gb = float(appr_estimate_ondeday.split(' ')[0])*(1024)


		if dpi_estimate_ondeday == None:
			check_result = 'Failed'
			check_analysis = 'The status of Index-DPI a is not success'
			check_action = 'Investigate why the Index-DPI status is not "success"'

		elif dpi_estimate_ondeday != None:
			total_estimate_oneday_gb = dpi_estimate_ondeday_gb + appr_estimate_ondeday_gb

			if server_type == 'on-cloud' :
				if total_estimate_oneday_gb > 500.0:
					check_result = 'Failed'
					check_analysis = 'The incoming rate of DPI is higher than expected.Consider using vAnalytics for DPI. Contact Cisco TAC for more information on this.'
					check_action = 'Server hardware size may need to be changed according to the rate of incoming DPI data.'
				else:
					check_result = 'SUCCESSFUL'
					check_analysis = 'The rate of daily incoming DPI data is within limits.'
					check_action = None

			elif server_type == 'on-prem':
				if dpi_estimate_ondeday_gb <= 50.0:
					if cpu_count < 32 or  memory_size < 128:
						check_result = 'Failed'
						check_analysis = 'The CPU Count/Memory size is insufficient for the daily incoming DPI data.'
						check_action =  'Server hardware size may need to be changed according to the DPI incoming rate.'

				elif dpi_estimate_ondeday_gb > 50.0 and dpi_estimate_ondeday_gb <= 100.0: 
					if cluster_size < 3 or cpu_count < 32 or memory_size < 128:
						check_result = 'Failed'
						check_analysis = 'The CPU Count/Memory size is insufficient for the daily incoming DPI data.'
						check_action =  'Server hardware size may need to be changed according to the DPI incoming rate.'

				elif dpi_estimate_ondeday_gb > 100.0 and total_devices < 1000: 
					if cluster_size < 3 or cpu_count < 32 or memory_size < 128:
						check_result = 'Failed'
						check_analysis = 'The CPU Count/Memory size is insufficient for the daily incoming DPI data.'
						check_action =  'Server hardware size may need to be changed according to the DPI incoming rate.'

				elif dpi_estimate_ondeday_gb > 100.0 and total_devices >= 1000: 
					if cluster_size < 6 or cpu_count < 32 or memory_size < 128:
						check_result = 'Failed'
						check_analysis = 'The CPU Count/Memory size is insufficient for the daily incoming DPI data.'
						check_action =  'Server hardware size may need to be changed according to the DPI incoming rate.'

				else:
					check_result = 'SUCCESSFUL'
					check_analysis = '''The rate of daily incoming DPI data is within limits.'''
					check_action = None
		
	return  appr_estimate_ondeday, dpi_estimate_ondeday, check_result, check_analysis, check_action
		


#10:Check:vManage:NTP status across network
def criticalCheckten(version_tuple, controllers_info):
	ntp_nonworking = []
	if version_tuple[0:2] < ('19','2'):
		for key in controllers_info:
			if controllers_info[key][0] != 'vbond':
				ntp_data = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'device/ntp/associations?deviceId=%s'%(controllers_info[key][1]), args.vmanage_port))
				if ntp_data['data'] == []:
					ntp_nonworking.append(controllers_info[key][1])
				else:
					continue
	elif version_tuple[0:2] >= ('19','2') and version_tuple[0:2] < ('20','5'):
		for key in controllers_info:
			if controllers_info[key][0] != 'vbond':
				ntp_data = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'device/ntp/associations?deviceId=%s'%(controllers_info[key][1]), args.vmanage_port, tokenid))
				if ntp_data['data'] == []:
					ntp_nonworking.append(controllers_info[key][1])
				else:
					continue
	elif version_tuple[0:2] > ('20','5'):
		for key in controllers_info:
			if controllers_info[key][0] != 'vbond':
				ntp_data = json.loads(getRequestpy3(version_tuple, vmanage_lo_ip, jsessionid, 'device/ntp/associations?deviceId=%s'%(controllers_info[key][1]), args.vmanage_port, tokenid))
				if ntp_data['data'] == []:
					ntp_nonworking.append(controllers_info[key][1])
				else:
					continue
	if len(ntp_nonworking) == 0:
		check_result = 'SUCCESSFUL'
		check_analysis = 'All controllers (vSmart\'s and vManage\'s) have valid ntp association'
		check_action = None
	elif len(ntp_nonworking) != 0:
		check_result = 'Failed'
		check_analysis = 'Devices with invalid ntp association found'
		check_action = 'Please validate the NTP time synchronization across the network '
	return ntp_nonworking, check_result, check_analysis, check_action

#11:Check:Controllers:Validate vSmart/vBond CPU count for scale 
def criticalCheckeleven(total_devices, vbond_info, vsmart_info):
	failed_vbonds = {}
	failed_vsmarts = {}
	
	for vsmart in vsmart_info:
		if vsmart_info[vsmart][7] < 2 and total_devices <= 50:
			failed_vsmarts[vsmart] = vsmart_info[vsmart]
		elif vsmart_info[vsmart][7] < 4 and total_devices > 50 and  total_devices <= 1000:
			failed_vsmarts[vsmart] = vsmart_info[vsmart]
		elif vsmart_info[vsmart][7] < 8 and total_devices > 1000:
			failed_vsmarts[vsmart] = vsmart_info[vsmart]
			
	for vbond in vbond_info:
		if vbond_info[vbond][7] < 2 and total_devices <= 1000:
			failed_vbonds[vbond] = vbond_info[vbond]
		elif vbond_info[vbond][7] < 4 and total_devices > 1000:
			failed_vbonds[vbond] = vbond_info[vbond]

	if len(failed_vbonds) != 0 or len(failed_vsmarts) != 0:
		check_result = 'Failed'
		check_analysis = 'vSmart/vBond CPU allocation count is not matching the design recommendation, for  the number of devices present'
		check_action = 'It is advisable to do VM resizing to match the network scale. For more information: https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html'
		
	else:
		check_result = 'SUCCESSFUL'
		check_analysis = 'vSmart/vBond CPU count is sufficient for the number of devices present'
		check_action = 'None'
			
	return failed_vbonds, failed_vsmarts, check_result, check_analysis, check_action

#12:Check:Cluster:Version consistency
def criticalChecktwelve(vmanage_info):
	for vmanage in vmanage_info:
		version = []
		version.append(vmanage_info[vmanage][2])
	if len(set(version)) == 1:
		check_result = 'SUCCESFUL'
		check_analysis = 'All the servers on the cluster have same version'
		check_action = 'None'
	else:
		check_result = 'Failed'
		check_analysis = 'Version in use across  all the servers in the cluster is not consistent'
		check_action = 'Evaluate if specific server should be upgraded before attempting overlay full upgrade'
	return check_result,check_analysis, check_action

#13:Check:Cluster:Cluster health
def criticalCheckthirteen(cluster_health_data):
	services_down = []
	for device in cluster_health_data['data'][0]['data']:
		(device['configJson'].pop('deviceIP'))
		(device['configJson'].pop('system-ip'))
		(device['configJson'].pop('uuid'))
		(device['configJson'].pop('host-name'))
		(device['configJson'].pop('state'))
		
		for service in device['configJson']:
			if device['configJson'][service]['status'] != 'normal' and device['configJson'][service]['status'] != 'disabled':
				services_down.append('vManageID:{} service: {}'.format(device['vmanageID'], service))

		 
	if len(services_down) != 0:
		check_result = 'Failed'
		check_analysis = 'The cluster has relevant services down'
		check_action = 'Troubleshoot why specific services show as down on a server '
	elif len(services_down) == 0:
		check_result = 'SUCCESFUL'
		check_analysis = 'The cluster has all relevant services up and running'
		check_action = 'None'
	return services_down, check_result,check_analysis, check_action
	
#14:Check:Cluster:Cluster ConfigDB topology
def criticalCheckfourteen(cluster_health_data):
	configDB_count = 0
	for device in cluster_health_data['data'][0]['data']:
		for service in device['configJson']:
			if (service == 'configuration-db'):
				configDB_count+=1
	if (configDB_count % 2) == 0:
		check_result = 'Failed'
		check_analysis = 'The cluster has even number of configDB servers'
		check_action = ' Cluster is not on a supported configuration. Modify cluster to have odd number of configDB owners (1,3,5) '
	else:
		check_result = 'SUCCESFUL'
		check_analysis = 'The cluster has odd number of configDB servers'
		check_action = None
	return configDB_count,check_result,check_analysis, check_action

#15:Check:Cluster:Messaging server
def criticalCheckfifteen(cluster_health_data):
	cluster_msdown = []
	for device in cluster_health_data['data'][0]['data']:
		for service in device['configJson']:
			if (service == 'messaging-server') and device['configJson'][service]['status'] != 'normal' and device['configJson'][service]['status'] != 'disabled':
				cluster_msdown.append('vManageID: {}, Host-name: {}'.format(device['vmanageID'],device['configJson']['host-name']))
	if len(cluster_msdown) != 0:
		check_result = 'Failed'
		check_analysis = 'All the servers in the cluster dont have message-service running'
		check_action = 'Cluster is not on a supported configuration. Modify cluster to have messaging server running '
	elif len(cluster_msdown) == 0:
		check_result = 'SUCCESFUL'
		check_analysis = 'All the servers in the cluster have message-service running'
		check_action = None
	return cluster_msdown,check_result,check_analysis, check_action


#16:Check:Cluster:DR replication status
def criticalChecksixteen(dr_data):
	dr_status = ''
	if dr_data['replicationDetails'] == []:
		dr_status = 'disabled'
		check_result = 'SUCCESSFUL'
		check_analysis = 'DR Replication is Disabled'
		check_action = None
	elif dr_data['replicationDetails']:
		dr_status = 'enabled'
		if dr_data['replicationDetails'][0]['replicationStatus'] == 'Success':
			check_action = 'SUCCESSFUL'
			check_analysis = 'DR replication Successful'
			check_result = None
		else:
			check_result = 'Failed'
			check_analysis = 'DR replication Failed'
			check_action = 'Troubleshoot why DR replication did not happen properly. Correct before attempting upgrade'
	else:
		dr_status = 'enabled'
		check_result = 'Failed'
		check_analysis = 'DR replication Failed'
		check_action = 'Troubleshoot why DR replication did not happen properly. Correct before attempting upgrade'
	return dr_status, check_action, check_analysis, check_result

all_processes = []

#17:Check:Cluster:Intercluster communication
def threadedpy3(f, daemon=False):

	def wrapped_f(q, *args, **kwargs):
		'''this function calls the decorated function and puts the 
		result in a queue'''

		ret = f(*args, **kwargs)
		q.put(ret)


	def wrap(*args, **kwargs):
		'''this is the function returned from the decorator. It fires off
		wrapped_f in a new thread and returns the thread object with
		the result queue attached'''
		q = queue.Queue()
		t = threading.Thread(target=wrapped_f, args=(q,) + args, kwargs=kwargs)
		t.daemon = daemon
		t.start()
		all_processes.append(t)
		t.result_queue = q       
		return t
	return wrap

@threadedpy3
def criticalCheckseventeenpy3(vmanage_info,  system_ip, log_file_logger):
	try:
		ping_output = {}
		ping_output_failed = {}

		for device in cluster_health_data['data'][0]['data']:
			vmanage_system_ip = device['configJson']['system-ip']
			vmanage_cluster_ip = device['configJson']['deviceIP']
			vmanage_host_name = device['configJson']['host-name']
			if vmanage_system_ip != system_ip:
				output = executeCommand('ping -w 5 {} &'.format(vmanage_cluster_ip))
				output = output.split('\n')[-3:]
				xmit_stats = output[0].split(",")
				timing_stats = xmit_stats[3]
				packet_loss = float(xmit_stats[2].split("%")[0])
				ping_output[vmanage_host_name] = vmanage_cluster_ip, packet_loss, timing_stats
				if packet_loss != 0:
					ping_output_failed[vmanage_host_name] = vmanage_cluster_ip, packet_loss, timing_stats

		if len(ping_output_failed) == 0:
			check_result = 'SUCCESSFUL'
			check_analysis = 'Intercluster communication is ok, ping to cluster nodes successful'
			check_action = None
		else:
			check_result = 'Failed'
			check_analysis = 'Intercluster connectivity issues found'
			check_action = 'Review network used between cluster members, and resolve any connectivity issues before upgrade process '
		return ping_output, ping_output_failed,check_result,check_analysis,check_action 
	except Exception as e:
		log_file_logger.exception(e)


def threaded(f, daemon=False):

	def wrapped_f(q, *args, **kwargs):
		'''this function calls the decorated function and puts the 
		result in a queue'''
		ret = f(*args, **kwargs)
		q.put(ret)

	def wrap(*args, **kwargs):
		'''this is the function returned from the decorator. It fires off
		wrapped_f in a new thread and returns the thread object with
		the result queue attached'''
		q = Queue.Queue()

		t = threading.Thread(target=wrapped_f, args=(q,)+args, kwargs=kwargs)
		t.daemon = daemon
		t.start()
		all_processes.append(t)
		t.result_queue = q        
		return t
	return wrap
	

@threaded 
def criticalCheckseventeen(cluster_health_data, system_ip, log_file_logger):
	try:
		ping_output = {}
		ping_output_failed = {}

		for device in cluster_health_data['data'][0]['data']:
			vmanage_system_ip = device['configJson']['system-ip']
			vmanage_cluster_ip = device['configJson']['deviceIP']
			vmanage_host_name = device['configJson']['host-name']
			if vmanage_system_ip != system_ip:
				output = executeCommand('ping -w 5 {} &'.format(vmanage_cluster_ip))
				output = output.split('\n')[-3:]
				xmit_stats = output[0].split(",")
				timing_stats = xmit_stats[3]
				packet_loss = float(xmit_stats[2].split("%")[0])
				ping_output[vmanage_host_name] = vmanage_cluster_ip, packet_loss, timing_stats
				if packet_loss != 0:
					ping_output_failed[vmanage_host_name] = vmanage_cluster_ip, packet_loss, timing_stats

		if len(ping_output_failed) == 0:
			check_result = 'SUCCESSFUL'
			check_analysis = 'Intercluster communication is ok, ping to cluster nodes successful'
			check_action = None
		else:
			check_result = 'Failed'
			check_analysis = 'Intercluster connectivity issues found'
			check_action = 'Review network used between cluster members, and resolve any connectivity issues before upgrade process '
		return ping_output, ping_output_failed,check_result,check_analysis,check_action 
	except Exception as e:
		log_file_logger.exception(e)


#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#Warning Checks

#01:Check:vManage:CPU Speed
def warningCheckone(cpu_speed):
	if cpu_speed < 2.8:
		check_result = 'Failed'
		check_analysis = 'CPU clock speed is {}, it is below recommended range as per the hardware guide. CPU clock speed should be greater than 2.8.'.format(cpu_speed)
		check_action = 'Upgrade the hardware type'
	else:
		check_result = 'SUCCESSFUL'
		check_analysis = 'CPU Clock speed is {}, matches hardware recommendations'.format(cpu_speed)
		check_action = None
	return check_result,check_analysis,check_action

#02:Check:vManage:Network Card type
def warningChecktwo():
	eth_data = executeCommand("ifconfig | grep '^eth[0-9]'")
	eth_drivers = {}
	eth_data = [e for e in eth_data.split() if 'eth' in e]
	for eth in eth_data:
		driver = executeCommand('ethtool -i {} | grep driver'.format(eth))
		if 'e1000' in driver.split()[1]:
			eth_drivers[eth] = driver.split()[1]
							  
	if len(eth_drivers) == 0:
		check_result = 'SUCCESSFUL'
		check_action = None
		check_analysis = 'VM is not using Intel e1000 card type'
		
	else:
		check_action = 'Intel e1000 controller types can lead to crashes and other stability issues. Customer should change NIC  hardware type used for the VM as soon as possible'
		check_analysis = 'VM is using Intel e1000 card type'
		check_result = 'Failed'
	return eth_drivers, check_action, check_analysis, check_result
  
#03:Check:vManage:Backup status
def warningCheckthree():
	if os.path.isfile('/var/log/nms/neo4j-backup.log') == False:
		date_time_obj = 'unknown'
		check_result = 'Failed'
		check_analysis = '/var/log/nms/neo4j-backup.log file not found'
		check_action = 'Investigate why the /var/log/nms/neo4j-backup.log is missing'

	elif os.path.isfile('/var/log/nms/neo4j-backup.log') == True:
		last_48hr_date = datetime.now() - timedelta(hours = 48)
		backup_log_data = executeCommand('tail -n 50 /var/log/nms/neo4j-backup.log')
		backup_log_data_list = re.split('(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', str(backup_log_data))
		if 'Backup complete' not in str(backup_log_data):
			check_result = 'Failed'
			check_analysis = 'Unable to identify when the last backup was performed.'
			check_action = 'Please validate if there has been any recent backup available, before performing the upgrade'
			date_time_obj = 'unknown'
		elif 'Backup complete' in str(backup_log_data):
			for line in backup_log_data_list:
				if 'Backup complete' in line:
					last_backup_date = (backup_log_data_list[backup_log_data_list.index(line)-1])
					date_time_obj = datetime.strptime(last_backup_date, '%Y-%m-%d %H:%M:%S')
					if date_time_obj < last_48hr_date:
						check_result = 'Failed'
						check_analysis = 'The last backup is older than 48h, it is advisable to have a recent upgrade before attempting an upgrade.'
						check_action = 'Perform a Backup before upgrading'
					elif date_time_obj >= last_48hr_date:
						check_result = 'SUCCESSFUL'
						check_analysis = 'Last Backup preformed recently, it meets best practices recommendations'
						check_action = None
	

	return date_time_obj, check_result, check_analysis, check_action


#04:Check:vManage:Evaluate Neo4j performance
def warningCheckfour():
	if os.path.isfile('/var/log/nms/query.log') == False:
		check_result = 'Failed'
		check_analysis = '/var/log/nms/query.log file not found'
		check_action = 'Investigate why the /var/log/nms/query.log is missing'

	elif os.path.isfile('/var/log/nms/query.log') == True:
		with open ('/var/log/nms/query.log') as query_log_file:
			query_text = query_log_file.readlines()
		matches = []
		number = 0 
		for line in query_text:
			match1 = re.findall(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',  line)
			match2 = re.findall(r"\d+ ms", line)
			if match1 != [] and match2 != []:
				matches.append((match1,match2))

		last_24hr_date_time = datetime.now() - timedelta(hours = 24)
		num = len(matches)+1
		slow_queries = []
		for match in matches:
			date = match[0][0]
			time = int((match[1][0].split())[0])
			date_time_obj = datetime.strptime(date, '%Y-%m-%d %H:%M:%S')
			if date_time_obj > last_24hr_date_time and  time > 5000:
				slow_queries.append(match)

		if slow_queries != [] and len(slow_queries) >= 5:
			check_result = 'Failed'
			check_analysis = 'More than 5 slow queries found in /var/log/nms/query.log during the last 24 hours. Slow queries are queries that take more than 5 sec.'
			check_action = 'Open TAC case to investigate possible root causes. Most common cause is use of IDE as disk controller, they may point towards perfomance issues'
 
		elif slow_queries != [] and len(slow_queries) > 0 and len(slow_queries) < 5:
			check_result = 'SUCCESSFUL'
			check_analysis = 'No database performance issues found.'
			check_action = None 

		else:
			check_result = 'SUCCESSFUL'
			check_analysis = 'No database performance issues found.'
			check_action = None 

	return check_result, check_analysis, check_action


#05:Check:vManage:Confirm there are no pending tasks
def warningCheckfive(tasks):
	tasks_running= {}
	if tasks['runningTasks'] == []:
		check_result = 'SUCCESSFUL'
		check_analysis = 'There are no stuck or pending tasks on the server'
		check_action = None
	else:
		for task in tasks:
			name = tasks[task][0]['name']
			start_time = tasks[task][0]['startTime']
			tasks_running[name] = start_time
		check_result = 'Failed'
		check_analysis = 'Stuck/Pending Tasks found'
		check_action = 'Clear pending tasks, wait for them to complete, or open TAC case to get task removed'
	return tasks_running, check_result, check_analysis, check_action
			

#06:Check:vManage:Validate there are no empty password users
def warningChecksix(version_tuple):
	if version_tuple[0:2] != ('20','3'):
		users_emptypass = []
		check_result = 'SUCCESSFUL'
		check_analysis = '#06:Check is not required on the current version'
		check_action = None
	else:
		json_userinfo = json.loads(showCommand('show aaa users | display json'))
		users_emptypass = []
		for user in (json_userinfo['data']['viptela-oper-system:aaa']['users']):
			if 'auth-type' not in user.keys():
				users_emptypass.append(user['name'])
		if len(users_emptypass) == 0:
			check_result = 'SUCCESSFUL'
			check_analysis = 'All users have authentication configured'
			check_action = None
		else:
			check_result = 'Failed'
			check_analysis = 'Users with missing passwords found'
			check_action = 'Add password to the users with missing password, or remove them'
	return users_emptypass, check_result, check_analysis, check_action



#07:Check:Controllers:Controller versions
def warningCheckseven(controllers_info):
	version_list = []
	for controller in controllers_info:
		version_list.append('.'.join(controllers_info[controller][2].split('.')[0:2]))
	if len(set(version_list))==1:
		check_result = 'SUCCESSFUL'
		check_analysis = 'Versions of all the controllers are same'
		check_action = None
	else:
		check_result = 'Failed'
		check_analysis = 'Versions of all the controllers do not match'
		check_action = 'All overlay components should belong to the same major.minor version family'
	return check_result, check_analysis, check_action
		

#08:Check:Controllers:Confirm Certificate Expiration Dates
def warningCheckeight(controllers_info):
	controllers_exp = {}
	controllers_notexp = {}
	for controller in controllers_info: 
		time_remaining = timedelta(seconds=controllers_info[controller][5])
		if timedelta(seconds=controllers_info[controller][5]) <= timedelta(seconds=2592000):
			controllers_exp[controller] = str(time_remaining)
		elif timedelta(seconds=controllers_info[controller][5]) > timedelta(seconds=2592000):
			controllers_notexp[controller] = str(time_remaining)
	if len(controllers_exp) == 0:
		check_result = 'SUCCESSFUL'
		check_analysis = 'Certificates are ok'
		check_action = None
	elif len(controllers_exp) != 0:
		check_result = 'Failed'
		check_analysis = 'Controllers with certificates close to expiration present'
		check_action = 'Renew respective certificates'
	return controllers_exp, controllers_notexp, check_result, check_analysis, check_action


#09:Check:Controllers:vEdge list sync
def warningChecknine(controllers_info):
	state_vedgeList = []
	for controller in controllers_info:
		if controllers_info[controller][6] != 'Sync':
			state_vedgeList.append(controller, controllers_info[controller][0], controllers_info[controller][1])
	if state_vedgeList == []:
		check_result = 'SUCCESSFUL'
		check_analysis = 'All the controllers have consistent state_vedgeList '
		check_action = None
	else:
		check_result = 'Failed'
		check_analysis = 'All the controllers do not have consistent state_vedgeList'
		check_action = 'Customer should do controller sync on vManage'
	return state_vedgeList ,check_result, check_analysis, check_action
		
#10:Check:Controllers: Confirm control connections
def warningCheckten(vsmart_count, vbond_count):

	control_sum_json = json.loads(showCommand('show control summary | display json'))
	control_sum_tab = showCommand('show control summary | tab')
	discrepancy = []
	for instance in control_sum_json['data']["viptela-security:control"]["summary"]:
		if (instance['vbond_counts']) != vbond_count or (instance['vsmart_counts']) != vsmart_count:
			discrepancy.append(instance)
	if len(discrepancy) != 0:
		check_result = 'Failed'
		check_analysis = 'The vbond and vsmart count on API call does not match the currently control connected devices.'
		check_action = 'Troubleshoot: vBond and vSmart count showing discrepancy.'
	elif len(discrepancy) == 0:
		check_result = 'SUCCESSFUL'
		check_analysis = 'The vBond and vSmart count on API call matches the currently control connected devices. '
		check_action = None                      
	return control_sum_tab, discrepancy, check_result, check_analysis, check_action

#11:Check:xEdge:Version compatibility



#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#Information Checks

#01:Check:vManage:Disk controller type
def infoCheckone(server_type, disk_controller):
	if server_type == 'on-prem':
		if 'hd' in [d for d in disk_controller.split('/') if d!= ''][1]:
			check_result = 'Failed'
			check_analysis = 'Disk Type is IDE'
			check_action = 'On most scenarios, changing IDE to SCSI can improve disk IO performance. When using 20.3 or higher, it is advisable to change the controller type on the VM configuration.'
		else:
			check_result = 'SUCCESSFUL'
			check_analysis = 'Disk type is not IDE, safe to upgrade. '
			check_action = None
	elif server_type == 'on-cloud':
		check_result = 'SUCCESSFUL'
		check_analysis = 'Check is not required for on-cloud deployments'
		check_action = None
	return check_result, check_analysis, check_action

#02:Check:Controllers:Validate there is at minimum vBond, vSmart present 
def infoChecktwo(vsmart_count, vbond_count):
	if vsmart_count >= 1 and vbond_count >= 1:
		check_result = 'SUCCESSFUL'
		check_analysis = 'One or more than one vBond and vSmart present, safe to upgrade'
		check_action = None
	else:
		check_result = 'Failed'
		check_analysis = 'At Minimum one vBond and vSmart not present'
		check_action = 'Customer to confirm if this is a lab scenario (and not full overlay)'
		
	return check_result, check_analysis, check_action


#03:Check:Controllers:Validate all controllers are reachable
def infoChecktthree(controllers_info):
	unreach_controllers = []
	for controller in controllers_info:
		if (controllers_info[controller][3]) != 'reachable' :
			unreach_controllers.append((controller,controllers_info[controller][1],controllers_info[controller][2]))
	if len(unreach_controllers) != 0:
		check_result = 'Failed'
		check_analysis = 'The vManage reported Controllers that are not reachable. '
		check_action = 'Either troubleshoot why the controller is down, or delete any invalid device from the overlay '
	elif len(unreach_controllers) == 0:
		check_result = 'SUCCESSFUL'
		check_analysis = 'All the controllers are reachable'
		check_action = None
	return unreach_controllers,check_result, check_analysis, check_action



if __name__ == "__main__":
	start_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

	#Validating the vmanage sever
	try:
		is_vmanage = is_vmanage() 
	except:
		raise SystemExit('\033[1;31m \n\n ERROR: Failed to identify if the server you are currently executing the script on is a vManage server, verify if you are running the script on a vManage server. \033[0;0m \n\n')
	
	if is_vmanage == False:
		raise SystemExit('\033[1;31m \n\n ERROR: The server on which you are currently executing the script is not a vManage server, AURA tool is specifically for vManage servers. \033[0;0m \n\n')

	#Parsing the arguments and validating the flag
	try:
		args = argumentParser()
		argValidation(args)
	except:
		raise SystemExit('\033[1;31m \n\n ERROR: Error validating the command line arguments. \033[0;0m \n\n')
	
	#Getting the password and validating it
	try:
		password = getpass.getpass('vManage Password:')
		if len(password) == 0:
			raise SystemExit('\033[1;31m \n\nERROR: Invalid Password provided \033[0;0m \n\n')
	except:
		raise SystemExit('\033[1;31m \n\nERROR: Invalid Password provided \033[0;0m \n\n')
	

	#vManage version and loopback ip address
	try:
		version, version_tuple = vManageVersion()
	except:
		raise SystemExit('\033[1;31m ERROR: Error identifying the current vManage version. \033[0;0m \n\n')

	try:
		vmanage_lo_ip = getLoip()
	except:
		vmanage_lo_ip = '127.0.0.1'
		print('\033[1;31m ERROR: Error retrieving the vManage loopback IP address. This may be related to issues on server name resolution (check with hostname -f). \033[0;0m \n\n')

	
	#Creating Directory
	directory_name = 'sdwan_sure'
	dir_path = '{}'.format(directory_name)
	try:
		createDir(dir_path)
	except:
		raise SystemExit('\033[1;31m ERROR: Error creating {} directory. \033[0;0m \n\n'.format(dir_path))
		
	#Creating Log file and Report File
	try:
		report_file_path =  '{}/sure_report_{}.txt'.format(dir_path, datetime.now().strftime("%d_%m_%Y_%H_%M_%S"))
		log_file_path = '{}/sure_logs_{}.log'.format(dir_path, datetime.now().strftime("%d_%m_%Y_%H_%M_%S"))
		report_file = createFile(report_file_path)
		log_file = createFile(log_file_path)

		setup_logger('log_file_logger', log_file_path)
		log_file_logger = logging.getLogger('log_file_logger')
	except:
		raise SystemExit('\033[1;31m ERROR: Error creating Report file and Log file. \033[0;0m \n\n')


	writeFile(report_file, 'Cisco SDWAN AURA v{} Report\n\n'.format(__sure_version))
	writeFile(report_file,	'''Cisco SDWAN AURA command line tool performed a total of 32 checks at different levels of the SDWAN overlay.
							 \nReach out to sure-tool@cisco.com  if you have any questions or feedback\n\n''')
	writeFile(report_file, 'Summary of the Results:\n')
	writeFile(report_file, '-----------------------------------------------------------------------------------------------------------------\n\n\n')
	
	

	print('#########################################################')
	print('###   	AURA SDWAN (SURE) - Version {}               ###'.format(__sure_version))
	print('#########################################################')
	print('###    Performing SD-WAN Audit & Upgrade Readiness    ###')
	print('#########################################################\n\n')


	#Normal  Execution 
	if args.quiet == False and args.debug  == False and args.verbose == False:
		log_file_logger.info('Executing the script in Normal execution mode')

		#version below 19.2
		if version_tuple[0:2] < ('19','2'):
			#Creating a session
			try:
				log_file_logger.info('Generating a JSessionID ')
				jsessionid = generateSessionID(vmanage_lo_ip, args.username, password, args.vmanage_port) 
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error generating JSessionID, make sure that the username and password entered is correct. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file.  \033[0;0m \n\n'.format(log_file_path))

			#Preliminary Data
			log_file_logger.info('****Collecting Preliminary Data\n')

			try:
				controllers = json.loads(getRequest(version_tuple, vmanage_lo_ip , jsessionid,'system/device/controllers', args.vmanage_port))
				controllers_info = controllersInfo(controllers)
				log_file_logger.info('Collected controllers information: {}'.format(controllers_info))

				out = getRequest(version_tuple, vmanage_lo_ip , jsessionid,'device/vmanage', args.vmanage_port)

				print(out)
				print(type(out))
				print(json.loads(getRequest(version_tuple, vmanage_lo_ip , jsessionid,'device/vmanage', args.vmanage_port)))
				system_ip_data = json.loads(getRequest(version_tuple, vmanage_lo_ip , jsessionid,'device/vmanage', args.vmanage_port))
				system_ip = system_ip_data['data']['ipAddress']
				log_file_logger.info('Collected vManage System IP address: {}'.format(system_ip))

				cpu_speed = cpuSpeed()
				log_file_logger.info('Collected vManage CPU Speed GHz: {}'.format(cpu_speed))

				cpu_count = cpuCount()
				log_file_logger.info('Collected vManage CPU Count: {}'.format(cpu_count))

				vedges = json.loads(getRequest(version_tuple, vmanage_lo_ip , jsessionid,'system/device/vedges', args.vmanage_port))
				vedge_count,vedge_count_active, vedge_info = vedgeCount(vedges)
				log_file_logger.info('Collected  xEdge Count: {}'.format(vedge_count))

				cluster_size, server_mode, vmanage_info = serverMode(controllers_info)
				log_file_logger.info('Collected vManage Cluster Size: {}'.format(cluster_size))
				log_file_logger.info('Collected vManage Server Mode: {}'.format(server_mode))

				disk_controller = diskController()
				log_file_logger.info('Collected vManage Disk Controller Type: {}'.format(disk_controller))

				dpi_stats = json.loads(getRequest(version_tuple, vmanage_lo_ip,jsessionid,  'statistics/settings/status', args.vmanage_port))
				dpi_status = dpiStatus(dpi_stats)
				log_file_logger.info('Collected DPI status: {}'.format(dpi_status))

				server_type = serverType()
				log_file_logger.info('Collected Server Type: {}'.format(server_type))

				vbond_info, vsmart_info = vbondvmartInfo(controllers_info)
				vbond_count = len(vbond_info)
				vsmart_count = len(vsmart_info)
				log_file_logger.info('vSmart info: {}'.format(vbond_info))
				log_file_logger.info('vBond info: {}'.format(vsmart_info))

				total_devices = len(controllers_info) + vedge_count
				log_file_logger.info('Total devices: {}'.format(total_devices))
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error Collecting Preliminary Data. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				
			print('*Starting Checks, this may take several minutes')

			#Critical Checks
			critical_checks = {}
			log_file_logger.info('*** Performing Critical Checks\n')
			print('\n**** Performing Critical checks\n')

			#Begining #30:Check:Cluster:Intercluster communication  in the background
			if cluster_size>1:
				log_file_logger.info('Beginging #30:Check:Cluster:Intercluster communication  in the background\n')
				try:    
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'clusterManagement/list', args.vmanage_port))
					criticalCheckseventeen =  criticalCheckseventeen(cluster_health_data,  system_ip, log_file_logger)
				except Exception as e:
					log_file_logger.exception('{}\n'.format(e))
				
			#01:Check:vManage:Validate current version
			print(' Critical Check:#01')
			log_file_logger.info('#01:Check:vManage:Validate current version')
			writeFile(report_file, '#01:Check:vManage:Validate current version\n\n')
			
			try:
				boot_partition_size, check_result, check_analysis, check_action =  criticalCheckone(version)
				if check_result == 'Failed':
					critical_checks['#01:Check:vManage:Validate current version'] = [ check_analysis, check_action]

					log_file_logger.error('#01: Check result:   {}'.format(check_result))
					log_file_logger.error('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#01: version: {}'.format(version))
					log_file_logger.error('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n'.format(check_action))
					
				else:
					log_file_logger.info('#01: Check result:   {}'.format(check_result))
					log_file_logger.info('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#01: version: {}'.format(version))
					log_file_logger.info('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
				   
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #01:Check:vManage:Validate current version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#02:Check:vManage:vManage sever disk space
			print(' Critical Check:#02')
			log_file_logger.info('#02:Check:vManage:At minimum 20%  server disk space should be available')
			writeFile(report_file, '#02:Check:vManage:At minimum 20%  server disk space should be available\n\n')

			try:
				optdata_partition_size, rootfs_partition_size, check_result, check_analysis, check_action =  criticalCheckTwo()
				if check_result == 'Failed': 
					critical_checks['#02:Check:vManage:At minimum 20%  server disk space should be available'] = [check_analysis, check_action]

					log_file_logger.error('#02: Check result:   {}'.format(check_result))
					log_file_logger.error('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.error('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#02: Check result:   {}'.format(check_result))
					log_file_logger.info('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.info('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: INFO -  {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #02:Check:vManage:At minimum 20%  server disk space should be available. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
			
			

			#03:Check:vManage:Memory size
			print(' Critical Check:#03')
			log_file_logger.info('#03:Check:vManage:Memory size')
			writeFile(report_file, '#03:Check:vManage:Memory size\n')
			writeFile(report_file, 'Link to the official documentation: \n https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html\n\n')
			try:
				memory_size, memory_size_str, dpi_status, server_type, check_result, check_analysis, check_action =  criticalCheckthree(vedge_count, dpi_status, server_type, cluster_size, version_tuple)
				if check_result == 'Failed':
					critical_checks['#03:Check:vManage:Memory size'] = [ check_analysis, check_action]

					log_file_logger.error('#03: Check result:   {}'.format(check_result))
					log_file_logger.error('#03: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#03: Memory Size GB: {}'.format(memory_size_str))
					log_file_logger.error('#03: /rootfs.rw Used: {}'.format(rootfs_partition_size))
					log_file_logger.error('#03: Server Type: {}'.format(server_type))
					log_file_logger.error('#03: vEdge Count: {}\n'.format(vedge_count))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#03: Check result:   {}'.format(check_result))
					log_file_logger.info('#03: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #03:Check:vManage:Memory size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			
			#04:Check:vManage:CPU Count
			print(' Critical Check:#04')
			log_file_logger.info('#04:Check:vManage:CPU Count')
			writeFile(report_file, '#04:Check:vManage:CPU Count\n\n')

			try:
				check_result, check_analysis, check_action = criticalCheckfour(cpu_count, vedge_count, dpi_status, server_type)
				if check_result == 'Failed':
					critical_checks['#04:Check:vManage:CPU Count'] = [ check_analysis, check_action]

					log_file_logger.error('#04: Check result:   {}'.format(check_result))
					log_file_logger.error('#04: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#04: CPU Count: {}\n'.format(cpu_count))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#04: Check result:   {}'.format(check_result))
					log_file_logger.info('#04: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #04:Check:vManage:CPU Count. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#05:Check:vManage:ElasticSearch Indices status
			print(' Critical Check:#05')
			log_file_logger.info('#05:Check:vManage:ElasticSearch Indices status')
			writeFile(report_file, '#05:Check:vManage:ElasticSearch Indices status\n\n')

			try:
				es_indexes_one = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'management/elasticsearch/index/info', args.vmanage_port))
				es_index_red_one, check_result_one, check_analysis_one, check_action_one = criticalCheckfive(es_indexes_one)
				time.sleep(5)
				es_indexes_two = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'management/elasticsearch/index/info', args.vmanage_port))
				es_index_red_two, check_result_two, check_analysis_two, check_action_two = criticalCheckfive(es_indexes_two)

				if check_result_one == 'Failed' and check_result_two == 'Failed':
					critical_checks['#05:Check:vManage:ElasticSearch Indices status'] = [ check_analysis_two, check_action_two]

					log_file_logger.error('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.error('#05: Check Analysis: {}\n'.format(check_analysis_two))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis_two))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action_two))
				   
				elif check_result_one == 'SUCCESSFUL':
					log_file_logger.info('#05: Check result:   {}'.format(check_result_one))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_one))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_one))

				elif check_result_two == 'SUCCESSFUL':

					log_file_logger.info('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_two))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_two))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #05:Check:vManage:ElasticSearch Indices status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#06:Check:vManage:Look for any neo4j exception errors
			print(' Critical Check:#06')
			log_file_logger.info('#06:Check:vManage:Look for any neo4j exception errors')
			writeFile(report_file, '#06:Check:vManage:Look for any neo4j exception errors\n\n')

			try:
				check_result, check_analysis, check_action = criticalChecksix()
				if check_result == 'Failed':
					critical_checks['#06:Check:vManage:Look for any neo4j exception errors'] = [check_analysis, check_action]

					log_file_logger.error('#06: Check result:   {}'.format(check_result))
					log_file_logger.error('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))


				else:
					log_file_logger.info('#06: Check result:   {}'.format(check_result))
					log_file_logger.info('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #06:Check:vManage:Look for any neo4j exception errors. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#07:Check:vManage:Validate all services are up
			print(' Critical Check:#07')
			log_file_logger.info('#07:Check:vManage:Validate all services are up')
			writeFile(report_file, '#07:Check:vManage:Validate all services are up\n\n')

			try:
				nms_data, nms_failed, check_result, check_analysis, check_action =   criticalCheckseven() 
				if check_result == 'Failed':
					critical_checks['#07:Check:vManage:Validate all services are up'] = [check_analysis, check_action]

					log_file_logger.error('#07: Check result:   {}'.format(check_result))
					log_file_logger.error('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#07: List of services that are enabled but not running:\n{}\n'.format(nms_failed))
					log_file_logger.error('#07: Status of all services  :\n{}\n'.format(nms_data))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
			 

				else:
					log_file_logger.info('#07: Check result:   {}'.format(check_result))
					log_file_logger.info('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#07: Status of all the services:\n{}\n'.format(nms_data))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #07:Check:vManage:Validate all services are up. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#08:Check:vManage:Elasticsearch Indices version
			print(' Critical Check:#08')
			log_file_logger.info('#08:Check:vManage:Elasticsearch Indices version')
			writeFile(report_file, '#08:Check:vManage:Elasticsearch Indices version\n\n')

			try:
				version_list, check_result, check_analysis, check_action = criticalCheckeight(version_tuple)
				if check_result == 'Failed':
					critical_checks['#08:Check:vManage:Elasticsearch Indices version'] = [ check_analysis, check_action]

					log_file_logger.error('#08: Check result:   {}'.format(check_result))
					log_file_logger.error('#08: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#08: List of indices with older versions  :\n{}\n'.format(version_list))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
	   
				else:
					log_file_logger.info('#08: Check result:   {}'.format(check_result))
					log_file_logger.info('#08: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #08:Check:vManage:Elasticsearch Indices version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#09:Check:vManage:Evaluate incoming DPI data size
			print(' Critical Check:#09')
			log_file_logger.info('#09:Check:vManage:Evaluate incoming DPI data size')
			writeFile(report_file, '#09:Check:vManage:Evaluate incoming DPI data size\n\n')

			try:
				es_indices_est = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'management/elasticsearch/index/size/estimate', args.vmanage_port))
				appr_estimate_ondeday, dpi_estimate_ondeday, check_result,check_analysis,check_action = criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count, total_devices, dpi_status)
				if check_result == 'Failed':
					critical_checks['#09:Check:vManage:Evaluate incoming DPI data size'] = [ check_analysis, check_action]

					log_file_logger.error('#09: Check result:   {}'.format(check_result))
					log_file_logger.error('#09: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#09: Daily incoming DPI data : {}'.format(dpi_estimate_ondeday))
					log_file_logger.error('#09: Daily incoming Approute data : {}\n'.format(appr_estimate_ondeday))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#09: Check result:   {}'.format(check_result))
					log_file_logger.info('#09: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #09:Check:vManage:Evaluate incoming DPI data size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#10:Check:vManage:NTP status across network
			print(' Critical Check:#10')
			log_file_logger.info('#10:Check:vManage:NTP status across network')
			writeFile(report_file, '#10:Check:vManage:NTP status across network\n\n')

			try:
				ntp_nonworking, check_result, check_analysis, check_action = criticalCheckten(version_tuple, controllers_info)
				if check_result == 'Failed':
					critical_checks['#10:Check:vManage:NTP status across network'] = [check_analysis, check_action]

					log_file_logger.error('#10: Check result:   {}'.format(check_result))
					log_file_logger.error('#10: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#10: Devices with invalid ntp associations:\n{}\n'.format(ntp_nonworking))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#10: Check result:   {}'.format(check_result))
					log_file_logger.info('#10: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #10:Check:vManage:NTP status across network. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#11:Check:Controllers:Validate vSmart/vBond CPU count for scale
			print(' Critical Check:#11')
			log_file_logger.info('#11:Check:Controllers:Validate vSmart/vBond CPU count for scale')
			writeFile(report_file, '#11:Check:Controllers:Validate vSmart/vBond CPU count for scale\n\n')
			
			try:
				for vbond in vbond_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip, jsessionid,'device/system/synced/status?deviceId={}'.format(vbond_info[vbond][1]),args.vmanage_port ))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vbond_info[vbond].append(total_cpu_count)

				for vsmart in vsmart_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip,jsessionid,'device/system/synced/status?deviceId={}'.format(vsmart_info[vsmart][1]), args.vmanage_port))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vsmart_info[vsmart].append(total_cpu_count)

				failed_vbonds,failed_vsmarts,check_result,check_analysis, check_action = criticalCheckeleven(total_devices, vbond_info, vsmart_info)
				if check_result == 'Failed':
					critical_checks['#11:Check:Controllers:Validate vSmart/vBond CPU count for scale'] = [ check_analysis, check_action]

					log_file_logger.error('#11: Check result:   {}'.format(check_result))
					log_file_logger.error('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#11: vBonds with insufficient CPU count: \n{}'.format(failed_vbonds))
					log_file_logger.error('#11: vSmarts with insufficient CPU count: \n{}'.format(failed_vsmarts))
					log_file_logger.error('#11: All vBonds info with total_cpu_count: \n{}'.format(vbond_info))
					log_file_logger.error('#11: All vSmarts info with total_cpu_count: \n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#11: Check result:   {}'.format(check_result))
					log_file_logger.info('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#11: All vBonds info with total_cpu_count:\n{}'.format(vbond_info))
					log_file_logger.info('#11: All vSmarts info with total_cpu_count:\n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #11:Check:Controllers:Validate vSmart/vBond CPU count for scale. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
			
			#Warning Checks
			print('\n**** Performing Warning checks\n')
			warning_checks = {}
			log_file_logger.info('*** Performing Warning Checks')

			#12:Check:vManage:CPU Speed
			print(' Warning Check:#12')
			log_file_logger.info('#12:Check:vManage:CPU Speed')
			writeFile(report_file, '#12:Check:vManage:CPU Speed\n\n')

			try:
				check_result,check_analysis,check_action = warningCheckone(cpu_speed)
				if check_result == 'Failed':
					warning_checks['#12:Check:vManage:CPU Speed'] = [ check_analysis, check_action]

					log_file_logger.error('#12: Check result:   {}'.format(check_result))
					log_file_logger.error('#12: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#12: CPU clock speed: {}\n'.format(cpu_speed))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#12: Check result:   {}'.format(check_result))
					log_file_logger.info('#12: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #12:Check:vManage:CPU Speed. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			
			#13:Check:vManage:Network Card type
			print(' Warning Check:#13')
			log_file_logger.info('#13:Check:vManage:Network Card type')
			writeFile(report_file, '#13:Check:vManage:Network Card type\n\n')

			try:
				eth_drivers, check_action, check_analysis, check_result = warningChecktwo()
				if check_result == 'Failed':
					warning_checks['#13:Check:vManage:Network Card type'] = [ check_analysis, check_action]

					log_file_logger.error('#13: Check result:   {}'.format(check_result))
					log_file_logger.error('#13: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#13: Ethercardswith e1000 card types: {}\n'.format(eth_drivers))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				 

				else:
					log_file_logger.info('#13: Check result:   {}'.format(check_result))
					log_file_logger.info('#13: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #13:Check:vManage:Network Card type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			
			#14:Check:vManage:Backup status
			print(' Warning Check:#14')
			log_file_logger.info('#14:Check:vManage:Backup status')
			writeFile(report_file, '#14:Check:vManage:Backup status\n\n')

			try:
				date_time_obj, check_result, check_analysis, check_action = warningCheckthree()
				if check_result == 'Failed':
					warning_checks['#14:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#14: Check result:   {}'.format(check_result))
					log_file_logger.error('#14: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#14: Last Backup was performed on:{}\n'.format(date_time_obj))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#14: Check result:   {}'.format(check_result))
					log_file_logger.info('#14: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #14:Check:vManage:Backup status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
			
			#15:Check:vManage:Evaluate Neo4j performance
			print(' Warning Check:#15')
			log_file_logger.info('#15:Check:vManage:Evaluate Neo4j performance')
			writeFile(report_file, '#15:Check:vManage:Evaluate Neo4j performance\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckfour()
				if check_result == 'Failed':
					warning_checks['#15:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#15: Check result:   {}'.format(check_result))
					log_file_logger.error('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#15: Check result:   {}'.format(check_result))
					log_file_logger.info('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #15:Check:vManage:Evaluate Neo4j performance. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
			
			#16:Check:vManage:Confirm there are no pending tasks
			print(' Warning Check:#16')
			log_file_logger.info('#16:Check:vManage:Confirm there are no pending tasks')
			writeFile(report_file, '#16:Check:vManage:Confirm there are no pending tasks\n\n')

			try:
				tasks = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'device/action/status/tasks', args.vmanage_port))
				tasks_running, check_result, check_analysis, check_action  = warningCheckfive(tasks)
				if check_result == 'Failed':
					warning_checks['#16:Check:vManage:Confirm there are no pending tasks'] = [ check_analysis, check_action]
					log_file_logger.error('#16: Check result:   {}'.format(check_result))
					log_file_logger.error('#16: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#16: Tasks still running: {}\n'.format(tasks_running))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#16: Check result:   {}'.format(check_result))
					log_file_logger.info('#16: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #16:Check:vManage:Confirm there are no pending tasks. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
			
			#17:Check:vManage:Validate there are no empty password users
			print(' Warning Check:#17')
			log_file_logger.info('#17:Check:vManage:Validate there are no empty password users')
			writeFile(report_file, '#17:Check:vManage:Validate there are no empty password users\n\n')
				
			try:
				users_emptypass, check_result, check_analysis, check_action = warningChecksix(version_tuple)
				if check_result == 'Failed':
					warning_checks['#17:Check:vManage:Validate there are no empty password users'] = [ check_analysis, check_action]
					log_file_logger.error('#17: Check result:   {}'.format(check_result))
					log_file_logger.error('#17: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#17: Users with empty passwords: {}\n'.format(users_emptypass))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#17: Check result:   {}'.format(check_result))
					log_file_logger.info('#17: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #17:Check:vManage:Validate there are no empty password users. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
			
			#18:Check:Controllers:Controller versions
			print(' Warning Check:#18')
			log_file_logger.info('#18:Check:Controllers:Controller versions')
			writeFile(report_file, '#18:Check:Controllers:Controller versions\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckseven(controllers_info)
				if check_result == 'Failed':
					warning_checks['#18:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#18: Check result:   {}'.format(check_result))
					log_file_logger.error('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#18: Check result:   {}'.format(check_result))
					log_file_logger.info('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #18:Check:Controllers:Controller versions. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
			
			#19:Check:Controllers:Confirm Certificate Expiration Dates
			print(' Warning Check:#19')
			log_file_logger.info('#19:Check:Controllers:Confirm Certificate Expiration Dates')
			writeFile(report_file, '#19:Check:Controllers:Confirm Certificate Expiration Dates\n\n')

			try:
				controllers_exp, controllers_notexp, check_result, check_analysis, check_action = warningCheckeight(controllers_info)
				if check_result == 'Failed':
					warning_checks['#19:Check:Controllers:Confirm Certificate Expiration Dates'] = [ check_analysis, check_action]
					log_file_logger.error('#19: Check result:   {}'.format(check_result))
					log_file_logger.error('#19: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#19: Controllers with certificates close to expiration:\n{}\n'.format(controllers_exp))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				  

				else:
					log_file_logger.info('#19: Check result:   {}'.format(check_result))
					log_file_logger.info('#19: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				 
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #19:Check:Controllers:Confirm Certificate Expiration Dates. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
			
			#20:Check:Controllers:vEdge list sync
			print(' Warning Check:#20')
			log_file_logger.info('#20:Check:Controllers:vEdge list sync')
			writeFile(report_file, '#20:Check:Controllers:vEdge list sync\n\n')

			try:
				state_vedgeList,check_result, check_analysis, check_action  = warningChecknine(controllers_info)
				if check_result == 'Failed':
					warning_checks['#20:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#20: Check result:   {}'.format(check_result))
					log_file_logger.error('#20: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#20: Controllers with inconsistent state_vedgeList: {}\n'.format(state_vedgeList))
					
					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				   
				else:
					log_file_logger.info('#20: Check result:   {}'.format(check_result))
					log_file_logger.info('#20: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #20:Check:Controllers:vEdge list sync. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
			
			#21:Check:Controllers: Confirm control connections
			print(' Warning Check:#21')
			log_file_logger.info('#21:Check:Controllers: Confirm control connections')
			writeFile(report_file, '#21:Check:Controllers: Confirm control connections\n\n')

			try:
				control_sum_tab, discrepancy,check_result, check_analysis, check_action = warningCheckten(vsmart_count, vbond_count)
				if check_result == 'Failed':
					warning_checks['#21:Check:Controllers: Confirm control connections'] = [ check_analysis, check_action]

					log_file_logger.error('#21: Check result:   {}'.format(check_result))
					log_file_logger.error('#21: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#21: Control Connections Summary\n{}\n'.format(control_sum_tab))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#21: Check result:   {}'.format(check_result))
					log_file_logger.info('#21: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #21:Check:Controllers: Confirm control connections. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
			
		  
			#Informational Checks
			print('\n**** Performing Informational checks\n')
			log_file_logger.info('*** Performing Informational Checks')

			#22:Check:vManage:Disk controller type
			print(' Informational Check:#22')
			log_file_logger.info('#22:Check:vManage:Disk controller type')
			writeFile(report_file, '#22:Check:vManage:Disk controller type\n\n')

			try:
				check_result, check_analysis, check_action = infoCheckone(server_type, disk_controller)
				if check_result == 'Failed':
					warning_checks['#22:Check:vManage:Disk controller type'] = [ check_analysis, check_action]

					log_file_logger.error('#22: Check result:   {}'.format(check_result))
					log_file_logger.error('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#22: Check result:   {}'.format(check_result))
					log_file_logger.info('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #22:Check:vManage:Disk controller type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
			
			#23:Check:Controllers:Validate there is at minimum vBond, vSmart present
			print(' Informational Check:#23')
			log_file_logger.info('#23:Check:Controllers:Validate there is at minimum vBond, vSmart present')
			writeFile(report_file, '#23:Check:Controllers:Validate there is at minimum vBond, vSmart present\n\n')

			try:
				check_result, check_analysis, check_action = infoChecktwo(vsmart_count,vbond_count)
				if check_result == 'Failed':
					warning_checks['#23:Check:Controllers:Validate there is at minimum vBond, vSmart present'] = [ check_analysis, check_action]

					log_file_logger.error('#23: Check result:   {}'.format(check_result))
					log_file_logger.error('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.error('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
			   

				else:
					log_file_logger.info('#23: Check result:   {}'.format(check_result))
					log_file_logger.info('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.info('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #23:Check:Controllers:Validate there is at minimum vBond, vSmart present. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
			
			#24:Check:Controllers:Validate all controllers are reachable
			print(' Informational Check:#24')
			log_file_logger.info('#24:Check:Controllers:Validate all controllers are reachable')
			writeFile(report_file, '#24:Check:Controllers:Validate all controllers are reachable\n\n')
				
			try:
				unreach_controllers,check_result, check_analysis, check_action = infoChecktthree(controllers_info)
				if check_result == 'Failed':
					warning_checks['#24:Check:Controllers:Validate all controllers are reachable'] = [ check_analysis, check_action]

					log_file_logger.error('#24: Check result:   {}'.format(check_result))
					log_file_logger.error('#24: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#24: Unreachable Controllers: {}\n'.format(unreach_controllers))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#24: Check result:   {}'.format(check_result))
					log_file_logger.info('#24: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #24:Check:Controllers:Validate all controllers are reachable. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			if cluster_size>1:
				cluster_checks = {}
				log_file_logger.info('*** Performing Cluster Checks')
				print('\n**** Performing Cluster checks\n')

				#25:Check:Cluster:Version consistency
				print(' Cluster Check:#25')
				log_file_logger.info('#25:Check:Cluster:Version consistency')
				writeFile(report_file, '#25:Check:Cluster:Version consistency\n\n')

				try:
					check_result,check_analysis, check_action = criticalChecktwelve(vmanage_info)
					if check_result == 'Failed':
						cluster_checks['#25:Check:Cluster:Version consistency'] = [ check_analysis, check_action]

						log_file_logger.error('#25: Check result:   {}'.format(check_result))
						log_file_logger.error('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
						

					else:
						log_file_logger.info('#25: Check result:   {}'.format(check_result))
						log_file_logger.info('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						
				except Exception as e:
					print('\033[1;31m ERROR: Error performing #25:Check:Cluster:Version consistency. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#26:Check:Cluster:Cluster health
				print(' Cluster Check:#26')
				log_file_logger.info('#26:Check:Cluster:Cluster health')
				writeFile(report_file, '#26:Check:Cluster:Cluster health\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'clusterManagement/list', args.vmanage_port))
					services_down, check_result, check_analysis, check_action = criticalCheckthirteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#26:Check:Cluster:Cluster health'] = [ check_analysis, check_action]

						log_file_logger.error('#26: Check result:   {}'.format(check_result))
						log_file_logger.error('#26: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#26: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

					else: 
						log_file_logger.info('#26: Check result:   {}'.format(check_result))
						log_file_logger.info('#26: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #26:Check:Cluster:Cluster health. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#27:Check:Cluster:Cluster ConfigDB topology
				print(' Cluster Check:#27')
				log_file_logger.info('#27:Check:Cluster:Cluster ConfigDB topology')
				writeFile(report_file, '#27:Check:Cluster:Cluster ConfigDB topology\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid,'clusterManagement/list', args.vmanage_port))           
					configDB_count, check_result, check_analysis, check_action = criticalCheckfourteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#27:Check:Cluster:Cluster ConfigDB topology'] = [ check_analysis, check_action]

						log_file_logger.error('#27: Check result:   {}'.format(check_result))
						log_file_logger.error('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					else: 
						log_file_logger.info('#27: Check result:   {}'.format(check_result))
						log_file_logger.info('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #27:Check:Cluster:Cluster ConfigDB topology. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#28:Check:Cluster:Messaging server
				print(' Cluster Check:#28')
				log_file_logger.info('#28:Check:Cluster:Messaging server')
				writeFile(report_file, '#28:Check:Cluster:Messaging server\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'clusterManagement/list', args.vmanage_port))           
					cluster_msdown,check_result,check_analysis, check_action = criticalCheckfifteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#28:Check:Cluster:Messaging server'] = [ check_analysis, check_action]

						log_file_logger.error('#28: Check result:   {}'.format(check_result))
						log_file_logger.error('#28: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#28: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					else: 
						log_file_logger.info('#28: Check result:   {}'.format(check_result))
						log_file_logger.info('#28: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #28:Check:Cluster:Messaging server. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#29:Check:Cluster:DR replication status
				print(' Cluster Check:#29')
				log_file_logger.info('#29:Check:Cluster:DR replication status')
				writeFile(report_file, '#29:Check:Cluster:DR replication status\n\n')

				try:
					dr_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'disasterrecovery/details', args.vmanage_port))           
					dr_status, check_action, check_analysis, check_result = criticalChecksixteen(dr_data)
					if check_result == 'Failed':
						cluster_checks['#29:Check:Cluster:DR replication status'] = [ check_analysis, check_action]

						log_file_logger.error('#29: Check result:   {}'.format(check_result))
						log_file_logger.error('#29: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#29: DR Replication status: {}\n'.format(dr_status))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					else:
						log_file_logger.info('#29: Check result:   {}'.format(check_result))
						log_file_logger.info('#29: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #29:Check:Cluster:DR replication status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#30:Check:Cluster:Intercluster communication
				print(' Cluster Check:#30')
				log_file_logger.info('#30:Check:Cluster:Intercluster communication')
				writeFile(report_file, '#30:Check:Cluster:Intercluster communication\n\n')

				try:
					if criticalCheckseventeen.isAlive():
						criticalCheckseventeen.join(10)

					if not criticalCheckseventeen.result_queue.empty():
						ping_output, ping_output_failed, ping_check_result, ping_check_analysis, ping_check_action = criticalCheckseventeen.result_queue.get()
						if ping_check_result == 'Failed':
							cluster_checks['#30:Check:Cluster:Intercluster communication'] = [ ping_check_analysis, ping_check_action]

							log_file_logger.error('#30: Check result:   {}'.format(ping_check_result))
							log_file_logger.error('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.error('#30: Cluster nodes with ping failure: {}\n'.format(ping_output_failed))

						
							writeFile(report_file, 'Result: ERROR - {}\n'.format(ping_check_analysis))
							writeFile(report_file, 'Action: {}\n\n'.format(ping_check_analysis))

						else:
							log_file_logger.info('#30: Check result:   {}'.format(ping_check_result))
							log_file_logger.info('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.info('#30: Cluster nodes details: {}\n'.format(ping_output))

							writeFile(report_file, 'Result: INFO - {}\n\n'.format(ping_check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #30:Check:Cluster:Intercluster communication. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

			#Logging out of the Session using jsessionid
			log_file_logger.info('Logging out of the Session')
			sessionLogout(vmanage_lo_ip,jsessionid,args.vmanage_port)
			log_file_logger.info('Successfully closed the connection')
			
			

		#version equal to or above 19.2 and below 20.5
		elif version_tuple[0:2] >= ('19','2') and version_tuple[0:2] < ('20','5'): 
			try:
				log_file_logger.info('Generating a JSessionID')
				jsessionid = generateSessionID(vmanage_lo_ip, args.username, password, args.vmanage_port)
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error generating JSessionID, make sure that the username and password entered is correct. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))

			try:
				log_file_logger.info('Generating CSRF Token')
				tokenid = CSRFToken(vmanage_lo_ip,jsessionid,args.vmanage_port)
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error generating CSRF Token. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))

			#Preliminary data
			log_file_logger.info('****Collecting Preliminary Data\n')

			try:
				controllers = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'system/device/controllers', args.vmanage_port, tokenid))
				controllers_info = controllersInfo(controllers)
				log_file_logger.info('Collected controllers information: {}'.format(controllers_info))

				
				system_ip_data = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'device/vmanage', args.vmanage_port, tokenid))
				system_ip = system_ip_data['data']['ipAddress']
				log_file_logger.info('Collected vManage System IP address: {}'.format(system_ip))

				cpu_speed = cpuSpeed()
				log_file_logger.info('Collected vManage CPU Speed GHz: {}'.format(cpu_speed))

				cpu_count = cpuCount()
				log_file_logger.info('Collected vManage CPU Count: {}'.format(cpu_count))

				vedges = json.loads(getRequest(version_tuple, vmanage_lo_ip,jsessionid, 'system/device/vedges', args.vmanage_port , tokenid))
				vedge_count,vedge_count_active, vedge_info = vedgeCount(vedges)
				log_file_logger.info('Collected  xEdge Count: {}'.format(vedge_count))

				cluster_size, server_mode, vmanage_info = serverMode(controllers_info)
				log_file_logger.info('Collected vManage Cluster Size: {}'.format(cluster_size))
				log_file_logger.info('Collected vManage Server Mode: {}'.format(server_mode))

				disk_controller = diskController()
				log_file_logger.info('Collected vManage Disk Controller Type: {}'.format(disk_controller))

				dpi_stats = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid,'statistics/settings/status', args.vmanage_port, tokenid))
				dpi_status = dpiStatus(dpi_stats)
				log_file_logger.info('Collected DPI Status: {}'.format(dpi_status))

				server_type = serverType()
				log_file_logger.info('Collected Server Type: {}'.format(server_type))

				vbond_info, vsmart_info = vbondvmartInfo(controllers_info)
				vbond_count = len(vbond_info)
				vsmart_count = len(vsmart_info)
				log_file_logger.info('vSmart info: {}'.format(vbond_info))
				log_file_logger.info('vBond info: {}'.format(vsmart_info))
				
				total_devices = len(controllers_info.keys()) + vedge_count
				log_file_logger.info('Total devices: {}'.format(total_devices))

			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error Collecting Preliminary Data. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				

			print('*Starting Checks, this may take several minutes\n\n')

			#Critical Checks
			print('\n**** Performing Critical checks\n')

			#Begining #30:Check:Cluster:Intercluster communication  in the background
			if cluster_size>1:
				log_file_logger.info('Beginging #30:Check:Cluster:Intercluster communication  in the background\n')
				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid,  'clusterManagement/list', args.vmanage_port, tokenid))
					criticalCheckseventeen =  criticalCheckseventeen(cluster_health_data,  system_ip, log_file_logger)
				except Exception as e:
					log_file_logger.exception('{}\n'.format(e))

			critical_checks = {}
			log_file_logger.info('*** Performing Critical Checks\n')

			#01:Check:vManage:Validate current version
			print(' Critical Check:#01')
			log_file_logger.info('#01:Check:vManage:Validate current version')
			writeFile(report_file, '#01:Check:vManage:Validate current version\n\n')
			
			try:
				boot_partition_size, check_result, check_analysis, check_action =  criticalCheckone(version)
				if check_result == 'Failed':
					critical_checks['#01:Check:vManage:Validate current version'] = [ check_analysis, check_action]

					log_file_logger.error('#01: Check result:   {}'.format(check_result))
					log_file_logger.error('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#01: version: {}'.format(version))
					log_file_logger.error('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				   
				else:
					log_file_logger.info('#01: Check result:   {}'.format(check_result))
					log_file_logger.info('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#01: version: {}'.format(version))
					log_file_logger.info('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
			
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #01:Check:vManage:Validate current version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#02:Check:vManage:At minimum 20%  server disk space should be available
			print(' Critical Check:#02')
			log_file_logger.info('#02:Check:vManage:At minimum 20%  server disk space should be available')
			writeFile(report_file, '#02:Check:vManage:At minimum 20%  server disk space should be available\n\n')

			try:
				optdata_partition_size, rootfs_partition_size, check_result, check_analysis, check_action =  criticalCheckTwo()
				if check_result == 'Failed': 
					critical_checks['#02:Check:vManage:At minimum 20%  server disk space should be available'] = [check_analysis, check_action]

					log_file_logger.error('#02: Check result:   {}'.format(check_result))
					log_file_logger.error('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.error('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#02: Check result:   {}'.format(check_result))
					log_file_logger.info('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.info('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #02:Check:vManage:At minimum 20%  server disk space should be available. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#03:Check:vManage:Memory size
			print(' Critical Check:#03')
			log_file_logger.info('#03:Check:vManage:Memory size')
			writeFile(report_file, '#03:Check:vManage:Memory size\n')
			writeFile(report_file, 'Link to the official documentation: \n https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html\n\n')

			try:
				memory_size, memory_size_str, dpi_status, server_type, check_result, check_analysis, check_action =  criticalCheckthree(vedge_count, dpi_status, server_type, cluster_size, version_tuple)
				if check_result == 'Failed':
					critical_checks['#03:Check:vManage:Memory size'] = [ check_analysis, check_action]

					log_file_logger.error('#03: Check result:   {}'.format(check_result))
					log_file_logger.error('#03: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#03: Memory Size GB: {}'.format(memory_size_str))
					log_file_logger.error('#03: /rootfs.rw Used: {}'.format(rootfs_partition_size))
					log_file_logger.error('#03: Server Type: {}'.format(server_type))
					log_file_logger.error('#03: vEdge Count: {}\n'.format(vedge_count))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				  
				else:
					log_file_logger.info('#03: Check result:   {}'.format(check_result))
					log_file_logger.info('#03: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #03:Check:vManage:Memory size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
	 
			#04:Check:vManage:CPU Count
			print(' Critical Check:#04')
			log_file_logger.info('#04:Check:vManage:CPU Count')
			writeFile(report_file, '#04:Check:vManage:CPU Count\n\n')

			try:
				check_result, check_analysis, check_action = criticalCheckfour(cpu_count, vedge_count, dpi_status, server_type)
				if check_result == 'Failed':
					critical_checks['#04:Check:vManage:CPU Count'] = [ check_analysis, check_action]

					log_file_logger.error('#04: Check result:   {}'.format(check_result))
					log_file_logger.error('#04: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#04: CPU Count: {}\n'.format(cpu_count))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#04: Check result:   {}'.format(check_result))
					log_file_logger.info('#04: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #04:Check:vManage:CPU Count. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#05:Check:vManage:ElasticSearch Indices status
			print(' Critical Check:#05')
			log_file_logger.info('#05:Check:vManage:ElasticSearch Indices status')
			writeFile(report_file, '#05:Check:vManage:ElasticSearch Indices status\n\n')

			try:
				es_indexes_one = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_index_red_one, check_result_one, check_analysis_one, check_action_one = criticalCheckfive(es_indexes_one)

				time.sleep(5)

				es_indexes_two = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_index_red_two, check_result_two, check_analysis_two, check_action_two = criticalCheckfive(es_indexes_two)

				if check_result_one == 'Failed' and check_result_two == 'Failed':
					critical_checks['#05:Check:vManage:ElasticSearch Indices status'] = [ check_analysis_two, check_action_two]

					log_file_logger.error('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.error('#05: Check Analysis: {}\n'.format(check_analysis_two))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis_two))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action_two))
				   
				elif check_result_one == 'SUCCESSFUL':
					log_file_logger.info('#05: Check result:   {}'.format(check_result_one))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_one))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_one))

				elif check_result_two == 'SUCCESSFUL':

					log_file_logger.info('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_two))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_two))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #05:Check:vManage:ElasticSearch Indices status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#06:Check:vManage:Look for any neo4j exception errors
			print(' Critical Check:#06')
			log_file_logger.info('#06:Check:vManage:Look for any neo4j exception errors')
			writeFile(report_file, '#06:Check:vManage:Look for any neo4j exception errors\n\n')

			try:
				check_result, check_analysis, check_action = criticalChecksix()
				if check_result == 'Failed':
					critical_checks['#06:Check:vManage:Look for any neo4j exception errors'] = [check_analysis, check_action]

					log_file_logger.error('#06: Check result:   {}'.format(check_result))
					log_file_logger.error('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#06: Check result:   {}'.format(check_result))
					log_file_logger.info('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #06:Check:vManage:Look for any neo4j exception errors. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#07:Check:vManage:Validate all services are up
			print(' Critical Check:#07')
			log_file_logger.info('#07:Check:vManage:Validate all services are up')
			writeFile(report_file, '#07:Check:vManage:Validate all services are up\n\n')

			try:
				nms_data, nms_failed, check_result, check_analysis, check_action =   criticalCheckseven() 
				if check_result == 'Failed':
					critical_checks['#07:Check:vManage:Validate all services are up'] = [check_analysis, check_action]

					log_file_logger.error('#07: Check result:   {}'.format(check_result))
					log_file_logger.error('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#07: List of services that are enabled but not running:\n{}'.format(nms_failed))
					log_file_logger.error('#07: Status of all services  :\n{}\n'.format(nms_data))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))                   

				else:
					log_file_logger.info('#07: Check result:   {}'.format(check_result))
					log_file_logger.info('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#07: Status of all the services:\n{}\n'.format(nms_data))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #07:Check:vManage:Validate all services are up. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#08:Check:vManage:Elasticsearch Indices version
			print(' Critical Check:#08')
			log_file_logger.info('#08:Check:vManage:Elasticsearch Indices version')
			writeFile(report_file, '#08:Check:vManage:Elasticsearch Indices version\n\n')

			try:
				version_list, check_result, check_analysis, check_action = criticalCheckeight(version_tuple)
				if check_result == 'Failed':
					critical_checks['#08:Check:vManage:Elasticsearch Indices version'] = [ check_analysis, check_action]

					log_file_logger.error('#08: Check result:   {}'.format(check_result))
					log_file_logger.error('#08: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#08: List of indices with older versions  :\n{}\n'.format(version_list))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#08: Check result:   {}'.format(check_result))
					log_file_logger.info('#08: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #08:Check:vManage:Elasticsearch Indices version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#09:Check:vManage:Evaluate incoming DPI data size
			print(' Critical Check:#09')
			log_file_logger.info('#09:Check:vManage:Evaluate incoming DPI data size')
			writeFile(report_file, '#09:Check:vManage:Evaluate incoming DPI data size\n\n')

			try:
				es_indices_est = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'management/elasticsearch/index/size/estimate', args.vmanage_port, tokenid))
				appr_estimate_ondeday, dpi_estimate_ondeday, check_result, check_analysis,check_action = criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count , total_devices, dpi_status)
				if check_result == 'Failed':
					critical_checks['#09:Check:vManage:Evaluate incoming DPI data size'] = [check_analysis, check_action]

					log_file_logger.error('#09: Check result:    {}'.format(check_result))
					log_file_logger.error('#09: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#09: Daily incoming DPI data : {}'.format(dpi_estimate_ondeday))
					log_file_logger.error('#09: Daily incoming Approute data : {}\n'.format(appr_estimate_ondeday))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#09: Check result:    {}'.format(check_result))
					log_file_logger.info('#09: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #09:Check:vManage:Evaluate incoming DPI data size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#10:Check:vManage:NTP status across network
			print(' Critical Check:#10')
			log_file_logger.info('#10:Check:vManage:NTP status across network')
			writeFile(report_file, '#10:Check:vManage:NTP status across network\n\n')

			try:
				ntp_nonworking, check_result, check_analysis, check_action = criticalCheckten(version_tuple, controllers_info)
				if check_result == 'Failed':
					critical_checks['#10:Check:vManage:NTP status across network'] = [check_analysis, check_action]

					log_file_logger.error('#10: Check result:   {}'.format(check_result))
					log_file_logger.error('#10: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#10: Devices with invalid ntp associations:\n{}\n'.format(ntp_nonworking))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				   
				else:
					log_file_logger.info('#10: Check result:   {}'.format(check_result))
					log_file_logger.info('#10: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #10:Check:vManage:NTP status across network. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#11:Check:Controllers:Validate vSmart/vBond CPU count for scale
			print(' Critical Check:#11')
			log_file_logger.info('#11:Check:Controllers:Validate vSmart/vBond CPU count for scale')
			writeFile(report_file, '#11:Check:Controllers:Validate vSmart/vBond CPU count for scale\n\n')

			try:
				for vbond in vbond_info:

					output = json.loads(getRequest( version_tuple,vmanage_lo_ip,jsessionid,'device/system/synced/status?deviceId={}'.format(vbond_info[vbond][1]),args.vmanage_port, tokenid))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vbond_info[vbond].append(total_cpu_count)

				for vsmart in vsmart_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip,jsessionid,'device/system/synced/status?deviceId={}'.format(vsmart_info[vsmart][1]),args.vmanage_port,tokenid))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vsmart_info[vsmart].append(total_cpu_count)

				failed_vbonds,failed_vsmarts,check_result,check_analysis, check_action = criticalCheckeleven(total_devices, vbond_info, vsmart_info)
				if check_result == 'Failed':
					critical_checks['#11:Check:Controllers:Validate vSmart/vBond CPU count for scale'] = [check_analysis, check_action]

					log_file_logger.error('#11:Check result:    {}'.format(check_result))
					log_file_logger.error('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#11: vBonds with insufficient CPU count:\n{}'.format(failed_vbonds))
					log_file_logger.error('#11: vSmarts with insufficient CPU count:\n{}'.format(failed_vsmarts))
					log_file_logger.error('#11: All vBonds info with total_cpu_count:\n{}'.format(vbond_info))
					log_file_logger.error('#11: All vSmarts info with total_cpu_count:\n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#11:Check result:    {}'.format(check_result))
					log_file_logger.info('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#11: All vBonds info with total_cpu_count:\n{}'.format(vbond_info))
					log_file_logger.info('#11: All vSmarts info with total_cpu_count:\n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #11:Check:Controllers:Validate vSmart/vBond CPU count for scale. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
			
			#Warning Checks
			print('\n**** Performing Warning checks\n')
			warning_checks = {}
			log_file_logger.info('*** Performing Warning Checks')

			#12:Check:vManage:CPU Speed
			print(' Warning Check:#12')
			log_file_logger.info('#12:Check:vManage:CPU Speed')
			writeFile(report_file, '#12:Check:vManage:CPU Speed\n\n')

			try:
				check_result,check_analysis,check_action = warningCheckone(cpu_speed)
				if check_result == 'Failed':
					warning_checks['#12:Check:vManage:CPU Speed'] = [ check_analysis, check_action]

					log_file_logger.error('#12: Check result:   {}'.format(check_result))
					log_file_logger.error('#12: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#12: CPU clock speed: {}\n'.format(cpu_speed))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#12: Check result:   {}'.format(check_result))
					log_file_logger.info('#12: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #12:Check:vManage:CPU Speed. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#13:Check:vManage:Network Card type
			print(' Warning Check:#13')
			log_file_logger.info('#13:Check:vManage:Network Card type')
			writeFile(report_file, '#13:Check:vManage:Network Card type\n\n')

			try:
				eth_drivers, check_action, check_analysis, check_result = warningChecktwo()
				if check_result == 'Failed':
					warning_checks['#13:Check:vManage:Network Card type'] = [ check_analysis, check_action]

					log_file_logger.error('#13: Check result:   {}'.format(check_result))
					log_file_logger.error('#13: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#13: Ethercardswith e1000 card types: {}\n'.format(eth_drivers))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#13: Check result:   {}'.format(check_result))
					log_file_logger.info('#13: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #13:Check:vManage:Network Card type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#14:Check:vManage:Backup status
			print(' Warning Check:#14')
			log_file_logger.info('#14:Check:vManage:Backup status')
			writeFile(report_file, '#14:Check:vManage:Backup status\n\n')

			try:
				date_time_obj, check_result, check_analysis, check_action = warningCheckthree()
				if check_result == 'Failed':
					warning_checks['#14:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#14: Check result:   {}'.format(check_result))
					log_file_logger.error('#14: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#14: Last Backup was performed on:{}\n'.format(date_time_obj))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#14: Check result:   {}'.format(check_result))
					log_file_logger.info('#14: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #14:Check:vManage:Backup status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#15:Check:vManage:Evaluate Neo4j performance
			print(' Warning Check:#15')
			log_file_logger.info('#15:Check:vManage:Evaluate Neo4j performance')
			writeFile(report_file, '#15:Check:vManage:Evaluate Neo4j performance\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckfour()
				if check_result == 'Failed':
					warning_checks['#15:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#15: Check result:   {}'.format(check_result))
					log_file_logger.error('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#15: Check result:   {}'.format(check_result))
					log_file_logger.info('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #15:Check:vManage:Evaluate Neo4j performance. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#16:Check:vManage:Confirm there are no pending tasks
			print(' Warning Check:#16')
			log_file_logger.info('#16:Check:vManage:Confirm there are no pending tasks')
			writeFile(report_file, '#16:Check:vManage:Confirm there are no pending tasks\n\n')

			try:
				tasks = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'device/action/status/tasks', args.vmanage_port, tokenid))
				tasks_running, check_result, check_analysis, check_action  = warningCheckfive(tasks)
				if check_result == 'Failed':
					warning_checks['#16:Check:vManage:Confirm there are no pending tasks'] = [ check_analysis, check_action]

					log_file_logger.error('#16: Check result:   {}'.format(check_result))
					log_file_logger.error('#16: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#16: Tasks still running: {}\n'.format(tasks_running))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#16: Check result:   {}'.format(check_result))
					log_file_logger.info('#16: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #16:Check:vManage:Confirm there are no pending tasks. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#17:Check:vManage:Validate there are no empty password users
			print(' Warning Check:#17')
			log_file_logger.info('#17:Check:vManage:Validate there are no empty password users')
			writeFile(report_file, '#17:Check:vManage:Validate there are no empty password users\n\n')
			
			try:
				users_emptypass, check_result, check_analysis, check_action = warningChecksix(version_tuple)
				if check_result == 'Failed':
					warning_checks['#17:Check:vManage:Validate there are no empty password users'] = [check_analysis, check_action]

					log_file_logger.error('#17: Check result:   {}'.format(check_result))
					log_file_logger.error('#17: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#17: Users with empty passwords: {}\n'.format(users_emptypass))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#17: Check result:   {}'.format(check_result))
					log_file_logger.info('#17: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #17:Check:vManage:Validate there are no empty password users. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#18:Check:Controllers:Controller versions
			print(' Warning Check:#18')
			log_file_logger.info('#18:Check:Controllers:Controller versions')
			writeFile(report_file, '#18:Check:Controllers:Controller versions\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckseven(controllers_info)
				if check_result == 'Failed':
					warning_checks['18:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#18: Check result:   {}'.format(check_result))
					log_file_logger.error('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#18: Check result:   {}'.format(check_result))
					log_file_logger.info('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #18:Check:Controllers:Controller versions. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#19:Check:Controllers:Confirm Certificate Expiration Dates
			print(' Warning Check:#19')
			log_file_logger.info('#19:Check:Controllers:Confirm Certificate Expiration Dates')
			writeFile(report_file, '#19:Check:Controllers:Confirm Certificate Expiration Dates\n\n')

			try:
				controllers_exp, controllers_notexp, check_result, check_analysis, check_action = warningCheckeight(controllers_info)
				if check_result == 'Failed':
					warning_checks['#19:Check:Controllers:Confirm Certificate Expiration Dates'] = [ check_analysis, check_action]

					log_file_logger.error('#19:Check result:    {}'.format(check_result))
					log_file_logger.error('#19: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#19: Controllers with certificates close to expiration:\n{}\n'.format(controllers_exp))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				   
				else: 
					log_file_logger.info('#19:Check result:    {}'.format(check_result))
					log_file_logger.info('#19: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #19:Check:Controllers:Confirm Certificate Expiration Dates. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#20:Check:Controllers:vEdge list sync
			print(' Warning Check:#20')
			log_file_logger.info('#20:Check:Controllers:vEdge list sync')
			writeFile(report_file, '#20:Check:Controllers:vEdge list sync\n\n')

			try:
				state_vedgeList,check_result, check_analysis, check_action  = warningChecknine(controllers_info)
				if check_result == 'Failed':
					warning_checks['#20:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#20:Check result:    {}'.format(check_result))
					log_file_logger.error('#20: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#20: Controllers with inconsistent state_vedgeList: {}\n'.format(state_vedgeList))
					
					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))                   

				else:
					log_file_logger.info('#20:Check result:    {}'.format(check_result))
					log_file_logger.info('#20: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing  #20:Check:Controllers:vEdge list sync. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#21:Check:Controllers: Confirm control connections
			print(' Warning Check:#21')
			log_file_logger.info('#21:Check:Controllers: Confirm control connections')
			writeFile(report_file, '#21:Check:Controllers: Confirm control connections\n\n')

			try:
				control_sum_tab, discrepancy,check_result, check_analysis, check_action = warningCheckten(vsmart_count, vbond_count)
				if check_result == 'Failed':
					warning_checks['#21:Check:Controllers: Confirm control connections'] = [check_analysis, check_action]

					log_file_logger.error('#21: Check result:   {}'.format(check_result))
					log_file_logger.error('#21: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#21: Control  Connections Summary:\n{}\n'.format(control_sum_tab))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#21:Check result:    {}'.format(check_result))
					log_file_logger.info('#21: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #21:Check:Controllers: Confirm control connections. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

		  
			#Informational Checks
			print('\n**** Performing Informational checks\n')

			log_file_logger.info('*** Performing Informational Checks')

			#22:Check:vManage:Disk controller type
			print(' Informational Check:#22')
			log_file_logger.info('#22:Check:vManage:Disk controller type')
			writeFile(report_file, '#22:Check:vManage:Disk controller type\n\n')

			try:
				check_result, check_analysis, check_action = infoCheckone(server_type, disk_controller)
				if check_result == 'Failed':
					warning_checks['#22:Check:vManage:Disk controller type'] = [ check_analysis, check_action]

					log_file_logger.error('#22: Check result:   {}'.format(check_result))
					log_file_logger.error('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#22: Check result:   {}'.format(check_result))
					log_file_logger.info('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #22:Check:vManage:Disk controller type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#23:Check:Controllers:Validate there is at minimum vBond, vSmart present
			print(' Informational Check:#23')
			log_file_logger.info('#23:Check:Controllers:Validate there is at minimum vBond, vSmart present')
			writeFile(report_file, '#23:Check:Controllers:Validate there is at minimum vBond, vSmart present\n\n')

			try:
				check_result, check_analysis, check_action = infoChecktwo(vsmart_count,vbond_count)
				if check_result == 'Failed':
					warning_checks['#23:Check:Controllers:Validate there is at minimum vBond, vSmart present'] = [ check_analysis, check_action]

					log_file_logger.error('#23: Check result:   {}'.format(check_result))
					log_file_logger.error('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.error('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#23: Check result:   {}'.format(check_result))
					log_file_logger.info('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.info('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #23:Check:Controllers:Validate there is at minimum vBond, vSmart present. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#24:Check:Controllers:Validate all controllers are reachable
			print(' Informational Check:#24')
			log_file_logger.info('#24:Check:Controllers:Validate all controllers are reachable')
			writeFile(report_file, '#24:Check:Controllers:Validate all controllers are reachable\n\n')
			
			try:
				unreach_controllers,check_result, check_analysis, check_action = infoChecktthree(controllers_info)
				if check_result == 'Failed':
					warning_checks['#24:Check:Controllers:Validate all controllers are reachable'] = [check_analysis, check_action]

					log_file_logger.error('#24: Check result:   {}'.format(check_result))
					log_file_logger.error('#24: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#24: Unreachable Controllers: {}\n'.format(unreach_controllers))


					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#24: Check result:   {}'.format(check_result))
					log_file_logger.info('#24: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #24:Check:Controllers:Validate all controllers are reachable. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			if cluster_size>1:
				cluster_checks = {}
				log_file_logger.info('*** Performing Cluster Checks')
				print('\n**** Performing Cluster checks\n')

				#25:Check:Cluster:Version consistency
				print(' Cluster Check:#25')
				log_file_logger.info('#25:Check:Cluster:Version consistency')
				writeFile(report_file, '#25:Check:Cluster:Version consistency\n\n')

				try:
					check_result,check_analysis, check_action = criticalChecktwelve(vmanage_info)
					if check_result == 'Failed':
						cluster_checks['#25:Check:Cluster:Version consistency'] = [ check_analysis, check_action]

						log_file_logger.error('#25: Check result:   {}'.format(check_result))
						log_file_logger.error('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					   

					else:
						log_file_logger.info('#25: Check result:   {}'.format(check_result))
						log_file_logger.info('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					   
				except Exception as e:
					print('\033[1;31m ERROR: Error performing #25:Check:Cluster:Version consistency. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#26:Check:Cluster:Cluster health
				print(' Cluster Check:#26')
				log_file_logger.info('#26:Check:Cluster:Cluster health')
				writeFile(report_file, '#26:Check:Cluster:Cluster health\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid,  'clusterManagement/list', args.vmanage_port, tokenid))
					services_down, check_result, check_analysis, check_action = criticalCheckthirteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#26:Check:Cluster:Cluster health'] = [ check_analysis, check_action]

						log_file_logger.error('#26: Check result:   {}'.format(check_result))
						log_file_logger.error('#26: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#26: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					   

					else: 
						log_file_logger.info('#26: Check result:   {}'.format(check_result))
						log_file_logger.info('#26: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #26:Check:Cluster:Cluster health. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#27:Check:Cluster:Cluster ConfigDB topology
				print(' Cluster Check:#27')
				log_file_logger.info('#27:Check:Cluster:Cluster ConfigDB topology')
				writeFile(report_file, '#27:Check:Cluster:Cluster ConfigDB topology\n\n')
		
				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid,'clusterManagement/list', args.vmanage_port, tokenid))           
					configDB_count, check_result, check_analysis, check_action = criticalCheckfourteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#27:Check:Cluster:Cluster ConfigDB topology'] = [ check_analysis, check_action]

						log_file_logger.error('#27: Check result:   {}'.format(check_result))
						log_file_logger.error('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					else: 
						log_file_logger.info('#27: Check result:   {}'.format(check_result))
						log_file_logger.info('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #27:Check:Cluster:Cluster ConfigDB topology. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#28:Check:Cluster:Messaging server
				print(' Cluster Check:#28')
				log_file_logger.info('#28:Check:Cluster:Messaging server')
				writeFile(report_file, '#28:Check:Cluster:Messaging server\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'clusterManagement/list', args.vmanage_port, tokenid ))           
					cluster_msdown,check_result,check_analysis, check_action = criticalCheckfifteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#28:Check:Cluster:Messaging server'] = [ check_analysis, check_action]

						log_file_logger.error('#28: Check result:   {}'.format(check_result))
						log_file_logger.error('#28: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#28: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
						

					else: 
						log_file_logger.info('#28: Check result:   {}'.format(check_result))
						log_file_logger.info('#28: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #28:Check:Cluster:Messaging server. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))
				
				#29:Check:Cluster:DR replication status
				print(' Cluster Check:#29')
				log_file_logger.info('#29:Check:Cluster:DR replication status')
				writeFile(report_file, '#29:Check:Cluster:DR replication status\n\n')

				try:
					dr_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'disasterrecovery/details', args.vmanage_port, tokenid))           
					dr_status, check_action, check_analysis, check_result = criticalChecksixteen(dr_data)
					if check_result == 'Failed':
						cluster_checks['#29:Check:Cluster:DR replication status'] = [ check_analysis, check_action]

						log_file_logger.error('#29: Check result:   {}'.format(check_result))
						log_file_logger.error('#29: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#29: DR Replication status: {}\n'.format(dr_status))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					else:
						log_file_logger.info('#29: Check result:   {}'.format(check_result))
						log_file_logger.info('#29: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #29:Check:Cluster:DR replication status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))
					
				#30:Check:Cluster:Intercluster communication
				print(' Cluster Check:#30')
				log_file_logger.info('#30:Check:Cluster:Intercluster communication')
				writeFile(report_file, '#30:Check:Cluster:Intercluster communication\n\n')
				
				try:    
					if criticalCheckseventeen.isAlive():
						criticalCheckseventeen.join(10)

					if not criticalCheckseventeen.result_queue.empty():
						ping_output, ping_output_failed, ping_check_result, ping_check_analysis, ping_check_action = criticalCheckseventeen.result_queue.get()
						if ping_check_result == 'Failed':
							cluster_checks['#30:Check:Cluster:Intercluster communication'] = [ ping_check_analysis, ping_check_action]

							log_file_logger.error('#30: Check result:   {}'.format(ping_check_result))
							log_file_logger.error('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.error('#30: Cluster nodes with ping failure: {}\n'.format(ping_output_failed))

						
							writeFile(report_file, 'Result: ERROR - {}\n'.format(ping_check_analysis))
							writeFile(report_file, 'Action: {}\n\n'.format(ping_check_action))

						else:
							log_file_logger.info('#30: Check result:   {}'.format(ping_check_result))
							log_file_logger.info('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.info('#30: Cluster nodes details: {}\n'.format(ping_output))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(ping_check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #30:Check:Cluster:Intercluster communication. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

			#Logging out of the Session using jsessionid
			log_file_logger.info('Logging out of the Session')
			sessionLogout(vmanage_lo_ip, jsessionid, args.vmanage_port)
			log_file_logger.info('Successfully closed the connection')
			

		#version equal to or above 20.5
		elif version_tuple[0:2] >= ('20','5'): 

			try:
				log_file_logger.info('Generating a JSessionID')
				jsessionid = generateSessionIDpy3(vmanage_lo_ip, args.username, password, args.vmanage_port)
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error generating JSessionID, make sure that the username and password entered is correct. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))


			try:
				log_file_logger.info('Generating CSRF Token')
				tokenid = CSRFTokenpy3(vmanage_lo_ip,jsessionid,args.vmanage_port)
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error generating CSRF Token. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file.  \033[0;0m \n\n'.format(log_file_path))


			#Preliminary data
			log_file_logger.info('****Collecting Preliminary Data\n')

			try:
				controllers = json.loads(getRequestpy3(version_tuple, vmanage_lo_ip, jsessionid , 'system/device/controllers', args.vmanage_port, tokenid))
				controllers_info = controllersInfo(controllers)
				log_file_logger.info('Collected controllers information: {}'.format(controllers_info))

				system_ip_data = json.loads(getRequestpy3(version_tuple, vmanage_lo_ip, jsessionid , 'device/vmanage', args.vmanage_port, tokenid))
				system_ip = system_ip_data['data']['ipAddress']
				log_file_logger.info('Collected vManage System IP address: {}'.format(system_ip))

				cpu_speed = cpuSpeed()
				log_file_logger.info('Collected vManage CPU Speed GHz: {}'.format(cpu_speed))

				cpu_count = cpuCount()
				log_file_logger.info('Collected vManage CPU Count: {}'.format(cpu_count))

				vedges = json.loads(getRequestpy3(version_tuple, vmanage_lo_ip, jsessionid , 'system/device/vedges', args.vmanage_port , tokenid))
				vedge_count,vedge_count_active, vedge_info = vedgeCount(vedges)
				log_file_logger.info('Collected  xEdge Count: {}'.format(vedge_count))

				cluster_size, server_mode, vmanage_info = serverMode(controllers_info)
				log_file_logger.info('Collected vManage Cluster Size: {}'.format(cluster_size))
				log_file_logger.info('Collected vManage Server Mode: {}'.format(server_mode))

				disk_controller = diskController()
				log_file_logger.info('Collected vManage Disk Controller Type: {}'.format(disk_controller))

				dpi_stats = json.loads(getRequestpy3(version_tuple, vmanage_lo_ip, jsessionid , 'statistics/settings/status', args.vmanage_port, tokenid))
				dpi_status = dpiStatus(dpi_stats)
				log_file_logger.info('Collected DPI Status: {}'.format(dpi_status))

				server_type = serverType()
				log_file_logger.info('Collected Server Type: {}'.format(server_type))

				vbond_info, vsmart_info = vbondvmartInfo(controllers_info)
				vbond_count = len(vbond_info)
				vsmart_count = len(vsmart_info)
				log_file_logger.info('vSmart info: {}'.format(vbond_info))
				log_file_logger.info('vBond info: {}'.format(vsmart_info))
				

				total_devices = len(controllers_info.keys()) + vedge_count
				log_file_logger.info('Total devices: {}'.format(total_devices))

			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error Collecting Preliminary Data. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				


			print('*Starting Checks, this may take several minutes')

			#Critical Checks
			print('\n**** Performing Critical checks\n')


			#Begining #30Check:Cluster:Intercluster communication  in the background
			if cluster_size>1:
				log_file_logger.info('Beginging #30:Check:Cluster:Intercluster communication  in the background\n')
				try:    
					cluster_health_data = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))
					criticalCheckseventeen =  criticalCheckseventeenpy3(cluster_health_data,  system_ip, log_file_logger)
				except Exception as e:
					log_file_logger.exception('{}\n'.format(e))

			critical_checks = {}
			log_file_logger.info('*** Performing Critical Checks\n')

			#01:Check:vManage:Validate current version
			print(' Critical Check:#01')
			log_file_logger.info('#01:Check:vManage:Validate current version')
			writeFile(report_file, '#01:Check:vManage:Validate current version\n\n')
			
			try:
				boot_partition_size, check_result, check_analysis, check_action =  criticalCheckone(version)
				if check_result == 'Failed':
					critical_checks['#01:Check:vManage:Validate current version'] = [ check_analysis, check_action]

					log_file_logger.error('#01: Check result:   {}'.format(check_result))
					log_file_logger.error('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#01: version: {}'.format(version))
					log_file_logger.error('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#01: Check result:   {}'.format(check_result))
					log_file_logger.info('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#01: version: {}'.format(version))
					log_file_logger.info('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
					
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #01:Check:vManage:Validate current version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#02:Check:vManage:At minimum 20%  server disk space should be available
			print(' Critical Check:#02')
			log_file_logger.info('#02:Check:vManage:At minimum 20%  server disk space should be available')
			writeFile(report_file, '#02:Check:vManage:At minimum 20%  server disk space should be available\n\n')

			try:
				optdata_partition_size, rootfs_partition_size, check_result, check_analysis, check_action =  criticalCheckTwo()
				if check_result == 'Failed': 
					critical_checks['#02:Check:vManage:At minimum 20%  server disk space should be available'] = [check_analysis, check_action]

					log_file_logger.error('#02: Check result:   {}'.format(check_result))
					log_file_logger.error('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.error('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#02: Check result:   {}'.format(check_result))
					log_file_logger.info('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.info('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #02:Check:vManage:At minimum 20%  server disk space should be available. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#03:Check:vManage:Memory size
			print(' Critical Check:#03')
			log_file_logger.info('#03:Check:vManage:Memory size')
			writeFile(report_file, '#03:Check:vManage:Memory size\n')
			writeFile(report_file, 'Link to the official documentation: \n https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html\n\n')

			try:
				memory_size, memory_size_str, dpi_status, server_type, check_result, check_analysis, check_action =  criticalCheckthree(vedge_count, dpi_status, server_type, cluster_size, version_tuple)
				if check_result == 'Failed':
					critical_checks['#03:Check:vManage:Memory size'] = [ check_analysis, check_action]

					log_file_logger.error('#03: Check result:   {}'.format(check_result))
					log_file_logger.error('#03: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#03: Memory Size GB: {}'.format(memory_size_str))
					log_file_logger.error('#03: /rootfs.rw Used: {}'.format(rootfs_partition_size))
					log_file_logger.error('#03: Server Type: {}'.format(server_type))
					log_file_logger.error('#03: vEdge Count: {}\n'.format(vedge_count))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#03: Check result:   {}'.format(check_result))
					log_file_logger.info('#03: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #03:Check:vManage:Memory size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

	 
			#04:Check:vManage:CPU Count
			print(' Critical Check:#04')
			log_file_logger.info('#04:Check:vManage:CPU Count')
			writeFile(report_file, '#04:Check:vManage:CPU Count\n\n')

			try:
				check_result, check_analysis, check_action = criticalCheckfour(cpu_count, vedge_count, dpi_status, server_type)
				if check_result == 'Failed':
					critical_checks['#04:Check:vManage:CPU Count'] = [ check_analysis, check_action]

					log_file_logger.error('#04: Check result:   {}'.format(check_result))
					log_file_logger.error('#04: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#04: CPU Count: {}\n'.format(cpu_count))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#04: Check result:   {}'.format(check_result))
					log_file_logger.info('#04: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #04:Check:vManage:CPU Count. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#05:Check:vManage:ElasticSearch Indices status
			print(' Critical Check:#05')
			log_file_logger.info('#05:Check:vManage:ElasticSearch Indices status')
			writeFile(report_file, '#05:Check:vManage:ElasticSearch Indices status\n\n')

			try:
				es_indexes_one = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_index_red_one, check_result_one, check_analysis_one, check_action_one = criticalCheckfive(es_indexes_one)

				time.sleep(5)

				es_indexes_two = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_index_red_two, check_result_two, check_analysis_two, check_action_two = criticalCheckfive(es_indexes_two)

				if check_result_one == 'Failed' and check_result_two == 'Failed':
					critical_checks['#05:Check:vManage:ElasticSearch Indices status'] = [ check_analysis_two, check_action_two]

					log_file_logger.error('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.error('#05: Check Analysis: {}\n'.format(check_analysis_two))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis_two))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action_two))
				   
				elif check_result_one == 'SUCCESSFUL':
					log_file_logger.info('#05: Check result:   {}'.format(check_result_one))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_one))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_one))

				elif check_result_two == 'SUCCESSFUL':

					log_file_logger.info('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_two))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_two))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #05:Check:vManage:ElasticSearch Indices status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#06:Check:vManage:Look for any neo4j exception errors
			print(' Critical Check:#06')
			log_file_logger.info('#06:Check:vManage:Look for any neo4j exception errors')
			writeFile(report_file, '#06:Check:vManage:Look for any neo4j exception errors\n\n')

			try:
				check_result, check_analysis, check_action = criticalChecksix()
				if check_result == 'Failed':
					critical_checks['#06:Check:vManage:Look for any neo4j exception errors'] = [check_analysis, check_action]

					log_file_logger.error('#06: Check result:   {}'.format(check_result))
					log_file_logger.error('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))


				else:
					log_file_logger.info('#06: Check result:   {}'.format(check_result))
					log_file_logger.info('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #06:Check:vManage:Look for any neo4j exception errors. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#07:Check:vManage:Validate all services are up
			print(' Critical Check:#07')
			log_file_logger.info('#07:Check:vManage:Validate all services are up')
			writeFile(report_file, '#07:Check:vManage:Validate all services are up\n\n')

			try:
				nms_data, nms_failed, check_result, check_analysis, check_action =   criticalCheckseven() 
				if check_result == 'Failed':
					critical_checks['#07:Check:vManage:Validate all services are up'] = [check_analysis, check_action]

					log_file_logger.error('#07: Check result:   {}'.format(check_result))
					log_file_logger.error('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#07: List of services that are enabled but not running:\n{}'.format(nms_failed))
					log_file_logger.error('#07: Status of all services  :\n{}\n'.format(nms_data))

					writeFile(report_file, 'Result: ERROR - {}\n\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#07: Check result:   {}'.format(check_result))
					log_file_logger.info('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#07: Status of all the services:\n{}\n'.format(nms_data))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))


			except Exception as e:
				print('\033[1;31m ERROR: Error performing #07:Check:vManage:Validate all services are up. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#08:Check:vManage:Elasticsearch Indices version
			print(' Critical Check:#08')
			log_file_logger.info('#08:Check:vManage:Elasticsearch Indices version')
			writeFile(report_file, '#08:Check:vManage:Elasticsearch Indices version\n\n')

			try:
				version_list, check_result, check_analysis, check_action = criticalCheckeight(version_tuple)
				if check_result == 'Failed':
					critical_checks['#08:Check:vManage:Elasticsearch Indices version'] = [ check_analysis, check_action]

					log_file_logger.error('#08: Check result:   {}'.format(check_result))
					log_file_logger.error('#08: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#08: List of indices with older versions:\n{}\n'.format(version_list))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#08: Check result:   {}'.format(check_result))
					log_file_logger.info('#08: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #08:Check:vManage:Elasticsearch Indices version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#09:Check:vManage:Evaluate incoming DPI data size
			print(' Critical Check:#09')
			log_file_logger.info('#09:Check:vManage:Evaluate incoming DPI data size')
			writeFile(report_file, '#09:Check:vManage:Evaluate incoming DPI data size\n\n')

			try:
				es_indices_est = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/size/estimate', args.vmanage_port, tokenid))
				appr_estimate_ondeday, dpi_estimate_ondeday, check_result, check_analysis,check_action = criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count, total_devices,  dpi_status)
				if check_result == 'Failed':
					critical_checks['#09:Check:vManage:Evaluate incoming DPI data size'] = [ check_analysis, check_action]

					log_file_logger.error('#09: Check result:   {}'.format(check_result))
					log_file_logger.error('#09: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#09: Daily incoming DPI data : {}'.format(dpi_estimate_ondeday))
					log_file_logger.error('#09: Daily incoming Approute data : {}\n'.format(appr_estimate_ondeday))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#09: Check result:   {}'.format(check_result))
					log_file_logger.info('#09: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #09:Check:vManage:Evaluate incoming DPI data size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#10:Check:vManage:NTP status across network
			print(' Critical Check:#10')
			log_file_logger.info('#10:Check:vManage:NTP status across network')
			writeFile(report_file, '#10:Check:vManage:NTP status across network\n\n')
			
			try:
				ntp_nonworking, check_result, check_analysis, check_action = criticalCheckten(version_tuple, controllers_info)
				if check_result == 'Failed':
					critical_checks['#10:Check:vManage:NTP status across network'] = [ check_analysis, check_action]

					log_file_logger.error('#10: Check result:   {}'.format(check_result))
					log_file_logger.error('#10: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#10: Devices with invalid ntp associations:\n{}\n'.format(ntp_nonworking))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#10: Check result:   {}'.format(check_result))
					log_file_logger.info('#10: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error perforiming #10:Check:vManage:NTP status across network. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#11:Check:Controllers:Validate vSmart/vBond CPU count for scale
			print(' Critical Check:#11')
			log_file_logger.info('#11:Check:Controllers:Validate vSmart/vBond CPU count for scale')
			writeFile(report_file, '#11:Check:Controllers:Validate vSmart/vBond CPU count for scale\n\n')

			try:
				for vbond in vbond_info:
					output = json.loads(getRequestpy3( version_tuple,vmanage_lo_ip, jsessionid, 'device/system/synced/status?deviceId={}'.format(vbond_info[vbond][1]),args.vmanage_port, tokenid))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vbond_info[vbond].append(total_cpu_count)

				for vsmart in vsmart_info:
					output = json.loads(getRequestpy3( version_tuple,vmanage_lo_ip, jsessionid, 'device/system/synced/status?deviceId={}'.format(vsmart_info[vsmart][1]),args.vmanage_port,tokenid))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vsmart_info[vsmart].append(total_cpu_count)

				failed_vbonds,failed_vsmarts,check_result,check_analysis, check_action = criticalCheckeleven(total_devices, vbond_info, vsmart_info)
				if check_result == 'Failed':
					critical_checks['#11:Check:Controllers:Validate vSmart/vBond CPU count for scale'] = [ check_analysis, check_action]

					log_file_logger.error('#11: Check result:   {}'.format(check_result))
					log_file_logger.error('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#11: vBonds with insufficient CPU count: \n{}'.format(failed_vbonds))
					log_file_logger.error('#11: vSmarts with insufficient CPU count: \n{}'.format(failed_vsmarts))
					log_file_logger.error('#11: All vBonds info with total_cpu_count: \n{}'.format(vbond_info))
					log_file_logger.error('#11: All vSmarts info with total_cpu_count: \n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#11: Check result:   {}'.format(check_result))
					log_file_logger.info('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#11: All vBonds info with total_cpu_count:\n{}'.format(vbond_info))
					log_file_logger.info('#11: All vSmarts info with total_cpu_count:\n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #11:Check:Controllers:Validate vSmart/vBond CPU count for scale. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Warning Checks
			print('\n**** Performing Warning checks\n')
			warning_checks = {}
			log_file_logger.info('*** Performing Warning Checks')

			#12:Check:vManage:CPU Speed
			print(' Warning Check:#12')
			log_file_logger.info('#12:Check:vManage:CPU Speed')
			writeFile(report_file, '#12:Check:vManage:CPU Speed\n\n')

			try:
				check_result,check_analysis,check_action = warningCheckone(cpu_speed)
				if check_result == 'Failed':
					warning_checks['#12:Check:vManage:CPU Speed'] = [ check_analysis, check_action]

					log_file_logger.error('#12: Check result:   {}'.format(check_result))
					log_file_logger.error('#12: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#12: CPU clock speed: {}\n'.format(cpu_speed))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#12: Check result:   {}'.format(check_result))
					log_file_logger.info('#12: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #12:Check:vManage:CPU Speed. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#13:Check:vManage:Network Card type
			print(' Warning Check:#13')
			log_file_logger.info('#13:Check:vManage:Network Card type')
			writeFile(report_file, '#13:Check:vManage:Network Card type\n\n')
	
			try:
				eth_drivers, check_action, check_analysis, check_result = warningChecktwo()
				if check_result == 'Failed':
					warning_checks['#13:Check:vManage:Network Card type'] = [ check_analysis, check_action]

					log_file_logger.error('#13: Check result:   {}'.format(check_result))
					log_file_logger.error('#13: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#13: Ethercardswith e1000 card types: {}\n'.format(eth_drivers))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#13: Check result:   {}'.format(check_result))
					log_file_logger.info('#13: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #13:Check:vManage:Network Card type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#14:Check:vManage:Backup status
			print(' Warning Check:#14')
			log_file_logger.info('#14:Check:vManage:Backup status')
			writeFile(report_file, '#14:Check:vManage:Backup status\n\n')

			try:
				date_time_obj, check_result, check_analysis, check_action = warningCheckthree()
				if check_result == 'Failed':
					warning_checks['#14:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#14: Check result:   {}'.format(check_result))
					log_file_logger.error('#14: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#14: Last Backup was performed on:{}\n'.format(date_time_obj))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#14: Check result:   {}'.format(check_result))
					log_file_logger.info('#14: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #14:Check:vManage:Backup status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#15:Check:vManage:Evaluate Neo4j performance
			print(' Warning Check:#15')
			log_file_logger.info('#15:Check:vManage:Evaluate Neo4j performance')
			writeFile(report_file, '#15:Check:vManage:Evaluate Neo4j performance\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckfour()
				if check_result == 'Failed':
					warning_checks['#15:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#15: Check result:   {}'.format(check_result))
					log_file_logger.error('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#15: Check result:   {}'.format(check_result))
					log_file_logger.info('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #15:Check:vManage:Evaluate Neo4j performance. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#16:Check:vManage:Confirm there are no pending tasks
			print(' Warning Check:#16')
			log_file_logger.info('#16:Check:vManage:Confirm there are no pending tasks')
			writeFile(report_file, '#16:Check:vManage:Confirm there are no pending tasks\n\n')

			try:
				tasks = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid,'device/action/status/tasks', args.vmanage_port, tokenid))
				tasks_running, check_result, check_analysis, check_action  = warningCheckfive(tasks)
				if check_result == 'Failed':
					warning_checks['#16:Check:vManage:Confirm there are no pending tasks'] = [ check_analysis, check_action]

					log_file_logger.error('#16: Check result:   {}'.format(check_result))
					log_file_logger.error('#16: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#16: Tasks still running: {}\n'.format(tasks_running))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#16: Check result:   {}'.format(check_result))
					log_file_logger.info('#16: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #16:Check:vManage:Confirm there are no pending tasks. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#17:Check:vManage:Validate there are no empty password users
			print(' Warning Check:#17')
			log_file_logger.info('#17:Check:vManage:Validate there are no empty password users')
			writeFile(report_file, '#17:Check:vManage:Validate there are no empty password users\n\n')

			try:
				users_emptypass, check_result, check_analysis, check_action = warningChecksix(version_tuple)
				if check_result == 'Failed':
					warning_checks['#17:Check:vManage:Validate there are no empty password users'] = [ check_analysis, check_action]

					log_file_logger.error('#17: Check result:   {}'.format(check_result))
					log_file_logger.error('#17: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#17: Users with empty passwords: {}\n'.format(users_emptypass))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#17: Check result:   {}'.format(check_result))
					log_file_logger.info('#17: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #17:Check:vManage:Validate there are no empty password users. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#18:Check:Controllers:Controller versions
			print(' Warning Check:#18')
			log_file_logger.info('#18:Check:Controllers:Controller versions')
			writeFile(report_file, '#18:Check:Controllers:Controller versions\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckseven(controllers_info)
				if check_result == 'Failed':
					warning_checks['#18:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#18: Check result:   {}'.format(check_result))
					log_file_logger.error('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#18: Check result:   {}'.format(check_result))
					log_file_logger.info('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #18:Check:Controllers:Controller versions. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#19:Check:Controllers:Confirm Certificate Expiration Dates
			print(' Warning Check:#19')
			log_file_logger.info('#19:Check:Controllers:Confirm Certificate Expiration Dates')
			writeFile(report_file, '#19:Check:Controllers:Confirm Certificate Expiration Dates\n\n')

			try:
				controllers_exp, controllers_notexp, check_result, check_analysis, check_action = warningCheckeight(controllers_info)
				if check_result == 'Failed':
					warning_checks['#19:Check:Controllers:Confirm Certificate Expiration Dates'] = [ check_analysis, check_action]

					log_file_logger.error('#19: Check result:   {}'.format(check_result))
					log_file_logger.error('#19: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#19: Controllers with certificates close to expiration:\n{}\n'.format(controllers_exp))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#19: Check result:   {}'.format(check_result))
					log_file_logger.info('#19: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #19:Check:Controllers:Confirm Certificate Expiration Dates. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#20:Check:Controllers:vEdge list sync
			print(' Warning Check:#20')
			log_file_logger.info('#20:Check:Controllers:vEdge list sync')
			writeFile(report_file, '#20:Check:Controllers:vEdge list sync\n\n')

			try:
				state_vedgeList,check_result, check_analysis, check_action  = warningChecknine(controllers_info)
				if check_result == 'Failed':
					warning_checks['#20:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#20: Check result:   {}'.format(check_result))
					log_file_logger.error('#20: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#20: Controllers with inconsistent state_vedgeList:\n{}\n'.format(state_vedgeList))
					
					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))                

				else:
					log_file_logger.info('#20: Check result:   {}'.format(check_result))
					log_file_logger.info('#20: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #20:Check:Controllers:vEdge list sync. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#21:Check:Controllers: Confirm control connections
			print(' Warning Check:#21')
			log_file_logger.info('#21:Check:Controllers: Confirm control connections')
			writeFile(report_file, '#21:Check:Controllers: Confirm control connections\n\n')

			try:
				control_sum_tab, discrepancy,check_result, check_analysis, check_action = warningCheckten(vsmart_count, vbond_count)
				if check_result == 'Failed':
					warning_checks['#21:Check:Controllers: Confirm control connections'] = [ check_analysis, check_action]

					log_file_logger.error('#21: Check result:   {}'.format(check_result))
					log_file_logger.error('#21: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#21: Control  Connections Summary:\n{}\n'.format(control_sum_tab))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#21: Check result:   {}'.format(check_result))
					log_file_logger.info('#21: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #21:Check:Controllers: Confirm control connections. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

	  
			#Informational Checks
			print('\n**** Performing Informational checks\n')

			log_file_logger.info('*** Performing Informational Checks \n\n')

			#22:Check:vManage:Disk controller type
			print(' Informational Check:#22')
			log_file_logger.info('#22:Check:vManage:Disk controller type')
			writeFile(report_file, '#22:Check:vManage:Disk controller type\n\n')

			try:
				check_result, check_analysis, check_action = infoCheckone(server_type, disk_controller)
				if check_result == 'Failed':
					warning_checks['#22:Check:vManage:Disk controller type'] = [ check_analysis, check_action]

					log_file_logger.error('#22: Check result:   {}'.format(check_result))
					log_file_logger.error('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#22: Check result:   {}'.format(check_result))
					log_file_logger.info('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #22:Check:vManage:Disk controller type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#23:Check:Controllers:Validate there is at minimum vBond, vSmart present
			print(' Informational Check:#23')
			log_file_logger.info('#23:Check:Controllers:Validate there is at minimum vBond, vSmart present')
			writeFile(report_file, '#23:Check:Controllers:Validate there is at minimum vBond, vSmart present\n\n')

			try:
				check_result, check_analysis, check_action = infoChecktwo(vsmart_count,vbond_count)
				if check_result == 'Failed':
					warning_checks['#23:Check:Controllers:Validate there is at minimum vBond, vSmart present'] = [ check_analysis, check_action]

					log_file_logger.error('#23: Check result:   {}'.format(check_result))
					log_file_logger.error('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.error('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))                  

				else:
					log_file_logger.info('#23: Check result:   {}'.format(check_result))
					log_file_logger.info('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.info('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #23:Check:Controllers:Validate there is at minimum vBond, vSmart present. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#24:Check:Controllers:Validate all controllers are reachable
			print(' Informational Check:#24')
			log_file_logger.info('#24:Check:Controllers:Validate all controllers are reachable')
			writeFile(report_file, '#24:Check:Controllers:Validate all controllers are reachable\n\n')
				
			try:
				unreach_controllers,check_result, check_analysis, check_action = infoChecktthree(controllers_info)
				if check_result == 'Failed':
					warning_checks['#24:Check:Controllers:Validate all controllers are reachable'] = [ check_analysis, check_action]

					log_file_logger.error('#24: Check result:   {}'.format(check_result))
					log_file_logger.error('#24: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#24: Unreachable Controllers: {}\n'.format(unreach_controllers))


					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#24: Check result:   {}'.format(check_result))
					log_file_logger.info('#24: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #24:Check:Controllers:Validate all controllers are reachable. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			if cluster_size>1:
				cluster_checks = {}
				log_file_logger.info('*** Performing Cluster Checks')
				print('\n**** Performing Cluster checks\n')

				#25:Check:Cluster:Version consistency
				print(' Cluster Check:#25')
				log_file_logger.info('#25:Check:Cluster:Version consistency')
				writeFile(report_file, '#25:Check:Cluster:Version consistency\n\n')

				try:
					check_result,check_analysis, check_action = criticalChecktwelve(vmanage_info)
					if check_result == 'Failed':
						cluster_checks['#25:Check:Cluster:Version consistency'] = [ check_analysis, check_action]

						log_file_logger.error('#25: Check result:   {}'.format(check_result))
						log_file_logger.error('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))                        

					else:
						log_file_logger.info('#25: Check result:   {}'.format(check_result))
						log_file_logger.info('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						
				except Exception as e:
					print('\033[1;31m ERROR: Error performing #25:Check:Cluster:Version consistency. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#26:Check:Cluster:Cluster health
				print(' Cluster Check:#26')
				log_file_logger.info('#26:Check:Cluster:Cluster health')
				writeFile(report_file, '#26:Check:Cluster:Cluster health\n\n')

				try:
					cluster_health_data = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))
					services_down, check_result, check_analysis, check_action = criticalCheckthirteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#26:Check:Cluster:Cluster health'] = [ check_analysis, check_action]

						log_file_logger.error('#26: Check result:   {}'.format(check_result))
						log_file_logger.error('#26: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#26: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))                  

					else: 
						log_file_logger.info('#26: Check result:   {}'.format(check_result))
						log_file_logger.info('#26: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #26:Check:Cluster:Cluster health. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#27:Check:Cluster:Cluster ConfigDB topology
				print(' Cluster Check:#27')
				log_file_logger.info('#27:Check:Cluster:Cluster ConfigDB topology')
				writeFile(report_file, '#27:Check:Cluster:Cluster ConfigDB topology\n\n')
		
				try:
					cluster_health_data = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))           
					configDB_count, check_result, check_analysis, check_action = criticalCheckfourteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#27:Check:Cluster:Cluster ConfigDB topology'] = [ check_analysis, check_action]

						log_file_logger.error('#27: Check result:   {}'.format(check_result))
						log_file_logger.error('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					else: 
						log_file_logger.info('#27: Check result:   {}'.format(check_result))
						log_file_logger.info('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #27:Check:Cluster:Cluster ConfigDB topology. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#28:Check:Cluster:Messaging server
				print(' Cluster Check:#28')
				log_file_logger.info('#28:Check:Cluster:Messaging server')
				writeFile(report_file, '#28:Check:Cluster:Messaging server\n\n')

				try:
					cluster_health_data = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid ))           
					cluster_msdown,check_result,check_analysis, check_action = criticalCheckfifteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#28:Check:Cluster:Messaging server'] = [ check_analysis, check_action]

						log_file_logger.error('#28:Check result:    {}'.format(check_result))
						log_file_logger.error('#28: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#28: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
		   
					else: 
						log_file_logger.info('#28:Check result:    {}'.format(check_result))
						log_file_logger.info('#28: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #28:Check:Cluster:Messaging server. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#29:Check:Cluster:DR replication status
				print(' Cluster Check:#29')
				log_file_logger.info('#29:Check:Cluster:DR replication status')
				writeFile(report_file, '#29:Check:Cluster:DR replication status\n\n')

				try:
					dr_data = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'disasterrecovery/details', args.vmanage_port, tokenid))           
					dr_status, check_action, check_analysis, check_result = criticalChecksixteen(dr_data)
					if check_result == 'Failed':
						cluster_checks['#29:Check:Cluster:DR replication status'] = [ check_analysis, check_action]

						log_file_logger.error('#29: Check result:   {}'.format(check_result))
						log_file_logger.error('#29: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#29: DR Replication status: {}\n'.format(dr_status))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					else:
						log_file_logger.info('#29: Check result:   {}'.format(check_result))
						log_file_logger.info('#29: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #29:Check:Cluster:DR replication status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#30:Check:Cluster:Intercluster communication
				print(' Cluster Check:#30')
				log_file_logger.info('#30:Check:Cluster:Intercluster communication')
				writeFile(report_file, '#30:Check:Cluster:Intercluster communication\n\n')
				
				try:
					if criticalCheckseventeenpy3.isAlive():
						criticalCheckseventeenpy3.join(10)

					if not criticalCheckseventeenpy3.result_queue.empty():
						ping_output, ping_output_failed, ping_check_result, ping_check_analysis, ping_check_action = criticalCheckseventeenpy3.result_queue.get()
						if ping_check_result == 'Failed':
							cluster_checks['#30:Check:Cluster:Intercluster communication'] = [ ping_check_analysis, ping_check_action]

							log_file_logger.error('#30: Check result:   {}'.format(ping_check_result))
							log_file_logger.error('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.error('#30: Cluster nodes with ping failure: {}\n'.format(ping_output_failed))
						
							writeFile(report_file, 'Result: ERROR - {}\n'.format(ping_check_analysis))
							writeFile(report_file, 'Action: {}\n\n'.format(ping_check_action))

						else:
							log_file_logger.info('#30: Check result:   {}'.format(ping_check_result))
							log_file_logger.info('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.info('#30: Cluster nodes details: {}\n'.format(ping_output))

							writeFile(report_file, 'Result: INFO - {}\n\n'.format(ping_check_analysis))
					
				except Exception as e:
					print('\033[1;31m ERROR: Error performing #30:Check:Cluster:Intercluster communication. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

			#Logging out of the Session using jsessionid
			log_file_logger.info('Logging out of the Session')
			sessionLogoutpy3(vmanage_lo_ip,jsessionid,args.vmanage_port)
			log_file_logger.info('Successfully closed the connection')
			




	#Quiet  Execution
	elif args.quiet == True:
		log_file_logger.info('Executing the script in Quiet execution mode')

		#version below 19.2
		if version_tuple[0:2] < ('19','2'):
			try:
				#Creating a session
				log_file_logger.info('Generating a JSessionID')
				jsessionid = generateSessionID(vmanage_lo_ip, args.username, password, args.vmanage_port) 
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error generating JSessionID, make sure that the username and password entered is correct. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))


			#Preliminary Data
			log_file_logger.info('****Collecting Preliminary Data\n')

			try:
				controllers = json.loads(getRequest(version_tuple, vmanage_lo_ip,jsessionid,  'system/device/controllers', args.vmanage_port))
				controllers_info = controllersInfo(controllers)
				log_file_logger.info('Collected controllers information: {}'.format(controllers_info))

				system_ip_data = json.loads(getRequest(version_tuple, vmanage_lo_ip,jsessionid, 'device/vmanage', args.vmanage_port))
				system_ip = system_ip_data['data']['ipAddress']
				log_file_logger.info('Collected vManage System IP address: {}'.format(system_ip))

				cpu_speed = cpuSpeed()
				log_file_logger.info('Collected vManage CPU Speed GHz: {}'.format(cpu_speed))

				cpu_count = cpuCount()
				log_file_logger.info('Collected vManage CPU Count: {}'.format(cpu_count))

				vedges = json.loads(getRequest(version_tuple, vmanage_lo_ip,jsessionid,  'system/device/vedges', args.vmanage_port))
				vedge_count,vedge_count_active, vedge_info = vedgeCount(vedges)
				log_file_logger.info('Collected  xEdge Count: {}'.format(vedge_count))

				cluster_size, server_mode, vmanage_info = serverMode(controllers_info)
				log_file_logger.info('Collected vManage Cluster Size: {}'.format(cluster_size))
				log_file_logger.info('Collected vManage Server Mode: {}'.format(server_mode))

				disk_controller = diskController()
				log_file_logger.info('Collected vManage Disk Controller Type: {}'.format(disk_controller))

				dpi_stats = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'statistics/settings/status', args.vmanage_port))
				dpi_status = dpiStatus(dpi_stats)
				log_file_logger.info('Collected DPI status: {}'.format(dpi_status))

				server_type = serverType()
				log_file_logger.info('Collected Server Type: {}'.format(server_type))

				vbond_info, vsmart_info = vbondvmartInfo(controllers_info)
				vbond_count = len(vbond_info)
				vsmart_count = len(vsmart_info)
				log_file_logger.info('vSmart info: {}'.format(vbond_info))
				log_file_logger.info('vBond info: {}'.format(vsmart_info))

				total_devices = len(controllers_info) + vedge_count
				log_file_logger.info('Total devices: {}'.format(total_devices))

			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error Collecting Preliminary Data. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				

			print('*Starting Checks, this may take several minutes')

			#Critical Checks
			critical_checks = {}
			log_file_logger.info('*** Performing Critical Checks\n')

			#Begining #30:Check:Cluster:Intercluster communication  in the background
			if cluster_size>1:
				log_file_logger.info('Beginging #30:Check:Cluster:Intercluster communication  in the background\n')
				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'clusterManagement/list', args.vmanage_port))
					criticalCheckseventeen =  criticalCheckseventeen(cluster_health_data,  system_ip, log_file_logger)
				except Exception as e:
					log_file_logger.exception('{}\n'.format(e))


			#01:Check:vManage:Validate current version
			log_file_logger.info('#01:Check:vManage:Validate current version')
			writeFile(report_file, '#01:Check:vManage:Validate current version\n\n')
			
			try:
				boot_partition_size, check_result, check_analysis, check_action =  criticalCheckone(version)
				if check_result == 'Failed':
					critical_checks['#01:Check:vManage:Validate current version'] = [ check_analysis, check_action]

					log_file_logger.error('#01: Check result:   {}'.format(check_result))
					log_file_logger.error('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#01: version: {}'.format(version))
					log_file_logger.error('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n'.format(check_action))
					
				else:
					log_file_logger.info('#01: Check result:   {}'.format(check_result))
					log_file_logger.info('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#01: version: {}'.format(version))
					log_file_logger.info('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
					
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #01:Check:vManage:Validate current version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#02:Check:vManage:At minimum 20%  server disk space should be available
			log_file_logger.info('#02:Check:vManage:At minimum 20%  server disk space should be available')
			writeFile(report_file, '#02:Check:vManage:At minimum 20%  server disk space should be available\n\n')

			try:
				optdata_partition_size, rootfs_partition_size, check_result, check_analysis, check_action =  criticalCheckTwo()
				if check_result == 'Failed': 
					critical_checks['#02:Check:vManage:At minimum 20%  server disk space should be available'] = [check_analysis, check_action]

					log_file_logger.error('#02: Check result:   {}'.format(check_result))
					log_file_logger.error('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.error('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))


				else:
					log_file_logger.info('#02: Check result:   {}'.format(check_result))
					log_file_logger.info('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.info('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				   
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #02:Check:vManage:At minimum 20%  server disk space should be available. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#03:Check:vManage:Memory size
			log_file_logger.info('#03:Check:vManage:Memory size')
			writeFile(report_file, '#03:Check:vManage:Memory size\n')
			writeFile(report_file, 'Link to the official documentation: \n https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html\n\n')

			try:
				memory_size, memory_size_str, dpi_status, server_type, check_result, check_analysis, check_action =  criticalCheckthree(vedge_count, dpi_status, server_type, cluster_size, version_tuple)
				if check_result == 'Failed':
					critical_checks['#03:Check:vManage:vManage sever disk space'] = [ check_analysis, check_action]

					log_file_logger.error('#03: Check result:   {}'.format(check_result))
					log_file_logger.error('#03: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#03: Memory Size GB: {}'.format(memory_size_str))
					log_file_logger.error('#03: /rootfs.rw Used: {}'.format(rootfs_partition_size))
					log_file_logger.error('#03: Server Type: {}'.format(server_type))
					log_file_logger.error('#03: vEdge Count: {}\n'.format(vedge_count))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#03: Check result:   {}'.format(check_result))
					log_file_logger.info('#03: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #03:Check:vManage:Memory size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			
			#04:Check:vManage:CPU Count
			log_file_logger.info('#04:Check:vManage:CPU Count')
			writeFile(report_file, '#04:Check:vManage:CPU Count\n\n')

			try:
				check_result, check_analysis, check_action = criticalCheckfour(cpu_count, vedge_count, dpi_status, server_type)
				if check_result == 'Failed':
					critical_checks['#04:Check:vManage:CPU Count'] = [ check_analysis, check_action]

					log_file_logger.error('#04: Check result:   {}'.format(check_result))
					log_file_logger.error('#04: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#04: CPU Count: {}\n'.format(cpu_count))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#04: Check result:   {}'.format(check_result))
					log_file_logger.info('#04: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #04:Check:vManage:CPU Count. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#05:Check:vManage:ElasticSearch Indices status
			log_file_logger.info('#05:Check:vManage:ElasticSearch Indices status')
			writeFile(report_file, '#05:Check:vManage:ElasticSearch Indices status\n\n')

			try:
				es_indexes_one = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'management/elasticsearch/index/info', args.vmanage_port))
				es_index_red_one, check_result_one, check_analysis_one, check_action_one = criticalCheckfive(es_indexes_one)
				
				time.sleep(5)

				es_indexes_two = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'management/elasticsearch/index/info', args.vmanage_port))
				es_index_red_two, check_result_two, check_analysis_two, check_action_two = criticalCheckfive(es_indexes)

				if check_result_one == 'Failed' and check_result_two == 'Failed':
					critical_checks['#05:Check:vManage:ElasticSearch Indices status'] = [ check_analysis_two, check_action_two]

					log_file_logger.error('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.error('#05: Check Analysis: {}\n'.format(check_analysis_two))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis_two))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action_two))
				   
				elif check_result_one == 'SUCCESSFUL':
					log_file_logger.info('#05: Check result:   {}'.format(check_result_one))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_one))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_one))

				elif check_result_two == 'SUCCESSFUL':

					log_file_logger.info('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_two))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_two))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #05:Check:vManage:ElasticSearch Indices status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#06:Check:vManage:Look for any neo4j exception errors
			log_file_logger.info('#06:Check:vManage:Look for any neo4j exception errors')
			writeFile(report_file, '#06:Check:vManage:Look for any neo4j exception errors\n\n')

			try:
				check_result, check_analysis, check_action = criticalChecksix()
				if check_result == 'Failed':
					critical_checks['#06:Check:vManage:Look for any neo4j exception errors'] = [check_analysis, check_action]
					log_file_logger.error('#06: Check result:   {}'.format(check_result))
					log_file_logger.error('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#06: Check result:   {}'.format(check_result))
					log_file_logger.info('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #06:Check:vManage:Look for any neo4j exception errors. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#07:Check:vManage:Validate all services are up
			log_file_logger.info('#07:Check:vManage:Validate all services are up')
			writeFile(report_file, '#07:Check:vManage:Validate all services are up\n\n')

			try:
				nms_data, nms_failed, check_result, check_analysis, check_action =   criticalCheckseven() 
				if check_result == 'Failed':
					critical_checks['#07:Check:vManage:Validate all services are up'] = [check_analysis, check_action]

					log_file_logger.error('#07: Check result:   {}'.format(check_result))
					log_file_logger.error('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#07: List of services that are enabled but not running:\n\n {}\n\n'.format(nms_failed))
					log_file_logger.error('#07: Status of all services  :\n{}\n'.format(nms_data))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#07: Check result:   {}'.format(check_result))
					log_file_logger.info('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#07: Status of all the services:\n{}\n'.format(nms_data))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #07:Check:vManage:Validate all services are up. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#08:Check:vManage:Elasticsearch Indices version
			log_file_logger.info('#08:Check:vManage:Elasticsearch Indices version')
			writeFile(report_file, '#08:Check:vManage:Elasticsearch Indices version\n\n')

			try:
				version_list, check_result, check_analysis, check_action = criticalCheckeight(version_tuple)
				if check_result == 'Failed':
					critical_checks['#08:Check:vManage:Elasticsearch Indices version'] = [ check_analysis, check_action]

					log_file_logger.error('#08: Check result:   {}'.format(check_result))
					log_file_logger.error('#08: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#08: List of indices with older versions  :\n{}\n'.format(version_list))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#08: Check result:   {}'.format(check_result))
					log_file_logger.info('#08: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #08:Check:vManage:Elasticsearch Indices version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#09:Check:vManage:Evaluate incoming DPI data size
			log_file_logger.info('#09:Check:vManage:Evaluate incoming DPI data size')
			writeFile(report_file, '#09:Check:vManage:Evaluate incoming DPI data size\n\n')

			try:
				es_indices_est = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid,'management/elasticsearch/index/size/estimate', args.vmanage_port))
				appr_estimate_ondeday, dpi_estimate_ondeday, check_result,check_analysis,check_action = criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count, total_devices, dpi_status)
				if check_result == 'Failed':
					critical_checks['#09:Check:vManage:Evaluate incoming DPI data size'] = [ check_analysis, check_action]

					log_file_logger.error('#09: Check result:   {}'.format(check_result))
					log_file_logger.error('#09: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#09: Daily incoming DPI data : {}'.format(dpi_estimate_ondeday))
					log_file_logger.error('#09: Daily incoming Approute data : {}\n'.format(appr_estimate_ondeday))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#09: Check result:   {}'.format(check_result))
					log_file_logger.info('#09: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #09:Check:vManage:Evaluate incoming DPI data size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#10:Check:vManage:NTP status across network
				log_file_logger.info('#10:Check:vManage:NTP status across network')
				writeFile(report_file, '#10:Check:vManage:NTP status across network\n\n')

				try:
				  ntp_nonworking, check_result, check_analysis, check_action = criticalCheckten(version_tuple, controllers_info)
				  if check_result == 'Failed':
					  critical_checks['#10:Check:vManage:NTP status across network'] = [ check_analysis, check_action]

					  log_file_logger.error('#10: Check result:   {}'.format(check_result))
					  log_file_logger.error('#10: Check Analysis: {}'.format(check_analysis))
					  log_file_logger.error('#10: Devices with invalid ntp associations:\n{}\n'.format(ntp_nonworking))

					  writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					  writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				  else:
					  log_file_logger.info('#10: Check result:   {}'.format(check_result))
					  log_file_logger.info('#10: Check Analysis: {}\n'.format(check_analysis))

					  writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #10:Check:vManage:NTP status across network. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

			#11:Check:Controllers:Validate vSmart/vBond CPU count for scale
				log_file_logger.info('#11:Check:Controllers:Validate vSmart/vBond CPU count for scale')
				writeFile(report_file, '#11:Check:Controllers:Validate vSmart/vBond CPU count for scale\n\n')

				try:
					for vbond in vbond_info:
						output = json.loads(getRequest( version_tuple,vmanage_lo_ip, jsessionid,'device/system/synced/status?deviceId={}'.format(vbond_info[vbond][1]),args.vmanage_port ))
						total_cpu_count = int(output['data'][0]['total_cpu_count'])
						vbond_info[vbond].append(total_cpu_count)

					for vsmart in vsmart_info:
						output = json.loads(getRequest( version_tuple,vmanage_lo_ip, jsessionid,'device/system/synced/status?deviceId={}'.format(vsmart_info[vsmart][1]), args.vmanage_port))
						total_cpu_count = int(output['data'][0]['total_cpu_count'])
						vsmart_info[vsmart].append(total_cpu_count)

					failed_vbonds,failed_vsmarts,check_result,check_analysis, check_action = criticalCheckeleven(total_devices, vbond_info, vsmart_info)
					if check_result == 'Failed':
						critical_checks['#11:Check:Controllers:Validate vSmart/vBond CPU count for scale'] = [ check_analysis, check_action]

						log_file_logger.error('#11: Check result:   {}'.format(check_result))
						log_file_logger.error('#11: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#11: vBonds with insufficient CPU count: \n{}'.format(failed_vbonds))
						log_file_logger.error('#11: vSmarts with insufficient CPU count: \n{}'.format(failed_vsmarts))
						log_file_logger.error('#11: All vBonds info with total_cpu_count: \n{}'.format(vbond_info))
						log_file_logger.error('#11: All vSmarts info with total_cpu_count: \n{}\n'.format(vsmart_info))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
						
					else:
						log_file_logger.info('#11: Check result:   {}'.format(check_result))
						log_file_logger.info('#11: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#11: All vBonds info with total_cpu_count: \n{}'.format(vbond_info))
						log_file_logger.info('#11: All vSmarts info with total_cpu_count: \n{}\n'.format(vsmart_info))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #11:Check:Controllers:Validate vSmart/vBond CPU count for scale. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))
				
			#Warning Checks
			warning_checks = {}
			log_file_logger.info('*** Performing Warning Checks')

			#12:Check:vManage:CPU Speed
			log_file_logger.info('#12:Check:vManage:CPU Speed')
			writeFile(report_file, '#12:Check:vManage:CPU Speed\n\n')

			try:
				check_result,check_analysis,check_action = warningCheckone(cpu_speed)
				if check_result == 'Failed':
					warning_checks['#12:Check:vManage:CPU Speed'] = [ check_analysis, check_action]

					log_file_logger.error('#12: Check result: {}'.format(check_result))
					log_file_logger.error('#12: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#12: CPU clock speed: {}\n'.format(cpu_speed))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#12: Check result: {}'.format(check_result))
					log_file_logger.info('#12: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #12:Check:vManage:CPU Speed. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#13:Check:vManage:Network Card type
			log_file_logger.info('#13:Check:vManage:Network Card type')
			writeFile(report_file, '#13:Check:vManage:Network Card type\n\n')

			try:
				eth_drivers, check_action, check_analysis, check_result = warningChecktwo()
				if check_result == 'Failed':
					warning_checks['#13:Check:vManage:Network Card type'] = [ check_analysis, check_action]

					log_file_logger.error('#13: Check result:   {}'.format(check_result))
					log_file_logger.error('#13: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#13: Ethercards with e1000 card types: {}\n'.format(eth_drivers))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#13: Check result:   {}'.format(check_result))
					log_file_logger.info('#13: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #13:Check:vManage:Network Card type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#14:Check:vManage:Backup status
			log_file_logger.info('#14:Check:vManage:Backup status')
			writeFile(report_file, '#14:Check:vManage:Backup status\n\n')

			try:
				date_time_obj, check_result, check_analysis, check_action = warningCheckthree()
				if check_result == 'Failed':
					warning_checks['#14:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#14: Check result:   {}'.format(check_result))
					log_file_logger.error('#14: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#14: Last Backup was performed on: {}\n'.format(date_time_obj))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#14: Check result:   {}'.format(check_result))
					log_file_logger.info('#14: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #14:Check:vManage:Backup status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#15:Check:vManage:Evaluate Neo4j performance
			log_file_logger.info('#15:Check:vManage:Evaluate Neo4j performance')
			writeFile(report_file, '#15:Check:vManage:Evaluate Neo4j performance\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckfour()
				if check_result == 'Failed':
					warning_checks['#15:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#15: Check result:   {}'.format(check_result))
					log_file_logger.error('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#15: Check result:   {}'.format(check_result))
					log_file_logger.info('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #15:Check:vManage:Evaluate Neo4j performance. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#16:Check:vManage:Confirm there are no pending tasks
			log_file_logger.info('#16:Check:vManage:Confirm there are no pending tasks')
			writeFile(report_file, '#16:Check:vManage:Confirm there are no pending tasks\n\n')

			try:
				tasks = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'device/action/status/tasks', args.vmanage_port))
				tasks_running, check_result, check_analysis, check_action  = warningCheckfive(tasks)
				if check_result == 'Failed':
					warning_checks['#16:Check:vManage:Confirm there are no pending tasks'] = [ check_analysis, check_action]
					log_file_logger.error('#16: Check result:   {}'.format(check_result))
					log_file_logger.error('#16: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#16: Tasks still running: {}\n'.format(tasks_running))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))                   

				else:
					log_file_logger.info('#16: Check result:   {}'.format(check_result))
					log_file_logger.info('#16: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #16:Check:vManage:Confirm there are no pending tasks. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#17:Check:vManage:Validate there are no empty password users
			log_file_logger.info('#17:Check:vManage:Validate there are no empty password users')
			writeFile(report_file, '#17:Check:vManage:Validate there are no empty password users\n\n')
			
			try:
				users_emptypass, check_result, check_analysis, check_action = warningChecksix(version_tuple)
				if check_result == 'Failed':
					warning_checks['#17:Check:vManage:Validate there are no empty password users'] = [ check_analysis, check_action]
					log_file_logger.error('#17: Check result:   {}'.format(check_result))
					log_file_logger.error('#17: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#17: Users with empty passwords: {}\n'.format(users_emptypass))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#17: Check result:   {}'.format(check_result))
					log_file_logger.info('#17: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
			
			except Exception as e:
				print('\033[1;31m ERROR: Error performing  #17:Check:vManage:Validate there are no empty password users. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#18:Check:Controllers:Controller versions
			log_file_logger.info('#18:Check:Controllers:Controller versions')
			writeFile(report_file, '#18:Check:Controllers:Controller versions\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckseven(controllers_info)
				if check_result == 'Failed':
					warning_checks['#18:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#18: Check result:   {}'.format(check_result))
					log_file_logger.error('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#18: Check result:   {}'.format(check_result))
					log_file_logger.info('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #18:Check:Controllers:Controller versions. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#19:Check:Controllers:Confirm Certificate Expiration Dates
			log_file_logger.info('#19:Check:Controllers:Confirm Certificate Expiration Dates')
			writeFile(report_file, '#19:Check:Controllers:Confirm Certificate Expiration Dates\n\n')

			try:
				controllers_exp, controllers_notexp, check_result, check_analysis, check_action = warningCheckeight(controllers_info)
				if check_result == 'Failed':
					warning_checks['#19:Check:Controllers:Confirm Certificate Expiration Dates'] = [ check_analysis, check_action]
					log_file_logger.error('#19: Check result:   {}'.format(check_result))
					log_file_logger.error('#19: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#19: Controllers with certificates close to expiration:\n{}\n'.format(controllers_exp))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				   
				else:
					log_file_logger.info('#19: Check result:   {}'.format(check_result))
					log_file_logger.info('#19: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #19:Check:Controllers:Confirm Certificate Expiration Dates. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#20:Check:Controllers:vEdge list sync
			log_file_logger.info('#20:Check:Controllers:vEdge list sync')
			writeFile(report_file, '#20:Check:Controllers:vEdge list sync\n\n')

			try:
				state_vedgeList,check_result, check_analysis, check_action  = warningChecknine(controllers_info)
				if check_result == 'Failed':
					warning_checks['#20:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#20: Check result:   {}'.format(check_result))
					log_file_logger.error('#20: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#20: Controllers with inconsistent state_vedgeList: {}\n'.format(state_vedgeList))
					
					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))                  

				else:
					log_file_logger.info('#20: Check result:   {}'.format(check_result))
					log_file_logger.info('#20: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #20:Check:Controllers:vEdge list sync. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#21:Check:Controllers: Confirm control connections
			log_file_logger.info('#21:Check:Controllers: Confirm control connections')
			writeFile(report_file, '#21:Check:Controllers: Confirm control connections\n\n')

			try:
				control_sum_tab, discrepancy,check_result, check_analysis, check_action = warningCheckten(vsmart_count, vbond_count)
				if check_result == 'Failed':
					warning_checks['#21:Check:Controllers: Confirm control connections'] = [ check_analysis, check_action]

					log_file_logger.error('#21: Check result:   {}'.format(check_result))
					log_file_logger.error('#21: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#21: Control  Connections Summary:\n{}\n'.format(control_sum_tab))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#21: Check result:   {}'.format(check_result))
					log_file_logger.info('#21: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #21:Check:Controllers: Confirm control connections. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

		 
			#Informational Checks
			log_file_logger.info('*** Performing Informational Checks')

			#22:Check:vManage:Disk controller type
			log_file_logger.info('#22:Check:vManage:Disk controller type')
			writeFile(report_file, '#22:Check:vManage:Disk controller type\n\n')

			try:
				check_result, check_analysis, check_action = infoCheckone(server_type, disk_controller)
				if check_result == 'Failed':
					warning_checks['#22:Check:vManage:Disk controller type'] = [ check_analysis, check_action]

					log_file_logger.error('#22: Check result:   {}'.format(check_result))
					log_file_logger.error('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#22: Check result:   {}'.format(check_result))
					log_file_logger.info('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #22:Check:vManage:Disk controller type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#23:Check:Controllers:Validate there is at minimum vBond, vSmart present
			log_file_logger.info('#23:Check:Controllers:Validate there is at minimum vBond, vSmart present')
			writeFile(report_file, '#23:Check:Controllers:Validate there is at minimum vBond, vSmart present\n\n')
			
			try:
				check_result, check_analysis, check_action = infoChecktwo(vsmart_count,vbond_count)
				if check_result == 'Failed':
					warning_checks['#23:Check:Controllers:Validate there is at minimum vBond, vSmart present'] = [ check_analysis, check_action]

					log_file_logger.error('#23: Check result:   {}'.format(check_result))
					log_file_logger.error('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.error('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#23: Check result:   {}'.format(check_result))
					log_file_logger.info('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.info('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #23:Check:Controllers:Validate there is at minimum vBond, vSmart present. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#24:Check:Controllers:Validate all controllers are reachable
			log_file_logger.info('#24:Check:Controllers:Validate all controllers are reachable')
			writeFile(report_file, '#24:Check:Controllers:Validate all controllers are reachable\n\n')
			
			try:
				unreach_controllers,check_result, check_analysis, check_action = infoChecktthree(controllers_info)
				if check_result == 'Failed':
					warning_checks['#24:Check:Controllers:Validate all controllers are reachable'] = [ check_analysis, check_action]

					log_file_logger.error('#24: Check result:   {}'.format(check_result))
					log_file_logger.error('#24: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#24: Unreachable Controllers: {}\n'.format(unreach_controllers))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#24: Check result:   {}'.format(check_result))
					log_file_logger.info('#24: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #24:Check:Controllers:Validate all controllers are reachable. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			if cluster_size>1:
				cluster_checks = {}
				log_file_logger.info('*** Performing Cluster Checks')

				#25:Check:Cluster:Version consistency
				log_file_logger.info('#25:Check:Cluster:Version consistency')
				writeFile(report_file, '#25:Check:Cluster:Version consistency\n\n')

				try:
					check_result,check_analysis, check_action = criticalChecktwelve(vmanage_info)
					if check_result == 'Failed':
						cluster_checks['#25:Check:Cluster:Version consistency'] = [ check_analysis, check_action]

						log_file_logger.error('#25: Check result:   {}'.format(check_result))
						log_file_logger.error('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					   
					else:
						log_file_logger.info('#25: Check result:   {}'.format(check_result))
						log_file_logger.info('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						
				except Exception as e:
					print('\033[1;31m ERROR: Error performing #25:Check:Cluster:Version consistency. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#26:Check:Cluster:Cluster health
				log_file_logger.info('#26:Check:Cluster:Cluster health')
				writeFile(report_file, '#26:Check:Cluster:Cluster health\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'clusterManagement/list', args.vmanage_port))
					services_down, check_result, check_analysis, check_action = criticalCheckthirteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#26:Check:Cluster:Cluster health'] = [ check_analysis, check_action]

						log_file_logger.error('#26: Check result:   {}'.format(check_result))
						log_file_logger.error('#26: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#26: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					   
					else: 
						log_file_logger.info('#26: Check result:   {}'.format(check_result))
						log_file_logger.info('#26: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #26:Check:Cluster:Cluster health. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#27:Check:Cluster:Cluster ConfigDB topology
				log_file_logger.info('#27:Check:Cluster:Cluster ConfigDB topology')
				writeFile(report_file, '#27:Check:Cluster:Cluster ConfigDB topology\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'clusterManagement/list', args.vmanage_port))           
					configDB_count, check_result, check_analysis, check_action = criticalCheckfourteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#27:Check:Cluster:Cluster ConfigDB topology'] = [ check_analysis, check_action]

						log_file_logger.error('#27: Check result:   {}'.format(check_result))
						log_file_logger.error('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					else: 
						log_file_logger.info('#27: Check result:   {}'.format(check_result))
						log_file_logger.info('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #27:Check:Cluster:Cluster ConfigDB topology. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#28:Check:Cluster:Messaging server
				log_file_logger.info('#28:Check:Cluster:Messaging server')
				writeFile(report_file, '#28:Check:Cluster:Messaging server\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'clusterManagement/list', args.vmanage_port))           
					cluster_msdown,check_result,check_analysis, check_action = criticalCheckfifteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#28:Check:Cluster:Messaging server'] = [ check_analysis, check_action]

						log_file_logger.error('#28: Check result:   {}'.format(check_result))
						log_file_logger.error('#28: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#28: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					   
					else: 
						log_file_logger.info('#28: Check result:   {}'.format(check_result))
						log_file_logger.info('#28: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #28:Check:Cluster:Messaging server. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))
				
				#29:Check:Cluster:DR replication status
				log_file_logger.info('#29:Check:Cluster:DR replication status')
				writeFile(report_file, '#29:Check:Cluster:DR replication status\n\n')

				try:
					dr_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'disasterrecovery/details', args.vmanage_port))           
					dr_status, check_action, check_analysis, check_result = criticalChecksixteen(dr_data)
					if check_result == 'Failed':
						cluster_checks['#29:Check:Cluster:DR replication status'] = [ check_analysis, check_action]

						log_file_logger.error('#29: Check result:   {}'.format(check_result))
						log_file_logger.error('#29: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#29: DR Replication status: {}\n'.format(dr_status))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					else:
						log_file_logger.info('#29: Check result:   {}'.format(check_result))
						log_file_logger.info('#29: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #29:Check:Cluster:DR replication status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#30:Check:Cluster:Intercluster communication
				log_file_logger.info('#30:Check:Cluster:Intercluster communication')
				writeFile(report_file, '#30:Check:Cluster:Intercluster communication\n\n')
				
				try:
					if criticalCheckseventeen.isAlive():
						criticalCheckseventeen.join(10)

					if not criticalCheckseventeen.result_queue.empty():
						ping_output, ping_output_failed, ping_check_result, ping_check_analysis, ping_check_action = criticalCheckseventeen.result_queue.get()
						if ping_check_result == 'Failed':
							cluster_checks['#30:Check:Cluster:Intercluster communication'] = [ ping_check_analysis, ping_check_action]

							log_file_logger.error('#30: Check result:   {}'.format(ping_check_result))
							log_file_logger.error('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.error('#30: Cluster nodes with ping failure: {}\n'.format(ping_output_failed))

							writeFile(report_file, 'Result: ERROR - {}\n'.format(ping_check_analysis))
							writeFile(report_file, 'Action: {}\n\n'.format(ping_check_action))

						else:
							log_file_logger.info('#30: Check result:   {}'.format(ping_check_result))
							log_file_logger.info('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.info('#30: Cluster nodes details: {}\n'.format(ping_output))

							writeFile(report_file, 'Result: INFO - {}\n\n'.format(ping_check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #30:Check:Cluster:Intercluster communication. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


			#Logging out of the Session using jsessionid
			log_file_logger.info('Logging out of the Session')
			sessionLogout(vmanage_lo_ip, jsessionid, args.vmanage_port)
			log_file_logger.info('Successfully closed the connection')
			

		#version equal to or above 19.2
		elif version_tuple[0:2] >= ('19','2') and version_tuple[0:2] < ('20','5'): 
			try:
				log_file_logger.info('Generating a JSessionID')
				jsessionid = generateSessionID(vmanage_lo_ip, args.username, password, args.vmanage_port)
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error generating JSessionID, make sure that the username and password entered is correct. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))

			try:
				log_file_logger.info('Generating CSRF Token')
				tokenid = CSRFToken(vmanage_lo_ip,jsessionid,args.vmanage_port)
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error generating CSRF Token. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file.  \033[0;0m \n\n'.format(log_file_path))

			#Preliminary data
			log_file_logger.info('****Collecting Preliminary Data\n')

			try:
				controllers = json.loads(getRequest(version_tuple, vmanage_lo_ip,jsessionid, 'system/device/controllers', args.vmanage_port, tokenid))
				controllers_info = controllersInfo(controllers)
				log_file_logger.info('Collected controllers information: {}'.format(controllers_info))

				system_ip_data = json.loads(getRequest(version_tuple, vmanage_lo_ip,jsessionid, 'device/vmanage', args.vmanage_port, tokenid))
				system_ip = system_ip_data['data']['ipAddress']
				#system_ip = controllers_info[hostname][1]
				log_file_logger.info('Collected vManage System IP address: {}'.format(system_ip))

				cpu_speed = cpuSpeed()
				log_file_logger.info('Collected vManage CPU Speed GHz: {}'.format(cpu_speed))

				cpu_count = cpuCount()
				log_file_logger.info('Collected vManage CPU Count: {}'.format(cpu_count))

				vedges = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'system/device/vedges', args.vmanage_port , tokenid))
				vedge_count,vedge_count_active, vedge_info = vedgeCount(vedges)
				log_file_logger.info('Collected  xEdge Count: {}'.format(vedge_count))

				cluster_size, server_mode, vmanage_info = serverMode(controllers_info)
				log_file_logger.info('Collected vManage Cluster Size: {}'.format(cluster_size))
				log_file_logger.info('Collected vManage Server Mode: {}'.format(server_mode))

				disk_controller = diskController()
				log_file_logger.info('Collected vManage Disk Controller Type: {}'.format(disk_controller))

				dpi_stats = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid,'statistics/settings/status', args.vmanage_port, tokenid))
				dpi_status = dpiStatus(dpi_stats)
				log_file_logger.info('Collected DPI Status: {}'.format(dpi_status))

				server_type = serverType()
				log_file_logger.info('Collected Server Type: {}'.format(server_type))

				vbond_info, vsmart_info = vbondvmartInfo(controllers_info)
				vbond_count = len(vbond_info)
				vsmart_count = len(vsmart_info)
				log_file_logger.info('vSmart info: {}'.format(vbond_info))
				log_file_logger.info('vBond info: {}'.format(vsmart_info))
				

				total_devices = len(controllers_info.keys()) + vedge_count
				log_file_logger.info('Total devices: {}'.format(total_devices))

			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error Collecting Preliminary Data. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				

			print('*Starting Checks, this may take several minutes\n\n')

			#Critical Checks
			critical_checks = {}
			log_file_logger.info('*** Performing Critical Checks\n')

			#Begining #30:Check:Cluster:Intercluster communication  in the background
			if cluster_size>1:
				log_file_logger.info('Beginging #30:Check:Cluster:Intercluster communication  in the background\n')
				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))
					criticalCheckseventeen =  criticalCheckseventeen(cluster_health_data,  system_ip, log_file_logger)
				except Exception as e:
					log_file_logger.exception('{}\n'.format(e))

			#01:Check:vManage:Validate current version
			log_file_logger.info('#01:Check:vManage:Validate current version')
			writeFile(report_file, '#01:Check:vManage:Validate current version\n\n')
			
			try:
				boot_partition_size, check_result, check_analysis, check_action =  criticalCheckone(version)
				if check_result == 'Failed':
					critical_checks['#01:Check:vManage:Validate current version'] = [ check_analysis, check_action]

					log_file_logger.error('#01: Check result:   {}'.format(check_result))
					log_file_logger.error('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#01: version: {}'.format(version))
					log_file_logger.error('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#01: Check result:   {}'.format(check_result))
					log_file_logger.info('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#01: version: {}'.format(version))
					log_file_logger.info('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #01:Check:vManage:Validate current version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#02:Check:vManage:At minimum 20%  server disk space should be available
			log_file_logger.info('#02:Check:vManage:At minimum 20%  server disk space should be available')
			writeFile(report_file, '#02:Check:vManage:At minimum 20%  server disk space should be available\n\n')

			try:
				optdata_partition_size, rootfs_partition_size, check_result, check_analysis, check_action =  criticalCheckTwo()
				if check_result == 'Failed': 
					critical_checks['#02:Check:vManage:At minimum 20%  server disk space should be available'] = [check_analysis, check_action]

					log_file_logger.error('#02: Check result:   {}'.format(check_result))
					log_file_logger.error('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.error('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#02: Check result:   {}'.format(check_result))
					log_file_logger.info('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.info('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #02:Check:vManage:At minimum 20%  server disk space should be available. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#03:Check:vManage:Memory size
			log_file_logger.info('#03:Check:vManage:Memory size')
			writeFile(report_file, '#03:Check:vManage:Memory size\n')
			writeFile(report_file, 'Link to the official documentation: \n https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html\n\n')

			try:
				memory_size, memory_size_str, dpi_status, server_type, check_result, check_analysis, check_action =  criticalCheckthree(vedge_count, dpi_status, server_type, cluster_size, version_tuple)
				if check_result == 'Failed':
					critical_checks['#03:Check:vManage:Memory size'] = [ check_analysis, check_action]

					log_file_logger.error('#03: Check result:   {}'.format(check_result))
					log_file_logger.error('#03: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#03: Memory Size GB: {}'.format(memory_size_str))
					log_file_logger.error('#03: /rootfs.rw Used: {}'.format(rootfs_partition_size))
					log_file_logger.error('#03: Server Type: {}'.format(server_type))
					log_file_logger.error('#03: vEdge Count: {}\n'.format(vedge_count))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#03: Check result:   {}'.format(check_result))
					log_file_logger.info('#03: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #03:Check:vManage:Memory size \033[0;0m. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
		 
			#04:Check:vManage:CPU Count
			log_file_logger.info('#04:Check:vManage:CPU Count')
			writeFile(report_file, '#04:Check:vManage:CPU Count\n\n')

			try:
				check_result, check_analysis, check_action = criticalCheckfour(cpu_count, vedge_count, dpi_status, server_type)
				if check_result == 'Failed':
					critical_checks['#04:Check:vManage:CPU Count'] = [ check_analysis, check_action]

					log_file_logger.error('#04: Check result:   {}'.format(check_result))
					log_file_logger.error('#04: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#04: CPU Count: {}\n'.format(cpu_count))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#04: Check result:   {}'.format(check_result))
					log_file_logger.info('#04: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #04:Check:vManage:CPU Count \033[0;0m. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#05:Check:vManage:ElasticSearch Indices status
			log_file_logger.info('#05:Check:vManage:ElasticSearch Indices status')
			writeFile(report_file, '#05:Check:vManage:ElasticSearch Indices status\n\n')

			try:
				es_indexes_one = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_index_red_one, check_result_one, check_analysis_one, check_action_one = criticalCheckfive(es_indexes_one)

				time.sleep(5)

				es_indexes_two = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_index_red_two, check_result_two, check_analysis_two, check_action_two = criticalCheckfive(es_indexes_two)

				
				if check_result_one == 'Failed' and check_result_two == 'Failed':
					critical_checks['#05:Check:vManage:ElasticSearch Indices status'] = [ check_analysis_two, check_action_two]

					log_file_logger.error('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.error('#05: Check Analysis: {}\n'.format(check_analysis_two))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis_two))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action_two))
				   
				elif check_result_one == 'SUCCESSFUL':
					log_file_logger.info('#05: Check result:   {}'.format(check_result_one))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_one))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_one))

				elif check_result_two == 'SUCCESSFUL':

					log_file_logger.info('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_two))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_two))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #05:Check:vManage:ElasticSearch Indices status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#06:Check:vManage:Look for any neo4j exception errors
			log_file_logger.info('#06:Check:vManage:Look for any neo4j exception errors')
			writeFile(report_file, '#06:Check:vManage:Look for any neo4j exception errors\n\n')

			try:
				check_result, check_analysis, check_action = criticalChecksix()
				if check_result == 'Failed':
					critical_checks['#06:Check:vManage:Look for any neo4j exception errors'] = [check_analysis, check_action]

					log_file_logger.error('#06: Check result:   {}'.format(check_result))
					log_file_logger.error('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))


				else:
					log_file_logger.info('#06: Check result:   {}'.format(check_result))
					log_file_logger.info('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #06:Check:vManage:Look for any neo4j exception errors. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#07:Check:vManage:Validate all services are up
				log_file_logger.info('#07:Check:vManage:Validate all services are up')
				writeFile(report_file, '#07:Check:vManage:Validate all services are up\n\n')

				try:
				  nms_data, nms_failed, check_result, check_analysis, check_action =   criticalCheckseven() 
				  if check_result == 'Failed':
					  critical_checks['#07:Check:vManage:Validate all services are up'] = [check_analysis, check_action]

					  log_file_logger.error('#07: Check result:   {}'.format(check_result))
					  log_file_logger.error('#07: Check Analysis: {}'.format(check_analysis))
					  log_file_logger.error('#07: List of services that are enabled but not running:\n{}'.format(nms_failed))
					  log_file_logger.error('#07: Status of all services  :\n{}\n'.format(nms_data))

					  writeFile(report_file, 'Result: ERROR - {}\n\n'.format(check_analysis))
					  writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					 
				  else:
					  log_file_logger.info('#07: Check result:   {}'.format(check_result))
					  log_file_logger.info('#07: Check Analysis: {}'.format(check_analysis))
					  log_file_logger.info('#07: Status of all the services:\n{}\n'.format(nms_data))

					  writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #07:Check:vManage:Validate all services are up. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


			#08:Check:vManage:Elasticsearch Indices version
			log_file_logger.info('#08:Check:vManage:Elasticsearch Indices version')
			writeFile(report_file, '#08:Check:vManage:Elasticsearch Indices version\n\n')

			try:
				version_list, check_result, check_analysis, check_action = criticalCheckeight(version_tuple)
				if check_result == 'Failed':
					critical_checks['#08:Check:vManage:Elasticsearch Indices version'] = [ check_analysis, check_action]

					log_file_logger.error('#08: Check result:   {}'.format(check_result))
					log_file_logger.error('#08: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#08: List of indices with older versions:\n{}\n'.format(version_list))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#08: Check result:   {}'.format(check_result))
					log_file_logger.info('#08: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #08:Check:vManage:Elasticsearch Indices version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#09:Check:vManage:Evaluate incoming DPI data size
			log_file_logger.info('#09:Check:vManage:Evaluate incoming DPI data size')
			writeFile(report_file, '#09:Check:vManage:Evaluate incoming DPI data size\n\n')

			try:
				es_indices_est = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'management/elasticsearch/index/size/estimate', args.vmanage_port, tokenid))
				appr_estimate_ondeday, dpi_estimate_ondeday, check_result, check_analysis,check_action = criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count, total_devices, dpi_status)
				if check_result == 'Failed':
					critical_checks['#09:Check:vManage:Evaluate incoming DPI data size'] = [ check_analysis, check_action]

					log_file_logger.error('#09: Check result:   {}'.format(check_result))
					log_file_logger.error('#09: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#09: Daily incoming DPI data : {}'.format(dpi_estimate_ondeday))
					log_file_logger.error('#09: Daily incoming Approute data : {}\n'.format(appr_estimate_ondeday))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#09: Check result:   {}'.format(check_result))
					log_file_logger.info('#09: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #09:Check:vManage:Evaluate incoming DPI data size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#10:Check:vManage:NTP status across network
			log_file_logger.info('#10:Check:vManage:NTP status across network')
			writeFile(report_file, '#10:Check:vManage:NTP status across network\n\n')

			try:
				ntp_nonworking, check_result, check_analysis, check_action = criticalCheckten(version_tuple, controllers_info)
				if check_result == 'Failed':
					critical_checks['#10:Check:vManage:NTP status across network'] = [ check_analysis, check_action]

					log_file_logger.error('#10: Check result:   {}'.format(check_result))
					log_file_logger.error('#10: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#10: Devices with invalid ntp associations:\n{}\n'.format(ntp_nonworking))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#10: Check result:   {}'.format(check_result))
					log_file_logger.info('#10: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #10:Check:vManage:NTP status across network. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#11:Check:Controllers:Validate vSmart/vBond CPU count for scale
			log_file_logger.info('#11:Check:Controllers:Validate vSmart/vBond CPU count for scale')
			writeFile(report_file, '#11:Check:Controllers:Validate vSmart/vBond CPU count for scale\n\n')

			try:
				for vbond in vbond_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip, jsessionid, 'device/system/synced/status?deviceId={}'.format(vbond_info[vbond][1]),args.vmanage_port, tokenid))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vbond_info[vbond].append(total_cpu_count)

				for vsmart in vsmart_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip,jsessionid, 'device/system/synced/status?deviceId={}'.format(vsmart_info[vsmart][1]),args.vmanage_port,tokenid))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vsmart_info[vsmart].append(total_cpu_count)

				failed_vbonds,failed_vsmarts,check_result,check_analysis, check_action = criticalCheckeleven(total_devices, vbond_info, vsmart_info)
				if check_result == 'Failed':
					critical_checks['#11:Check:Controllers:Validate vSmart/vBond CPU count for scale'] = [ check_analysis, check_action]

					log_file_logger.error('#11: Check result:   {}'.format(check_result))
					log_file_logger.error('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#11: vBonds with insufficient CPU count: \n{}'.format(failed_vbonds))
					log_file_logger.error('#11: vSmarts with insufficient CPU count: \n{}'.format(failed_vsmarts))
					log_file_logger.error('#11: All vBonds info with total_cpu_count: \n{}'.format(vbond_info))
					log_file_logger.error('#11: All vSmarts info with total_cpu_count: \n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#11: Check result:   {}'.format(check_result))
					log_file_logger.info('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#11: All vBonds info with total_cpu_count:\n{}'.format(vbond_info))
					log_file_logger.info('#11: All vSmarts info with total_cpu_count: \n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #11:Check:Controllers:Validate vSmart/vBond CPU count for scale. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Warning Checks
			warning_checks = {}
			log_file_logger.info('*** Performing Warning Checks')

			#12:Check:vManage:CPU Speed
			log_file_logger.info('#12:Check:vManage:CPU Speed')
			writeFile(report_file, '#12:Check:vManage:CPU Speed\n\n')

			try:
				check_result,check_analysis,check_action = warningCheckone(cpu_speed)
				if check_result == 'Failed':
					warning_checks['#12:Check:vManage:CPU Speed'] = [ check_analysis, check_action]

					log_file_logger.error('#12: Check result:   {}'.format(check_result))
					log_file_logger.error('#12: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#12: CPU clock speed: {}\n'.format(cpu_speed))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#12: Check result:   {}'.format(check_result))
					log_file_logger.info('#12: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #12:Check:vManage:CPU Speed. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#13:Check:vManage:Network Card type
			log_file_logger.info('#13:Check:vManage:Network Card type')
			writeFile(report_file, '#13:Check:vManage:Network Card type\n\n')

			try:
				eth_drivers, check_action, check_analysis, check_result = warningChecktwo()
				if check_result == 'Failed':
					warning_checks['#13:Check:vManage:Network Card type'] = [ check_analysis, check_action]

					log_file_logger.error('#13: Check result:   {}'.format(check_result))
					log_file_logger.error('#13: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#13: Ethercardswith e1000 card types: {}\n'.format(eth_drivers))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#13: Check result:   {}'.format(check_result))
					log_file_logger.info('#13: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #13:Check:vManage:Network Card type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#14:Check:vManage:Backup status
			log_file_logger.info('#14:Check:vManage:Backup status')
			writeFile(report_file, '#14:Check:vManage:Backup status\n\n')

			try:
				date_time_obj, check_result, check_analysis, check_action = warningCheckthree()
				if check_result == 'Failed':
					warning_checks['#14:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#14: Check result:   {}'.format(check_result))
					log_file_logger.error('#14: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#14: Last Backup was performed on:{}\n'.format(date_time_obj))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#14: Check result:   {}'.format(check_result))
					log_file_logger.info('#14: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #14:Check:vManage:Backup status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#15:Check:vManage:Evaluate Neo4j performance
			log_file_logger.info('#15:Check:vManage:Evaluate Neo4j performance')
			writeFile(report_file, '#15:Check:vManage:Evaluate Neo4j performance\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckfour()
				if check_result == 'Failed':
					warning_checks['#15:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#15: Check result:   {}'.format(check_result))
					log_file_logger.error('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#15: Check result:   {}'.format(check_result))
					log_file_logger.info('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #15:Check:vManage:Evaluate Neo4j performance. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#16:Check:vManage:Confirm there are no pending tasks
			log_file_logger.info('#16:Check:vManage:Confirm there are no pending tasks')
			writeFile(report_file, '#16:Check:vManage:Confirm there are no pending tasks\n\n')

			try:
				tasks = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'device/action/status/tasks', args.vmanage_port, tokenid))
				tasks_running, check_result, check_analysis, check_action  = warningCheckfive(tasks)
				if check_result == 'Failed':
					warning_checks['#16:Check:vManage:Confirm there are no pending tasks'] = [ check_analysis, check_action]
					log_file_logger.error('#16: Check result:   {}'.format(check_result))
					log_file_logger.error('#16: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#16: Tasks still running: {}\n'.format(tasks_running))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#16: Check result:   {}'.format(check_result))
					log_file_logger.info('#16: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #16:Check:vManage:Confirm there are no pending tasks. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#17:Check:vManage:Validate there are no empty password users
			log_file_logger.info('#17:Check:vManage:Validate there are no empty password users')
			writeFile(report_file, '#17:Check:vManage:Validate there are no empty password users\n\n')
			
			try:
				users_emptypass, check_result, check_analysis, check_action = warningChecksix(version_tuple)
				if check_result == 'Failed':
					warning_checks['#17:Check:vManage:Validate there are no empty password users'] = [ check_analysis, check_action]
					log_file_logger.error('#17: Check result:   {}'.format(check_result))
					log_file_logger.error('#17: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#17: Users with empty passwords: {}\n'.format(users_emptypass))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#17: Check result:   {}'.format(check_result))
					log_file_logger.info('#17: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #17:Check:vManage:Validate there are no empty password users. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#18:Check:Controllers:Controller versions
			log_file_logger.info('#18:Check:Controllers:Controller versions')
			writeFile(report_file, '#18:Check:Controllers:Controller versions\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckseven(controllers_info)
				if check_result == 'Failed':
					warning_checks['18:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#18: Check result:   {}'.format(check_result))
					log_file_logger.error('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#18: Check result:   {}'.format(check_result))
					log_file_logger.info('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #18:Check:Controllers:Controller versions. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#19:Check:Controllers:Confirm Certificate Expiration Dates
			log_file_logger.info('#19:Check:Controllers:Confirm Certificate Expiration Dates')
			writeFile(report_file, '#19:Check:Controllers:Confirm Certificate Expiration Dates\n\n')

			try:
				controllers_exp, controllers_notexp, check_result, check_analysis, check_action = warningCheckeight(controllers_info)
				if check_result == 'Failed':
					warning_checks['#19:Check:Controllers:Confirm Certificate Expiration Dates'] = [ check_analysis, check_action]
					log_file_logger.error('#19: Check result:   {}'.format(check_result))
					log_file_logger.error('#19: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#19: Controllers with certificates close to expiration:\n{}\n'.format(controllers_exp))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#19: Check result:   {}'.format(check_result))
					log_file_logger.info('#19: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #19:Check:Controllers:Confirm Certificate Expiration Dates. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#20:Check:Controllers:vEdge list sync
			log_file_logger.info('#20:Check:Controllers:vEdge list sync')
			writeFile(report_file, '#20:Check:Controllers:vEdge list sync\n\n')

			try:
				state_vedgeList,check_result, check_analysis, check_action  = warningChecknine(controllers_info)
				if check_result == 'Failed':
					warning_checks['#20:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#20: Check result:   {}'.format(check_result))
					log_file_logger.error('#20: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#20: Controllers with inconsistent state_vedgeList: {}\n'.format(state_vedgeList))
					
					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#20: Check result:   {}'.format(check_result))
					log_file_logger.info('#20: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #20:Check:Controllers:vEdge list sync. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#21:Check:Controllers: Confirm control connections
			log_file_logger.info('#21:Check:Controllers: Confirm control connections')
			writeFile(report_file, '#21:Check:Controllers: Confirm control connections\n\n')

			try:
				control_sum_tab, discrepancy,check_result, check_analysis, check_action = warningCheckten(vsmart_count, vbond_count)
				if check_result == 'Failed':
					warning_checks['#21:Check:Controllers: Confirm control connections'] = [ check_analysis, check_action]

					log_file_logger.error('#21: Check result:   {}'.format(check_result))
					log_file_logger.error('#21: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#21: Control  Connections Summary: \n{}\n'.format(control_sum_tab))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#21: Check result:   {}'.format(check_result))
					log_file_logger.info('#21: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #21:Check:Controllers: Confirm control connections. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

		  
			#Informational Checks
			log_file_logger.info('*** Performing Informational Checks')

			#22:Check:vManage:Disk controller type
			log_file_logger.info('#22:Check:vManage:Disk controller type')
			writeFile(report_file, '#22:Check:vManage:Disk controller type\n\n')

			try:
				check_result, check_analysis, check_action = infoCheckone(server_type, disk_controller)
				if check_result == 'Failed':
					warning_checks['#22:Check:vManage:Disk controller type'] = [ check_analysis, check_action]

					log_file_logger.error('#22: Check result:   {}'.format(check_result))
					log_file_logger.error('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#22: Check result:   {}'.format(check_result))
					log_file_logger.info('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #22:Check:vManage:Disk controller type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#23:Check:Controllers:Validate there is at minimum vBond, vSmart present
			log_file_logger.info('#23:Check:Controllers:Validate there is at minimum vBond, vSmart present')
			writeFile(report_file, '#23:Check:Controllers:Validate there is at minimum vBond, vSmart present\n\n')

			try:
				check_result, check_analysis, check_action = infoChecktwo(vsmart_count,vbond_count)
				if check_result == 'Failed':
					warning_checks['#23:Check:Controllers:Validate there is at minimum vBond, vSmart present'] = [ check_analysis, check_action]

					log_file_logger.error('#23: Check result:   {}'.format(check_result))
					log_file_logger.error('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.error('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#23: Check result:   {}'.format(check_result))
					log_file_logger.info('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.info('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				   
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #23:Check:Controllers:Validate there is at minimum vBond, vSmart present. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#24:Check:Controllers:Validate all controllers are reachable
			log_file_logger.info('#24:Check:Controllers:Validate all controllers are reachable')
			writeFile(report_file, '#24:Check:Controllers:Validate all controllers are reachable\n\n')
			
			try:
				unreach_controllers,check_result, check_analysis, check_action = infoChecktthree(controllers_info)
				if check_result == 'Failed':
					warning_checks['#24:Check:Controllers:Validate all controllers are reachable'] = [ check_analysis, check_action]

					log_file_logger.error('#24: Check result:   {}'.format(check_result))
					log_file_logger.error('#24: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#24: Unreachable Controllers: {}\n'.format(unreach_controllers))


					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#24: Check result:   {}'.format(check_result))
					log_file_logger.info('#24: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #24:Check:Controllers:Validate all controllers are reachable. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			if cluster_size>1:
				cluster_checks = {}
				log_file_logger.info('*** Performing Cluster Checks')
				#25:Check:Cluster:Version consistency
				log_file_logger.info('#25:Check:Cluster:Version consistency')
				writeFile(report_file, '#25:Check:Cluster:Version consistency\n\n')

				try:
					check_result,check_analysis, check_action = criticalChecktwelve(vmanage_info)
					if check_result == 'Failed':
						cluster_checks['#25:Check:Cluster:Version consistency'] = [ check_analysis, check_action]

						log_file_logger.error('#25: Check result:   {}'.format(check_result))
						log_file_logger.error('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					else:
						log_file_logger.info('#25: Check result:   {}'.format(check_result))
						log_file_logger.info('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #25:Check:Cluster:Version consistency. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#26:Check:Cluster:Cluster health
				log_file_logger.info('#26:Check:Cluster:Cluster health')
				writeFile(report_file, '#26:Check:Cluster:Cluster health\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))
					services_down, check_result, check_analysis, check_action = criticalCheckthirteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#26:Check:Cluster:Cluster health'] = [ check_analysis, check_action]

						log_file_logger.error('#26: Check result:   {}'.format(check_result))
						log_file_logger.error('#26: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#26: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
						
					else: 
						log_file_logger.info('#26: Check result:   {}'.format(check_result))
						log_file_logger.info('#26: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #26:Check:Cluster:Cluster health. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#27:Check:Cluster:Cluster ConfigDB topology
				log_file_logger.info('#27:Check:Cluster:Cluster ConfigDB topology')
				writeFile(report_file, '#27:Check:Cluster:Cluster ConfigDB topology\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))           
					configDB_count, check_result, check_analysis, check_action = criticalCheckfourteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#27:Check:Cluster:Cluster ConfigDB topology'] = [ check_analysis, check_action]

						log_file_logger.error('#27: Check result:   {}'.format(check_result))
						log_file_logger.error('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					else: 
						log_file_logger.info('#27: Check result:   {}'.format(check_result))
						log_file_logger.info('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #27:Check:Cluster:Cluster ConfigDB topology. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#28:Check:Cluster:Messaging server
				log_file_logger.info('#28:Check:Cluster:Messaging server')
				writeFile(report_file, '#28:Check:Cluster:Messaging server\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'clusterManagement/list', args.vmanage_port, tokenid))           
					cluster_msdown,check_result,check_analysis, check_action = criticalCheckfifteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#28:Check:Cluster:Messaging server'] = [ check_analysis, check_action]

						log_file_logger.error('#28: Check result:   {}'.format(check_result))
						log_file_logger.error('#28: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#28: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))                       

					else: 
						log_file_logger.info('#28: Check result:   {}'.format(check_result))
						log_file_logger.info('#28: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #28:Check:Cluster:Messaging server. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				
				#29:Check:Cluster:DR replication status
				log_file_logger.info('#29:Check:Cluster:DR replication status')
				writeFile(report_file, '#29:Check:Cluster:DR replication status\n\n')

				try:
					dr_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'disasterrecovery/details', args.vmanage_port, tokenid))           
					dr_status, check_action, check_analysis, check_result = criticalChecksixteen(dr_data)
					if check_result == 'Failed':
						cluster_checks['#29:Check:Cluster:DR replication status'] = [ check_analysis, check_action]

						log_file_logger.error('#29: Check result:   {}'.format(check_result))
						log_file_logger.error('#29: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#29: DR Replication status: {}\n'.format(dr_status))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					else:
						log_file_logger.info('#29: Check result:   {}'.format(check_result))
						log_file_logger.info('#29: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #29:Check:Cluster:DR replication status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#30:Check:Cluster:Intercluster communication
				log_file_logger.info('#30:Check:Cluster:Intercluster communication')
				writeFile(report_file, '#30:Check:Cluster:Intercluster communication\n\n')
				
				try:
					if criticalCheckseventeen.isAlive():
						criticalCheckseventeen.join(10)

					if not criticalCheckseventeen.result_queue.empty():
						ping_output, ping_output_failed, ping_check_result, ping_check_analysis, ping_check_action = criticalCheckseventeen.result_queue.get()
						if ping_check_result == 'Failed':
							cluster_checks['#30:Check:Cluster:Intercluster communication'] = [ ping_check_analysis, ping_check_action]

							log_file_logger.error('#30: Check result: {}'.format(ping_check_result))
							log_file_logger.error('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.error('#30: Cluster nodes with ping failure: {}\n'.format(ping_output_failed))

						
							writeFile(report_file, 'Result: ERROR - {}\n'.format(ping_check_analysis))
							writeFile(report_file, 'Action: {}\n\n'.format(ping_check_action))

						else:
							log_file_logger.info('#30: Check result: {}'.format(ping_check_result))
							log_file_logger.info('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.info('#30: Cluster nodes details: {}\n'.format(ping_output))

							writeFile(report_file, 'Result: INFO - {}\n\n'.format(ping_check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #30:Check:Cluster:Intercluster communication. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


			#Logging out of the Session using jsessionid
			log_file_logger.info('Logging out of the Session')
			sessionLogout(vmanage_lo_ip, jsessionid, args.vmanage_port)
			log_file_logger.info('Successfully closed the connection')

		#version equal to or above 20.5
		elif version_tuple[0:2] >= ('20','5'): 
			try:
				log_file_logger.info('Generating a JSessionID')
				jsessionid = generateSessionIDpy3(vmanage_lo_ip, args.username, password, args.vmanage_port)   
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error generating JSessionID, make sure that the username and password entered is correct. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))

			try:
				log_file_logger.info('Generating CSRF Token')
				tokenid = CSRFTokenpy3(vmanage_lo_ip,jsessionid,args.vmanage_port)
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error generating CSRF Token. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file.  \033[0;0m \n\n'.format(log_file_path))


			#Preliminary data
			log_file_logger.info('****Collecting Preliminary Data\n')

			try:
				controllers = json.loads(getRequestpy3(version_tuple, vmanage_lo_ip, jsessionid , 'system/device/controllers', args.vmanage_port, tokenid))
				controllers_info = controllersInfo(controllers)
				log_file_logger.info('Collected controllers information: {}'.format(controllers_info))

				system_ip_data = json.loads(getRequestpy3(version_tuple, vmanage_lo_ip, jsessionid , 'device/vmanage', args.vmanage_port, tokenid))
				system_ip = system_ip_data['data']['ipAddress']
				#system_ip = controllers_info[hostname][1]
				log_file_logger.info('Collected vManage System IP address: {}'.format(system_ip))

				cpu_speed = cpuSpeed()
				log_file_logger.info('Collected vManage CPU Speed GHz: {}'.format(cpu_speed))

				cpu_count = cpuCount()
				log_file_logger.info('Collected vManage CPU Count: {}'.format(cpu_count))

				vedges = json.loads(getRequestpy3(version_tuple, vmanage_lo_ip, jsessionid , 'system/device/vedges', args.vmanage_port , tokenid))
				vedge_count,vedge_count_active, vedge_info = vedgeCount(vedges)
				log_file_logger.info('Collected  xEdge Count: {}'.format(vedge_count))

				cluster_size, server_mode, vmanage_info = serverMode(controllers_info)
				log_file_logger.info('Collected vManage Cluster Size: {}'.format(cluster_size))
				log_file_logger.info('Collected vManage Server Mode: {}'.format(server_mode))

				disk_controller = diskController()
				log_file_logger.info('Collected vManage Disk Controller Type: {}'.format(disk_controller))

				dpi_stats = json.loads(getRequestpy3(version_tuple, vmanage_lo_ip, jsessionid , 'statistics/settings/status', args.vmanage_port, tokenid))
				dpi_status = dpiStatus(dpi_stats)
				log_file_logger.info('Collected DPI Status: {}'.format(dpi_status))

				server_type = serverType()
				log_file_logger.info('Collected Server Type: {}'.format(server_type))

				vbond_info, vsmart_info = vbondvmartInfo(controllers_info)
				vbond_count = len(vbond_info)
				vsmart_count = len(vsmart_info)
				log_file_logger.info('vSmart info: {}'.format(vbond_info))
				log_file_logger.info('vBond info: {}'.format(vsmart_info))

				total_devices = len(controllers_info.keys()) + vedge_count
				log_file_logger.info('Total devices: {}'.format(total_devices))

			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error Collecting Preliminary Data. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				


			print('*Starting Checks, this may take several minutes\n\n')

			#Critical Checks
			critical_checks = {}
			log_file_logger.info('*** Performing Critical Checks\n')

			#Begining #30:Check:Cluster:Intercluster communication  in the background
			if cluster_size>1:
				log_file_logger.info('Beginging #30:Check:Cluster:Intercluster communication  in the background\n')
				try:
					cluster_health_data = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))
					criticalCheckseventeen =  criticalCheckseventeenpy3(cluster_health_data,  system_ip, log_file_logger)
				except Exception as e:
					log_file_logger.exception('{}\n'.format(e))


			#01:Check:vManage:Validate current version
			log_file_logger.info('#01:Check:vManage:Validate current version')
			writeFile(report_file, '#01:Check:vManage:Validate current version\n\n')
			
			try:
				boot_partition_size, check_result, check_analysis, check_action =  criticalCheckone(version)
				if check_result == 'Failed':
					critical_checks['#01:Check:vManage:Validate current version'] = [ check_analysis, check_action]
					log_file_logger.error('#01: Check result:   {}'.format(check_result))
					log_file_logger.error('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#01: version: {}'.format(version))
					log_file_logger.error('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				   
				else:
					log_file_logger.info('#01: Check result:   {}'.format(check_result))
					log_file_logger.info('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#01: version: {}'.format(version))
					log_file_logger.info('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
					

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #01:Check:vManage:Validate current version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#02:Check:vManage:At minimum 20%  server disk space should be available
			log_file_logger.info('#02:Check:vManage:At minimum 20%  server disk space should be available')
			writeFile(report_file, '#02:Check:vManage:At minimum 20%  server disk space should be available\n\n')

			try:
				optdata_partition_size, rootfs_partition_size, check_result, check_analysis, check_action =  criticalCheckTwo()
				if check_result == 'Failed': 
					critical_checks['#02:Check:vManage:At minimum 20%  server disk space should be available'] = [check_analysis, check_action]
					log_file_logger.error('#02: Check result:   {}'.format(check_result))
					log_file_logger.error('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.error('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#02: Check result:   {}'.format(check_result))
					log_file_logger.info('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.info('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #02:Check:vManage:At minimum 20%  server disk space should be available. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#03:Check:vManage:Memory size
			log_file_logger.info('#03:Check:vManage:Memory size')
			writeFile(report_file, '#03:Check:vManage:Memory size\n')
			writeFile(report_file, 'Link to the official documentation: \n https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html\n\n')

			try:
				memory_size, memory_size_str, dpi_status, server_type, check_result, check_analysis, check_action =  criticalCheckthree(vedge_count, dpi_status, server_type, cluster_size, version_tuple)
				if check_result == 'Failed':
					critical_checks['#03:Check:vManage:vManage sever disk space'] = [ check_analysis, check_action]
					log_file_logger.error('#03: Check result:   {}'.format(check_result))
					log_file_logger.error('#03: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#03: Memory Size GB: {}'.format(memory_size_str))
					log_file_logger.error('#03: /rootfs.rw Used: {}'.format(rootfs_partition_size))
					log_file_logger.error('#03: Server Type: {}'.format(server_type))
					log_file_logger.error('#03: vEdge Count: {}\n'.format(vedge_count))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#03: Check result:   {}'.format(check_result))
					log_file_logger.info('#03: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )

			except Exception as e:
				print('\033[1;31m ERROR: Error performing 03:Check:vManage:Memory size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

	 
			#04:Check:vManage:CPU Count
			log_file_logger.info('#04:Check:vManage:CPU Count')
			writeFile(report_file, '#04:Check:vManage:CPU Count\n\n')

			try:
				check_result, check_analysis, check_action = criticalCheckfour(cpu_count, vedge_count, dpi_status, server_type)
				if check_result == 'Failed':
					critical_checks['#04:Check:vManage:CPU Count'] = [ check_analysis, check_action]
					log_file_logger.error('#04: Check result:   {}'.format(check_result))
					log_file_logger.error('#04: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#04:CPU Count: {}\n'.format(cpu_count))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#04: Check result:   {}'.format(check_result))
					log_file_logger.info('#04: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #04:Check:vManage:CPU Count. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#05:Check:vManage:ElasticSearch Indices status
			log_file_logger.info('#05:Check:vManage:ElasticSearch Indices status')
			writeFile(report_file, '#05:Check:vManage:ElasticSearch Indices status\n\n')

			try:
				es_indexes_one = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_index_red_one, check_result_one, check_analysis_one, check_action_one = criticalCheckfive(es_indexes_one)

				time.sleep(5)

				es_indexes_two = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_index_red_two, check_result_two, check_analysis_two, check_action_two = criticalCheckfive(es_indexes_two)

				if check_result_one == 'Failed' and check_result_two == 'Failed':
					critical_checks['#05:Check:vManage:ElasticSearch Indices status'] = [ check_analysis_two, check_action_two]

					log_file_logger.error('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.error('#05: Check Analysis: {}\n'.format(check_analysis_two))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis_two))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action_two))
				   
				elif check_result_one == 'SUCCESSFUL':
					log_file_logger.info('#05: Check result:   {}'.format(check_result_one))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_one))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_one))

				elif check_result_two == 'SUCCESSFUL':

					log_file_logger.info('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_two))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_two))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #05:Check:vManage:ElasticSearch Indices status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#06:Check:vManage:Look for any neo4j exception errors
			log_file_logger.info('#06:Check:vManage:Look for any neo4j exception errors')
			writeFile(report_file, '#06:Check:vManage:Look for any neo4j exception errors\n\n')

			try:
				check_result, check_analysis, check_action = criticalChecksix()
				if check_result == 'Failed':
					critical_checks['#06:Check:vManage:Look for any neo4j exception errors'] = [check_analysis, check_action]
					log_file_logger.error('#06: Check result:   {}'.format(check_result))
					log_file_logger.error('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#06: Check result:   {}'.format(check_result))
					log_file_logger.info('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #06:Check:vManage:Look for any neo4j exception errors. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#07:Check:vManage:Validate all services are up
			log_file_logger.info('#07:Check:vManage:Validate all services are up')
			writeFile(report_file, '#07:Check:vManage:Validate all services are up\n\n')

			try:
				nms_data, nms_failed, check_result, check_analysis, check_action =   criticalCheckseven() 
				if check_result == 'Failed':
					critical_checks['#07:Check:vManage:Validate all services are up'] = [check_analysis, check_action]

					log_file_logger.error('#07: Check result:   {}'.format(check_result))
					log_file_logger.error('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#07: List of services that are enabled but not running:\n\n {}\n\n'.format(nms_failed))
					log_file_logger.error('#07: Status of all services  :\n{}\n'.format(nms_data))

					writeFile(report_file, 'Result: ERROR - {}\n\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#07: Check result:   {}'.format(check_result))
					log_file_logger.info('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#07: Status of all the services:\n{}\n'.format(nms_data))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #07:Check:vManage:Validate all services are up. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#08:Check:vManage:Elasticsearch Indices version
			log_file_logger.info('#08:Check:vManage:Elasticsearch Indices version')
			writeFile(report_file, '#08:Check:vManage:Elasticsearch Indices version\n\n')

			try:
				version_list, check_result, check_analysis, check_action = criticalCheckeight(version_tuple)
				if check_result == 'Failed':
					critical_checks['#08:Check:vManage:Elasticsearch Indices version'] = [ check_analysis, check_action]

					log_file_logger.error('#08: Check result:   {}'.format(check_result))
					log_file_logger.error('#08: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#08: List of indices with older versions: \n{}\n'.format(version_list))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				   
				else:
					log_file_logger.info('#08: Check result:   {}'.format(check_result))
					log_file_logger.info('#08: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
			
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #08:Check:vManage:Elasticsearch Indices version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#09:Check:vManage:Evaluate incoming DPI data size
			log_file_logger.info('#09:Check:vManage:Evaluate incoming DPI data size')
			writeFile(report_file, '#09:Check:vManage:Evaluate incoming DPI data size\n\n')

			try:
				es_indices_est = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/size/estimate', args.vmanage_port, tokenid))
				appr_estimate_ondeday, dpi_estimate_ondeday, check_result, check_analysis,check_action = criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count, total_devices, dpi_status)
				if check_result == 'Failed':
					critical_checks['#09:Check:vManage:Evaluate incoming DPI data size'] = [ check_analysis, check_action]

					log_file_logger.error('#09: Check result:   {}'.format(check_result))
					log_file_logger.error('#09: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#09: Daily incoming DPI data : {}'.format(dpi_estimate_ondeday))
					log_file_logger.error('#09: Daily incoming Approute data : {}\n'.format(appr_estimate_ondeday))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#09: Check result:   {}'.format(check_result))
					log_file_logger.info('#09: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #09:Check:vManage:Evaluate incoming DPI data size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#10:Check:vManage:NTP status across network
			log_file_logger.info('#10:Check:vManage:NTP status across network')
			writeFile(report_file, '#10:Check:vManage:NTP status across network\n\n')


			try:
				ntp_nonworking, check_result, check_analysis, check_action = criticalCheckten(version_tuple, controllers_info)
				if check_result == 'Failed':
					critical_checks['#10:Check:vManage:NTP status across network'] = [ check_analysis, check_action]

					log_file_logger.error('#10: Check result:   {}'.format(check_result))
					log_file_logger.error('#10: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#10: Devices with invalid ntp associations: \n{}\n'.format(ntp_nonworking))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#10: Check result:   {}'.format(check_result))
					log_file_logger.info('#10: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error perforiming #10:Check:vManage:NTP status across network. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#11:Check:Controllers:Validate vSmart/vBond CPU count for scale
			log_file_logger.info('#11:Check:Controllers:Validate vSmart/vBond CPU count for scale')
			writeFile(report_file, '#11:Check:Controllers:Validate vSmart/vBond CPU count for scale\n\n')

			try:
				for vbond in vbond_info:
					output = json.loads(getRequestpy3( version_tuple,vmanage_lo_ip, jsessionid, 'device/system/synced/status?deviceId={}'.format(vbond_info[vbond][1]),args.vmanage_port, tokenid))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vbond_info[vbond].append(total_cpu_count)

				for vsmart in vsmart_info:
					output = json.loads(getRequestpy3( version_tuple,vmanage_lo_ip, jsessionid, 'device/system/synced/status?deviceId={}'.format(vsmart_info[vsmart][1]),args.vmanage_port,tokenid))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vsmart_info[vsmart].append(total_cpu_count)

				failed_vbonds,failed_vsmarts,check_result,check_analysis, check_action = criticalCheckeleven(total_devices, vbond_info, vsmart_info)
				if check_result == 'Failed':
					critical_checks['#11:Check:Controllers:Validate vSmart/vBond CPU count for scale'] = [ check_analysis, check_action]

					log_file_logger.error('#11: Check result:   {}'.format(check_result))
					log_file_logger.error('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#11: vBonds with insufficient CPU count: \n{}'.format(failed_vbonds))
					log_file_logger.error('#11: vSmarts with insufficient CPU count: \n{}'.format(failed_vsmarts))
					log_file_logger.error('#11: All vBonds info with total_cpu_count: \n{}'.format(vbond_info))
					log_file_logger.error('#11: All vSmarts info with total_cpu_count: \n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				  
				else:
					log_file_logger.info('#11: Check result:   {}'.format(check_result))
					log_file_logger.info('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#11: All vBonds info with total_cpu_count: \n{}'.format(vbond_info))
					log_file_logger.info('#11: All vSmarts info with total_cpu_count: \n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #11:Check:Controllers:Validate vSmart/vBond CPU count for scale. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			
			#Warning Checks
			warning_checks = {}
			log_file_logger.info('*** Performing Warning Checks')

			#12:Check:vManage:CPU Speed
			log_file_logger.info('#12:Check:vManage:CPU Speed')
			writeFile(report_file, '#12:Check:vManage:CPU Speed\n\n')

			try:
				check_result,check_analysis,check_action = warningCheckone(cpu_speed)
				if check_result == 'Failed':
					warning_checks['#12:Check:vManage:CPU Speed'] = [ check_analysis, check_action]

					log_file_logger.error('#12: Check result:   {}'.format(check_result))
					log_file_logger.error('#12: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#12: CPU clock speed: {}\n'.format(cpu_speed))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#12: Check result:   {}'.format(check_result))
					log_file_logger.info('#12: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #12:Check:vManage:CPU Speed. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#13:Check:vManage:Network Card type
			log_file_logger.info('#13:Check:vManage:Network Card type')
			writeFile(report_file, '#13:Check:vManage:Network Card type\n\n')

			try:
				eth_drivers, check_action, check_analysis, check_result = warningChecktwo()
				if check_result == 'Failed':
					warning_checks['#13:Check:vManage:Network Card type'] = [ check_analysis, check_action]

					log_file_logger.error('#13: Check result:   {}'.format(check_result))
					log_file_logger.error('#13: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#13: Ethercardswith e1000 card types: {}\n'.format(eth_drivers))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#13: Check result:   {}'.format(check_result))
					log_file_logger.info('#13: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #13:Check:vManage:Network Card type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#14:Check:vManage:Backup status
			log_file_logger.info('#14:Check:vManage:Backup status')
			writeFile(report_file, '#14:Check:vManage:Backup status\n\n')

			try:
				date_time_obj, check_result, check_analysis, check_action = warningCheckthree()
				if check_result == 'Failed':
					warning_checks['#14:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#14: Check result:   {}'.format(check_result))
					log_file_logger.error('#14: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#14: Last Backup was performed on:{}\n'.format(date_time_obj))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#14: Check result:   {}'.format(check_result))
					log_file_logger.info('#14: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #14:Check:vManage:Backup status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#15:Check:vManage:Evaluate Neo4j performance
			log_file_logger.info('#15:Check:vManage:Evaluate Neo4j performance')
			writeFile(report_file, '#15:Check:vManage:Evaluate Neo4j performance\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckfour()
				if check_result == 'Failed':
					warning_checks['#15:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#15: Check result:   {}'.format(check_result))
					log_file_logger.error('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#15: Check result:   {}'.format(check_result))
					log_file_logger.info('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #15:Check:vManage:Evaluate Neo4j performance. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#16:Check:vManage:Confirm there are no pending tasks
			log_file_logger.info('#16:Check:vManage:Confirm there are no pending tasks')
			writeFile(report_file, '#16:Check:vManage:Confirm there are no pending tasks\n\n')

			try:
				tasks = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid,'device/action/status/tasks', args.vmanage_port, tokenid))
				tasks_running, check_result, check_analysis, check_action  = warningCheckfive(tasks)
				if check_result == 'Failed':
					warning_checks['#16:Check:vManage:Confirm there are no pending tasks'] = [ check_analysis, check_action]
					log_file_logger.error('#16: Check result:   {}'.format(check_result))
					log_file_logger.error('#16: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#16: Tasks still running: {}\n'.format(tasks_running))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))                  

				else:
					log_file_logger.info('#16: Check result:   {}'.format(check_result))
					log_file_logger.info('#16: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #16:Check:vManage:Confirm there are no pending tasks. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#17:Check:vManage:Validate there are no empty password users
			log_file_logger.info('#17:Check:vManage:Validate there are no empty password users')
			writeFile(report_file, '#17:Check:vManage:Validate there are no empty password users\n\n')

			try:
				users_emptypass, check_result, check_analysis, check_action = warningChecksix(version_tuple)
				if check_result == 'Failed':
					warning_checks['#17:Check:vManage:Validate there are no empty password users'] = [ check_analysis, check_action]
					log_file_logger.error('#17: Check result:   {}'.format(check_result))
					log_file_logger.error('#17: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#17: Users with empty passwords: {}\n'.format(users_emptypass))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#17: Check result:   {}'.format(check_result))
					log_file_logger.info('#17: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #17:Check:vManage:Validate there are no empty password users. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#18:Check:Controllers:Controller versions
			log_file_logger.info('#18:Check:Controllers:Controller versions')
			writeFile(report_file, '#18:Check:Controllers:Controller versions\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckseven(controllers_info)
				if check_result == 'Failed':
					warning_checks['#18:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#18: Check result:   {}'.format(check_result))
					log_file_logger.error('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#18: Check result:   {}'.format(check_result))
					log_file_logger.info('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #18:Check:Controllers:Controller versions. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#19:Check:Controllers:Confirm Certificate Expiration Dates
			log_file_logger.info('#19:Check:Controllers:Confirm Certificate Expiration Dates')
			writeFile(report_file, '#19:Check:Controllers:Confirm Certificate Expiration Dates\n\n')

			try:
				controllers_exp, controllers_notexp, check_result, check_analysis, check_action = warningCheckeight(controllers_info)
				if check_result == 'Failed':
					warning_checks['#19:Check:Controllers:Confirm Certificate Expiration Dates'] = [ check_analysis, check_action]
					log_file_logger.error('#19: Check result:   {}'.format(check_result))
					log_file_logger.error('#19: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#19: Controllers with certificates close to expiration: \n{}\n'.format(controllers_exp))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))                   

				else:
					log_file_logger.info('#19: Check result:   {}'.format(check_result))
					log_file_logger.info('#19: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))                   

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #19:Check:Controllers:Confirm Certificate Expiration Dates. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))   

			#20:Check:Controllers:vEdge list sync
			log_file_logger.info('#20:Check:Controllers:vEdge list sync')
			writeFile(report_file, '#20:Check:Controllers:vEdge list sync\n\n')

			try:
				state_vedgeList,check_result, check_analysis, check_action  = warningChecknine(controllers_info)
				if check_result == 'Failed':
					warning_checks['#20:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#20: Check result:   {}'.format(check_result))
					log_file_logger.error('#20: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#20: Controllers with inconsistent state_vedgeList: {}\n'.format(state_vedgeList))
					
					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#20: Check result:   {}'.format(check_result))
					log_file_logger.info('#20: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #20:Check:Controllers:vEdge list sync. \n Please check error details in log file: {}.\n. If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))  
				log_file_logger.exception('{}\n'.format(e))


			#21:Check:Controllers: Confirm control connections
			log_file_logger.info('#21:Check:Controllers: Confirm control connections')
			writeFile(report_file, '#21:Check:Controllers: Confirm control connections\n\n')

			try:
				control_sum_tab, discrepancy,check_result, check_analysis, check_action = warningCheckten(vsmart_count, vbond_count)
				if check_result == 'Failed':
					warning_checks['#21:Check:Controllers: Confirm control connections'] = [ check_analysis, check_action]

					log_file_logger.error('#21: Check result:   {}'.format(check_result))
					log_file_logger.error('#21: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#21: Control  Connections Summary: \n{}\n'.format(control_sum_tab))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))                    


				else:
					log_file_logger.info('#21:Check result: {}'.format(check_result))
					log_file_logger.info('#21: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))


			except Exception as e:
				print('\033[1;31m ERROR: Error performing #21:Check:Controllers: Confirm control connections. \n Please check error details in log file: {}.\n. If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#Informational Checks
			log_file_logger.info('*** Performing Informational Checks')

			#22:Check:vManage:Disk controller type
			log_file_logger.info('#22:Check:vManage:Disk controller type')
			writeFile(report_file, '#22:Check:vManage:Disk controller type\n\n')

			try:
				check_result, check_analysis, check_action = infoCheckone(server_type, disk_controller)
				if check_result == 'Failed':
					warning_checks['#22:Check:vManage:Disk controller type'] = [ check_analysis, check_action]

					log_file_logger.error('#22: Check result:   {}'.format(check_result))
					log_file_logger.error('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#22: Check result:   {}'.format(check_result))
					log_file_logger.info('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #22:Check:vManage:Disk controller type. \n Please check error details in log file: {}.\n. If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#23:Check:Controllers:Validate there is at minimum vBond, vSmart present
			log_file_logger.info('#23:Check:Controllers:Validate there is at minimum vBond, vSmart present')
			writeFile(report_file, '#23:Check:Controllers:Validate there is at minimum vBond, vSmart present\n\n')

			try:

				check_result, check_analysis, check_action = infoChecktwo(vsmart_count,vbond_count)
				if check_result == 'Failed':
					warning_checks['#23:Check:Controllers:Validate there is at minimum vBond, vSmart present'] = [ check_analysis, check_action]

					log_file_logger.error('#23: Check result:   {}'.format(check_result))
					log_file_logger.error('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.error('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#23: Check result:   {}'.format(check_result))
					log_file_logger.info('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.info('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #23:Check:Controllers:Validate there is at minimum vBond, vSmart present. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#24:Check:Controllers:Validate all controllers are reachable
			log_file_logger.info('#24:Check:Controllers:Validate all controllers are reachable')
			writeFile(report_file, '#24:Check:Controllers:Validate all controllers are reachable\n\n')
			
			try:
				unreach_controllers,check_result, check_analysis, check_action = infoChecktthree(controllers_info)
				if check_result == 'Failed':
					warning_checks['#24:Check:Controllers:Validate all controllers are reachable'] = [ check_analysis, check_action]

					log_file_logger.error('#24: Check result:   {}'.format(check_result))
					log_file_logger.error('#24: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#24: Unreachable Controllers: {}\n'.format(unreach_controllers))


					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#24: Check result:   {}'.format(check_result))
					log_file_logger.info('#24: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #24:Check:Controllers:Validate all controllers are reachable. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			if cluster_size>1:
				cluster_checks = {}
				log_file_logger.info('*** Performing Cluster Checks')

				#25:Check:Cluster:Version consistency
				log_file_logger.info('#25:Check:Cluster:Version consistency')
				writeFile(report_file, '#25:Check:Cluster:Version consistency\n\n')

				try:
					check_result,check_analysis, check_action = criticalChecktwelve(vmanage_info)
					if check_result == 'Failed':
						cluster_checks['#25:Check:Cluster:Version consistency'] = [ check_analysis, check_action]

						log_file_logger.error('#25: Check result:   {}'.format(check_result))
						log_file_logger.error('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					   
					else:
						log_file_logger.info('#25: Check result:   {}'.format(check_result))
						log_file_logger.info('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						
				except Exception as e:
					print('\033[1;31m ERROR: Error performing #25:Check:Cluster:Version consistency. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#26:Check:Cluster:Cluster health
				log_file_logger.info('#26:Check:Cluster:Cluster health')
				writeFile(report_file, '#26:Check:Cluster:Cluster health\n\n')

				try:
					cluster_health_data = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))
					services_down, check_result, check_analysis, check_action = criticalCheckthirteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#26:Check:Cluster:Cluster health'] = [ check_analysis, check_action]

						log_file_logger.error('#26: Check result:   {}'.format(check_result))
						log_file_logger.error('#26: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#26: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))                       

					else: 
						log_file_logger.info('#26: Check result:   {}'.format(check_result))
						log_file_logger.info('#26: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #26:Check:Cluster:Cluster health. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#27:Check:Cluster:Cluster ConfigDB topology
				log_file_logger.info('#27:Check:Cluster:Cluster ConfigDB topology')
				writeFile(report_file, '#27:Check:Cluster:Cluster ConfigDB topology\n\n')

				try:
					cluster_health_data = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))           
					configDB_count, check_result, check_analysis, check_action = criticalCheckfourteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#27:Check:Cluster:Cluster ConfigDB topology'] = [ check_analysis, check_action]

						log_file_logger.error('#27: Check result:   {}'.format(check_result))
						log_file_logger.error('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					else: 
						log_file_logger.info('#27: Check result:   {}'.format(check_result))
						log_file_logger.info('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #27:Check:Cluster:Cluster ConfigDB topology. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#28:Check:Cluster:Messaging server
				log_file_logger.info('#28:Check:Cluster:Messaging server')
				writeFile(report_file, '#28:Check:Cluster:Messaging server\n\n')

				try:
					cluster_health_data = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))           
					cluster_msdown,check_result,check_analysis, check_action = criticalCheckfifteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#28:Check:Cluster:Messaging server'] = [ check_analysis, check_action]

						log_file_logger.error('#28: Check result:   {}'.format(check_result))
						log_file_logger.error('#28: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#28: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
						
					else: 
						log_file_logger.info('#28: Check result:   {}'.format(check_result))
						log_file_logger.info('#28: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #28:Check:Cluster:Messaging server. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				
				#29:Check:Cluster:DR replication status
				log_file_logger.info('#29:Check:Cluster:DR replication status')
				writeFile(report_file, '#29:Check:Cluster:DR replication status\n\n')

				try:
					dr_data = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'disasterrecovery/details', args.vmanage_port, tokenid))           
					dr_status, check_action, check_analysis, check_result = criticalChecksixteen(dr_data)
					if check_result == 'Failed':
						cluster_checks['#29:Check:Cluster:DR replication status'] = [ check_analysis, check_action]

						log_file_logger.error('#29: Check result:   {}'.format(check_result))
						log_file_logger.error('#29: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#29: DR Replication status: {}\n'.format(dr_status))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					else:
						log_file_logger.info('#29: Check result:   {}'.format(check_result))
						log_file_logger.info('#29: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #29:Check:Cluster:DR replication status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#30:Check:Cluster:Intercluster communication
				log_file_logger.info('#30:Check:Cluster:Intercluster communication')
				writeFile(report_file, '#30:Check:Cluster:Intercluster communication\n\n')
					
				try:
					if criticalCheckseventeenpy3.isAlive():
						criticalCheckseventeenpy3.join(10)

					if not criticalCheckseventeenpy3.result_queue.empty():
						ping_output, ping_output_failed, ping_check_result, ping_check_analysis, ping_check_action = criticalCheckseventeenpy3.result_queue.get()
						if ping_check_result == 'Failed':
							cluster_checks['#30:Check:Cluster:Intercluster communication'] = [ ping_check_analysis, ping_check_action]

							log_file_logger.error('#30: Check result:   {}'.format(ping_check_result))
							log_file_logger.error('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.error('#30: Cluster nodes with ping failure: {}\n'.format(ping_output_failed))

						
							writeFile(report_file, 'Result: ERROR - {}\n'.format(ping_check_analysis))
							writeFile(report_file, 'Action: {}\n\n'.format(ping_check_action))

						else:
							log_file_logger.info('#30: Check result:   {}'.format(ping_check_result))
							log_file_logger.info('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.info('#30: Cluster nodes details: {}\n'.format(ping_output))

							writeFile(report_file, 'Result: INFO - {}\n\n'.format(ping_check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #30:Check:Cluster:Intercluster communication. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

			#Logging out of the Session using jsessionid
			log_file_logger.info('Logging out of the Session')
			sessionLogoutpy3(vmanage_lo_ip,jsessionid,args.vmanage_port)
			log_file_logger.info('Successfully closed the connection')



	#Verbose Execution
	elif args.verbose == True:
		log_file_logger.info('Executing the script in Verbose execution mode')

		#version below 19.2
		if version_tuple[0:2] < ('19','2'):
			#Creating a session
			try:
				log_file_logger.info('Generating a JSessionID')
				jsessionid = generateSessionID(vmanage_lo_ip, args.username, password, args.vmanage_port) 
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error generating JSessionID, make sure that the username and password entered is correct. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))

			

			#Preliminary Data
			log_file_logger.info('****Collecting Preliminary Data\n')
			print ('****Collecting Preliminary Data\n')

			try:
				controllers = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid,'system/device/controllers', args.vmanage_port))
				controllers_info = controllersInfo(controllers)
				log_file_logger.info('Collected controllers information: {}'.format(controllers_info))

				system_ip_data = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid,'device/vmanage', args.vmanage_port))
				system_ip = system_ip_data['data']['ipAddress']
				#system_ip = controllers_info[hostname][1]
				log_file_logger.info('Collected vManage System IP address: {}'.format(system_ip))

				cpu_speed = cpuSpeed()
				log_file_logger.info('Collected vManage CPU Speed GHz: {}'.format(cpu_speed))

				cpu_count = cpuCount()
				log_file_logger.info('Collected vManage CPU Count: {}'.format(cpu_count))

				vedges = json.loads(getRequest(version_tuple, vmanage_lo_ip,jsessionid, 'system/device/vedges', args.vmanage_port))
				vedge_count,vedge_count_active, vedge_info = vedgeCount(vedges)
				log_file_logger.info('Collected  xEdge Count: {}'.format(vedge_count))

				cluster_size, server_mode, vmanage_info = serverMode(controllers_info)
				log_file_logger.info('Collected vManage Cluster Size: {}'.format(cluster_size))
				log_file_logger.info('Collected vManage Server Mode: {}'.format(server_mode))

				disk_controller = diskController()
				log_file_logger.info('Collected vManage Disk Controller Type: {}'.format(disk_controller))

				dpi_stats = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'statistics/settings/status', args.vmanage_port))
				dpi_status = dpiStatus(dpi_stats)
				log_file_logger.info('Collected DPI status: {}'.format(dpi_status))

				server_type = serverType()
				log_file_logger.info('Collected Server Type: {}'.format(server_type))

				vbond_info, vsmart_info = vbondvmartInfo(controllers_info)
				vbond_count = len(vbond_info)
				vsmart_count = len(vsmart_info)
				log_file_logger.info('vSmart info: {}'.format(vbond_info))
				log_file_logger.info('vBond info: {}'.format(vsmart_info))

				total_devices = len(controllers_info) + vedge_count
				log_file_logger.info('Total devices: {}'.format(total_devices))

			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error Collecting Preliminary Data. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				

			print('*Starting Checks, this may take several minutes\n\n')

			#Critical Checks
			print('\n**** Performing Critical checks\n')
			critical_checks = {}
			log_file_logger.info('*** Performing Critical Checks\n')

			#Begining #30:Check:Cluster:Intercluster communication  in the background
			if cluster_size>1:
				log_file_logger.info('Beginging #30:Check:Cluster:Intercluster communication  in the background\n')
				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'clusterManagement/list', args.vmanage_port))
					criticalCheckseventeen =  criticalCheckseventeen(cluster_health_data,  system_ip, log_file_logger)
				except Exception as e:
					log_file_logger.exception('{}\n'.format(e))

			#01:Check:vManage:Validate current version
			print('  #01:Checking:vManage:Validate current version')
			log_file_logger.info('#01:Check:vManage:Validate current version')
			writeFile(report_file, '#01:Check:vManage:Validate current version\n\n')
			
			try:
				boot_partition_size, check_result, check_analysis, check_action =  criticalCheckone(version)
				if check_result == 'Failed':
					critical_checks['#01:Check:vManage:Validate current version'] = [ check_analysis, check_action]

					log_file_logger.error('#01: Check result:   {}'.format(check_result))
					log_file_logger.error('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#01: version: {}'.format(version))
					log_file_logger.error('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n'.format(check_action))
					
				else:
					log_file_logger.info('#01: Check result:   {}'.format(check_result))
					log_file_logger.info('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#01: version: {}'.format(version))
					log_file_logger.info('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #01:Check:vManage:Validate current version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#02:Check:vManage:At minimum 20%  server disk space should be available
			print('  #02:Checking:vManage:vManage sever disk space')
			log_file_logger.info('#02:Check:vManage:At minimum 20%  server disk space should be available')
			writeFile(report_file, '#02:Check:vManage:At minimum 20%  server disk space should be available\n\n')

			try:
				optdata_partition_size, rootfs_partition_size, check_result, check_analysis, check_action =  criticalCheckTwo()
				if check_result == 'Failed': 
					critical_checks['#02:Check:vManage:At minimum 20%  server disk space should be available'] = [check_analysis, check_action]

					log_file_logger.error('#02: Check result:   {}'.format(check_result))
					log_file_logger.error('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.error('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#02: Check result:   {}'.format(check_result))
					log_file_logger.info('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.info('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #02:Check:vManage:At minimum 20%  server disk space should be available. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
				

			#03:Check:vManage:Memory size
			print('  #03:Checking:vManage:Memory size')
			log_file_logger.info('#03:Check:vManage:Memory size')
			writeFile(report_file, '#03:Check:vManage:Memory size\n')
			writeFile(report_file, 'Link to the official documentation: \n https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html\n\n')

			try:
				memory_size, memory_size_str, dpi_status, server_type, check_result, check_analysis, check_action =  criticalCheckthree(vedge_count, dpi_status, server_type, cluster_size, version_tuple)
				if check_result == 'Failed':
					critical_checks['#03:Check:vManage:Memory size'] = [ check_analysis, check_action]

					log_file_logger.error('#03: Check result:   {}'.format(check_result))
					log_file_logger.error('#03: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#03: Memory Size GB: {}'.format(memory_size_str))
					log_file_logger.error('#03: /rootfs.rw Used: {}'.format(rootfs_partition_size))
					log_file_logger.error('#03: Server Type: {}'.format(server_type))
					log_file_logger.error('#03: vEdge Count: {}\n'.format(vedge_count))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#03: Check result:   {}'.format(check_result))
					log_file_logger.info('#03: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #03:Check:vManage:Memory size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
			
			#04:Check:vManage:CPU Count
			print('  #04:Checking:vManage:CPU Count')
			log_file_logger.info('#04:Check:vManage:CPU Count')
			writeFile(report_file, '#04:Check:vManage:CPU Count\n\n')

			try:
				check_result, check_analysis, check_action = criticalCheckfour(cpu_count, vedge_count, dpi_status, server_type)
				if check_result == 'Failed':
					critical_checks['#04:Check:vManage:CPU Count'] = [ check_analysis, check_action]

					log_file_logger.error('#04: Check result:   {}'.format(check_result))
					log_file_logger.error('#04: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#04: CPU Count: {}\n'.format(cpu_count))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#04: Check result:   {}'.format(check_result))
					log_file_logger.info('#04: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #04:Check:vManage:CPU Count. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#05:Check:vManage:ElasticSearch Indices status
			print('  #05:Checking:vManage:ElasticSearch Indices status')
			log_file_logger.info('#05:Check:vManage:ElasticSearch Indices status')
			writeFile(report_file, '#05:Check:vManage:ElasticSearch Indices status\n\n')

			try:
				es_indexes_one = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/info', args.vmanage_port))
				es_index_red_one, check_result_one, check_analysis_one, check_action_one = criticalCheckfive(es_indexes_one)

				time.sleep(5)

				es_indexes_two = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/info', args.vmanage_port))
				es_index_red_two, check_result_two, check_analysis_two, check_action_two = criticalCheckfive(es_indexes_two)

				if check_result_one == 'Failed' and check_result_two == 'Failed':
					critical_checks['#05:Check:vManage:ElasticSearch Indices status'] = [ check_analysis_two, check_action_two]

					log_file_logger.error('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.error('#05: Check Analysis: {}\n'.format(check_analysis_two))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis_two))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action_two))
				   
				elif check_result_one == 'SUCCESSFUL':
					log_file_logger.info('#05: Check result:   {}'.format(check_result_one))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_one))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_one))

				elif check_result_two == 'SUCCESSFUL':

					log_file_logger.info('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_two))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_two))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #05:Check:vManage:ElasticSearch Indices status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#06:Check:vManage:Look for any neo4j exception errors
			print('  #06:Checking:vManage:Look for any neo4j exception errors')
			log_file_logger.info('#06:Check:vManage:Look for any neo4j exception errors')
			writeFile(report_file, '#06:Check:vManage:Look for any neo4j exception errors\n\n')

			try:
				check_result, check_analysis, check_action = criticalChecksix()
				if check_result == 'Failed':
					critical_checks['#06:Check:vManage:Look for any neo4j exception errors'] = [check_analysis, check_action]

					log_file_logger.error('#06: Check result:   {}'.format(check_result))
					log_file_logger.error('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#06: Check result:   {}'.format(check_result))
					log_file_logger.info('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #06:Check:vManage:Look for any neo4j exception errors. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#07:Check:vManage:Validate all services are up
			print('  #07:Checking:vManage:Validate all services are up')
			log_file_logger.info('#07:Check:vManage:Validate all services are up')
			writeFile(report_file, '#07:Check:vManage:Validate all services are up\n\n')

			try:
				nms_data, nms_failed, check_result, check_analysis, check_action =   criticalCheckseven() 
				if check_result == 'Failed':
					critical_checks['#07:Check:vManage:Validate all services are up'] = [check_analysis, check_action]

					log_file_logger.error('#07: Check result:   {}'.format(check_result))
					log_file_logger.error('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#07: List of services that are enabled but not running:\n{}'.format(nms_failed))
					log_file_logger.error('#07: Status of all services  :\n{}\n'.format(nms_data))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#07: Check result:   {}'.format(check_result))
					log_file_logger.info('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#07: Status of all the services:\n{}\n'.format(nms_data))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #07:Check:vManage:Validate all services are up. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#08:Check:vManage:Elasticsearch Indices version
			print('  #08:Checking:vManage:Elasticsearch Indices version')
			log_file_logger.info('#08:Check:vManage:Elasticsearch Indices version')
			writeFile(report_file, '#08:Check:vManage:Elasticsearch Indices version\n\n')

			try:
				version_list, check_result, check_analysis, check_action = criticalCheckeight(version_tuple)
				if check_result == 'Failed':
					critical_checks['#08:Check:vManage:Elasticsearch Indices version'] = [ check_analysis, check_action]

					log_file_logger.error('#08: Check result:   {}'.format(check_result))
					log_file_logger.error('#08: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#08: List of indices with older versions  :\n{}\n'.format(version_list))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				 
				else:
					log_file_logger.info('#08: Check result:   {}'.format(check_result))
					log_file_logger.info('#08: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #08:Check:vManage:Elasticsearch Indices version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#09:Check:vManage:Evaluate incoming DPI data size
			print('  #09:Checking:vManage:Evaluate incoming DPI data size')
			log_file_logger.info('#09:Check:vManage:Evaluate incoming DPI data size')
			writeFile(report_file, '#09:Check:vManage:Evaluate incoming DPI data size\n\n')

			try:
				es_indices_est = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/size/estimate', args.vmanage_port))
				appr_estimate_ondeday, dpi_estimate_ondeday, check_result,check_analysis,check_action = criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count, total_devices, dpi_status)
				if check_result == 'Failed':
					critical_checks['#09:Check:vManage:Evaluate incoming DPI data size'] = [ check_analysis, check_action]

					log_file_logger.error('#09: Check result:   {}'.format(check_result))
					log_file_logger.error('#09: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#09: Daily incoming DPI data : {}'.format(dpi_estimate_ondeday))
					log_file_logger.error('#09: Daily incoming Approute data : {}\n'.format(appr_estimate_ondeday))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#09: Check result:   {}'.format(check_result))
					log_file_logger.info('#09: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #09:Check:vManage:Evaluate incoming DPI data size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#10:Check:vManage:NTP status across network
			print('  #10:Checking:vManage:NTP status across network')
			log_file_logger.info('#10:Check:vManage:NTP status across network')
			writeFile(report_file, '#10:Check:vManage:NTP status across network\n\n')

			try:
				ntp_nonworking, check_result, check_analysis, check_action = criticalCheckten(version_tuple, controllers_info)
				if check_result == 'Failed':
					critical_checks['#10:Check:vManage:NTP status across network'] = [ check_analysis, check_action]

					log_file_logger.error('#10: Check result:   {}'.format(check_result))
					log_file_logger.error('#10: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#10: Devices with invalid ntp associations: \n{}\n'.format(ntp_nonworking))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#10: Check result:   {}'.format(check_result))
					log_file_logger.info('#10: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #10:Check:vManage:NTP status across network. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#11:Check:Controllers:Validate vSmart/vBond CPU count for scale
			print('  #11:Checking:Controllers:Validate vSmart/vBond CPU count for scale')
			log_file_logger.info('#11:Check:Controllers:Validate vSmart/vBond CPU count for scale')
			writeFile(report_file, '#11:Check:Controllers:Validate vSmart/vBond CPU count for scale\n\n')
			
			try:
				for vbond in vbond_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip, jsessionid,'device/system/synced/status?deviceId={}'.format(vbond_info[vbond][1]),args.vmanage_port ))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vbond_info[vbond].append(total_cpu_count)

				for vsmart in vsmart_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip,jsessionid, 'device/system/synced/status?deviceId={}'.format(vsmart_info[vsmart][1]), args.vmanage_port))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vsmart_info[vsmart].append(total_cpu_count)

				failed_vbonds,failed_vsmarts,check_result,check_analysis, check_action = criticalCheckeleven(total_devices, vbond_info, vsmart_info)
				if check_result == 'Failed':
					critical_checks['#11:Check:Controllers:Validate vSmart/vBond CPU count for scale'] = [ check_analysis, check_action]

					log_file_logger.error('#11: Check result:   {}'.format(check_result))
					log_file_logger.error('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#11: vBonds with insufficient CPU count: \n{}'.format(failed_vbonds))
					log_file_logger.error('#11: vSmarts with insufficient CPU count: \n{}'.format(failed_vsmarts))
					log_file_logger.error('#11: All vBonds info with total_cpu_count: \n{}'.format(vbond_info))
					log_file_logger.error('#11: All vSmarts info with total_cpu_count: \n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				  

				else:
					log_file_logger.info('#11: Check result:   {}'.format(check_result))
					log_file_logger.info('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#11: All vBonds info with total_cpu_count: \n{}'.format(vbond_info))
					log_file_logger.info('#11: All vSmarts info with total_cpu_count: \n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing  #11:Check:Controllers:Validate vSmart/vBond CPU count for scale. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
			
			#Warning Checks
			print('\n**** Performing Warning checks\n')

			warning_checks = {}
			log_file_logger.info('*** Performing Warning Checks')

			#12:Check:vManage:CPU Speed
			print('  #12:Checking:vManage:CPU Speed')
			log_file_logger.info('#12:Check:vManage:CPU Speed')
			writeFile(report_file, '#12:Check:vManage:CPU Speed\n\n')

			try:
				check_result,check_analysis,check_action = warningCheckone(cpu_speed)
				if check_result == 'Failed':
					warning_checks['#12:Check:vManage:CPU Speed'] = [ check_analysis, check_action]

					log_file_logger.error('#12: Check result:   {}'.format(check_result))
					log_file_logger.error('#12: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#12: CPU clock speed: {}\n'.format(cpu_speed))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#12: Check result:   {}'.format(check_result))
					log_file_logger.info('#12: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #12:Check:vManage:CPU Speed. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#13:Check:vManage:Network Card type
			print('  #13:Checking:vManage:Network Card type')
			log_file_logger.info('#13:Check:vManage:Network Card type')
			writeFile(report_file, '#13:Check:vManage:Network Card type\n\n')

			try:
				eth_drivers, check_action, check_analysis, check_result = warningChecktwo()
				if check_result == 'Failed':
					warning_checks['#13:Check:vManage:Network Card type'] = [ check_analysis, check_action]

					log_file_logger.error('#13: Check result:   {}'.format(check_result))
					log_file_logger.error('#13: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#13: Ethercardswith e1000 card types: {}\n'.format(eth_drivers))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#13: Check result:   {}'.format(check_result))
					log_file_logger.info('#13: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
		   
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #13:Check:vManage:Network Card type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#14:Check:vManage:Backup status
			print('  #14:Checking:vManage:Backup status')
			log_file_logger.info('#14:Check:vManage:Backup status')
			writeFile(report_file, '#14:Check:vManage:Backup status\n\n')

			try:
				date_time_obj, check_result, check_analysis, check_action = warningCheckthree()
				if check_result == 'Failed':
					warning_checks['#14:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#14: Check result:   {}'.format(check_result))
					log_file_logger.error('#14: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#14: Last Backup was performed on: {}\n'.format(date_time_obj))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#14: Check result:   {}'.format(check_result))
					log_file_logger.info('#14: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #14:Check:vManage:Backup status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#15:Check:vManage:Evaluate Neo4j performance
			print('  #15:Checking:vManage:Evaluate Neo4j performance')
			log_file_logger.info('#15:Check:vManage:Evaluate Neo4j performance')
			writeFile(report_file, '#15:Check:vManage:Evaluate Neo4j performance\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckfour()
				if check_result == 'Failed':
					warning_checks['#15:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#15: Check result:   {}'.format(check_result))
					log_file_logger.error('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#15: Check result:   {}'.format(check_result))
					log_file_logger.info('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #15:Check:vManage:Evaluate Neo4j performance. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#16:Check:vManage:Confirm there are no pending tasks
			print('  #16:Checking:vManage:Confirm there are no pending tasks')
			log_file_logger.info('#16:Check:vManage:Confirm there are no pending tasks')
			writeFile(report_file, '#16:Check:vManage:Confirm there are no pending tasks\n\n')

			try:
				tasks = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'device/action/status/tasks', args.vmanage_port))
				tasks_running, check_result, check_analysis, check_action  = warningCheckfive(tasks)
				if check_result == 'Failed':
					warning_checks['#16:Check:vManage:Confirm there are no pending tasks'] = [ check_analysis, check_action]
					log_file_logger.error('#16:Check result: {}'.format(check_result))
					log_file_logger.error('#16: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#16: Tasks still running: {}\n'.format(tasks_running))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#16:Check result: {}'.format(check_result))
					log_file_logger.info('#16: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #16:Check:vManage:Confirm there are no pending tasks. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#17:Check:vManage:Validate there are no empty password users
			print('  #17:Checking:vManage:Validate there are no empty password users')
			log_file_logger.info('#17:Check:vManage:Validate there are no empty password users')
			writeFile(report_file, '#17:Check:vManage:Validate there are no empty password users\n\n')
				
			try:
				users_emptypass, check_result, check_analysis, check_action = warningChecksix(version_tuple)
				if check_result == 'Failed':
					warning_checks['#17:Check:vManage:Validate there are no empty password users'] = [ check_analysis, check_action]
					log_file_logger.error('#17: Check result:   {}'.format(check_result))
					log_file_logger.error('#17: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#17: Users with empty passwords: {}\n'.format(users_emptypass))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#17: Check result:   {}'.format(check_result))
					log_file_logger.info('#17: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #17:Check:vManage:Validate there are no empty password users. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#18:Check:Controllers:Controller versions
			print('  #18:Checking:Controllers:Controller versions')
			log_file_logger.info('#18:Check:Controllers:Controller versions')
			writeFile(report_file, '#18:Check:Controllers:Controller versions\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckseven(controllers_info)
				if check_result == 'Failed':
					warning_checks['18:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#18: Check result:   {}'.format(check_result))
					log_file_logger.error('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#18: Check result:   {}'.format(check_result))
					log_file_logger.info('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #18:Check:Controllers:Controller versions. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#19:Check:Controllers:Confirm Certificate Expiration Dates
			print('  #19:Checking:Controllers:Confirm Certificate Expiration Dates')
			log_file_logger.info('#19:Check:Controllers:Confirm Certificate Expiration Dates')
			writeFile(report_file, '#19:Check:Controllers:Confirm Certificate Expiration Dates\n\n')

			try:
				controllers_exp, controllers_notexp, check_result, check_analysis, check_action = warningCheckeight(controllers_info)
				if check_result == 'Failed':
					warning_checks['#19:Check:Controllers:Confirm Certificate Expiration Dates'] = [ check_analysis, check_action]
					log_file_logger.error('#19: Check result:   {}'.format(check_result))
					log_file_logger.error('#19: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#19: Controllers with certificates close to expiration: \n{}\n'.format(controllers_exp))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#19: Check result:   {}'.format(check_result))
					log_file_logger.info('#19: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				   
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #19:Check:Controllers:Confirm Certificate Expiration Dates. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#20:Check:Controllers:vEdge list sync
			print('  #20:Checking:Controllers:vEdge list sync')
			log_file_logger.info('#20:Check:Controllers:vEdge list sync')
			writeFile(report_file, '#20:Check:Controllers:vEdge list sync\n\n')

			try:
				state_vedgeList,check_result, check_analysis, check_action  = warningChecknine(controllers_info)
				if check_result == 'Failed':
					warning_checks['#20:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#20: Check result:   {}'.format(check_result))
					log_file_logger.error('#20: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#20: Controllers with inconsistent state_vedgeList: {}\n'.format(state_vedgeList))
					
					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#20: Check result:   {}'.format(check_result))
					log_file_logger.info('#20: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #20:Check:Controllers:vEdge list sync. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#21:Check:Controllers: Confirm control connections
			print('  #21:Checking:Controllers: Confirm control connections')
			log_file_logger.info('#21:Check:Controllers: Confirm control connections')
			writeFile(report_file, '#21:Check:Controllers: Confirm control connections\n\n')

			try:
				control_sum_tab, discrepancy,check_result, check_analysis, check_action = warningCheckten(vsmart_count, vbond_count)
				if check_result == 'Failed':
					warning_checks['#21:Check:Controllers: Confirm control connections'] = [ check_analysis, check_action]

					log_file_logger.error('#21: Check result:   {}'.format(check_result))
					log_file_logger.error('#21: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#21: Control  Connections Summary: \n{}\n'.format(control_sum_tab))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#21: Check result:   {}'.format(check_result))
					log_file_logger.info('#21: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #21:Check:Controllers: Confirm control connections. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Informational Checks
			print('\n**** Performing Informational checks\n') 
			log_file_logger.info('*** Performing Informational Checks')

			#22:Check:vManage:Disk controller type
			print('  #22:Check:vManage:Disk controller type')
			log_file_logger.info('#22:Check:vManage:Disk controller type')
			writeFile(report_file, '#22:Check:vManage:Disk controller type\n\n')

			try:
				check_result, check_analysis, check_action = infoCheckone(server_type, disk_controller)
				if check_result == 'Failed':
					warning_checks['#22:Check:vManage:Disk controller type'] = [ check_analysis, check_action]

					log_file_logger.error('#22: Check result:   {}'.format(check_result))
					log_file_logger.error('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#22: Check result:   {}'.format(check_result))
					log_file_logger.info('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #22:Check:vManage:Disk controller type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#23:Check:Controllers:Validate there is at minimum vBond, vSmart present
			print('  #23:Check:Controllers:Validate there is at minimum vBond, vSmart present')
			log_file_logger.info('#23:Check:Controllers:Validate there is at minimum vBond, vSmart present')
			writeFile(report_file, '#23:Check:Controllers:Validate there is at minimum vBond, vSmart present\n\n')
			
			try:
				check_result, check_analysis, check_action = infoChecktwo(vsmart_count,vbond_count)
				if check_result == 'Failed':
					warning_checks['#23:Check:Controllers:Validate there is at minimum vBond, vSmart present'] = [ check_analysis, check_action]

					log_file_logger.error('#23: Check result:   {}'.format(check_result))
					log_file_logger.error('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.error('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				   
				else:
					log_file_logger.info('#23: Check result:   {}'.format(check_result))
					log_file_logger.info('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.info('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				 
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #23:Check:Controllers:Validate there is at minimum vBond, vSmart present. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#24:Check:Controllers:Validate all controllers are reachable
			print('  #24:Check:Controllers:Validate all controllers are reachable')
			log_file_logger.info('#24:Check:Controllers:Validate all controllers are reachable')
			writeFile(report_file, '#24:Check:Controllers:Validate all controllers are reachable\n\n')
			
			try:
				unreach_controllers,check_result, check_analysis, check_action = infoChecktthree(controllers_info)
				if check_result == 'Failed':
					warning_checks['#24:Check:Controllers:Validate all controllers are reachable'] = [ check_analysis, check_action]

					log_file_logger.error('#24: Check result:   {}'.format(check_result))
					log_file_logger.error('#24: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#24: Unreachable Controllers: {}\n'.format(unreach_controllers))


					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#24: Check result:   {}'.format(check_result))
					log_file_logger.info('#24: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #24:Check:Controllers:Validate all controllers are reachable. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			if cluster_size>1:
				cluster_checks = {}

				log_file_logger.info('*** Performing Cluster Checks')
				print('\n**** Performing Cluster checks\n')

				#25:Check:Cluster:Version consistency
				print('  #25:Checking:Cluster:Version consistency')
				log_file_logger.info('#25:Check:Cluster:Version consistency')
				writeFile(report_file, '#25:Check:Cluster:Version consistency\n\n')

				try:
					check_result,check_analysis, check_action = criticalChecktwelve(vmanage_info)
					if check_result == 'Failed':
						cluster_checks['#25:Check:Cluster:Version consistency'] = [ check_analysis, check_action]

						log_file_logger.error('#25: Check result:   {}'.format(check_result))
						log_file_logger.error('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
						
					else:
						log_file_logger.info('#25: Check result:   {}'.format(check_result))
						log_file_logger.info('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						
				except Exception as e:
					print('\033[1;31m ERROR: Error performing #25:Check:Cluster:Version consistency. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#26:Check:Cluster:Cluster health
				print('  #26:Checking:Cluster:Cluster health')
				log_file_logger.info('#26:Check:Cluster:Cluster health')
				writeFile(report_file, '#26:Check:Cluster:Cluster health\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'clusterManagement/list', args.vmanage_port))
					services_down, check_result, check_analysis, check_action = criticalCheckthirteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#26:Check:Cluster:Cluster health'] = [ check_analysis, check_action]

						log_file_logger.error('#26: Check result:   {}'.format(check_result))
						log_file_logger.error('#26: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#26: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
						
					else: 
						log_file_logger.info('#26: Check result:   {}'.format(check_result))
						log_file_logger.info('#26: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #26:Check:Cluster:Cluster health. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#27:Check:Cluster:Cluster ConfigDB topology
				print('  #27:Checking:Cluster:Cluster ConfigDB topology')
				log_file_logger.info('#27:Check:Cluster:Cluster ConfigDB topology')
				writeFile(report_file, '#27:Check:Cluster:Cluster ConfigDB topology\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'clusterManagement/list', args.vmanage_port))           
					configDB_count, check_result, check_analysis, check_action = criticalCheckfourteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#27:Check:Cluster:Cluster ConfigDB topology'] = [ check_analysis, check_action]

						log_file_logger.error('#27: Check result:   {}'.format(check_result))
						log_file_logger.error('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					else: 
						log_file_logger.info('#27: Check result:   {}'.format(check_result))
						log_file_logger.info('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #27:Check:Cluster:Cluster ConfigDB topology. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#28:Check:Cluster:Messaging server
				print('  #28:Checking:Cluster:Messaging server')
				log_file_logger.info('#28:Check:Cluster:Messaging server')
				writeFile(report_file, '#28:Check:Cluster:Messaging server\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid,'clusterManagement/list', args.vmanage_port))           
					cluster_msdown,check_result,check_analysis, check_action = criticalCheckfifteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#28:Check:Cluster:Messaging server'] = [ check_analysis, check_action]

						log_file_logger.error('#28: Check result:   {}'.format(check_result))
						log_file_logger.error('#28: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#28: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					   

					else: 
						log_file_logger.info('#28: Check result:   {}'.format(check_result))
						log_file_logger.info('#28: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #28:Check:Cluster:Messaging server. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#29:Check:Cluster:DR replication status
				print('  #29:Checking:Cluster:DR replication status')
				log_file_logger.info('#29:Check:Cluster:DR replication status')
				writeFile(report_file, '#29:Check:Cluster:DR replication status\n\n')

				try:
					dr_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'disasterrecovery/details', args.vmanage_port))           
					dr_status, check_action, check_analysis, check_result = criticalChecksixteen(dr_data)
					if check_result == 'Failed':
						cluster_checks['#29:Check:Cluster:DR replication status'] = [ check_analysis, check_action]

						log_file_logger.error('#29: Check result:   {}'.format(check_result))
						log_file_logger.error('#29: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#29: DR Replication status: {}\n'.format(dr_status))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					else:
						log_file_logger.info('#29: Check result:   {}'.format(check_result))
						log_file_logger.info('#29: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #29:Check:Cluster:DR replication status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#30:Check:Cluster:Intercluster communication
				print('  #30:Checking:Cluster:Intercluster communication')
				log_file_logger.info('#30:Check:Cluster:Intercluster communication')
				writeFile(report_file, '#30:Check:Cluster:Intercluster communication\n\n')
					
				try:
					if criticalCheckseventeen.isAlive():
						criticalCheckseventeen.join(10)

					if not criticalCheckseventeen.result_queue.empty():
						ping_output, ping_output_failed, ping_check_result, ping_check_analysis, ping_check_action = criticalCheckseventeen.result_queue.get()
						if ping_check_result == 'Failed':
							cluster_checks['#30:Check:Cluster:Intercluster communication'] = [ ping_check_analysis, ping_check_action]

							log_file_logger.error('#30: Check result:   {}'.format(ping_check_result))
							log_file_logger.error('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.error('#30: Cluster nodes with ping failure: {}\n'.format(ping_output_failed))

						
							writeFile(report_file, 'Result: ERROR - {}\n'.format(ping_check_analysis))
							writeFile(report_file, 'Action: {}\n\n'.format(ping_check_action))

						else:
							log_file_logger.info('#30: Check result:   {}'.format(ping_check_result))
							log_file_logger.info('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.info('#30: Cluster nodes details: {}\n'.format(ping_output))

							writeFile(report_file, 'Result: INFO - {}\n\n'.format(ping_check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #30:Check:Cluster:Intercluster communication. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


			#Logging out of the Session using jsessionid
			log_file_logger.info('Logging out of the Session')
			sessionLogout(vmanage_lo_ip, jsessionid, args.vmanage_port)
			log_file_logger.info('Successfully closed the connection')
			

		#version equal to or above 19.2
		elif version_tuple[0:2] >= ('19','2') and version_tuple[0:2] < ('20','5'): 
			try:
				log_file_logger.info('Generating a JSessionID')
				jsessionid = generateSessionID(vmanage_lo_ip, args.username, password, args.vmanage_port)
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error generating JSessionID, make sure that the username and password entered is correct. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))

			try:
				log_file_logger.info('Generating CSRF Token')
				tokenid = CSRFToken(vmanage_lo_ip,jsessionid,args.vmanage_port)
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error generating CSRF Token. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))

			#Preliminary data
			log_file_logger.info('****Collecting Preliminary Data\n')
			print ('****Collecting Preliminary Data\n')

			try:
				controllers = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'system/device/controllers', args.vmanage_port, tokenid))
				controllers_info = controllersInfo(controllers)
				log_file_logger.info('Collected controllers information: {}'.format(controllers_info))

				system_ip_data = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'device/vmanage', args.vmanage_port, tokenid))
				system_ip = system_ip_data['data']['ipAddress']
				#system_ip = controllers_info[hostname][1]
				log_file_logger.info('Collected vManage System IP address: {}'.format(system_ip))

				cpu_speed = cpuSpeed()
				log_file_logger.info('Collected vManage CPU Speed GHz: {}'.format(cpu_speed))

				cpu_count = cpuCount()
				log_file_logger.info('Collected vManage CPU Count: {}'.format(cpu_count))

				vedges = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'system/device/vedges', args.vmanage_port , tokenid))
				vedge_count,vedge_count_active, vedge_info = vedgeCount(vedges)
				log_file_logger.info('Collected  xEdge Count: {}'.format(vedge_count))

				cluster_size, server_mode, vmanage_info = serverMode(controllers_info)
				log_file_logger.info('Collected vManage Cluster Size: {}'.format(cluster_size))
				log_file_logger.info('Collected vManage Server Mode: {}'.format(server_mode))

				disk_controller = diskController()
				log_file_logger.info('Collected vManage Disk Controller Type: {}'.format(disk_controller))

				dpi_stats = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'statistics/settings/status', args.vmanage_port, tokenid))
				dpi_status = dpiStatus(dpi_stats)
				log_file_logger.info('Collected DPI Status: {}'.format(dpi_status))

				server_type = serverType()
				log_file_logger.info('Collected Server Type: {}'.format(server_type))

				vbond_info, vsmart_info = vbondvmartInfo(controllers_info)
				vbond_count = len(vbond_info)
				vsmart_count = len(vsmart_info)
				log_file_logger.info('vSmart info: {}'.format(vbond_info))
				log_file_logger.info('vBond info: {}'.format(vsmart_info))
				
				total_devices = len(controllers_info.keys()) + vedge_count
				log_file_logger.info('Total devices: {}'.format(total_devices))
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error Collecting Preliminary Data. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				
			print('*Starting Checks, this may take several minutes\n\n')

			#Critical Checks
			critical_checks = {}
			log_file_logger.info('*** Performing Critical Checks\n')
			
			#Begining #30:Check:Cluster:Intercluster communication  in the background
			if cluster_size>1:
				log_file_logger.info('Beginging #30:Check:Cluster:Intercluster communication  in the background\n')
				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid,'clusterManagement/list', args.vmanage_port, tokenid))
					criticalCheckseventeen =  criticalCheckseventeen(cluster_health_data,  system_ip, log_file_logger)
				except Exception as e:
					log_file_logger.exception('{}\n'.format(e))

			#01:Check:vManage:Validate current version
			print('  #01:Checking:vManage:Validate current version')
			log_file_logger.info('#01:Check:vManage:Validate current version')
			writeFile(report_file, '#01:Check:vManage:Validate current version\n\n')           
			
			try:
				boot_partition_size, check_result, check_analysis, check_action =  criticalCheckone(version)
				if check_result == 'Failed':
					critical_checks['#01:Check:vManage:Validate current version'] = [ check_analysis, check_action]

					log_file_logger.error('#01: Check result:   {}'.format(check_result))
					log_file_logger.error('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#01: version: {}'.format(version))
					log_file_logger.error('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				   
				else:
					log_file_logger.info('#01: Check result:   {}'.format(check_result))
					log_file_logger.info('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#01: version: {}'.format(version))
					log_file_logger.info('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
				   
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #01:Check:vManage:Validate current version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#02:Check:vManage:At minimum 20%  server disk space should be available
			print('  #02:Checking:vManage:vManage sever disk space')
			log_file_logger.info('#02:Check:vManage:At minimum 20%  server disk space should be available')
			writeFile(report_file, '#02:Check:vManage:At minimum 20%  server disk space should be available\n\n')

			try:
				optdata_partition_size, rootfs_partition_size, check_result, check_analysis, check_action =  criticalCheckTwo()
				if check_result == 'Failed': 
					critical_checks['#02:Check:vManage:At minimum 20%  server disk space should be available'] = [check_analysis, check_action]

					log_file_logger.error('#02: Check result:   {}'.format(check_result))
					log_file_logger.error('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.error('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#02: Check result:   {}'.format(check_result))
					log_file_logger.info('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.info('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #02:Check:vManage:At minimum 20%  server disk space should be available. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#03:Check:vManage:Memory size
			print('  #03:Checking:vManage:Memory size')
			log_file_logger.info('#03:Check:vManage:Memory size')
			writeFile(report_file, '#03:Check:vManage:Memory size\n')
			writeFile(report_file, 'Link to the official documentation: \n https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html\n\n')

			try:
				memory_size, memory_size_str, dpi_status, server_type, check_result, check_analysis, check_action =  criticalCheckthree(vedge_count, dpi_status, server_type, cluster_size, version_tuple)
				if check_result == 'Failed':
					critical_checks['#03:Check:vManage:Memory size'] = [ check_analysis, check_action]

					log_file_logger.error('#03: Check result:   {}'.format(check_result))
					log_file_logger.error('#03: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#03: Memory Size GB: {}'.format(memory_size_str))
					log_file_logger.error('#03: /rootfs.rw Used: {}'.format(rootfs_partition_size))
					log_file_logger.error('#03: Server Type: {}'.format(server_type))
					log_file_logger.error('#03: vEdge Count: {}\n'.format(vedge_count))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#03: Check result:   {}'.format(check_result))
					log_file_logger.info('#03: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #03:Check:vManage:Memory size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
	 
			#04:Check:vManage:CPU Count
			print('  #04:Checking:vManage:CPU Count')
			log_file_logger.info('#04:Check:vManage:CPU Count')
			writeFile(report_file, '#04:Check:vManage:CPU Count\n\n')

			try:
				check_result, check_analysis, check_action = criticalCheckfour(cpu_count, vedge_count, dpi_status, server_type)
				if check_result == 'Failed':
					critical_checks['#04:Check:vManage:CPU Count'] = [ check_analysis, check_action]

					log_file_logger.error('#04: Check result:   {}'.format(check_result))
					log_file_logger.error('#04: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#04: CPU Count: {}\n'.format(cpu_count))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#04: Check result:   {}'.format(check_result))
					log_file_logger.info('#04: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #04:Check:vManage:CPU Count. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#05:Check:vManage:ElasticSearch Indices status
			print('  #05:Checking:vManage:ElasticSearch Indices status')
			log_file_logger.info('#05:Check:vManage:ElasticSearch Indices status')
			writeFile(report_file, '#05:Check:vManage:ElasticSearch Indices status\n\n')

			try:
				es_indexes_one = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_index_red_one, check_result_one, check_analysis_one, check_action_one = criticalCheckfive(es_indexes_one)

				time.sleep(5)

				es_indexes_two = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_index_red_two, check_result_two, check_analysis_two, check_action_two = criticalCheckfive(es_indexes_two)

				if check_result_one == 'Failed' and check_result_two == 'Failed':
					critical_checks['#05:Check:vManage:ElasticSearch Indices status'] = [ check_analysis_two, check_action_two]

					log_file_logger.error('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.error('#05: Check Analysis: {}\n'.format(check_analysis_two))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis_two))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action_two))
				   
				elif check_result_one == 'SUCCESSFUL':
					log_file_logger.info('#05: Check result:   {}'.format(check_result_one))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_one))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_one))

				elif check_result_two == 'SUCCESSFUL':

					log_file_logger.info('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_two))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_two))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #05:Check:vManage:ElasticSearch Indices status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#06:Check:vManage:Look for any neo4j exception errors
			print('  #06:Checking:vManage:Look for any neo4j exception errors')
			log_file_logger.info('#06:Check:vManage:Look for any neo4j exception errors')
			writeFile(report_file, '#06:Check:vManage:Look for any neo4j exception errors\n\n')

			try:
				check_result, check_analysis, check_action = criticalChecksix()
				if check_result == 'Failed':
					critical_checks['#06:Check:vManage:Look for any neo4j exception errors'] = [check_analysis, check_action]

					log_file_logger.error('#06: Check result:   {}'.format(check_result))
					log_file_logger.error('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))


				else:
					log_file_logger.info('#06: Check result:   {}'.format(check_result))
					log_file_logger.info('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #06:Check:vManage:Look for any neo4j exception errors. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#07:Check:vManage:Validate all services are up
			print('  #07:Checking:vManage:Validate all services are up')
			log_file_logger.info('#07:Check:vManage:Validate all services are up')
			writeFile(report_file, '#07:Check:vManage:Validate all services are up\n\n')

			try:
				nms_data, nms_failed, check_result, check_analysis, check_action =   criticalCheckseven() 
				if check_result == 'Failed':
					critical_checks['#07:Check:vManage:Validate all services are up'] = [check_analysis, check_action]

					log_file_logger.error('#07: Check result:   {}'.format(check_result))
					log_file_logger.error('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#07: List of services that are enabled but not running:\n{}'.format(nms_failed))
					log_file_logger.error('#07: Status of all services  :\n{}\n'.format(nms_data))

					writeFile(report_file, 'Result: ERROR -{}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
					
				else:
					log_file_logger.info('#07: Check result:   {}'.format(check_result))
					log_file_logger.info('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#07: Status of all the services: \n{}\n'.format(nms_data))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #07:Check:vManage:Validate all services are up. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#08:Check:vManage:Elasticsearch Indices version
			print('  #08:Checking:vManage:Elasticsearch Indices version ')
			log_file_logger.info('#08:Check:vManage:Elasticsearch Indices version ')
			writeFile(report_file, '#08:Check:vManage:Elasticsearch Indices version \n\n')

			try:
				version_list, check_result, check_analysis, check_action = criticalCheckeight(version_tuple)
				if check_result == 'Failed':
					critical_checks['#08:Check:vManage:Elasticsearch Indices version'] = [ check_analysis, check_action]

					log_file_logger.error('#08: Check result:   {}'.format(check_result))
					log_file_logger.error('#08: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#08: List of indices with older versions  :\n{}\n'.format(version_list))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#08: Check result:   {}'.format(check_result))
					log_file_logger.info('#08: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #08:Check:vManage:Elasticsearch Indices version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#09:Check:vManage:Evaluate incoming DPI data size
			print('  #09:Checking:vManage:Evaluate incoming DPI data size')
			log_file_logger.info('#09:Check:vManage:Evaluate incoming DPI data size')
			writeFile(report_file, '#09:Check:vManage:Evaluate incoming DPI data size\n\n')

			try:
				es_indices_est = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'management/elasticsearch/index/size/estimate', args.vmanage_port, tokenid))
				appr_estimate_ondeday, dpi_estimate_ondeday, check_result, check_analysis,check_action = criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count, total_devices, dpi_status)
				if check_result == 'Failed':
					critical_checks['#09:Check:vManage:Evaluate incoming DPI data size'] = [ check_analysis, check_action]

					log_file_logger.error('#09: Check result:   {}'.format(check_result))
					log_file_logger.error('#09: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#09: Daily incoming DPI data : {}'.format(dpi_estimate_ondeday))
					log_file_logger.error('#09: Daily incoming Approute data : {}\n'.format(appr_estimate_ondeday))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#09: Check result:   {}'.format(check_result))
					log_file_logger.info('#09: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #09:Check:vManage:Evaluate incoming DPI data size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#10:Check:vManage:NTP status across network
			print('  #10:Checking:vManage:NTP status across network')
			log_file_logger.info('#10:Check:vManage:NTP status across network')
			writeFile(report_file, '#10:Check:vManage:NTP status across network\n\n')

			try:
				ntp_nonworking, check_result, check_analysis, check_action = criticalCheckten(version_tuple, controllers_info)
				if check_result == 'Failed':
					critical_checks['#10:Check:vManage:NTP status across network'] = [ check_analysis, check_action]

					log_file_logger.error('#10: Check result:   {}'.format(check_result))
					log_file_logger.error('#10: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#10: Devices with invalid ntp associations: \n{}\n'.format(ntp_nonworking))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#10: Check result:   {}'.format(check_result))
					log_file_logger.info('#10: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #10:Check:vManage:NTP status across network. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#11:Check:Controllers:Validate vSmart/vBond CPU count for scale
			print('  #11:Checking:Controllers:Validate vSmart/vBond CPU count for scale')
			log_file_logger.info('#11:Check:Controllers:Validate vSmart/vBond CPU count for scale')
			writeFile(report_file, '#11:Check:Controllers:Validate vSmart/vBond CPU count for scale\n\n')

			try:
				for vbond in vbond_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip, jsessionid,'device/system/synced/status?deviceId={}'.format(vbond_info[vbond][1]),args.vmanage_port, tokenid))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vbond_info[vbond].append(total_cpu_count)

				for vsmart in vsmart_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip,jsessionid, 'device/system/synced/status?deviceId={}'.format(vsmart_info[vsmart][1]),args.vmanage_port,tokenid))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vsmart_info[vsmart].append(total_cpu_count)

				failed_vbonds,failed_vsmarts,check_result,check_analysis, check_action = criticalCheckeleven(total_devices, vbond_info, vsmart_info)
				if check_result == 'Failed':
					critical_checks['#11:Check:Controllers:Validate vSmart/vBond CPU count for scale'] = [ check_analysis, check_action]

					log_file_logger.error('#11: Check result:   {}'.format(check_result))
					log_file_logger.error('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#11: vBonds with insufficient CPU count: \n{}'.format(failed_vbonds))
					log_file_logger.error('#11: vSmarts with insufficient CPU count: \n{}'.format(failed_vsmarts))
					log_file_logger.error('#11: All vBonds info with total_cpu_count: \n{}'.format(vbond_info))
					log_file_logger.error('#11: All vSmarts info with total_cpu_count: \n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				  

				else:
					log_file_logger.info('#11: Check result:   {}'.format(check_result))
					log_file_logger.info('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#11: All vBonds info with total_cpu_count: \n{}'.format(vbond_info))
					log_file_logger.info('#11: All vSmarts info with total_cpu_count: \n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #11:Check:Controllers:Validate vSmart/vBond CPU count for scale. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Warning Checks
			print('\n**** Performing Warning checks\n')
			warning_checks = {}
			log_file_logger.info('*** Performing Warning Checks')

			#12:Check:vManage:CPU Speed
			print('  #12:Checking:vManage:CPU Speed')
			log_file_logger.info('#12:Check:vManage:CPU Speed')
			writeFile(report_file, '#12:Check:vManage:CPU Speed\n\n')

			try:
				check_result,check_analysis,check_action = warningCheckone(cpu_speed)
				if check_result == 'Failed':
					warning_checks['#12:Check:vManage:CPU Speed'] = [ check_analysis, check_action]

					log_file_logger.error('#12: Check result:   {}'.format(check_result))
					log_file_logger.error('#12: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#12: CPU clock speed: {}\n'.format(cpu_speed))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else: 
					log_file_logger.info('#12: Check result:   {}'.format(check_result))
					log_file_logger.info('#12: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #12:Check:vManage:CPU Speed. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#13:Check:vManage:Network Card type
			print('  #13:Checking:vManage:Network Card type')
			log_file_logger.info('#13:Check:vManage:Network Card type')
			writeFile(report_file, '#13:Check:vManage:Network Card type\n\n')

			try:
				eth_drivers, check_action, check_analysis, check_result = warningChecktwo()
				if check_result == 'Failed':
					warning_checks['#13:Check:vManage:Network Card type'] = [ check_analysis, check_action]

					log_file_logger.error('#13: Check result:   {}'.format(check_result))
					log_file_logger.error('#13: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#13: Ethercardswith e1000 card types: {}\n'.format(eth_drivers))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#13: Check result:   {}'.format(check_result))
					log_file_logger.info('#13: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #13:Check:vManage:Network Card type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#14:Check:vManage:Backup status
			print('  #14:Checking:vManage:Backup status')
			log_file_logger.info('#14:Check:vManage:Backup status')
			writeFile(report_file, '#14:Check:vManage:Backup status\n\n')

			try:
				date_time_obj, check_result, check_analysis, check_action = warningCheckthree()
				if check_result == 'Failed':
					warning_checks['#14:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#14: Check result:   {}'.format(check_result))
					log_file_logger.error('#14: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#14: Last Backup was performed on:{}\n'.format(date_time_obj))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#14: Check result:   {}'.format(check_result))
					log_file_logger.info('#14: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #14:Check:vManage:Backup status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#15:Check:vManage:Evaluate Neo4j performance
			print('  #15:Checking:vManage:Evaluate Neo4j performance')
			log_file_logger.info('#15:Check:vManage:Evaluate Neo4j performance')
			writeFile(report_file, '#15:Check:vManage:Evaluate Neo4j performance\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckfour()
				if check_result == 'Failed':
					warning_checks['#15:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#15: Check result:   {}'.format(check_result))
					log_file_logger.error('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#15: Check result:   {}'.format(check_result))
					log_file_logger.info('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #15:Check:vManage:Evaluate Neo4j performance. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#16:Check:vManage:Confirm there are no pending tasks
			print('  #16:Checking:vManage:Confirm there are no pending tasks')
			log_file_logger.info('#16:Check:vManage:Confirm there are no pending tasks')
			writeFile(report_file, '#16:Check:vManage:Confirm there are no pending tasks\n\n')

			try:
				tasks = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid,'device/action/status/tasks', args.vmanage_port, tokenid))
				tasks_running, check_result, check_analysis, check_action  = warningCheckfive(tasks)
				if check_result == 'Failed':
					warning_checks['#16:Check:vManage:Confirm there are no pending tasks'] = [ check_analysis, check_action]
					log_file_logger.error('#16: Check result:   {}'.format(check_result))
					log_file_logger.error('#16: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#16: Tasks still running: {}\n'.format(tasks_running))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))                  

				else:
					log_file_logger.info('#16: Check result:   {}'.format(check_result))
					log_file_logger.info('#16: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #16:Check:vManage:Confirm there are no pending tasks. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#17:Check:vManage:Validate there are no empty password users
			print('  #17:Checking:vManage:Validate there are no empty password users')
			log_file_logger.info('#17:Check:vManage:Validate there are no empty password users')
			writeFile(report_file, '#17:Check:vManage:Validate there are no empty password users\n\n')
			
			try:
				users_emptypass, check_result, check_analysis, check_action = warningChecksix(version_tuple)
				if check_result == 'Failed':
					warning_checks['#17:Check:vManage:Validate there are no empty password users'] = [ check_analysis, check_action]
					log_file_logger.error('#17: Check result:   {}'.format(check_result))
					log_file_logger.error('#17: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#17: Users with empty passwords: {}\n'.format(users_emptypass))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#17: Check result:   {}'.format(check_result))
					log_file_logger.info('#17: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #17:Check:vManage:Validate there are no empty password users. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#18:Check:Controllers:Controller versions
			print('  #18:Checking:Controllers:Controller versions')
			log_file_logger.info('#18:Check:Controllers:Controller versions')
			writeFile(report_file, '#18:Check:Controllers:Controller versions\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckseven(controllers_info)
				if check_result == 'Failed':
					warning_checks['#18:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#18: Check result:   {}'.format(check_result))
					log_file_logger.error('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#18: Check result:   {}'.format(check_result))
					log_file_logger.info('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #18:Check:Controllers:Controller versions. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#19:Check:Controllers:Confirm Certificate Expiration Dates
			print('  #19:Checking:Controllers:Confirm Certificate Expiration Dates')
			log_file_logger.info('#19:Check:Controllers:Confirm Certificate Expiration Dates')
			writeFile(report_file, '#19:Check:Controllers:Confirm Certificate Expiration Dates\n\n')

			try:
				controllers_exp, controllers_notexp, check_result, check_analysis, check_action = warningCheckeight(controllers_info)
				if check_result == 'Failed':
					warning_checks['#19:Check:Controllers:Confirm Certificate Expiration Dates'] = [ check_analysis, check_action]
					log_file_logger.error('#19: Check result:   {}'.format(check_result))
					log_file_logger.error('#19: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#19: Controllers with certificates close to expiration: \n{}\n'.format(controllers_exp))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#19: Check result:   {}'.format(check_result))
					log_file_logger.info('#19: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					
			except Exception as e:
				print('\033[1;31m ERROR: Error performing  #19:Check:Controllers:Confirm Certificate Expiration Dates. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#20:Check:Controllers:vEdge list sync
			print('  #20:Checking:Controllers:vEdge list sync')
			log_file_logger.info('#20:Check:Controllers:vEdge list sync')
			writeFile(report_file, '#20:Check:Controllers:vEdge list sync\n\n')

			try:
				state_vedgeList,check_result, check_analysis, check_action  = warningChecknine(controllers_info)
				if check_result == 'Failed':
					warning_checks['#20:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#20: Check result:   {}'.format(check_result))
					log_file_logger.error('#20: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#20: Controllers with inconsistent state_vedgeList: {}\n'.format(state_vedgeList))
					
					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#20: Check result:   {}'.format(check_result))
					log_file_logger.info('#20: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #20:Check:Controllers:vEdge list sync. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#21:Check:Controllers: Confirm control connections
			print('  #21:Checking:Controllers: Confirm control connections')
			log_file_logger.info('#21:Check:Controllers: Confirm control connections')
			writeFile(report_file, '#21:Check:Controllers: Confirm control connections\n\n')

			try:
				control_sum_tab, discrepancy,check_result, check_analysis, check_action = warningCheckten(vsmart_count, vbond_count)
				if check_result == 'Failed':
					warning_checks['#21:Check:Controllers: Confirm control connections'] = [ check_analysis, check_action]

					log_file_logger.error('#21: Check result:   {}'.format(check_result))
					log_file_logger.error('#21: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#21: Control  Connections Summary: \n{}\n'.format(control_sum_tab))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#21: Check result:   {}'.format(check_result))
					log_file_logger.info('#21: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #21:Check:Controllers: Confirm control connections. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


		 
			#Informational Checks
			print('\n**** Performing Informational checks\n') 
			log_file_logger.info('*** Performing Informational Checks')

			#22:Check:vManage:Disk controller type
			print('  #22:Check:vManage:Disk controller type')
			log_file_logger.info('#22:Check:vManage:Disk controller type')
			writeFile(report_file, '#22:Check:vManage:Disk controller type\n\n')

			try:
				check_result, check_analysis, check_action = infoCheckone(server_type, disk_controller)
				if check_result == 'Failed':
					warning_checks['#22:Check:vManage:Disk controller type'] = [ check_analysis, check_action]

					log_file_logger.error('#22: Check result:   {}'.format(check_result))
					log_file_logger.error('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#22: Check result:   {}'.format(check_result))
					log_file_logger.info('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #22:Check:vManage:Disk controller type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#23:Check:Controllers:Validate there is at minimum vBond, vSmart present
			print('  #23:Check:Controllers:Validate there is at minimum vBond, vSmart present ')
			log_file_logger.info('#23:Check:Controllers:Validate there is at minimum vBond, vSmart present')
			writeFile(report_file, '#23:Check:Controllers:Validate there is at minimum vBond, vSmart present\n\n')

			try:
				check_result, check_analysis, check_action = infoChecktwo(vsmart_count,vbond_count)
				if check_result == 'Failed':
					warning_checks['#23:Check:Controllers:Validate there is at minimum vBond, vSmart present'] = [ check_analysis, check_action]

					log_file_logger.error('#23: Check result:   {}'.format(check_result))
					log_file_logger.error('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.error('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: WARNING - {}\n\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				   
				else:
					log_file_logger.info('#23: Check result:   {}'.format(check_result))
					log_file_logger.info('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.info('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #23:Check:Controllers:Validate there is at minimum vBond, vSmart present. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#24:Check:Controllers:Validate all controllers are reachable
			print('  #24:Check:Controllers:Validate all controllers are reachable')
			log_file_logger.info('#24:Check:Controllers:Validate all controllers are reachable')
			writeFile(report_file, '#24:Check:Controllers:Validate all controllers are reachable\n\n')
				
			try:
				unreach_controllers,check_result, check_analysis, check_action = infoChecktthree(controllers_info)
				if check_result == 'Failed':
					warning_checks['#24:Check:Controllers:Validate all controllers are reachable'] = [ check_analysis, check_action]

					log_file_logger.error('#24: Check result:   {}'.format(check_result))
					log_file_logger.error('#24: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#24: Unreachable Controllers: {}\n'.format(unreach_controllers))


					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#24: Check result:   {}'.format(check_result))
					log_file_logger.info('#24: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #24:Check:Controllers:Validate all controllers are reachable. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			
			if cluster_size>1:
				cluster_checks = {}

				log_file_logger.info('*** Performing Cluster Checks')
				print('\n**** Performing Cluster checks\n')

				#25:Check:Cluster:Version consistency
				print('  #25:Checking:Cluster:Version consistency')
				log_file_logger.info('#25:Check:Cluster:Version consistency')
				writeFile(report_file, '#25:Check:Cluster:Version consistency\n\n')

				try:
					check_result,check_analysis, check_action = criticalChecktwelve(vmanage_info)
					if check_result == 'Failed':
						cluster_checks['#25:Check:Cluster:Version consistency'] = [ check_analysis, check_action]

						log_file_logger.error('#25: Check result:   {}'.format(check_result))
						log_file_logger.error('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
						
					else:
						log_file_logger.info('#25: Check result:   {}'.format(check_result))
						log_file_logger.info('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #25:Check:Cluster:Version consistency. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#26:Check:Cluster:Cluster health
				print('  #26:Checking:Cluster:Cluster health')
				log_file_logger.info('#26:Check:Cluster:Cluster health')
				writeFile(report_file, '#26:Check:Cluster:Cluster health\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid,'clusterManagement/list', args.vmanage_port, tokenid))
					services_down, check_result, check_analysis, check_action = criticalCheckthirteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#26:Check:Cluster:Cluster health'] = [ check_analysis, check_action]

						log_file_logger.error('#26: Check result:   {}'.format(check_result))
						log_file_logger.error('#26: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#26: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					 

					else: 
						log_file_logger.info('#26: Check result:   {}'.format(check_result))
						log_file_logger.info('#26: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #26:Check:Cluster:Cluster health. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))



				#27:Check:Cluster:Cluster ConfigDB topology
				print('  #27:Checking:Cluster:Cluster ConfigDB topology')
				log_file_logger.info('#27:Check:Cluster:Cluster ConfigDB topology')
				writeFile(report_file, '#27:Check:Cluster:Cluster ConfigDB topology\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'clusterManagement/list', args.vmanage_port, tokenid))           
					configDB_count, check_result, check_analysis, check_action = criticalCheckfourteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#27:Check:Cluster:Cluster ConfigDB topology'] = [ check_analysis, check_action]

						log_file_logger.error('#27: Check result:   {}'.format(check_result))
						log_file_logger.error('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#27: : No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					else: 
						log_file_logger.info('#27: Check result:   {}'.format(check_result))
						log_file_logger.info('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#27: : No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing  #27:Check:Cluster:Cluster ConfigDB topology. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#28:Check:Cluster:Messaging server
				print('  #28:Checking:Cluster:Messaging server')
				log_file_logger.info('#28:Check:Cluster:Messaging server')
				writeFile(report_file, '#28:Check:Cluster:Messaging server\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'clusterManagement/list', args.vmanage_port, tokenid))           
					cluster_msdown,check_result,check_analysis, check_action = criticalCheckfifteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#28:Check:Cluster:Messaging server'] = [ check_analysis, check_action]

						log_file_logger.error('#28: Check result:   {}'.format(check_result))
						log_file_logger.error('#28: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#28: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
						

					else: 
						log_file_logger.info('#28: Check result:   {}'.format(check_result))
						log_file_logger.info('#28: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #28:Check:Cluster:Messaging server. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))
				
				#29:Check:Cluster:DR replication status
				print('  #29:Checking:Cluster:DR replication status')
				log_file_logger.info('#29:Check:Cluster:DR replication status')
				writeFile(report_file, '#29:Check:Cluster:DR replication status\n\n')

				try:
					dr_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'disasterrecovery/details', args.vmanage_port, tokenid))           
					dr_status, check_action, check_analysis, check_result = criticalChecksixteen(dr_data)
					if check_result == 'Failed':
						cluster_checks['#29:Check:Cluster:DR replication status'] = [ check_analysis, check_action]

						log_file_logger.error('#29: Check result:   {}'.format(check_result))
						log_file_logger.error('#29: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#29: DR Replication status: {}\n'.format(dr_status))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					else:
						log_file_logger.info('#29: Check result:   {}'.format(check_result))
						log_file_logger.info('#29: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #29:Check:Cluster:DR replication status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#30:Check:Cluster:Intercluster communication
				print('  #30:Checking:Cluster:Intercluster communication')
				log_file_logger.info('#30:Check:Cluster:Intercluster communication')
				writeFile(report_file, '#30:Check:Cluster:Intercluster communication\n\n')
				
				try:
					if criticalCheckseventeen.isAlive():
						criticalCheckseventeen.join(10)

					if not criticalCheckseventeen.result_queue.empty():
						ping_output, ping_output_failed, ping_check_result, ping_check_analysis, ping_check_action = criticalCheckseventeen.result_queue.get()
						if ping_check_result == 'Failed':
							cluster_checks['#30:Check:Cluster:Intercluster communication'] = [ ping_check_analysis, ping_check_action]

							log_file_logger.error('#30: Check result:   {}'.format(ping_check_result))
							log_file_logger.error('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.error('#30: Cluster nodes with ping failure: {}\n'.format(ping_output_failed))

						
							writeFile(report_file, 'Result: ERROR - {}\n'.format(ping_check_analysis))
							writeFile(report_file, 'Action: {}\n\n'.format(ping_check_action))

						else:
							log_file_logger.info('#30: Check result:   {}'.format(ping_check_result))
							log_file_logger.info('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.info('#30: Cluster nodes details: {}\n'.format(ping_output))

							writeFile(report_file, 'Result: INFO - {}\n\n'.format(ping_check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #30:Check:Cluster:Intercluster communication. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

			#Logging out of the Session using jsessionid
			log_file_logger.info('Logging out of the Session')
			sessionLogout(vmanage_lo_ip, jsessionid, args.vmanage_port)
			log_file_logger.info('Successfully closed the connection')
		
		#version equal to or above 20.5
		elif version_tuple[0:2] >= ('20','5'): 
			try: 
				log_file_logger.info('Generating a JSessionID')
				jsessionid = generateSessionIDpy3(vmanage_lo_ip, args.username, password, args.vmanage_port)
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error generating JSessionID, make sure that the username and password entered is correct. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))

			try:
				log_file_logger.info('Generating CSRF Token')
				tokenid = CSRFTokenpy3(vmanage_lo_ip,jsessionid,args.vmanage_port)
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error generating CSRF Token. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file.  \033[0;0m \n\n'.format(log_file_path))

			#Preliminary data
			log_file_logger.info('****Collecting Preliminary Data\n')
			print ('****Collecting Preliminary Data\n')

			try:
				controllers = json.loads(getRequestpy3(version_tuple, vmanage_lo_ip, jsessionid , 'system/device/controllers', args.vmanage_port, tokenid))
				controllers_info = controllersInfo(controllers)
				log_file_logger.info('Collected controllers information: {}'.format(controllers_info))

				system_ip_data = json.loads(getRequestpy3(version_tuple, vmanage_lo_ip, jsessionid ,'device/vmanage', args.vmanage_port, tokenid))
				system_ip = system_ip_data['data']['ipAddress']
				#system_ip = controllers_info[hostname][1]
				log_file_logger.info('Collected vManage System IP address: {}'.format(system_ip))

				cpu_speed = cpuSpeed()
				log_file_logger.info('Collected vManage CPU Speed GHz: {}'.format(cpu_speed))

				cpu_count = cpuCount()
				log_file_logger.info('Collected vManage CPU Count: {}'.format(cpu_count))

				vedges = json.loads(getRequestpy3(version_tuple, vmanage_lo_ip, jsessionid , 'system/device/vedges', args.vmanage_port , tokenid))
				vedge_count,vedge_count_active, vedge_info = vedgeCount(vedges)
				log_file_logger.info('Collected  xEdge Count: {}'.format(vedge_count))

				cluster_size, server_mode, vmanage_info = serverMode(controllers_info)
				log_file_logger.info('Collected vManage Cluster Size: {}'.format(cluster_size))
				log_file_logger.info('Collected vManage Server Mode: {}'.format(server_mode))

				disk_controller = diskController()
				log_file_logger.info('Collected vManage Disk Controller Type: {}'.format(disk_controller))

				dpi_stats = json.loads(getRequestpy3(version_tuple, vmanage_lo_ip, jsessionid , 'statistics/settings/status', args.vmanage_port, tokenid))
				dpi_status = dpiStatus(dpi_stats)
				log_file_logger.info('Collected DPI Status: {}'.format(dpi_status))

				server_type = serverType()
				log_file_logger.info('Collected Server Type: {}'.format(server_type))

				vbond_info, vsmart_info = vbondvmartInfo(controllers_info)
				vbond_count = len(vbond_info)
				vsmart_count = len(vsmart_info)
				log_file_logger.info('vSmart info: {}'.format(vbond_info))
				log_file_logger.info('vBond info: {}'.format(vsmart_info))
				

				total_devices = len(controllers_info.keys()) + vedge_count
				log_file_logger.info('Total devices: {}'.format(total_devices))

			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error Collecting Preliminary Data. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				

			print('*Starting Checks, this may take several minutes')

			#Critical Checks
			critical_checks = {}
			log_file_logger.info('*** Performing Critical Checks\n')
			
			#Begining #30:Check:Cluster:Intercluster communication  in the background
			if cluster_size>1:
				log_file_logger.info('Beginging #30:Check:Cluster:Intercluster communication  in the background\n')
				try:
					cluster_health_data = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))
					criticalCheckseventeen =  criticalCheckseventeenpy3(cluster_health_data,  system_ip, log_file_logger)
				except Exception as e:
					log_file_logger.exception('{}\n'.format(e))


			#01:Check:vManage:Validate current version
			print('  #01:Checking:vManage:Validate current version')
			log_file_logger.info('#01:Check:vManage:Validate current version')
			writeFile(report_file, '#01:Check:vManage:Validate current version\n\n')
			
			try:
				boot_partition_size, check_result, check_analysis, check_action =  criticalCheckone(version)
				if check_result == 'Failed':
					critical_checks['#01:Check:vManage:Validate current version'] = [ check_analysis, check_action]
					log_file_logger.error('#01: Check result:   {}'.format(check_result))
					log_file_logger.error('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#01: version: {}'.format(version))
					log_file_logger.error('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#01: Check result:   {}'.format(check_result))
					log_file_logger.info('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#01: version: {}'.format(version))
					log_file_logger.info('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
					
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #01:Check:vManage:Validate current version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#02:Check:vManage:vAt minimum 20%  server disk space should be available
			print('  #02:Checking:vManage:vManage sever disk space')
			log_file_logger.info('#02:Check:vManage:At minimum 20%  server disk space should be available')
			writeFile(report_file,'#02:Check:vManage:At minimum 20%  server disk space should be available\n\n')

			try:
				optdata_partition_size, rootfs_partition_size, check_result, check_analysis, check_action =  criticalCheckTwo()
				if check_result == 'Failed': 
					critical_checks['#02:Check:vManage:At minimum 20%  server disk space should be available'] = [check_analysis, check_action]
					log_file_logger.error('#02: Check result:   {}'.format(check_result))
					log_file_logger.error('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.error('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#02: Check result:   {}'.format(check_result))
					log_file_logger.info('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.info('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #02:Check:vManage:At minimum 20%  server disk space should be available. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#03:Check:vManage:Memory size
			print('  #03:Checking:vManage:Memory size')
			log_file_logger.info('#03:Check:vManage:Memory size')
			writeFile(report_file, '#03:Check:vManage:Memory size\n')
			writeFile(report_file, 'Link to the official documentation: \n https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html\n\n')

			try:
				memory_size, memory_size_str, dpi_status, server_type, check_result, check_analysis, check_action =  criticalCheckthree(vedge_count, dpi_status, server_type, cluster_size, version_tuple)
				if check_result == 'Failed':
					critical_checks['#03:Check:vManage:Memory size'] = [ check_analysis, check_action]

					log_file_logger.error('#03: Check result:   {}'.format(check_result))
					log_file_logger.error('#03: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#03: Memory Size GB: {}'.format(memory_size_str))
					log_file_logger.error('#03: /rootfs.rw Used: {}'.format(rootfs_partition_size))
					log_file_logger.error('#03: Server Type: {}'.format(server_type))
					log_file_logger.error('#03: vEdge Count: {}\n'.format(vedge_count))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#03: Check result:   {}'.format(check_result))
					log_file_logger.info('#03: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #03:Check:vManage:Memory size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

	 
			#04:Check:vManage:CPU Count
			print('  #04:Checking:vManage:CPU Count')
			log_file_logger.info('#04:Check:vManage:CPU Count')
			writeFile(report_file, '#04:Check:vManage:CPU Count\n\n')

			try:
				check_result, check_analysis, check_action = criticalCheckfour(cpu_count, vedge_count, dpi_status, server_type)
				if check_result == 'Failed':
					critical_checks['#04:Check:vManage:CPU Count'] = [ check_analysis, check_action]
					log_file_logger.error('#04: Check result:   {}'.format(check_result))
					log_file_logger.error('#04: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#04:CPU Count: {}\n'.format(cpu_count))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#04: Check result:   {}'.format(check_result))
					log_file_logger.info('#04: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #04:Check:vManage:CPU Count. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#05:Check:vManage:ElasticSearch Indices status
			print('  #05:Checking:vManage:ElasticSearch Indices status')
			log_file_logger.info('#05:Check:vManage:ElasticSearch Indices status')
			writeFile(report_file, '#05:Check:vManage:ElasticSearch Indices status\n\n')

			try:
				es_indexes_one = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_index_red_one, check_result_one, check_analysis_one, check_action_one = criticalCheckfive(es_indexes_one)

				time.sleep(5)

				es_indexes_two = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_index_red_two, check_result_two, check_analysis_two, check_action_two = criticalCheckfive(es_indexes_two)

				if check_result_one == 'Failed' and check_result_two == 'Failed':
					critical_checks['#05:Check:vManage:ElasticSearch Indices status'] = [ check_analysis_two, check_action_two]

					log_file_logger.error('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.error('#05: Check Analysis: {}\n'.format(check_analysis_two))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis_two))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action_two))
				   
				elif check_result_one == 'SUCCESSFUL':
					log_file_logger.info('#05: Check result:   {}'.format(check_result_one))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_one))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_one))

				elif check_result_two == 'SUCCESSFUL':

					log_file_logger.info('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_two))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_two))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing  #05:Check:vManage:ElasticSearch Indices status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#06:Check:vManage:Look for any neo4j exception errors
			print('  #06:Checking:vManage:Look for any neo4j exception errors')
			log_file_logger.info('#06:Check:vManage:Look for any neo4j exception errors')
			writeFile(report_file, '#06:Check:vManage:Look for any neo4j exception errors\n\n')

			try:
				check_result, check_analysis, check_action = criticalChecksix()
				if check_result == 'Failed':
					critical_checks['#06:Check:vManage:Look for any neo4j exception errors'] = [check_analysis, check_action]
					log_file_logger.error('#06: Check result:   {}'.format(check_result))
					log_file_logger.error('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))


				else:
					log_file_logger.info('#06: Check result:   {}'.format(check_result))
					log_file_logger.info('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #06:Check:vManage:Look for any neo4j exception errors. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#07:Check:vManage:Validate all services are up
			print('  #07:Checking:vManage:Validate all services are up')
			log_file_logger.info('#07:Check:vManage:Validate all services are up')
			writeFile(report_file, '#07:Check:vManage:Validate all services are up\n\n')

			try:
				nms_data, nms_failed, check_result, check_analysis, check_action =   criticalCheckseven() 
				if check_result == 'Failed':
					critical_checks['#07:Check:vManage:Validate all services are up'] = [check_analysis, check_action]

					log_file_logger.error('#07: Check result:   {}'.format(check_result))
					log_file_logger.error('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#07: List of services that are enabled but not running:\n{}\n'.format(nms_failed))
					log_file_logger.error('#07: Status of all services  :\n{}\n'.format(nms_data))

					writeFile(report_file, 'Result: ERROR - Services that are enabled but not running:\n')
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				 
				else:
					log_file_logger.info('#07: Check result:   {}'.format(check_result))
					log_file_logger.info('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#07: Status of all the services:\n{}\n'.format(nms_data))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #07:Check:vManage:Validate all services are up. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#08:Check:vManage:Elasticsearch Indices version
			print('  #08:Checking:vManage:Elasticsearch Indices version')
			log_file_logger.info('#08:Check:vManage:Elasticsearch Indices version')
			writeFile(report_file, '#08:Check:vManage:Elasticsearch Indices version\n\n')

			try:
				version_list, check_result, check_analysis, check_action = criticalCheckeight(version_tuple)
				if check_result == 'Failed':
					critical_checks['#08:Check:vManage:Elasticsearch Indices version'] = [ check_analysis, check_action]

					log_file_logger.error('#08: Check result:   {}'.format(check_result))
					log_file_logger.error('#08: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#08: List of indices with older versions  :\n{}\n'.format(version_list))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#08: Check result:   {}'.format(check_result))
					log_file_logger.info('#08: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #08:Check:vManage:Elasticsearch Indices version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#09:Check:vManage:Evaluate incoming DPI data size
			print('  #09:Checking:vManage:Evaluate incoming DPI data size')
			log_file_logger.info('#09:Check:vManage:Evaluate incoming DPI data size')
			writeFile(report_file, '#09:Check:vManage:Evaluate incoming DPI data size\n\n')

			try:
				es_indices_est = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/size/estimate', args.vmanage_port, tokenid))
				appr_estimate_ondeday, dpi_estimate_ondeday, check_result, check_analysis,check_action = criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count, total_devices, dpi_status)
				if check_result == 'Failed':
					critical_checks['#09:Check:vManage:Evaluate incoming DPI data size'] = [ check_analysis, check_action]

					log_file_logger.error('#09: Check result:   {}'.format(check_result))
					log_file_logger.error('#09: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#09: Daily incoming DPI data : {}'.format(dpi_estimate_ondeday))
					log_file_logger.error('#09: Daily incoming Approute data : {}\n'.format(appr_estimate_ondeday))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#08: Check result:   {}'.format(check_result))
					log_file_logger.info('#08: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #09:Check:vManage:Evaluate incoming DPI data size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#10:Check:vManage:NTP status across network
			print('  #10:Checking:vManage:NTP status across network')
			log_file_logger.info('#10:Check:vManage:NTP status across network')
			writeFile(report_file, '#10:Check:vManage:NTP status across network\n\n')
			try:
				ntp_nonworking, check_result, check_analysis, check_action = criticalCheckten(version_tuple, controllers_info)
				if check_result == 'Failed':
					critical_checks['#10:Check:vManage:NTP status across network'] = [ check_analysis, check_action]

					log_file_logger.error('#10: Check result:   {}'.format(check_result))
					log_file_logger.error('#10: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#10: Devices with invalid ntp associations: \n{}\n'.format(ntp_nonworking))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				  

				else:
					log_file_logger.info('#10: Check result:   {}'.format(check_result))
					log_file_logger.info('#10: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error perforiming #10:Check:vManage:NTP status across network. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#11:Check:Controllers:Validate vSmart/vBond CPU count for scale
			print('  #11:Checking:Controllers:Validate vSmart/vBond CPU count for scale')
			log_file_logger.info('#11:Check:Controllers:Validate vSmart/vBond CPU count for scale')
			writeFile(report_file, '#11:Check:Controllers:Validate vSmart/vBond CPU count for scale\n\n')

			try:
				for vbond in vbond_info:
					output = json.loads(getRequestpy3( version_tuple,vmanage_lo_ip, jsessionid, 'device/system/synced/status?deviceId={}'.format(vbond_info[vbond][1]),args.vmanage_port, tokenid))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vbond_info[vbond].append(total_cpu_count)

				for vsmart in vsmart_info:
					output = json.loads(getRequestpy3( version_tuple,vmanage_lo_ip, jsessionid, 'device/system/synced/status?deviceId={}'.format(vsmart_info[vsmart][1]),args.vmanage_port,tokenid))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vsmart_info[vsmart].append(total_cpu_count)

				failed_vbonds,failed_vsmarts,check_result,check_analysis, check_action = criticalCheckeleven(total_devices, vbond_info, vsmart_info)
				if check_result == 'Failed':
					critical_checks['#11:Check:Controllers:Validate vSmart/vBond CPU count for scale'] = [ check_analysis, check_action]

					log_file_logger.error('#11: Check result:   {}'.format(check_result))
					log_file_logger.error('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#11: vBonds with insufficient CPU count: \n{}'.format(failed_vbonds))
					log_file_logger.error('#11: vSmarts with insufficient CPU count: \n{}'.format(failed_vsmarts))
					log_file_logger.error('#11: All vBonds info with total_cpu_count: \n{}'.format(vbond_info))
					log_file_logger.error('#11: All vSmarts info with total_cpu_count: \n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#11: Check result:   {}'.format(check_result))
					log_file_logger.info('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#11: All vBonds info with total_cpu_count: \n{}'.format(vbond_info))
					log_file_logger.info('#11: All vSmarts info with total_cpu_count: \n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #11:Check:Controllers:Validate vSmart/vBond CPU count for scale. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file.\033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Warning Checks
			print('\n**** Performing Warning checks\n')

			warning_checks = {}
			log_file_logger.info('*** Performing Warning Checks')

			#12:Check:vManage:CPU Speed
			print('  #12:Checking:vManage:CPU Speed')
			log_file_logger.info('#12:Check:vManage:CPU Speed')
			writeFile(report_file, '#12:Check:vManage:CPU Speed\n\n')

			try:
				check_result,check_analysis,check_action = warningCheckone(cpu_speed)
				if check_result == 'Failed':
					warning_checks['#12:Check:vManage:CPU Speed'] = [ check_analysis, check_action]

					log_file_logger.error('#12: Check result:   {}'.format(check_result))
					log_file_logger.error('#12: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#12: CPU clock speed: {}\n'.format(cpu_speed))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#12: Check result:   {}'.format(check_result))
					log_file_logger.info('#12: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #12:Check:vManage:CPU Speed. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#13:Check:vManage:Network Card type
			print('  #13:Checking:vManage:Network Card type')
			log_file_logger.info('#13:Check:vManage:Network Card type')
			writeFile(report_file, '#13:Check:vManage:Network Card type\n\n')

			try:
				eth_drivers, check_action, check_analysis, check_result = warningChecktwo()
				if check_result == 'Failed':
					warning_checks['#13:Check:vManage:Network Card type'] = [ check_analysis, check_action]

					log_file_logger.error('#13: Check result:   {}'.format(check_result))
					log_file_logger.error('#13: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#13: Ethercardswith e1000 card types: {}\n'.format(eth_drivers))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				   

				else:
					log_file_logger.info('#13: Check result:   {}'.format(check_result))
					log_file_logger.info('#13: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #13:Check:vManage:Network Card type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#14:Check:vManage:Backup status
			print('  #14:Checking:vManage:Backup status')
			log_file_logger.info('#14:Check:vManage:Backup status')
			writeFile(report_file, '#14:Check:vManage:Backup status\n\n')

			try:
				date_time_obj, check_result, check_analysis, check_action = warningCheckthree()
				if check_result == 'Failed':
					warning_checks['#14:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#14: Check result:   {}'.format(check_result))
					log_file_logger.error('#14: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#14: Last Backup was performed on:{}\n'.format(date_time_obj))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#14: Check result:   {}'.format(check_result))
					log_file_logger.info('#14: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #14:Check:vManage:Backup status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#15:Check:vManage:Evaluate Neo4j performance
			print('  #15:Checking:vManage:Evaluate Neo4j performance')
			log_file_logger.info('#15:Check:vManage:Evaluate Neo4j performance')
			writeFile(report_file, '#15:Check:vManage:Evaluate Neo4j performance\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckfour()
				if check_result == 'Failed':
					warning_checks['#15:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#15: Check result:   {}'.format(check_result))
					log_file_logger.error('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#15: Check result:   {}'.format(check_result))
					log_file_logger.info('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #15:Check:vManage:Evaluate Neo4j performance. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#16:Check:vManage:Confirm there are no pending tasks
			print('  #16:Checking:vManage:Confirm there are no pending tasks')
			log_file_logger.info('#16:Check:vManage:Confirm there are no pending tasks')
			writeFile(report_file, '#16:Check:vManage:Confirm there are no pending tasks\n\n')

			try:
				tasks = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid,'device/action/status/tasks', args.vmanage_port, tokenid))
				tasks_running, check_result, check_analysis, check_action  = warningCheckfive(tasks)
				if check_result == 'Failed':
					warning_checks['#16:Check:vManage:Confirm there are no pending tasks'] = [ check_analysis, check_action]
					log_file_logger.error('#16: Check result:   {}'.format(check_result))
					log_file_logger.error('#16: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#16: Tasks still running: {}\n'.format(tasks_running))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#16: Check result:   {}'.format(check_result))
					log_file_logger.info('#16: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #16:Check:vManage:Confirm there are no pending tasks. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#17:Check:vManage:Validate there are no empty password users
			print('  #17:Checking:vManage:Validate there are no empty password users')
			log_file_logger.info('#17:Check:vManage:Validate there are no empty password users')
			writeFile(report_file, '#17:Check:vManage:Validate there are no empty password users\n\n')

			try:
				users_emptypass, check_result, check_analysis, check_action = warningChecksix(version_tuple)
				if check_result == 'Failed':
					warning_checks['#17:Check:vManage:Validate there are no empty password users'] = [ check_analysis, check_action]
					log_file_logger.error('#17: Check result:   {}'.format(check_result))
					log_file_logger.error('#17: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#17: Users with empty passwords: {}\n'.format(users_emptypass))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#17: Check result:   {}'.format(check_result))
					log_file_logger.info('#17: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #17:Check:vManage:Validate there are no empty password users. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#18:Check:Controllers:Controller versions
			print('  #18:Checking:Controllers:Controller versions')
			log_file_logger.info('#18:Check:Controllers:Controller versions')
			writeFile(report_file, '#18:Check:Controllers:Controller versions\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckseven(controllers_info)
				if check_result == 'Failed':
					warning_checks['#18:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#18: Check result:   {}'.format(check_result))
					log_file_logger.error('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

				else:
					log_file_logger.info('#18: Check result:   {}'.format(check_result))
					log_file_logger.info('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #18:Check:Controllers:Controller versions. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#19:Check:Controllers:Confirm Certificate Expiration Dates
			print('  #19:Checking:Controllers:Confirm Certificate Expiration Dates')
			log_file_logger.info('#19:Check:Controllers:Confirm Certificate Expiration Dates')
			writeFile(report_file, '#19:Check:Controllers:Confirm Certificate Expiration Dates\n\n')

			try:
				controllers_exp, controllers_notexp, check_result, check_analysis, check_action = warningCheckeight(controllers_info)
				if check_result == 'Failed':
					warning_checks['#19:Check:Controllers:Confirm Certificate Expiration Dates'] = [ check_analysis, check_action]

					log_file_logger.error('#19: Check result:   {}'.format(check_result))
					log_file_logger.error('#19: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#19: Controllers with certificates close to expiration: \n{}\n'.format(controllers_exp))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#19: Check result:   {}'.format(check_result))
					log_file_logger.info('#19: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				  
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #19:Check:Controllers:Confirm Certificate Expiration Dates. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#20:Check:Controllers:vEdge list sync
			print('  #20:Checking:Controllers:vEdge list sync')
			log_file_logger.info('#20:Check:Controllers:vEdge list sync')
			writeFile(report_file, '#20:Check:Controllers:vEdge list sync\n\n')

			try:
				state_vedgeList,check_result, check_analysis, check_action  = warningChecknine(controllers_info)
				if check_result == 'Failed':
					warning_checks['#20:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#20: Check result:   {}'.format(check_result))
					log_file_logger.error('#20: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#20: Controllers with inconsistent state_vedgeList:\n{}\n'.format(state_vedgeList))
					
					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				 
				else:
					log_file_logger.info('#20: Check result:   {}'.format(check_result))
					log_file_logger.info('#20: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #20:Check:Controllers:vEdge list sync. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#21:Check:Controllers: Confirm control connections
			print('  #21:Checking:Controllers: Confirm control connections')
			log_file_logger.info('#21:Check:Controllers: Confirm control connections')
			writeFile(report_file, '#21:Check:Controllers: Confirm control connections\n\n')

			try:
				control_sum_tab, discrepancy,check_result, check_analysis, check_action = warningCheckten(vsmart_count, vbond_count)
				if check_result == 'Failed':
					warning_checks['#21:Check:Controllers: Confirm control connections'] = [ check_analysis, check_action]

					log_file_logger.error('#21: Check result:   {}'.format(check_result))
					log_file_logger.error('#21: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#21: Control  Connections Summary: \n{}\n'.format(control_sum_tab))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
				else:
					log_file_logger.info('#21: Check result:   {}'.format(check_result))
					log_file_logger.info('#21: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #21:Check:Controllers: Confirm control connections. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Informational Checks
			print('\n**** Performing Informational checks\n') 
			log_file_logger.info('*** Performing Informational Checks')

			#22:Check:vManage:Disk controller type
			print('  #22:Check:vManage:Disk controller type')
			log_file_logger.info('#22:Check:vManage:Disk controller type')
			writeFile(report_file, '#22:Check:vManage:Disk controller type\n\n')

			try:
				check_result, check_analysis, check_action = infoCheckone(server_type, disk_controller)
				if check_result == 'Failed':
					warning_checks['#22:Check:vManage:Disk controller type'] = [ check_analysis, check_action]

					log_file_logger.error('#22: Check result:   {}'.format(check_result))
					log_file_logger.error('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#22: Check result:   {}'.format(check_result))
					log_file_logger.info('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #22:Check:vManage:Disk controller type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#23:Check:Controllers:Validate there is at minimum vBond, vSmart present
			print('  #23:Check:Controllers:Validate there is at minimum vBond, vSmart present ')
			log_file_logger.info('#23:Check:Controllers:Validate there is at minimum vBond, vSmart present')
			writeFile(report_file, '#23:Check:Controllers:Validate there is at minimum vBond, vSmart present\n\n')

			try:
				check_result, check_analysis, check_action = infoChecktwo(vsmart_count,vbond_count)
				if check_result == 'Failed':
					warning_checks['#23:Check:Controllers:Validate there is at minimum vBond, vSmart present'] = [ check_analysis, check_action]

					log_file_logger.error('#23: Check result:   {}'.format(check_result))
					log_file_logger.error('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.error('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, ' WARNING: {}\n\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				

				else:
					log_file_logger.info('#23: Check result:   {}'.format(check_result))
					log_file_logger.info('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.info('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #23:Check:Controllers:Validate there is at minimum vBond, vSmart present. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#24:Check:Controllers:Validate all controllers are reachable
			print('  #24:Check:Controllers:Validate all controllers are reachable')
			log_file_logger.info('#24:Check:Controllers:Validate all controllers are reachable')
			writeFile(report_file, '#24:Check:Controllers:Validate all controllers are reachable\n\n')
				
			try:
				unreach_controllers,check_result, check_analysis, check_action = infoChecktthree(controllers_info)
				if check_result == 'Failed':
					warning_checks['#24:Check:Controllers:Validate all controllers are reachable'] = [ check_analysis, check_action]

					log_file_logger.error('#24: Check result:   {}'.format(check_result))
					log_file_logger.error('#24: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#24: Unreachable Controllers: {}\n'.format(unreach_controllers))


					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

				else:
					log_file_logger.info('#24: Check result:   {}'.format(check_result))
					log_file_logger.info('#24: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing  #24:Check:Controllers:Validate all controllers are reachable. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

				
			if cluster_size>1:
				cluster_checks = {}

				log_file_logger.info('*** Performing Cluster Checks')
				print('\n**** Performing Cluster checks\n')

				#25:Check:Cluster:Version consistency
				print('  #25:Checking:Cluster:Version consistency')
				log_file_logger.info('#25:Check:Cluster:Version consistency')
				writeFile(report_file, '#25:Check:Cluster:Version consistency\n\n')

				try:
					check_result,check_analysis, check_action = criticalChecktwelve(vmanage_info)
					if check_result == 'Failed':
						cluster_checks['#25:Check:Cluster:Version consistency'] = [ check_analysis, check_action]

						log_file_logger.error('#25: Check result:   {}'.format(check_result))
						log_file_logger.error('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
						
					else:
						log_file_logger.info('#25: Check result:   {}'.format(check_result))
						log_file_logger.info('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						
				except Exception as e:
					print('\033[1;31m ERROR: Error performing #25:Check:Cluster:Version consistency. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#26:Check:Cluster:Cluster health
				print('  #26:Checking:Cluster:Cluster health')
				log_file_logger.info('#26:Check:Cluster:Cluster health')
				writeFile(report_file, '#26:Check:Cluster:Cluster health\n\n')

				try:
					cluster_health_data = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))
					services_down, check_result, check_analysis, check_action = criticalCheckthirteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#26:Check:Cluster:Cluster health'] = [ check_analysis, check_action]

						log_file_logger.error('#26: Check result:   {}'.format(check_result))
						log_file_logger.error('#26: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#26: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				   

					else: 
						log_file_logger.info('#26: Check result:   {}'.format(check_result))
						log_file_logger.info('#26: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #26:Check:Cluster:Cluster health. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#27:Check:Cluster:Cluster ConfigDB topology
				print('  #27:Checking:Cluster:Cluster ConfigDB topology')
				log_file_logger.info('#27:Check:Cluster:Cluster ConfigDB topology')
				writeFile(report_file, '#27:Check:Cluster:Cluster ConfigDB topology\n\n')

				try:
					cluster_health_data = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))           
					configDB_count, check_result, check_analysis, check_action = criticalCheckfourteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#27:Check:Cluster:Cluster ConfigDB topology'] = [ check_analysis, check_action]

						log_file_logger.error('#27: Check result:   {}'.format(check_result))
						log_file_logger.error('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					else: 
						log_file_logger.info('#27: Check result:   {}'.format(check_result))
						log_file_logger.info('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #27:Check:Cluster:Cluster ConfigDB topology. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#28:Check:Cluster:Messaging server
				print('  #28:Checking:Cluster:Messaging server')
				log_file_logger.info('#28:Check:Cluster:Messaging server')
				writeFile(report_file, '#28:Check:Cluster:Messaging server\n\n')

				try:
					cluster_health_data = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))           
					cluster_msdown,check_result,check_analysis, check_action = criticalCheckfifteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#28:Check:Cluster:Messaging server'] = [ check_analysis, check_action]

						log_file_logger.error('#28: Check result:   {}'.format(check_result))
						log_file_logger.error('#28: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#28: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					   

					else: 
						log_file_logger.info('#28: Check result:   {}'.format(check_result))
						log_file_logger.info('#28: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing  #28:Check:Cluster:Messaging server. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

			
				#29:Check:Cluster:DR replication status
				print('  #29:Checking:Cluster:DR replication status')
				log_file_logger.info('#29:Check:Cluster:DR replication status')
				writeFile(report_file, '#29:Check:Cluster:DR replication status\n\n')

				try:
					dr_data = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'disasterrecovery/details', args.vmanage_port, tokenid))           
					dr_status, check_action, check_analysis, check_result = criticalChecksixteen(dr_data)
					if check_result == 'Failed':
						cluster_checks['#29:Check:Cluster:DR replication status'] = [ check_analysis, check_action]

						log_file_logger.error('#29: Check result:   {}'.format(check_result))
						log_file_logger.error('#29: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#29: DR Replication status: {}\n'.format(dr_status))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					else:
						log_file_logger.info('#29: Check result:   {}'.format(check_result))
						log_file_logger.info('#29: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #29:Check:Cluster:DR replication status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#30:Check:Cluster:Intercluster communication
				print('  #30:Checking:Cluster:Intercluster communication')
				log_file_logger.info('#30:Check:Cluster:Intercluster communication')
				writeFile(report_file, '#30:Check:Cluster:Intercluster communication\n\n')
				
				try:
					if criticalCheckseventeenpy3.isAlive():
						criticalCheckseventeenpy3.join(10)

					if not criticalCheckseventeenpy3.result_queue.empty():
						ping_output, ping_output_failed, ping_check_result, ping_check_analysis, ping_check_action = criticalCheckseventeenpy3.result_queue.get()
						if ping_check_result == 'Failed':
							cluster_checks['#30:Check:Cluster:Intercluster communication'] = [ check_analysis, check_action]

							log_file_logger.error('#30: Check result:   {}'.format(check_result))
							log_file_logger.error('#30: Check Analysis: {}'.format(check_analysis))
							log_file_logger.error('#30: Cluster nodes with ping failure: {}\n'.format(ping_output_failed))

						
							writeFile(report_file, 'Result: ERROR - {}\n'.format(ping_check_analysis))
							writeFile(report_file, 'Action: {}\n\n'.format(ping_check_action))

						else:
							log_file_logger.info('#30: Check result:   {}'.format(check_result))
							log_file_logger.info('#30: Check Analysis: {}'.format(check_analysis))
							log_file_logger.info('#30: Cluster nodes details: {}\n'.format(ping_output))

							writeFile(report_file, 'Result: INFO - {}\n\n'.format(ping_check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #30:Check:Cluster:Intercluster communication. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

			#Logging out of the Session using jsessionid
			log_file_logger.info('Logging out of the Session')
			sessionLogoutpy3(vmanage_lo_ip,jsessionid,args.vmanage_port)
			log_file_logger.info('Successfully closed the connection')

	#Debug Execution
	elif args.debug == True:
		log_file_logger.info('Executing the script in Debug execution mode')

		#version below 19.2
		if version_tuple[0:2] < ('19','2'):
			 #Creating a session
			try:
				log_file_logger.info('Generating a JSessionID')
				jsessionid = generateSessionID(vmanage_lo_ip, args.username, password, args.vmanage_port) 
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error generating JSessionID, make sure that the username and password entered is correct. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))


			#Preliminary Data
			log_file_logger.info('****Collecting Preliminary Data\n')
			print ('****Collecting Preliminary Data\n')

			try:
				controllers = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'system/device/controllers', args.vmanage_port))
				controllers_info = controllersInfo(controllers)
				log_file_logger.info('Collected controllers information: {}'.format(controllers_info))

				system_ip_data = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'device/vmanage', args.vmanage_port))
				system_ip = system_ip_data['data']['ipAddress']
				#system_ip = controllers_info[hostname][1]
				log_file_logger.info('Collected vManage System IP address: {}'.format(system_ip))

				cpu_speed = cpuSpeed()
				log_file_logger.info('Collected vManage CPU Speed GHz: {}'.format(cpu_speed))

				cpu_count = cpuCount()
				log_file_logger.info('Collected vManage CPU Count: {}'.format(cpu_count))

				vedges = json.loads(getRequest(version_tuple, vmanage_lo_ip,jsessionid, 'system/device/vedges', args.vmanage_port))
				vedge_count,vedge_count_active, vedge_info = vedgeCount(vedges)
				log_file_logger.info('Collected  xEdge Count: {}'.format(vedge_count))

				cluster_size, server_mode, vmanage_info = serverMode(controllers_info)
				log_file_logger.info('Collected vManage Cluster Size: {}'.format(cluster_size))
				log_file_logger.info('Collected vManage Server Mode: {}'.format(server_mode))

				disk_controller = diskController()
				log_file_logger.info('Collected vManage Disk Controller Type: {}'.format(disk_controller))

				dpi_stats = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'statistics/settings/status', args.vmanage_port))
				dpi_status = dpiStatus(dpi_stats)
				log_file_logger.info('Collected DPI status: {}'.format(dpi_status))

				server_type = serverType()
				log_file_logger.info('Collected Server Type: {}'.format(server_type))

				vbond_info, vsmart_info = vbondvmartInfo(controllers_info)
				vbond_count = len(vbond_info)
				vsmart_count = len(vsmart_info)
				log_file_logger.info('vSmart info: {}'.format(vbond_info))
				log_file_logger.info('vBond info: {}'.format(vsmart_info))

				total_devices = len(controllers_info) + vedge_count
				log_file_logger.info('Total devices: {}'.format(total_devices))

			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error Collecting Preliminary Data. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				
			print('*Starting Checks, this may take several minutes\n\n')

			#Critical Checks
			critical_checks = {}
			log_file_logger.info('*** Performing Critical Checks\n')

			#Begining #30:Check:Cluster:Intercluster communication  in the background
			if cluster_size>1:
				log_file_logger.info('Beginging #`31:Check:Cluster:Intercluster communication  in the background')
				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port))
					criticalCheckseventeen =  criticalCheckseventeen(cluster_health_data,  system_ip, log_file_logger)
				except Exception as e:
					log_file_logger.exception('{}\n'.format(e))


			#01:Check:vManage:Validate current version
			print(' #01:Checking:vManage:Validate current version')
			log_file_logger.info('#01:Check:vManage:Validate current version')
			writeFile(report_file, '#01:Check:vManage:Validate current version\n\n')
				
			try:
				boot_partition_size, check_result, check_analysis, check_action =  criticalCheckone(version)
				if check_result == 'Failed':
					critical_checks['#01:Check:vManage:Validate current version'] = [ check_analysis, check_action]

					log_file_logger.error('#01: Check result:   {}'.format(check_result))
					log_file_logger.error('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#01: version: {}'.format(version))
					log_file_logger.error('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n'.format(check_action))

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#01: Check result:   {}'.format(check_result))
					log_file_logger.info('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#01: version: {}'.format(version))
					log_file_logger.info('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
			
					print(' INFO: {}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #01:Checking:vManage:Validate current version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#02:Check:vManage:At minimum 20%  server disk space should be available
			print(' #02:Checking:vManage:vManage sever disk space')
			log_file_logger.info('#02:Check:vManage:At minimum 20%  server disk space should be available')
			writeFile(report_file, '#02:Check:vManage:At minimum 20%  server disk space should be available\n\n')

			try:
				optdata_partition_size, rootfs_partition_size, check_result, check_analysis, check_action =  criticalCheckTwo()
				if check_result == 'Failed': 
					critical_checks['#02:Check:vManage:At minimum 20%  server disk space should be available'] = [check_analysis, check_action]

					log_file_logger.error('#02: Check result:   {}'.format(check_result))
					log_file_logger.error('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.error('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#02: Check result:   {}'.format(check_result))
					log_file_logger.info('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.info('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #02:Check:vManage:At minimum 20%  server disk space should be available. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
			
			#03:Check:vManage:Memory size
			print(' #03:Checking:vManage:Memory size')
			log_file_logger.info('#03:Check:vManage:Memory size')
			writeFile(report_file, '#03:Check:vManage:Memory size\n')
			writeFile(report_file, 'Link to the official documentation: \n https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html\n\n')

			try:
				memory_size, memory_size_str, dpi_status, server_type, check_result, check_analysis, check_action =  criticalCheckthree(vedge_count, dpi_status, server_type, cluster_size, version_tuple)
				if check_result == 'Failed':
					critical_checks['#03:Check:vManage:Memory size'] = [ check_analysis, check_action]

					log_file_logger.error('#03: Check result:   {}'.format(check_result))
					log_file_logger.error('#03: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#03: Memory Size GB: {}'.format(memory_size_str))
					log_file_logger.error('#03: /rootfs.rw Used: {}'.format(rootfs_partition_size))
					log_file_logger.error('#03: Server Type: {}'.format(server_type))
					log_file_logger.error('#03: vEdge Count: {}\n'.format(vedge_count))

					writeFile(report_file, 'Result: ERROR - {}\n '.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
		 
				else:
					log_file_logger.info('#03: Check result:   {}'.format(check_result))
					log_file_logger.info('#03: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
			
					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #03:Check:vManage:Memory size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#04:Check:vManage:CPU Count
			print(' #04:Checking:vManage:CPU Count')
			log_file_logger.info('#04:Check:vManage:CPU Count')
			writeFile(report_file, '#04:Check:vManage:CPU Count\n\n')

			try:
				check_result, check_analysis, check_action = criticalCheckfour(cpu_count, vedge_count, dpi_status, server_type)
				if check_result == 'Failed':
					critical_checks['#04:Check:vManage:CPU Count'] = [ check_analysis, check_action]

					log_file_logger.error('#04: Check result:   {}'.format(check_result))
					log_file_logger.error('#04: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#04: CPU Count: {}\n'.format(cpu_count))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#04: Check result:   {}'.format(check_result))
					log_file_logger.info('#04: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #04:Check:vManage:CPU Count. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#05:Check:vManage:ElasticSearch Indices status
			print(' #05:Checking:vManage:ElasticSearch Indices status')
			log_file_logger.info('#05:Check:vManage:ElasticSearch Indices status')
			writeFile(report_file, '#05:Check:vManage:ElasticSearch Indices status\n\n')

			try:
				es_indexes_one = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/info', args.vmanage_port))
				es_index_red_one, check_result_one, check_analysis_one, check_action_one = criticalCheckfive(es_indexes_one)

				time.sleep(5)

				es_indexes_two = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/info', args.vmanage_port))
				es_index_red_two, check_result_two, check_analysis_two, check_action_two = criticalCheckfive(es_indexes_two)


				if check_result_one == 'Failed' and check_result_two == 'Failed':
					critical_checks['#05:Check:vManage:ElasticSearch Indices status'] = [ check_analysis_two, check_action_two]

					log_file_logger.error('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.error('#05: Check Analysis: {}\n'.format(check_analysis_two))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis_two))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action_two))
					
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis_two))

				elif check_result_one == 'SUCCESSFUL':
					log_file_logger.info('#05: Check result:   {}'.format(check_result_one))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_one))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_one))

					print(' INFO:{}\n\n'.format(check_analysis_one))

				elif check_result_two == 'SUCCESSFUL':

					log_file_logger.info('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_two))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_two))

					print(' INFO:{}\n\n'.format(check_analysis_two))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #05:Check:vManage:ElasticSearch Indices status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#06:Check:vManage:Look for any neo4j exception errors
			print(' #06:Checking:vManage:Look for any neo4j exception errors')
			log_file_logger.info('#06:Check:vManage:Look for any neo4j exception errors')
			writeFile(report_file, '#06:Check:vManage:Look for any neo4j exception errors\n\n')

			try:
				check_result, check_analysis, check_action = criticalChecksix()
				if check_result == 'Failed':
					critical_checks['#06:Check:vManage:Look for any neo4j exception errors'] = [check_analysis, check_action]

					log_file_logger.error('#06: Check result:   {}'.format(check_result))
					log_file_logger.error('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#06: Check result:   {}'.format(check_result))
					log_file_logger.info('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))
			except Exception as e:
				print('\033[1;31m ERROR: Error performing  #06:Check:vManage:Look for any neo4j exception errors. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#07:Check:vManage:Validate all services are up
			print(' #07:Checking:vManage:Validate all services are up')
			log_file_logger.info('#07:Check:vManage:Validate all services are up')
			writeFile(report_file, '#07:Check:vManage:Validate all services are up\n\n')

			try:
				nms_data, nms_failed, check_result, check_analysis, check_action =   criticalCheckseven() 
				if check_result == 'Failed':
					critical_checks['#07:Check:vManage:Validate all services are up'] = [check_analysis, check_action]

					log_file_logger.error('#07: Check result:   {}'.format(check_result))
					log_file_logger.error('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#07: List of services that are enabled but not running:\n{}'.format(nms_failed))
					log_file_logger.error('#07: Status of all services  :\n{}\n'.format(nms_data))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#07: Check result:   {}'.format(check_result))
					log_file_logger.info('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#07: Status of all the services:\n{}\n'.format(nms_data))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #07:Check:vManage:Validate all services are up. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#08:Check:vManage:Elasticsearch Indices version
			print(' #08:Checking:vManage:Elasticsearch Indices version')
			log_file_logger.info('#08:Check:vManage:Elasticsearch Indices version')
			writeFile(report_file, '#08:Check:vManage:Elasticsearch Indices version\n\n')

			try:
				version_list, check_result, check_analysis, check_action = criticalCheckeight(version_tuple)
				if check_result == 'Failed':
					critical_checks['#08:Check:vManage:Elasticsearch Indices version'] = [ check_analysis, check_action]

					log_file_logger.error('#08: Check result:   {}'.format(check_result))
					log_file_logger.error('#08: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#08: List of indices with older versions  :\n{}\n'.format(version_list))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
			 

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#08: Check result:   {}'.format(check_result))
					log_file_logger.info('#08: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #08:Check:vManage:Elasticsearch Indices version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#09:Check:vManage:Evaluate incoming DPI data size
			print(' #09:Checking:vManage:Evaluate incoming DPI data size')
			log_file_logger.info('#09:Check:vManage:Evaluate incoming DPI data size')
			writeFile(report_file, '#09:Check:vManage:Evaluate incoming DPI data size\n\n')

			try:
				es_indices_est = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/size/estimate', args.vmanage_port))
				appr_estimate_ondeday, dpi_estimate_ondeday, check_result,check_analysis,check_action = criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count, total_devices, dpi_status)
				if check_result == 'Failed':
					critical_checks['#09:Check:vManage:Evaluate incoming DPI data size'] = [ check_analysis, check_action]

					log_file_logger.error('#09: Check result:   {}'.format(check_result))
					log_file_logger.error('#09: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#09: Daily incoming DPI data : {}'.format(dpi_estimate_ondeday))
					log_file_logger.error('#09: Daily incoming Approute data : {}\n'.format(appr_estimate_ondeday))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#09: Check result:   {}'.format(check_result))
					log_file_logger.info('#09: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #09:Check:vManage:Evaluate incoming DPI data size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#10:Check:vManage:NTP status across network
			print(' #10:Checking:vManage:NTP status across network')
			log_file_logger.info('#10:Check:vManage:NTP status across network')
			writeFile(report_file, '#10:Check:vManage:NTP status across network\n\n')

			try:
				ntp_nonworking, check_result, check_analysis, check_action = criticalCheckten(version_tuple, controllers_info)
				if check_result == 'Failed':
					critical_checks['#10:Check:vManage:NTP status across network'] = [ check_analysis, check_action]

					log_file_logger.error('#10: Check result:   {}'.format(check_result))
					log_file_logger.error('#10: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#10: Devices with invalid ntp associations: \n{}\n'.format(ntp_nonworking))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#10: Check result:   {}'.format(check_result))
					log_file_logger.info('#10: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #10:Check:vManage:NTP status across network. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file.  \033[0;0m \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#11:Check:Controllers:Validate vSmart/vBond CPU count for scale
			print(' #11:Checking:Controllers:Validate vSmart/vBond CPU count for scale')
			log_file_logger.info('#11:Check:Controllers:Validate vSmart/vBond CPU count for scale')
			writeFile(report_file, '#11:Check:Controllers:Validate vSmart/vBond CPU count for scale\n\n')
			
			try:
				for vbond in vbond_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip, jsessionid,'device/system/synced/status?deviceId={}'.format(vbond_info[vbond][1]),args.vmanage_port ))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vbond_info[vbond].append(total_cpu_count)

				for vsmart in vsmart_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip, jsessionid,'device/system/synced/status?deviceId={}'.format(vsmart_info[vsmart][1]), args.vmanage_port))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vsmart_info[vsmart].append(total_cpu_count)

				failed_vbonds,failed_vsmarts,check_result,check_analysis, check_action = criticalCheckeleven(total_devices, vbond_info, vsmart_info)
				if check_result == 'Failed':
					critical_checks['#11:Check:Controllers:Validate vSmart/vBond CPU count for scale'] = [ check_analysis, check_action]

					log_file_logger.error('#11: Check result:   {}'.format(check_result))
					log_file_logger.error('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#11: vBonds with insufficient CPU count: \n{}'.format(failed_vbonds))
					log_file_logger.error('#11: vSmarts with insufficient CPU count: \n{}'.format(failed_vsmarts))
					log_file_logger.error('#11: All vBonds info with total_cpu_count: \n{}'.format(vbond_info))
					log_file_logger.error('#11: All vSmarts info with total_cpu_count: \n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#11: Check result:   {}'.format(check_result))
					log_file_logger.info('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#11: All vBonds info with total_cpu_count: \n{}'.format(vbond_info))
					log_file_logger.info('#11: ll vSmarts info with total_cpu_count: \n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #11:Check:Controllers:Validate vSmart/vBond CPU count for scale. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
			
			#Warning Checks
			print('\n**** Performing Warning checks\n') 
			warning_checks = {}
			log_file_logger.info('*** Performing Warning Checks')

			#12:Check:vManage:CPU Speed
			print(' #12:Checking:vManage:CPU Speed')
			log_file_logger.info('#12:Check:vManage:CPU Speed')
			writeFile(report_file, '#12:Check:vManage:CPU Speed\n\n')

			try:
				check_result,check_analysis,check_action = warningCheckone(cpu_speed)
				if check_result == 'Failed':
					warning_checks['#12:Check:vManage:CPU Speed'] = [ check_analysis, check_action]

					log_file_logger.error('#12: Check result:   {}'.format(check_result))
					log_file_logger.error('#12: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#12: CPU clock speed: {}\n'.format(cpu_speed))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Result: INFO - Check Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#12: Check result:   {}'.format(check_result))
					log_file_logger.info('#12: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #12:Check:vManage:CPU Speed. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#13:Check:vManage:Network Card type
			print(' #13:Checking:vManage:Network Card type')
			log_file_logger.info('#13:Check:vManage:Network Card type')
			writeFile(report_file, '#13:Check:vManage:Network Card type\n\n')

			try:
				eth_drivers, check_action, check_analysis, check_result = warningChecktwo()
				if check_result == 'Failed':
					warning_checks['#13:Check:vManage:Network Card type'] = [ check_analysis, check_action]

					log_file_logger.error('#13: Check result:   {}'.format(check_result))
					log_file_logger.error('#13: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#13: Ethercardswith e1000 card types: {}\n'.format(eth_drivers))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
			 

					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#13: Check result:   {}'.format(check_result))
					log_file_logger.info('#13: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #13:Check:vManage:Network Card type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#14:Check:vManage:Backup status
			print(' #14:Checking:vManage:Backup status')
			log_file_logger.info('#14:Check:vManage:Backup status')
			writeFile(report_file, '#14:Check:vManage:Backup status\n\n')

			try:
				date_time_obj, check_result, check_analysis, check_action = warningCheckthree()
				if check_result == 'Failed':
					warning_checks['#14:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#14: Check result:   {}'.format(check_result))
					log_file_logger.error('#14: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#14: Last Backup was performed on: {}\n'.format(date_time_obj))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#14: Check result:   {}'.format(check_result))
					log_file_logger.info('#14: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #14:Check:vManage:Backup status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#15:Check:vManage:Evaluate Neo4j performance
			print(' #15:Checking:vManage:Evaluate Neo4j performance')
			log_file_logger.info('#15:Check:vManage:Evaluate Neo4j performance')
			writeFile(report_file, '#15:Check:vManage:Evaluate Neo4j performance\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckfour()
				if check_result == 'Failed':
					warning_checks['#15:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#15: Check result:   {}'.format(check_result))
					log_file_logger.error('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#15: Check result:   {}'.format(check_result))
					log_file_logger.info('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #15:Check:vManage:Evaluate Neo4j performance. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#16:Check:vManage:Confirm there are no pending tasks
			print(' #16:Checking:vManage:Confirm there are no pending tasks')
			log_file_logger.info('#16:Check:vManage:Confirm there are no pending tasks')
			writeFile(report_file, '#16:Check:vManage:Confirm there are no pending tasks\n\n')

			try:
				tasks = json.loads(getRequest(version_tuple,vmanage_lo_ip,  jsessionid,'device/action/status/tasks', args.vmanage_port))
				tasks_running, check_result, check_analysis, check_action  = warningCheckfive(tasks)
				if check_result == 'Failed':
					warning_checks['#16:Check:vManage:Confirm there are no pending tasks'] = [ check_analysis, check_action]
					log_file_logger.error('#16: Check result:   {}'.format(check_result))
					log_file_logger.error('#16: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#16: Tasks still running: {}\n'.format(tasks_running))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#16: Check result:   {}'.format(check_result))
					log_file_logger.info('#16: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #16:Check:vManage:Confirm there are no pending tasks. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#17:Check:vManage:Validate there are no empty password users
			print(' #17:Checking:vManage:Validate there are no empty password users')
			log_file_logger.info('#17:Check:vManage:Validate there are no empty password users')
			writeFile(report_file, '#17:Check:vManage:Validate there are no empty password users\n\n')
			
			try:
				users_emptypass, check_result, check_analysis, check_action = warningChecksix(version_tuple)
				if check_result == 'Failed':
					warning_checks['#17:Check:vManage:Validate there are no empty password users'] = [ check_analysis, check_action]
					log_file_logger.error('#17: Check result:   {}'.format(check_result))
					log_file_logger.error('#17: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#17: Users with empty passwords: {}\n'.format(users_emptypass))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#17: Check result:   {}'.format(check_result))
					log_file_logger.info('#17: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #17:Check:vManage:Validate there are no empty password users. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))
			
			#18:Check:Controllers:Controller versions
			print(' #18:Checking:Controllers:Controller versions')
			log_file_logger.info('#18:Check:Controllers:Controller versions')
			writeFile(report_file, '#18:Check:Controllers:Controller versions\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckseven(controllers_info)
				if check_result == 'Failed':
					warning_checks['18:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#18: Check result:   {}'.format(check_result))
					log_file_logger.error('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#18: Check result:   {}'.format(check_result))
					log_file_logger.info('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #18:Check:Controllers:Controller versions. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#19:Check:Controllers:Confirm Certificate Expiration Dates
			print(' #19:Checking:Controllers:Confirm Certificate Expiration Dates')
			log_file_logger.info('#19:Check:Controllers:Confirm Certificate Expiration Dates')
			writeFile(report_file, '#19:Check:Controllers:Confirm Certificate Expiration Dates\n\n')

			try:
				controllers_exp, controllers_notexp, check_result, check_analysis, check_action = warningCheckeight(controllers_info)
				if check_result == 'Failed':
					warning_checks['#19:Check:Controllers:Confirm Certificate Expiration Dates'] = [ check_analysis, check_action]
					log_file_logger.error('#19: Check result:   {}'.format(check_result))
					log_file_logger.error('#19: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#19: Controllers with certificates close to expiration:\n{}\n'.format(controllers_exp))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#19: Check result:   {}'.format(check_result))
					log_file_logger.info('#19: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #19:Check:Controllers:Confirm Certificate Expiration Dates. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#20:Check:Controllers:vEdge list sync
			print(' #20:Checking:Controllers:vEdge list sync')
			log_file_logger.info('#20:Check:Controllers:vEdge list sync')
			writeFile(report_file, '#20:Check:Controllers:vEdge list sync\n\n')

			try:
				state_vedgeList,check_result, check_analysis, check_action  = warningChecknine(controllers_info)
				if check_result == 'Failed':
					warning_checks['#20:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#20: Check result:   {}'.format(check_result))
					log_file_logger.error('#20: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#20: Controllers with inconsistent state_vedgeList: {}\n'.format(state_vedgeList))
					
					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#20: Check result:   {}'.format(check_result))
					log_file_logger.info('#20: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #20:Check:Controllers:vEdge list sync. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#21:Check:Controllers: Confirm control connections
			print(' #21:Checking:Controllers: Confirm control connections')
			log_file_logger.info('#21:Check:Controllers: Confirm control connections')
			writeFile(report_file, '#21:Check:Controllers: Confirm control connections\n\n')

			try:
				control_sum_tab, discrepancy,check_result, check_analysis, check_action = warningCheckten(vsmart_count, vbond_count)
				if check_result == 'Failed':
					warning_checks['#21:Check:Controllers: Confirm control connections'] = [ check_analysis, check_action]

					log_file_logger.error('#21: Check result:   {}'.format(check_result))
					log_file_logger.error('#21: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#21: Control  Connections Summary: \n{}\n'.format(control_sum_tab))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#21: Check result:   {}'.format(check_result))
					log_file_logger.info('#21: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #21:Check:Controllers: Confirm control connections. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Informational Checks
			print('\n**** Performing Informational checks\n' )
			log_file_logger.info('*** Performing Informational Checks')

			#22:Check:vManage:Disk controller type
			print(' #22:Check:vManage:Disk controller type')
			log_file_logger.info('#22:Check:vManage:Disk controller type')
			writeFile(report_file, '#22:Check:vManage:Disk controller type\n\n')

			try:
				check_result, check_analysis, check_action = infoCheckone(server_type, disk_controller)
				if check_result == 'Failed':
					warning_checks['#22:Check:vManage:Disk controller type'] = [ check_analysis, check_action]

					log_file_logger.error('#22: Check result:   {}'.format(check_result))
					log_file_logger.error('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#22: Check result:   {}'.format(check_result))
					log_file_logger.info('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #22:Check:vManage:Disk controller type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#23:Check:Controllers:Validate there is at minimum vBond, vSmart present
			print(' #23:Check:Controllers:Validate there is at minimum vBond, vSmart present ')
			log_file_logger.info('#23:Check:Controllers:Validate there is at minimum vBond, vSmart present')
			writeFile(report_file, '#23:Check:Controllers:Validate there is at minimum vBond, vSmart present\n\n')
			
			try:
				check_result, check_analysis, check_action = infoChecktwo(vsmart_count,vbond_count)
				if check_result == 'Failed':
					warning_checks['#23:Check:Controllers:Validate there is at minimum vBond, vSmart present'] = [ check_analysis, check_action]

					log_file_logger.error('#23: Check result:   {}'.format(check_result))
					log_file_logger.error('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.error('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#23: Check result:   {}'.format(check_result))
					log_file_logger.info('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.info('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #23:Check:Controllers:Validate there is at minimum vBond, vSmart present. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#24:Check:Controllers:Validate all controllers are reachable
			print(' #24:Check:Controllers:Validate all controllers are reachable')
			log_file_logger.info('#24:Check:Controllers:Validate all controllers are reachable')
			writeFile(report_file, '#24:Check:Controllers:Validate all controllers are reachable\n\n')
			
			try:
				unreach_controllers,check_result, check_analysis, check_action = infoChecktthree(controllers_info)
				if check_result == 'Failed':
					warning_checks['#24:Check:Controllers:Validate all controllers are reachable'] = [ check_analysis, check_action]

					log_file_logger.error('#24: Check result:   {}'.format(check_result))
					log_file_logger.error('#24: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#24: Unreachable Controllers: {}\n'.format(unreach_controllers))


					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				   
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#24: Check result:   {}'.format(check_result))
					log_file_logger.info('#24: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #24:Check:Controllers:Validate all controllers are reachable. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			if cluster_size>1:
				cluster_checks = {}

				log_file_logger.info('*** Performing Cluster Checks')
				print('\n**** Performing Cluster checks\n')

				#25:Check:Cluster:Version consistency
				print(' #25:Checking:Cluster:Version consistency')
				log_file_logger.info('#25:Check:Cluster:Version consistency')
				writeFile(report_file, '#25:Check:Cluster:Version consistency\n\n')

				try:
					check_result,check_analysis, check_action = criticalChecktwelve(vmanage_info)
					if check_result == 'Failed':
						cluster_checks['#25:Check:Cluster:Version consistency'] = [ check_analysis, check_action]

						log_file_logger.error('#25: Check result:   {}'.format(check_result))
						log_file_logger.error('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
						
						print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

					else:
						log_file_logger.info('#25: Check result:   {}'.format(check_result))
						log_file_logger.info('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						
						print(' INFO:{}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #25:Check:Cluster:Version consistency. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#26:Check:Cluster:Cluster health
				print(' #26:Checking:Cluster:Cluster health')
				log_file_logger.info('#26:Check:Cluster:Cluster health')
				writeFile(report_file, '#26:Check:Cluster:Cluster health\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port))
					services_down, check_result, check_analysis, check_action = criticalCheckthirteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#26:Check:Cluster:Cluster health'] = [ check_analysis, check_action]

						log_file_logger.error('#26: Check result:   {}'.format(check_result))
						log_file_logger.error('#26: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#26: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					   
						print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

					else: 
						log_file_logger.info('#26: Check result:   {}'.format(check_result))
						log_file_logger.info('#26: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

						print(' INFO:{}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #26:Check:Cluster:Cluster health. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))



				#27:Check:Cluster:Cluster ConfigDB topology
				print(' #27:Checking:Cluster:Cluster ConfigDB topology')
				log_file_logger.info('#27:Check:Cluster:Cluster ConfigDB topology')
				writeFile(report_file, '#27:Check:Cluster:Cluster ConfigDB topology\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'clusterManagement/list', args.vmanage_port))           
					configDB_count, check_result, check_analysis, check_action = criticalCheckfourteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#27:Check:Cluster:Cluster ConfigDB topology'] = [ check_analysis, check_action]

						log_file_logger.error('#27: Check result:   {}'.format(check_result))
						log_file_logger.error('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

						print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

					else: 
						log_file_logger.info('#27: Check result:   {}'.format(check_result))
						log_file_logger.info('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

						print(' INFO:{}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #27:Check:Cluster:Cluster ConfigDB topology. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#28:Check:Cluster:Messaging server
				print(' #28:Checking:Cluster:Messaging server')
				log_file_logger.info('#28:Check:Cluster:Messaging server')
				writeFile(report_file, '#28:Check:Cluster:Messaging server\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port))           
					cluster_msdown,check_result,check_analysis, check_action = criticalCheckfifteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#28:Check:Cluster:Messaging server'] = [ check_analysis, check_action]

						log_file_logger.error('#28: Check result:   {}'.format(check_result))
						log_file_logger.error('#28: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#28: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
						

						print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

					else: 
						log_file_logger.info('#28: Check result:   {}'.format(check_result))
						log_file_logger.info('#28: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

						print(' INFO:{}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #28:Check:Cluster:Messaging server. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

					
				#29:Check:Cluster:DR replication status
				print(' #29:Checking:Cluster:DR replication status')
				log_file_logger.info('#29:Check:Cluster:DR replication status')
				writeFile(report_file, '#29:Check:Cluster:DR replication status\n\n')

				try:
					dr_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'disasterrecovery/details', args.vmanage_port))           
					dr_status, check_action, check_analysis, check_result = criticalChecksixteen(dr_data)
					if check_result == 'Failed':
						cluster_checks['#29:Check:Cluster:DR replication status'] = [ check_analysis, check_action]

						log_file_logger.error('#29: Check result:   {}'.format(check_result))
						log_file_logger.error('#29: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#29: DR Replication status: {}\n'.format(dr_status))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

						print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

					else:
						log_file_logger.info('#29: Check result:   {}'.format(check_result))
						log_file_logger.info('#29: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

						print(' INFO:{}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #29:Check:Cluster:DR replication status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#30:Check:Cluster:Intercluster communication
				print(' #30:Checking:Cluster:Intercluster communication')
				log_file_logger.info('#30:Check:Cluster:Intercluster communication')
				writeFile(report_file, '#30:Check:Cluster:Intercluster communication\n\n')
				
				try:
					if criticalCheckseventeen.isAlive():
						criticalCheckseventeen.join(10)

					if not criticalCheckseventeen.result_queue.empty():
						ping_output, ping_output_failed, ping_check_result, ping_check_analysis, ping_check_action = criticalCheckseventeen.result_queue.get()
						if ping_check_result == 'Failed':
							cluster_checks['#30:Check:Cluster:Intercluster communication'] = [ ping_check_analysis, ping_check_action]

							log_file_logger.error('#30:Check result: {}'.format(ping_check_result))
							log_file_logger.error('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.error('#30: Cluster nodes with ping failure: {}\n'.format(ping_output_failed))

							writeFile(report_file, 'Result: ERROR - {}\n'.format(ping_check_analysis))
							writeFile(report_file, 'Action: {}\n\n'.format(ping_check_action))

							print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

						else:
							log_file_logger.info('#30:Check result: {}'.format(ping_check_result))
							log_file_logger.info('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.info('#30: Cluster nodes details: {}\n'.format(ping_output))

							writeFile(report_file, 'Result: INFO - {}\n\n'.format(ping_check_analysis))

							print(' INFO:{}\n\n'.format(ping_check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #30:Check:Cluster:Intercluster communication. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


			#Logging out of the Session using jsessionid
			log_file_logger.info('Logging out of the Session')
			sessionLogout(vmanage_lo_ip, jsessionid, args.vmanage_port)
			log_file_logger.info('Successfully closed the connection')
			
		#version above 19.2 and less than 20.5
		elif version_tuple[0:2] >= ('19','2') and version_tuple[0:2] < ('20','5'):
			try:
				log_file_logger.info('Generating a JSessionID')
				jsessionid = generateSessionID(vmanage_lo_ip, args.username, password, args.vmanage_port)
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error generating JSessionID, make sure that the username and password entered is correct. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))

			try:
				log_file_logger.info('Generating CSRF Token')
				tokenid = CSRFToken(vmanage_lo_ip,jsessionid,args.vmanage_port)
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error generating CSRF Token. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file.  \033[0;0m \n\n'.format(log_file_path))


			#Preliminary data
			log_file_logger.info('****Collecting Preliminary Data\n')
			print ('****Collecting Preliminary Data\n')

			try:
				controllers = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'system/device/controllers', args.vmanage_port, tokenid))
				controllers_info = controllersInfo(controllers)
				log_file_logger.info('Collected controllers information: {}'.format(controllers_info))

				system_ip_data = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'device/vmanage', args.vmanage_port, tokenid))
				system_ip = system_ip_data['data']['ipAddress']
				#system_ip = controllers_info[hostname][1]
				log_file_logger.info('Collected vManage System IP address: {}'.format(system_ip))

				cpu_speed = cpuSpeed()
				log_file_logger.info('Collected vManage CPU Speed GHz: {}'.format(cpu_speed))

				cpu_count = cpuCount()
				log_file_logger.info('Collected vManage CPU Count: {}'.format(cpu_count))

				vedges = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'system/device/vedges', args.vmanage_port , tokenid))
				vedge_count,vedge_count_active, vedge_info = vedgeCount(vedges)
				log_file_logger.info('Collected  xEdge Count: {}'.format(vedge_count))

				cluster_size, server_mode, vmanage_info = serverMode(controllers_info)
				log_file_logger.info('Collected vManage Cluster Size: {}'.format(cluster_size))
				log_file_logger.info('Collected vManage Server Mode: {}'.format(server_mode))

				disk_controller = diskController()
				log_file_logger.info('Collected vManage Disk Controller Type: {}'.format(disk_controller))

				dpi_stats = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'statistics/settings/status', args.vmanage_port, tokenid))
				dpi_status = dpiStatus(dpi_stats)
				log_file_logger.info('Collected DPI Status: {}'.format(dpi_status))

				server_type = serverType()
				log_file_logger.info('Collected Server Type: {}'.format(server_type))

				vbond_info, vsmart_info = vbondvmartInfo(controllers_info)
				vbond_count = len(vbond_info)
				vsmart_count = len(vsmart_info)
				log_file_logger.info('vSmart info: {}'.format(vbond_info))
				log_file_logger.info('vBond info: {}'.format(vsmart_info))
				

				total_devices = len(controllers_info.keys()) + vedge_count
				log_file_logger.info('Total devices: {}'.format(total_devices))

			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error Collecting Preliminary Data. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				

			print('*Starting Checks, this may take several minutes\n\n')

			#Critical Checks
			print('\n**** Performing Critical checks\n')

			#Begining 17:Check:Cluster:Intercluster communication  in the background
			if cluster_size>1:
				log_file_logger.info('Beginging #30:Check:Cluster:Intercluster communication  in the background\n')
				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))
					criticalCheckseventeen =  criticalCheckseventeen(cluster_health_data,  system_ip, log_file_logger)
				except Exception as e:
					log_file_logger.exception('{}\n'.format(e))

			critical_checks = {}
			log_file_logger.info('*** Performing Critical Checks\n')

			#01:Check:vManage:Validate current version
			print(' #01:Checking:vManage:Validate current version')
			log_file_logger.info('#01:Check:vManage:Validate current version')
			writeFile(report_file, '#01:Check:vManage:Validate current version\n\n')
			
			try:
				boot_partition_size, check_result, check_analysis, check_action =  criticalCheckone(version)
				if check_result == 'Failed':
					critical_checks['#01:Check:vManage:Validate current version'] = [ check_analysis, check_action]

					log_file_logger.error('#01: Check result:   {}'.format(check_result))
					log_file_logger.error('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#01: version: {}'.format(version))
					log_file_logger.error('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#01: Check result:   {}'.format(check_result))
					log_file_logger.info('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#01: version: {}'.format(version))
					log_file_logger.info('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
				   
					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #01:Check:vManage:Validate current version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#02:Check:vManage:At minimum 20%  server disk space should be available
			print(' #02:Checking:vManage:vManage sever disk space')
			log_file_logger.info('#02:Check:vManage:At minimum 20%  server disk space should be available')
			writeFile(report_file, '#02:Check:vManage:At minimum 20%  server disk space should be available\n\n')

			try:
				optdata_partition_size, rootfs_partition_size, check_result, check_analysis, check_action =  criticalCheckTwo()
				if check_result == 'Failed': 
					critical_checks['#02:Check:vManage:At minimum 20%  server disk space should be available'] = [check_analysis, check_action]

					log_file_logger.error('#02: Check result:   {}'.format(check_result))
					log_file_logger.error('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.error('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#02: Check result:   {}'.format(check_result))
					log_file_logger.info('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.info('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #02:Check:vManage:At minimum 20%  server disk space should be available. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#03:Check:vManage:Memory size
			print(' #03:Checking:vManage:Memory size')
			log_file_logger.info('#03:Check:vManage:Memory size')
			writeFile(report_file, '#03:Check:vManage:Memory size\n')
			writeFile(report_file, 'Link to the official documentation: \n https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html\n\n')

			try:
				memory_size, memory_size_str, dpi_status, server_type, check_result, check_analysis, check_action =  criticalCheckthree(vedge_count, dpi_status, server_type, cluster_size, version_tuple)
				if check_result == 'Failed':
					critical_checks['#03:Check:vManage:vManage sever disk space'] = [ check_analysis, check_action]

					log_file_logger.error('#03: Check result:   {}'.format(check_result))
					log_file_logger.error('#03: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#03: Memory Size GB: {}'.format(memory_size_str))
					log_file_logger.error('#03: /rootfs.rw Used: {}'.format(rootfs_partition_size))
					log_file_logger.error('#03: Server Type: {}'.format(server_type))
					log_file_logger.error('#03: vEdge Count: {}\n'.format(vedge_count))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#03: Check result:   {}'.format(check_result))
					log_file_logger.info('#03: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #03:Check:vManage:Memory size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#04:Check:vManage:CPU Count
			print(' #04:Checking:vManage:CPU Count')
			log_file_logger.info('#04:Check:vManage:CPU Count')
			writeFile(report_file, '#04:Check:vManage:CPU Count\n\n')

			try:
				check_result, check_analysis, check_action = criticalCheckfour(cpu_count, vedge_count, dpi_status, server_type)
				if check_result == 'Failed':
					critical_checks['#04:Check:vManage:CPU Count'] = [ check_analysis, check_action]

					log_file_logger.error('#04: Check result:   {}'.format(check_result))
					log_file_logger.error('#04: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#04: CPU Count: {}\n'.format(cpu_count))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#04: Check result:   {}'.format(check_result))
					log_file_logger.info('#04: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #04:Check:vManage:CPU Count. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#05:Check:vManage:ElasticSearch Indices status
			print(' #05:Checking:vManage:ElasticSearch Indices status')
			log_file_logger.info('#05:Check:vManage:ElasticSearch Indices status')
			writeFile(report_file, '#05:Check:vManage:ElasticSearch Indices status\n\n')

			try:
				es_indexes_one = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_index_red_one, check_result_one, check_analysis_one, check_action_one = criticalCheckfive(es_indexes_one)

				time.sleep(5)

				es_indexes_two = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_index_red_two, check_result_two, check_analysis_two, check_action_two = criticalCheckfive(es_indexes_two)

				if check_result_one == 'Failed' and check_result_two == 'Failed':
					critical_checks['#05:Check:vManage:ElasticSearch Indices status'] = [ check_analysis_two, check_action_two]

					log_file_logger.error('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.error('#05: Check Analysis: {}\n'.format(check_analysis_two))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis_two))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action_two))
					
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis_two))

				elif check_result_one == 'SUCCESSFUL':
					log_file_logger.info('#05: Check result:   {}'.format(check_result_one))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_one))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_one))

					print(' INFO:{}\n\n'.format(check_analysis_one))

				elif check_result_two == 'SUCCESSFUL':

					log_file_logger.info('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_two))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_two))

					print(' INFO:{}\n\n'.format(check_analysis_two))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #05:Check:vManage:ElasticSearch Indices status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#06:Check:vManage:Look for any neo4j exception errors
			print(' #06:Checking:vManage:Look for any neo4j exception errors')
			log_file_logger.info('#06:Check:vManage:Look for any neo4j exception errors')
			writeFile(report_file, '#06:Check:vManage:Look for any neo4j exception errors\n\n')

			try:
				check_result, check_analysis, check_action = criticalChecksix()
				if check_result == 'Failed':
					critical_checks['#06:Check:vManage:Look for any neo4j exception errors'] = [check_analysis, check_action]

					log_file_logger.error('#06: Check result:   {}'.format(check_result))
					log_file_logger.error('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#06: Check result:   {}'.format(check_result))
					log_file_logger.info('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #06:Check:vManage:Look for any neo4j exception errors. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#07:Check:vManage:Validate all services are up
			print(' #07:Checking:vManage:Validate all services are up')
			log_file_logger.info('#07:Check:vManage:Validate all services are up')
			writeFile(report_file, '#07:Check:vManage:Validate all services are up\n\n')

			try:
				nms_data, nms_failed, check_result, check_analysis, check_action =   criticalCheckseven() 
				if check_result == 'Failed':
					critical_checks['#07:Check:vManage:Validate all services are up'] = [check_analysis, check_action]

					log_file_logger.error('#07: Check result:   {}'.format(check_result))
					log_file_logger.error('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#07: List of services that are enabled but not running:\n{}\n'.format(nms_failed))
					log_file_logger.error('#07: Status of all services  :\n{}\n'.format(nms_data))

					writeFile(report_file, 'Check Analysis: {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#07: Check result:   {}'.format(check_result))
					log_file_logger.info('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#07: Status of all the services:\n{}\n'.format(nms_data))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #07:Check:vManage:Validate all services are up. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#08:Check:vManage:Elasticsearch Indices version
			print(' #08:Checking:vManage:Elasticsearch Indices version')
			log_file_logger.info('#08:Check:vManage:Elasticsearch Indices version')
			writeFile(report_file, '#08:Check:vManage:Elasticsearch Indices version\n\n')

			try:
				version_list, check_result, check_analysis, check_action = criticalCheckeight(version_tuple)
				if check_result == 'Failed':
					critical_checks['#08:Check:vManage:Elasticsearch Indices version'] = [ check_analysis, check_action]

					log_file_logger.error('#08: Check result:   {}'.format(check_result))
					log_file_logger.error('#08: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#08: List of indices with older versions  :\n{}\n'.format(version_list))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#08: Check result:   {}'.format(check_result))
					log_file_logger.info('#08: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #08:Check:vManage:Elasticsearch Indices version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#09:Check:vManage:Evaluate incoming DPI data size
			print(' #09:Checking:vManage:Evaluate incoming DPI data size')
			log_file_logger.info('#09:Check:vManage:Evaluate incoming DPI data size')
			writeFile(report_file, '#09:Check:vManage:Evaluate incoming DPI data size\n\n')

			try:
				es_indices_est = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'management/elasticsearch/index/size/estimate', args.vmanage_port, tokenid))
				appr_estimate_ondeday, dpi_estimate_ondeday, check_result, check_analysis,check_action = criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count, total_devices, dpi_status)
				if check_result == 'Failed':
					critical_checks['#09:Check:vManage:Evaluate incoming DPI data size'] = [ check_analysis, check_action]

					log_file_logger.error('#09: Check result:   {}'.format(check_result))
					log_file_logger.error('#09: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#09: Daily incoming DPI data : {}'.format(dpi_estimate_ondeday))
					log_file_logger.error('#09: Daily incoming Approute data : {}\n'.format(appr_estimate_ondeday))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#09: Check result:   {}'.format(check_result))
					log_file_logger.info('#09: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #09:Check:vManage:Evaluate incoming DPI data size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#10:Check:vManage:NTP status across network
			print(' #10:Checking:vManage:NTP status across network')
			log_file_logger.info('#10:Check:vManage:NTP status across network')
			writeFile(report_file, '#10:Check:vManage:NTP status across network\n\n')

			try:
				ntp_nonworking, check_result, check_analysis, check_action = criticalCheckten(version_tuple, controllers_info)
				if check_result == 'Failed':
					critical_checks['#10:Check:vManage:NTP status across network'] = [ check_analysis, check_action]

					log_file_logger.error('#10: Check result:   {}'.format(check_result))
					log_file_logger.error('#10: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#10: Devices with invalid ntp associations: \n{}\n'.format(ntp_nonworking))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				   
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#10: Check result:   {}'.format(check_result))
					log_file_logger.info('#10: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #10:Check:vManage:NTP status across network. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#11:Check:Controllers:Validate vSmart/vBond CPU count for scale
			print(' #11:Checking:Controllers:Validate vSmart/vBond CPU count for scale')
			log_file_logger.info('#11:Check:Controllers:Validate vSmart/vBond CPU count for scale')
			writeFile(report_file, '#11:Check:Controllers:Validate vSmart/vBond CPU count for scale\n\n')

			try:
				for vbond in vbond_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip, jsessionid, 'device/system/synced/status?deviceId={}'.format(vbond_info[vbond][1]),args.vmanage_port, tokenid))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vbond_info[vbond].append(total_cpu_count)

				for vsmart in vsmart_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip,jsessionid, 'device/system/synced/status?deviceId={}'.format(vsmart_info[vsmart][1]),args.vmanage_port,tokenid))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vsmart_info[vsmart].append(total_cpu_count)

				failed_vbonds,failed_vsmarts,check_result,check_analysis, check_action = criticalCheckeleven(total_devices, vbond_info, vsmart_info)
				if check_result == 'Failed':
					critical_checks['#11:Check:Controllers:Validate vSmart/vBond CPU count for scale'] = [ check_analysis, check_action]

					log_file_logger.error('#11: Check result:   {}'.format(check_result))
					log_file_logger.error('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#11: vBonds with insufficient CPU count: \n{}'.format(failed_vbonds))
					log_file_logger.error('#11: vSmarts with insufficient CPU count: \n{}'.format(failed_vsmarts))
					log_file_logger.error('#11: All vBonds info with total_cpu_count: \n{}'.format(vbond_info))
					log_file_logger.error('#11: All vSmarts info with total_cpu_count: \n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#11: Check result:   {}'.format(check_result))
					log_file_logger.info('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#11: All vBonds info with total_cpu_count:  \n{}'.format(vbond_info))
					log_file_logger.info('#11: All vSmarts info with total_cpu_count: \n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #11:Check:Controllers:Validate vSmart/vBond CPU count for scale. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			
			#Warning Checks
			print('\n**** Performing Warning checks\n') 
			warning_checks = {}
			log_file_logger.info('*** Performing Warning Checks')

			#12:Check:vManage:CPU Speed
			print(' #12:Checking:vManage:CPU Speed')
			log_file_logger.info('#12:Check:vManage:CPU Speed')
			writeFile(report_file, '#12:Check:vManage:CPU Speed\n\n')

			try:
				check_result,check_analysis,check_action = warningCheckone(cpu_speed)
				if check_result == 'Failed':
					warning_checks['#12:Check:vManage:CPU Speed'] = [ check_analysis, check_action]

					log_file_logger.error('#12: Check result:   {}'.format(check_result))
					log_file_logger.error('#12: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#12: CPU clock speed: {}\n'.format(cpu_speed))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#12: Check result:   {}'.format(check_result))
					log_file_logger.info('#12: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #12:Check:vManage:CPU Speed. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#13:Check:vManage:Network Card type
			print(' #13:Checking:vManage:Network Card type')
			log_file_logger.info('#13:Check:vManage:Network Card type')
			writeFile(report_file, '#13:Check:vManage:Network Card type\n\n')

			try:
				eth_drivers, check_action, check_analysis, check_result = warningChecktwo()
				if check_result == 'Failed':
					warning_checks['#13:Check:vManage:Network Card type'] = [ check_analysis, check_action]

					log_file_logger.error('#13: Check result:   {}'.format(check_result))
					log_file_logger.error('#13: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#13: Ethercardswith e1000 card types: {}\n'.format(eth_drivers))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))               

					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#13: Check result:   {}'.format(check_result))
					log_file_logger.info('#13: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #13:Check:vManage:Network Card type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#14:Check:vManage:Backup status
			print(' #14:Checking:vManage:Backup status')
			log_file_logger.info('#14:Check:vManage:Backup status')
			writeFile(report_file, '#14:Check:vManage:Backup status\n\n')

			try:
				date_time_obj, check_result, check_analysis, check_action = warningCheckthree()
				if check_result == 'Failed':
					warning_checks['#14:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#14: Check result:   {}'.format(check_result))
					log_file_logger.error('#14: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#14: Last Backup was performed on:{}\n'.format(date_time_obj))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#14: Check result:   {}'.format(check_result))
					log_file_logger.info('#14: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #14:Check:vManage:Backup status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#15:Check:vManage:Evaluate Neo4j performance
			print(' #15:Checking:vManage:Evaluate Neo4j performance')
			log_file_logger.info('#15:Check:vManage:Evaluate Neo4j performance')
			writeFile(report_file, '#15:Check:vManage:Evaluate Neo4j performance\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckfour()
				if check_result == 'Failed':
					warning_checks['#15:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#15: Check result:   {}'.format(check_result))
					log_file_logger.error('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
					
				else:
					log_file_logger.info('#15: Check result:   {}'.format(check_result))
					log_file_logger.info('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #15:Check:vManage:Evaluate Neo4j performance. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#16:Check:vManage:Confirm there are no pending tasks
			print(' #16:Checking:vManage:Confirm there are no pending tasks')
			log_file_logger.info('#16:Check:vManage:Confirm there are no pending tasks')
			writeFile(report_file, '#16:Check:vManage:Confirm there are no pending tasks\n\n')

			try:
				tasks = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'device/action/status/tasks', args.vmanage_port, tokenid))
				tasks_running, check_result, check_analysis, check_action  = warningCheckfive(tasks)
				if check_result == 'Failed':
					warning_checks['#16:Check:vManage:Confirm there are no pending tasks'] = [ check_analysis, check_action]

					log_file_logger.error('#16: Check result:   {}'.format(check_result))
					log_file_logger.error('#16: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#16: Tasks still running: {}\n'.format(tasks_running))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#16: Check result:   {}'.format(check_result))
					log_file_logger.info('#16: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #16:Check:vManage:Confirm there are no pending tasks. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#17:Check:vManage:Validate there are no empty password users
			print(' #17:Checking:vManage:Validate there are no empty password users')
			log_file_logger.info('#17:Check:vManage:Validate there are no empty password users')
			writeFile(report_file, '#17:Check:vManage:Validate there are no empty password users\n\n')
			
			try:
				users_emptypass, check_result, check_analysis, check_action = warningChecksix(version_tuple)
				if check_result == 'Failed':
					warning_checks['#17:Check:vManage:Validate there are no empty password users'] = [ check_analysis, check_action]
					log_file_logger.error('#17: Check result:   {}'.format(check_result))
					log_file_logger.error('#17: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#17: Users with empty passwords: {}\n'.format(users_emptypass))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m \n\n '.format(check_analysis))

				else:
					log_file_logger.info('#17: Check result:   {}'.format(check_result))
					log_file_logger.info('#17: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))
				
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #17:Check:vManage:Validate there are no empty password users. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#18:Check:Controllers:Controller versions
			print(' #18:Checking:Controllers:Controller versions')
			log_file_logger.info('#18:Check:Controllers:Controller versions')
			writeFile(report_file, '#18:Check:Controllers:Controller versions\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckseven(controllers_info)
				if check_result == 'Failed':
					warning_checks['18:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#18: Check result:   {}'.format(check_result))
					log_file_logger.error('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
					
				else:
					log_file_logger.info('#18: Check result:   {}'.format(check_result))
					log_file_logger.info('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #18:Check:Controllers:Controller versions. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#19:Check:Controllers:Confirm Certificate Expiration Dates
			print(' #19:Checking:Controllers:Confirm Certificate Expiration Dates')
			log_file_logger.info('#19:Check:Controllers:Confirm Certificate Expiration Dates')
			writeFile(report_file, '#19:Check:Controllers:Confirm Certificate Expiration Dates\n\n')

			try:
				controllers_exp, controllers_notexp, check_result, check_analysis, check_action = warningCheckeight(controllers_info)
				if check_result == 'Failed':
					warning_checks['#19:Check:Controllers:Confirm Certificate Expiration Dates'] = [ check_analysis, check_action]
					log_file_logger.error('#19: Check result:   {}'.format(check_result))
					log_file_logger.error('#19: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#19: Controllers with certificates close to expiration: \n{}\n'.format(controllers_exp))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
			 
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#19: Check result:   {}'.format(check_result))
					log_file_logger.info('#19: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				   
					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #19:Check:Controllers:Confirm Certificate Expiration Dates. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#20:Check:Controllers:vEdge list sync
			print(' #20:Checking:Controllers:vEdge list sync')
			log_file_logger.info('#20:Check:Controllers:vEdge list sync')
			writeFile(report_file, '#20:Check:Controllers:vEdge list sync\n\n')

			try:
				state_vedgeList,check_result, check_analysis, check_action  = warningChecknine(controllers_info)
				if check_result == 'Failed':
					warning_checks['#20:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#20: Check result:   {}'.format(check_result))
					log_file_logger.error('#20: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#20: Controllers with inconsistent state_vedgeList: {}\n'.format(state_vedgeList))
					
					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				 
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#20: Check result:   {}'.format(check_result))
					log_file_logger.info('#20: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #20:Check:Controllers:vEdge list sync. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#21:Check:Controllers: Confirm control connections
			print(' #21:Checking:Controllers: Confirm control connections')
			log_file_logger.info('#21:Check:Controllers: Confirm control connections')
			writeFile(report_file, '#21:Check:Controllers: Confirm control connections\n\n')

			try:
				control_sum_tab, discrepancy,check_result, check_analysis, check_action = warningCheckten(vsmart_count, vbond_count)
				if check_result == 'Failed':
					warning_checks['#21:Check:Controllers: Confirm control connections'] = [ check_analysis, check_action]

					log_file_logger.error('#21: Check result:   {}'.format(check_result))
					log_file_logger.error('#21: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#21: Control  Connections Summary: \n{}\n'.format(control_sum_tab))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#21: Check result:   {}'.format(check_result))
					log_file_logger.info('#21: Check Analysis: {}'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #21:Check:Controllers: Confirm control connections. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


		 
			#Informational Checks
			print('\n**** Performing Informational checks\n' )
			log_file_logger.info('*** Performing Informational Checks')

			#22:Check:vManage:Disk controller type
			print(' #22:Check:vManage:Disk controller type')
			log_file_logger.info('#22:Check:vManage:Disk controller type')
			writeFile(report_file, '#22:Check:vManage:Disk controller type\n\n')

			try:
				check_result, check_analysis, check_action = infoCheckone(server_type, disk_controller)
				if check_result == 'Failed':
					warning_checks['#22:Check:vManage:Disk controller type'] = [ check_analysis, check_action]

					log_file_logger.error('#22: Check result:   {}'.format(check_result))
					log_file_logger.error('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m\n\n'.format(check_analysis))

				else:
					log_file_logger.info('#22: Check result:   {}'.format(check_result))
					log_file_logger.info('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #22:Check:vManage:Disk controller type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#23:Check:Controllers:Validate there is at minimum vBond, vSmart present
			print(' #23:Check:Controllers:Validate there is at minimum vBond, vSmart present ')
			log_file_logger.info('#23:Check:Controllers:Validate there is at minimum vBond, vSmart present')
			writeFile(report_file, '#23:Check:Controllers:Validate there is at minimum vBond, vSmart present\n\n')

			try:
				check_result, check_analysis, check_action = infoChecktwo(vsmart_count,vbond_count)
				if check_result == 'Failed':
					warning_checks['#23:Check:Controllers:Validate there is at minimum vBond, vSmart present'] = [ check_analysis, check_action]

					log_file_logger.error('#23: Check result:   {}'.format(check_result))
					log_file_logger.error('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.error('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				   
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#23: Check result:   {}'.format(check_result))
					log_file_logger.info('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.info('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				  
					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #23:Check:Controllers:Validate there is at minimum vBond, vSmart present. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#24:Check:Controllers:Validate all controllers are reachable
			print(' #24:Check:Controllers:Validate all controllers are reachable')
			log_file_logger.info('#24:Check:Controllers:Validate all controllers are reachable')
			writeFile(report_file, '#24:Check:Controllers:Validate all controllers are reachable\n\n')
				
			try:
				unreach_controllers,check_result, check_analysis, check_action = infoChecktthree(controllers_info)
				if check_result == 'Failed':
					warning_checks['#24:Check:Controllers:Validate all controllers are reachable'] = [ check_analysis, check_action]

					log_file_logger.error('#24: Check result:   {}'.format(check_result))
					log_file_logger.error('#24: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#24: Unreachable Controllers: {}\n'.format(unreach_controllers))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#24: Check result:   {}'.format(check_result))
					log_file_logger.info('#24: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #24:Check:Controllers:Validate all controllers are reachable. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			if cluster_size>1:
				cluster_checks = {}

				log_file_logger.info('*** Performing Cluster Checks')
				print('\n**** Performing Cluster checks\n')

				#25:Check:Cluster:Version consistency
				print(' #25:Checking:Cluster:Version consistency')
				log_file_logger.info('#25:Check:Cluster:Version consistency')
				writeFile(report_file, '#25:Check:Cluster:Version consistency\n\n')

				try:
					check_result,check_analysis, check_action = criticalChecktwelve(vmanage_info)
					if check_result == 'Failed':
						cluster_checks['#25:Check:Cluster:Version consistency'] = [ check_analysis, check_action]

						log_file_logger.error('#25: Check result:   {}'.format(check_result))
						log_file_logger.error('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				
						print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

					else:
						log_file_logger.info('#25: Check result:   {}'.format(check_result))
						log_file_logger.info('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				  
						print(' INFO:{}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #25:Check:Cluster:Version consistency. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#26:Check:Cluster:Cluster health
				print(' #26:Checking:Cluster:Cluster health')
				log_file_logger.info('#26:Check:Cluster:Cluster health')
				writeFile(report_file, '#26:Check:Cluster:Cluster health\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))
					services_down, check_result, check_analysis, check_action = criticalCheckthirteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#26:Check:Cluster:Cluster health'] = [ check_analysis, check_action]

						log_file_logger.error('#26: Check result:   {}'.format(check_result))
						log_file_logger.error('#26: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#26: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				
						print('\033[1;31m ERROR: {} \033[0;0m\n\n'.format(check_analysis))

					else: 
						log_file_logger.info('#26: Check result:   {}'.format(check_result))
						log_file_logger.info('#26: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

						print(' INFO:{}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #26:Check:Cluster:Cluster health. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#27:Check:Cluster:Cluster ConfigDB topology
				print(' #27:Checking:Cluster:Cluster ConfigDB topology')
				log_file_logger.info('#27:Check:Cluster:Cluster ConfigDB topology')
				writeFile(report_file, '#27:Check:Cluster:Cluster ConfigDB topology\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))           
					configDB_count, check_result, check_analysis, check_action = criticalCheckfourteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#27:Check:Cluster:Cluster ConfigDB topology'] = [ check_analysis, check_action]

						log_file_logger.error('#27: Check result:   {}'.format(check_result))
						log_file_logger.error('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

						print('\033[1;31m ERROR: {} \033[0;0m\n\n'.format(check_analysis))

					else: 
						log_file_logger.info('#27: Check result:   {}'.format(check_result))
						log_file_logger.info('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

						print(' INFO:{}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #27:Check:Cluster:Cluster ConfigDB topology. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#28:Check:Cluster:Messaging server
				print(' #28:Checking:Cluster:Messaging server')
				log_file_logger.info('#28:Check:Cluster:Messaging server')
				writeFile(report_file, '#28:Check:Cluster:Messaging server\n\n')

				try:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))           
					cluster_msdown,check_result,check_analysis, check_action = criticalCheckfifteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#28:Check:Cluster:Messaging server'] = [ check_analysis, check_action]

						log_file_logger.error('#28: Check result:   {}'.format(check_result))
						log_file_logger.error('#28: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#28: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

						print('\033[1;31m ERROR: {} \033[0;0m\n\n'.format(check_analysis))

					else: 
						log_file_logger.info('#28: Check result:   {}'.format(check_result))
						log_file_logger.info('#28: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

						print(' INFO:{}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #28:Check:Cluster:Messaging server. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#29:Check:Cluster:DR replication status
				print(' #29:Checking:Cluster:DR replication status')
				log_file_logger.info('#29:Check:Cluster:DR replication status')
				writeFile(report_file, '#29:Check:Cluster:DR replication status\n\n')

				try:
					dr_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'disasterrecovery/details', args.vmanage_port, tokenid))           
					dr_status, check_action, check_analysis, check_result = criticalChecksixteen(dr_data)
					if check_result == 'Failed':
						cluster_checks['#29:Check:Cluster:DR replication status'] = [ check_analysis, check_action]

						log_file_logger.error('#29: Check result:   {}'.format(check_result))
						log_file_logger.error('#29: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#29: DR Replication status: {}\n'.format(dr_status))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

						print('\033[1;31m ERROR: {} \033[0;0m\n\n'.format(check_analysis))

					else:
						log_file_logger.info('#29: Check result:   {}'.format(check_result))
						log_file_logger.info('#29: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

						print(' INFO:{}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #29:Check:Cluster:DR replication status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))



				#30:Check:Cluster:Intercluster communication
				print(' #30:Checking:Cluster:Intercluster communication')
				log_file_logger.info('#30:Check:Cluster:Intercluster communication')
				writeFile(report_file, '#30:Check:Cluster:Intercluster communication\n\n')
					
				try:
					if criticalCheckseventeen.isAlive():
						criticalCheckseventeen.join(10)

					if not criticalCheckseventeen.result_queue.empty():
						ping_output, ping_output_failed, ping_check_result, ping_check_analysis, ping_check_action = criticalCheckseventeen.result_queue.get()
						if ping_check_result == 'Failed':
							cluster_checks['#30:Check:Cluster:Intercluster communication'] = [ ping_check_analysis, ping_check_action]

							log_file_logger.error('#30: Check result:   {}'.format(ping_check_result))
							log_file_logger.error('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.error('#30: Cluster nodes with ping failure: {}\n'.format(ping_output_failed))

						
							writeFile(report_file, 'Result: ERROR - {}\n'.format(ping_check_analysis))
							writeFile(report_file, 'Action: {}\n\n'.format(ping_check_action))

							print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(ping_check_analysis))

						else:
							log_file_logger.info('#30: Check result:   {}'.format(ping_check_result))
							log_file_logger.info('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.info('#30: Cluster nodes details: {}\n'.format(ping_output))

							writeFile(report_file, 'Result: INFO - {}\n\n'.format(ping_check_analysis))

							print(' INFO:{}\n\n'.format(ping_check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #30:Check:Cluster:Intercluster communication. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


			#Logging out of the Session using jsessionid
			log_file_logger.info('Logging out of the Session')
			sessionLogout(vmanage_lo_ip, jsessionid, args.vmanage_port)
			log_file_logger.info('Successfully closed the connection')
		

		#version equal to or above 20.5
		elif version_tuple[0:2] >= ('20','5'): 

			try:
				log_file_logger.info('Generating a JSessionID')
				jsessionid = generateSessionIDpy3(vmanage_lo_ip, args.username, password, args.vmanage_port)
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error generating JSessionID, make sure that the username and password entered is correct. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))

			try:
				log_file_logger.info('Generating CSRF Token')
				tokenid = CSRFTokenpy3(vmanage_lo_ip,jsessionid,args.vmanage_port)
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error generating CSRF Token. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file.  \033[0;0m \n\n'.format(log_file_path))

			#Preliminary data
			log_file_logger.info('****Collecting Preliminary Data\n')
			print ('****Collecting Preliminary Data\n')

			try:
				controllers = json.loads(getRequestpy3(version_tuple, vmanage_lo_ip, jsessionid , 'system/device/controllers', args.vmanage_port, tokenid))
				controllers_info = controllersInfo(controllers)
				log_file_logger.info('Collected controllers information: {}'.format(controllers_info))

				system_ip_data = json.loads(getRequestpy3(version_tuple, vmanage_lo_ip, jsessionid , 'device/vmanage', args.vmanage_port, tokenid))
				system_ip = system_ip_data['data']['ipAddress']
				#system_ip = controllers_info[hostname][1]
				log_file_logger.info('Collected vManage System IP address: {}'.format(system_ip))

				cpu_speed = cpuSpeed()
				log_file_logger.info('Collected vManage CPU Speed GHz: {}'.format(cpu_speed))

				cpu_count = cpuCount()
				log_file_logger.info('Collected vManage CPU Count: {}'.format(cpu_count))

				vedges = json.loads(getRequestpy3(version_tuple, vmanage_lo_ip, jsessionid , 'system/device/vedges', args.vmanage_port , tokenid))
				vedge_count,vedge_count_active, vedge_info = vedgeCount(vedges)
				log_file_logger.info('Collected  xEdge Count: {}'.format(vedge_count))

				cluster_size, server_mode, vmanage_info = serverMode(controllers_info)
				log_file_logger.info('Collected vManage Cluster Size: {}'.format(cluster_size))
				log_file_logger.info('Collected vManage Server Mode: {}'.format(server_mode))

				disk_controller = diskController()
				log_file_logger.info('Collected vManage Disk Controller Type: {}'.format(disk_controller))

				dpi_stats = json.loads(getRequestpy3(version_tuple, vmanage_lo_ip, jsessionid , 'statistics/settings/status', args.vmanage_port, tokenid))
				dpi_status = dpiStatus(dpi_stats)
				log_file_logger.info('Collected DPI Status: {}'.format(dpi_status))

				server_type = serverType()
				log_file_logger.info('Collected Server Type: {}'.format(server_type))

				vbond_info, vsmart_info = vbondvmartInfo(controllers_info)
				vbond_count = len(vbond_info)
				vsmart_count = len(vsmart_info)
				log_file_logger.info('vSmart info: {}'.format(vbond_info))
				log_file_logger.info('vBond info: {}'.format(vsmart_info))

				total_devices = len(controllers_info.keys()) + vedge_count
				log_file_logger.info('Total devices: {}'.format(total_devices))

			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error Collecting Preliminary Data. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				

			print('*Starting Checks, this may take several minutes')


			#Critical Checks
			print('\n**** Performing Critical checks\n')

			#Begining #30:Check:Cluster:Intercluster communication  in the background
			if cluster_size>1:
				log_file_logger.info('Beginging #30:Check:Cluster:Intercluster communication  in the background\n')
				try:
					cluster_health_data = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))
					criticalCheckseventeen =  criticalCheckseventeenpy3(cluster_health_data,  system_ip, log_file_logger)
				except Exception as e:
					log_file_logger.exception('{}\n'.format(e))

			critical_checks = {}
			log_file_logger.info('*** Performing Critical Checks\n')

			#01:Check:vManage:Validate current version
			print(' #01:Checking:vManage:Validate current version')
			log_file_logger.info('#01:Check:vManage:Validate current version')
			writeFile(report_file, '#01:Check:vManage:Validate current version\n\n')
			
			try:
				boot_partition_size, check_result, check_analysis, check_action =  criticalCheckone(version)
				if check_result == 'Failed':
					critical_checks['#01:Check:vManage:Validate current version'] = [ check_analysis, check_action]
					log_file_logger.error('#01: Check result:   {}'.format(check_result))
					log_file_logger.error('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#01: version: {}'.format(version))
					log_file_logger.error('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
			   
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#01: Check result:   {}'.format(check_result))
					log_file_logger.info('#01: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#01: version: {}'.format(version))
					log_file_logger.info('#01: Boot Partition Size: {}\n'.format(boot_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
			 
					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #01:Check:vManage:Validate current version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#02:Check:vManage:At minimum 20%  server disk space should be available
			print(' #02:Checking:vManage:vManage sever disk space')
			log_file_logger.info('#02:Check:vManage:At minimum 20%  server disk space should be available')
			writeFile(report_file, '#02:Check:vManage:At minimum 20%  server disk space should be available\n\n')

			try:
				optdata_partition_size, rootfs_partition_size, check_result, check_analysis, check_action =  criticalCheckTwo()
				if check_result == 'Failed': 
					critical_checks['#02:Check:vManage:At minimum 20%  server disk space should be available'] = [check_analysis, check_action]
					log_file_logger.error('#02: Check result:   {}'.format(check_result))
					log_file_logger.error('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.error('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#02: Check result:   {}'.format(check_result))
					log_file_logger.info('#02: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#02: /opt/data Used: {}'.format(optdata_partition_size))
					log_file_logger.info('#02: /rootfs.rw Used: {}\n'.format(rootfs_partition_size))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #02:Check:vManage:At minimum 20%  server disk space should be available. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#03:Check:vManage:Memory size
			print(' #03:Checking:vManage:Memory size')

			log_file_logger.info('#03:Check:vManage:Memory size')
			writeFile(report_file, '#03:Check:vManage:Memory size\n')
			writeFile(report_file, 'Link to the official documentation: \n https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html\n\n')

			try:
				memory_size, memory_size_str, dpi_status, server_type, check_result, check_analysis, check_action =  criticalCheckthree(vedge_count, dpi_status, server_type, cluster_size, version_tuple)
				if check_result == 'Failed':
					critical_checks['#03:Check:vManage:Memory size'] = [ check_analysis, check_action]
					log_file_logger.error('#03: Check result:   {}'.format(check_result))
					log_file_logger.error('#03: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#03: Memory Size GB: {}'.format(memory_size_str))
					log_file_logger.error('#03: /rootfs.rw Used: {}'.format(rootfs_partition_size))
					log_file_logger.error('#03: Server Type: {}'.format(server_type))
					log_file_logger.error('#03: vEdge Count: {}\n'.format(vedge_count))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#03: Check result:   {}'.format(check_result))
					log_file_logger.info('#03: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
				  
					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #03:Check:vManage:Memory size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

	 
			#04:Check:vManage:CPU Count
			print(' #04:Checking:vManage:CPU Count')
			log_file_logger.info('#04:Check:vManage:CPU Count')
			writeFile(report_file, '#04:Check:vManage:CPU Count\n\n')

			try:
				check_result, check_analysis, check_action = criticalCheckfour(cpu_count, vedge_count, dpi_status, server_type)
				if check_result == 'Failed':
					critical_checks['#04:Check:vManage:CPU Count'] = [ check_analysis, check_action]
					log_file_logger.error('#04: Check result:   {}'.format(check_result))
					log_file_logger.error('#04: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#04: CPU Count: {}\n'.format(cpu_count))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis) )
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#04: Check result:   {}'.format(check_result))
					log_file_logger.info('#04: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #04:Check:vManage:CPU Count. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#05:Check:vManage:ElasticSearch Indices status
			print(' #05:Checking:vManage:ElasticSearch Indices status')
			log_file_logger.info('#05:Check:vManage:ElasticSearch Indices status')
			writeFile(report_file, '#05:Check:vManage:ElasticSearch Indices status\n\n')

			try:
				es_indexes_one = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_index_red_one, check_result_one, check_analysis_one, check_action_one = criticalCheckfive(es_indexes_one)

				time.sleep(5)

				es_indexes_two = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_index_red_two, check_result_two, check_analysis_two, check_action_two = criticalCheckfive(es_indexes_two)

				if check_result_one == 'Failed' and check_result_two == 'Failed':
					critical_checks['#05:Check:vManage:ElasticSearch Indices status'] = [ check_analysis_two, check_action_two]

					log_file_logger.error('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.error('#05: Check Analysis: {}\n'.format(check_analysis_two))


					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis_two))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action_two))
					
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis_two))

				elif check_result_one == 'SUCCESSFUL':
					log_file_logger.info('#05: Check result:   {}'.format(check_result_one))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_one))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_one))

					print(' INFO:{}\n\n'.format(check_analysis_one))

				elif check_result_two == 'SUCCESSFUL':

					log_file_logger.info('#05: Check result:   {}'.format(check_result_two))
					log_file_logger.info('#05: Check Analysis: {}\n'.format(check_analysis_two))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_two))

					print(' INFO:{}\n\n'.format(check_analysis_two))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #05:Check:vManage:ElasticSearch Indices status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#06:Check:vManage:Look for any neo4j exception errors
			print(' #06:Checking:vManage:Look for any neo4j exception errors')
			log_file_logger.info('#06:Check:vManage:Look for any neo4j exception errors')
			writeFile(report_file, '#06:Check:vManage:Look for any neo4j exception errors\n\n')

			try:
				check_result, check_analysis, check_action = criticalChecksix()
				if check_result == 'Failed':
					critical_checks['#06:Check:vManage:Look for any neo4j exception errors'] = [check_analysis, check_action]
					log_file_logger.error('#06: Check result:   {}'.format(check_result))
					log_file_logger.error('#06: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#06: Check result:   {}'.format(check_result))
					log_file_logger.info('#06: Check Analysis: {}'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #06:Check:vManage:Look for any neo4j exception errors. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#07:Check:vManage:Validate all services are up
			print(' #07:Checking:vManage:Validate all services are up')
			log_file_logger.info('#07:Check:vManage:Validate all services are up')
			writeFile(report_file, '#07:Check:vManage:Validate all services are up\n\n')

			try:
				nms_data, nms_failed, check_result, check_analysis, check_action =   criticalCheckseven() 
				if check_result == 'Failed':
					critical_checks['#07:Check:vManage:Validate all services are up'] = [check_analysis, check_action]

					log_file_logger.error('#07: Check result:   {}'.format(check_result))
					log_file_logger.error('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#07: List of services that are enabled but not running:\n{}'.format(nms_failed))
					log_file_logger.error('#07: Status of all services  :\n{}\n'.format(nms_data))

					writeFile(report_file, 'Result: ERROR - {}\n\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				 
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#07: Check result:   {}'.format(check_result))
					log_file_logger.info('#07: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#07: Status of all the services:\n{}\n'.format(nms_data))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #07:Check:vManage:Validate all services are up. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#08:Check:vManage:Elasticsearch Indices version
			print(' #08:Checking:vManage:Elasticsearch Indices version')
			log_file_logger.info('#08:Check:vManage:Elasticsearch Indices version')
			writeFile(report_file, '#08:Check:vManage:Elasticsearch Indices version\n\n')

			try:
				version_list, check_result, check_analysis, check_action = criticalCheckeight(version_tuple)
				if check_result == 'Failed':
					critical_checks['#08:Check:vManage:Elasticsearch Indices version'] = [ check_analysis, check_action]

					log_file_logger.error('#08: Check result:   {}'.format(check_result))
					log_file_logger.error('#08: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#08: List of indices with older versions  :\n{}\n'.format(version_list))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#08: Check result:   {}'.format(check_result))
					log_file_logger.info('#08: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #08:Check:vManage:Elasticsearch Indices version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#09:Check:vManage:Evaluate incoming DPI data size
			print(' #09:Checking:vManage:Evaluate incoming DPI data size')
			log_file_logger.info('#09:Check:vManage:Evaluate incoming DPI data size')
			writeFile(report_file, '#09:Check:vManage:Evaluate incoming DPI data size\n\n')

			try:
				es_indices_est = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/size/estimate', args.vmanage_port, tokenid))
				appr_estimate_ondeday, dpi_estimate_ondeday, check_result, check_analysis,check_action = criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count, total_devices, dpi_status)
				if check_result == 'Failed':
					critical_checks['#09:Check:vManage:Evaluate incoming DPI data size'] = [ check_analysis, check_action]

					log_file_logger.error('#09: Check result:   {}'.format(check_result))
					log_file_logger.error('#09: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#09: Daily incoming DPI data : {}'.format(dpi_estimate_ondeday))
					log_file_logger.error('#09: Daily incoming Approute data : {}\n'.format(appr_estimate_ondeday))
					
					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#09: Check result:   {}'.format(check_result))
					log_file_logger.info('#09: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #09:Check:vManage:Evaluate incoming DPI data size. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#10:Check:vManage:NTP status across network
			print(' #10:Checking:vManage:NTP status across network')
			log_file_logger.info('#10:Check:vManage:NTP status across network')
			writeFile(report_file, '#10:Check:vManage:NTP status across network\n\n')
			try:
				ntp_nonworking, check_result, check_analysis, check_action = criticalCheckten(version_tuple, controllers_info)
				if check_result == 'Failed':
					critical_checks['#10:Check:vManage:NTP status across network'] = [ check_analysis, check_action]


					log_file_logger.error('#10: Check result:   {}'.format(check_result))
					log_file_logger.error('#10: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#10: Devices with invalid ntp associations: \n{}\n'.format(ntp_nonworking))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#10: Check result:   {}'.format(check_result))
					log_file_logger.info('#10: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error perforiming #10:Check:vManage:NTP status across network. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#11:Check:Controllers:Validate vSmart/vBond CPU count for scale
			print(' #11:Checking:Controllers:Validate vSmart/vBond CPU count for scale')
			log_file_logger.info('#11:Check:Controllers:Validate vSmart/vBond CPU count for scale')
			writeFile(report_file, '#11:Check:Controllers:Validate vSmart/vBond CPU count for scale\n\n')

			try:
				for vbond in vbond_info:
					output = json.loads(getRequestpy3( version_tuple,vmanage_lo_ip, jsessionid, 'device/system/synced/status?deviceId={}'.format(vbond_info[vbond][1]),args.vmanage_port, tokenid))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vbond_info[vbond].append(total_cpu_count)

				for vsmart in vsmart_info:
					output = json.loads(getRequestpy3( version_tuple,vmanage_lo_ip, jsessionid, 'device/system/synced/status?deviceId={}'.format(vsmart_info[vsmart][1]),args.vmanage_port,tokenid))
					total_cpu_count = int(output['data'][0]['total_cpu_count'])
					vsmart_info[vsmart].append(total_cpu_count)

				failed_vbonds,failed_vsmarts,check_result,check_analysis, check_action = criticalCheckeleven(total_devices, vbond_info, vsmart_info)
				if check_result == 'Failed':
					critical_checks['#11:Check:Controllers:Validate vSmart/vBond CPU count for scale'] = [ check_analysis, check_action]

					log_file_logger.error('#11: Check result:   {}'.format(check_result))
					log_file_logger.error('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#11: vBonds with insufficient CPU count: \n{}'.format(failed_vbonds))
					log_file_logger.error('#11: vSmarts with insufficient CPU count: \n{}'.format(failed_vsmarts))
					log_file_logger.error('#11: All vBonds info with total_cpu_count: \n{}'.format(vbond_info))
					log_file_logger.error('#11: All vSmarts info with total_cpu_count: \n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#11: Check result:   {}'.format(check_result))
					log_file_logger.info('#11: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#11: All vBonds info with total_cpu_count: \n{}'.format(vbond_info))
					log_file_logger.info('#11: All vSmarts info with total_cpu_count: \n{}\n'.format(vsmart_info))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #11:Check:Controllers:Validate vSmart/vBond CPU count for scale. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Warning Checks
			print('\n**** Performing Warning checks\n') 

			warning_checks = {}
			log_file_logger.info('*** Performing Warning Checks')

			#12:Check:vManage:CPU Speed
			print(' #12:Checking:vManage:CPU Speed')
			log_file_logger.info('#12:Check:vManage:CPU Speed')
			writeFile(report_file, '#12:Check:vManage:CPU Speed\n\n')

			try:
				check_result,check_analysis,check_action = warningCheckone(cpu_speed)
				if check_result == 'Failed':
					warning_checks['#12:Check:vManage:CPU Speed'] = [ check_analysis, check_action]

					log_file_logger.error('#12: Check result:   {}'.format(check_result))
					log_file_logger.error('#12: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#12: CPU clock speed: {}\n'.format(cpu_speed))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#12: Check result:   {}'.format(check_result))
					log_file_logger.info('#12: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #12:Check:vManage:CPU Speed. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file.failed_vsmarts \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#13:Check:vManage:Network Card type
			print(' #13:Checking:vManage:Network Card type')
			log_file_logger.info('#13:Check:vManage:Network Card type')
			writeFile(report_file, '#13:Check:vManage:Network Card type\n\n')

			try:
				eth_drivers, check_action, check_analysis, check_result = warningChecktwo()
				if check_result == 'Failed':
					warning_checks['#13:Check:vManage:Network Card type'] = [ check_analysis, check_action]

					log_file_logger.error('#13: Check result:   {}'.format(check_result))
					log_file_logger.error('#13: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#13: Ethercardswith e1000 card types: {}\n'.format(eth_drivers))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#13: Check result:   {}'.format(check_result))
					log_file_logger.info('#13: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #13:Check:vManage:Network Card type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#14:Check:vManage:Backup status
			print(' #14:Checking:vManage:Backup status')
			log_file_logger.info('#14:Check:vManage:Backup status')
			writeFile(report_file, '#14:Check:vManage:Backup status\n\n')

			try:
				date_time_obj, check_result, check_analysis, check_action = warningCheckthree()
				if check_result == 'Failed':
					warning_checks['#14:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#14: Check result:   {}'.format(check_result))
					log_file_logger.error('#14: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#14: Last Backup was performed on:{}\n'.format(date_time_obj))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#14: Check result:   {}'.format(check_result))
					log_file_logger.info('#14: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #14:Check:vManage:Backup status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#15:Check:vManage:Evaluate Neo4j performance
			print(' #15:Checking:vManage:Evaluate Neo4j performance')
			log_file_logger.info('#15:Check:vManage:Evaluate Neo4j performance')
			writeFile(report_file, '#15:Check:vManage:Evaluate Neo4j performance\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckfour()
				if check_result == 'Failed':
					warning_checks['#15:Check:vManage:Backup status'] = [ check_analysis, check_action]

					log_file_logger.error('#15: Check result:   {}'.format(check_result))
					log_file_logger.error('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#15: Check result:   {}'.format(check_result))
					log_file_logger.info('#15: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #15:Check:vManage:Evaluate Neo4j performance. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#16:Check:vManage:Confirm there are no pending tasks
			print(' #16:Checking:vManage:Confirm there are no pending tasks')
			log_file_logger.info('#16:Check:vManage:Confirm there are no pending tasks')
			writeFile(report_file, '#16:Check:vManage:Confirm there are no pending tasks\n\n')

			try:
				tasks = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid,'device/action/status/tasks', args.vmanage_port, tokenid))
				tasks_running, check_result, check_analysis, check_action  = warningCheckfive(tasks)
				if check_result == 'Failed':
					warning_checks['#16:Check:vManage:Confirm there are no pending tasks'] = [ check_analysis, check_action]
					log_file_logger.error('#16: Check result:   {}'.format(check_result))
					log_file_logger.error('#16: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#16: Tasks still running: {}\n'.format(tasks_running))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#16: Check result:   {}'.format(check_result))
					log_file_logger.info('#16: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #16:Check:vManage:Confirm there are no pending tasks. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#17:Check:vManage:Validate there are no empty password users
			print(' #17:Checking:vManage:Validate there are no empty password users')
			log_file_logger.info('#17:Check:vManage:Validate there are no empty password users')
			writeFile(report_file, '#17:Check:vManage:Validate there are no empty password users\n\n')

			try:
				
				users_emptypass, check_result, check_analysis, check_action = warningChecksix(version_tuple)
				if check_result == 'Failed':
					warning_checks['#17:Check:vManage:Validate there are no empty password users'] = [ check_analysis, check_action]
					log_file_logger.error('#17: Check result:   {}'.format(check_result))
					log_file_logger.error('#17: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#17: Users with empty passwords: {}\n'.format(users_emptypass))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m \n\n '.format(check_analysis))

				else:
					log_file_logger.info('#17: Check result:   {}'.format(check_result))
					log_file_logger.info('#17: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #17:Check:vManage:Validate there are no empty password users. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#18:Check:Controllers:Controller versions
			print(' #18:Checking:Controllers:Controller versions')
			log_file_logger.info('#18:Check:Controllers:Controller versions')
			writeFile(report_file, '#18:Check:Controllers:Controller versions\n\n')

			try:
				check_result, check_analysis, check_action = warningCheckseven(controllers_info)
				if check_result == 'Failed':
					warning_checks['18:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#18:Check result:    {}'.format(check_result))
					log_file_logger.error('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
					
				else:
					log_file_logger.info('#18:Check result:    {}'.format(check_result))
					log_file_logger.info('#18: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #18:Check:Controllers:Controller versions. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#19:Check:Controllers:Confirm Certificate Expiration Dates
			print(' #19:Checking:Controllers:Confirm Certificate Expiration Dates')
			log_file_logger.info('#19:Check:Controllers:Confirm Certificate Expiration Dates')
			writeFile(report_file, '#19:Check:Controllers:Confirm Certificate Expiration Dates\n\n')

			try:
				controllers_exp, controllers_notexp, check_result, check_analysis, check_action = warningCheckeight(controllers_info)
				if check_result == 'Failed':
					warning_checks['#19:Check:Controllers:Confirm Certificate Expiration Dates'] = [ check_analysis, check_action]
					log_file_logger.error('#19: Check result:   {}'.format(check_result))
					log_file_logger.error('#19: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#19: Controllers with certificates close to expiration: \n{}\n'.format(controllers_exp))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#19: Check result:   {}'.format(check_result))
					log_file_logger.info('#19: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				  
					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #19:Check:Controllers:Confirm Certificate Expiration Dates. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#20:Check:Controllers:vEdge list sync
			print(' #20:Checking:Controllers:vEdge list sync')
			log_file_logger.info('#20:Check:Controllers:vEdge list sync')
			writeFile(report_file, '#20:Check:Controllers:vEdge list sync\n\n')

			try:
				state_vedgeList,check_result, check_analysis, check_action  = warningChecknine(controllers_info)
				if check_result == 'Failed':
					warning_checks['#20:Check:Controllers:Controller versions'] = [ check_analysis, check_action]

					log_file_logger.error('#20: Check result:   {}'.format(check_result))
					log_file_logger.error('#20: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#20: Controllers with inconsistent state_vedgeList: \n{}\n'.format(state_vedgeList))
					
					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#20: Check result:   {}'.format(check_result))
					log_file_logger.info('#20: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #20:Check:Controllers:vEdge list sync. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#21:Check:Controllers: Confirm control connections
			print(' #21:Checking:Controllers: Confirm control connections')
			log_file_logger.info('#21:Check:Controllers: Confirm control connections')
			writeFile(report_file, '#21:Check:Controllers: Confirm control connections\n\n')

			try:
				control_sum_tab, discrepancy,check_result, check_analysis, check_action = warningCheckten(vsmart_count, vbond_count)
				if check_result == 'Failed':
					warning_checks['#21:Check:Controllers: Confirm control connections'] = [ check_analysis, check_action]

					log_file_logger.error('#21: Check result:   {}'.format(check_result))
					log_file_logger.error('#21: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#21: Control  Connections Summary: \n{}\n'.format(control_sum_tab))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#21: Check result:   {}'.format(check_result))
					log_file_logger.info('#21: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #21:Check:Controllers: Confirm control connections. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Informational Checks
			print('\n**** Performing Informational checks\n' )

			log_file_logger.info('*** Performing Informational Checks')

			#22:Check:vManage:Disk controller type
			print(' #22:Check:vManage:Disk controller type')
			log_file_logger.info('#22:Check:vManage:Disk controller type')
			writeFile(report_file, '#22:Check:vManage:Disk controller type\n\n')

			try:
				check_result, check_analysis, check_action = infoCheckone(server_type, disk_controller)
				if check_result == 'Failed':
					warning_checks['#22:Check:vManage:Disk controller type'] = [ check_analysis, check_action]

					log_file_logger.error('#22: Check result:   {}'.format(check_result))
					log_file_logger.error('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))

					print('\033[1;31m WARNING: {} \033[0;0m\n\n'.format(check_analysis))

				else:
					log_file_logger.info('#22: Check result:   {}'.format(check_result))
					log_file_logger.info('#22: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#22: Disk Controller type: {}\n'.format(disk_controller))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #22:Check:vManage:Disk controller type. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#23:Check:Controllers:Validate there is at minimum vBond, vSmart present
			print(' #23:Check:Controllers:Validate there is at minimum vBond, vSmart present')
			log_file_logger.info('#23:Check:Controllers:Validate there is at minimum vBond, vSmart present')
			writeFile(report_file, '#23:Check:Controllers:Validate there is at minimum vBond, vSmart present\n\n')

			try:
				check_result, check_analysis, check_action = infoChecktwo(vsmart_count,vbond_count)
				if check_result == 'Failed':
					warning_checks['#23:Check:Controllers:Validate there is at minimum vBond, vSmart present'] = [ check_analysis, check_action]

					log_file_logger.error('#23: Check result:   {}'.format(check_result))
					log_file_logger.error('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.error('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				   
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#23: Check result:   {}'.format(check_result))
					log_file_logger.info('#23: Check Analysis: {}'.format(check_analysis))
					log_file_logger.info('#23: vSmart Count: {}'.format(vsmart_count))
					log_file_logger.info('#23: vBond Count: {}\n'.format(vbond_count))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				   
					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #23:Check:Controllers:Validate there is at minimum vBond, vSmart present. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#24:Check:Controllers:Validate all controllers are reachable
			print(' #24:Check:Controllers:Validate all controllers are reachable')
			log_file_logger.info('#24:Check:Controllers:Validate all controllers are reachable')
			writeFile(report_file, '#24:Check:Controllers:Validate all controllers are reachable\n\n')
				
			try:
				unreach_controllers,check_result, check_analysis, check_action = infoChecktthree(controllers_info)
				if check_result == 'Failed':
					warning_checks['#24:Check:Controllers:Validate all controllers are reachable'] = [ check_analysis, check_action]

					log_file_logger.error('#24: Check result:   {}'.format(check_result))
					log_file_logger.error('#24: Check Analysis: {}'.format(check_analysis))
					log_file_logger.error('#24: Unreachable Controllers: {}\n'.format(unreach_controllers))


					writeFile(report_file, 'Result: WARNING - {}\n'.format(check_analysis))
					writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				   
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					log_file_logger.info('#24: Check result:   {}'.format(check_result))
					log_file_logger.info('#24: Check Analysis: {}\n'.format(check_analysis))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))

			except Exception as e:
				print('\033[1;31m ERROR: Error performing #24:Check:Controllers:Validate all controllers are reachable. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			if cluster_size>1:
				cluster_checks = {}

				log_file_logger.info('*** Performing Cluster Checks')
				print('\n**** Performing Cluster checks\n')

				#25:Check:Cluster:Version consistency
				print(' #25:Checking:Cluster:Version consistency')
				log_file_logger.info('#25:Check:Cluster:Version consistency')
				writeFile(report_file, '#25:Check:Cluster:Version consistency\n\n')

				try:
					check_result,check_analysis, check_action = criticalChecktwelve(vmanage_info)
					if check_result == 'Failed':
						cluster_checks['#25:Check:Cluster:Version consistency'] = [ check_analysis, check_action]

						log_file_logger.error('#25: Check result:   {}'.format(check_result))
						log_file_logger.error('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
					   
						print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

					else:
						log_file_logger.info('#25: Check result:   {}'.format(check_result))
						log_file_logger.info('#25: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#25: vManage info: {}\n'.format(vmanage_info))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					 
						print(' INFO:{}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #25:Check:Cluster:Version consistency. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#26:Check:Cluster:Cluster health
				print(' #26:Checking:Cluster:Cluster health')
				log_file_logger.info('#26:Check:Cluster:Cluster health')
				writeFile(report_file, '#26:Check:Cluster:Cluster health\n\n')

				try:
					cluster_health_data = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))
					services_down, check_result, check_analysis, check_action = criticalCheckthirteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#26:Check:Cluster:Cluster health'] = [ check_analysis, check_action]

						log_file_logger.error('#26: Check result:   {}'.format(check_result))
						log_file_logger.error('#26: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#26: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))
				   
						print('\033[1;31m ERROR: {} \033[0;0m\n\n'.format(check_analysis))

					else: 
						log_file_logger.info('#26: Check result:   {}'.format(check_result))
						log_file_logger.info('#26: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

						print(' INFO:{}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #26:Check:Cluster:Cluster health. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#27:Check:Cluster:Cluster ConfigDB topology
				print(' #27:Checking:Cluster:Cluster ConfigDB topology')
				log_file_logger.info('#27:Check:Cluster:Cluster ConfigDB topology')
				writeFile(report_file, '#27:Check:Cluster:Cluster ConfigDB topology\n\n')

				try: 
					cluster_health_data = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))           
					configDB_count, check_result, check_analysis, check_action = criticalCheckfourteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#27:Check:Cluster:Cluster ConfigDB topology'] = [ check_analysis, check_action]

						log_file_logger.error('#27: Check result:   {}'.format(check_result))
						log_file_logger.error('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

						print('\033[1;31m ERROR: {} \033[0;0m\n\n'.format(check_analysis))

					else: 
						log_file_logger.info('#27: Check result:   {}'.format(check_result))
						log_file_logger.info('#27: Check Analysis: {}'.format(check_analysis))
						log_file_logger.info('#27: No. of configDB servers in the cluster: {}\n'.format(configDB_count))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

						print(' INFO:{}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #27:Check:Cluster:Cluster ConfigDB topology. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#28:Check:Cluster:Messaging server
				print(' #28:Checking:Cluster:Messaging server')
				log_file_logger.info('#28:Check:Cluster:Messaging server')
				writeFile(report_file, '#28:Check:Cluster:Messaging server\n\n')

				try:
					cluster_health_data = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))           
					cluster_msdown,check_result,check_analysis, check_action = criticalCheckfifteen(cluster_health_data)
					if check_result == 'Failed':
						cluster_checks['#28:Check:Cluster:Messaging server'] = [ check_analysis, check_action]

						log_file_logger.error('#28: Check result:   {}'.format(check_result))
						log_file_logger.error('#28: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#28: Relevant cluster services that are down: {}\n'.format(services_down))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))                    

						print('\033[1;31m ERROR: {} \033[0;0m\n\n'.format(check_analysis))

					else: 
						log_file_logger.info('#28: Check result:   {}'.format(check_result))
						log_file_logger.info('#28: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

						print(' INFO:{}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #28:Check:Cluster:Messaging server. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#29:Check:Cluster:DR replication status
				print(' #29:Checking:Cluster:DR replication status')
				log_file_logger.info('#29:Check:Cluster:DR replication status')
				writeFile(report_file, '#29:Check:Cluster:DR replication status\n\n')

				try:
					dr_data = json.loads(getRequestpy3(version_tuple,vmanage_lo_ip, jsessionid, 'disasterrecovery/details', args.vmanage_port, tokenid))           
					dr_status, check_action, check_analysis, check_result = criticalChecksixteen(dr_data)
					if check_result == 'Failed':
						cluster_checks['#29:Check:Cluster:DR replication status'] = [ check_analysis, check_action]

						log_file_logger.error('#29: Check result:   {}'.format(check_result))
						log_file_logger.error('#29: Check Analysis: {}'.format(check_analysis))
						log_file_logger.error('#29: DR Replication status: {}\n'.format(dr_status))

						writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
						writeFile(report_file, 'Action: {}\n\n'.format(check_action))

						print('\033[1;31m ERROR: {} \033[0;0m\n\n'.format(check_analysis))

					else:
						log_file_logger.info('#29: Check result:   {}'.format(check_result))
						log_file_logger.info('#29: Check Analysis: {}\n'.format(check_analysis))

						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

						print(' INFO:{}\n\n'.format(check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #29:Check:Cluster:DR replication status. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#30:Check:Cluster:Intercluster communication
				print(' #30:Checking:Cluster:Intercluster communication')
				log_file_logger.info('#30:Check:Cluster:Intercluster communication')
				writeFile(report_file, '#30:Check:Cluster:Intercluster communication\n\n')
				
				try:
					if criticalCheckseventeenpy3.isAlive():
						criticalCheckseventeenpy3.join(10)

					if not criticalCheckseventeenpy3.result_queue.empty():
						ping_output, ping_output_failed, ping_check_result, ping_check_analysis, ping_check_action = criticalCheckseventeenpy3.result_queue.get()
						if ping_check_result == 'Failed':
							cluster_checks['#30:Check:Cluster:Intercluster communication'] = [ ping_check_analysis, ping_check_action]

							log_file_logger.error('#30: Check result:   {}'.format(ping_check_result))
							log_file_logger.error('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.error('#30: Cluster nodes with ping failure: {}\n'.format(ping_output_failed))

						
							writeFile(report_file, 'Result: ERROR - {}\n'.format(ping_check_analysis))
							writeFile(report_file, 'Action: {}\n\n'.format(ping_check_action))

							print('\033[1;31m ERROR: {} \033[0;0m\n\n'.format(ping_check_analysis))

						else:
							log_file_logger.info('#30: Check result:   {}'.format(ping_check_result))
							log_file_logger.info('#30: Check Analysis: {}'.format(ping_check_analysis))
							log_file_logger.info('#30: Cluster nodes details: {}\n'.format(ping_output))

							writeFile(report_file, 'Result: INFO - {}\n\n'.format(ping_check_analysis))

							print(' INFO:{}\n\n'.format(ping_check_analysis))

				except Exception as e:
					print('\033[1;31m ERROR: Error performing #30:Check:Cluster:Intercluster communication. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

			#Logging out of the Session using jsessionid
			log_file_logger.info('Logging out of the Session')
			sessionLogoutpy3(vmanage_lo_ip,jsessionid,args.vmanage_port)
			log_file_logger.info('Successfully closed the connection')

	report_file.close()


	end_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

	#Final evaluation
	if len(critical_checks) == 0:
		final_eval = 'No Issues Found'
	elif len(critical_checks) != 0:
		final_eval = 'Critical issues found that need to be resolved before an upgrade'

	#Failed Check Count
	if cluster_size>1:
		checks_failed = len(critical_checks) + len(cluster_checks)
		checks_passed = 30 - checks_failed
	else:
		checks_failed = len(critical_checks)
		checks_passed = 30 - checks_failed

	#Writing to the failed checks to the report
	check_failed_lst = []
	if len(critical_checks) != 0:
		for i in sorted (critical_checks.keys()):
			check_failed_lst.append(i + '\n\n')
			check_failed_lst.append('Result: ERROR - '+ critical_checks[i][0] + '\n')
			if critical_checks[i][1] != None:
				check_failed_lst.append('Action: '+ critical_checks[i][1] + '\n\n')
			else:
				check_failed_lst.append('\n')


	if cluster_size>1 and len(cluster_checks) != 0:
		for i in sorted (cluster_checks.keys()):
			check_failed_lst.append(i + '\n\n')
			check_failed_lst.append('Result: ERROR - '+ cluster_checks[i][0] + '\n')
			if cluster_checks[i][1] != None:
				check_failed_lst.append('Action: '+ cluster_checks[i][1] + '\n\n')
			else:
				check_failed_lst.append('\n')

	meta_data = [
	'AURA SDWAN Version:         {}\n\n'.format(__sure_version),
	'vManage Details:\n',
	'        Software Version:    {}'.format(version),
	'        System IP Address:   {}\n\n'.format(system_ip),
	'Script Execution Time:\n',
	'        Start Time:          {}\n'.format(start_time),
	'        End Time:            {}\n\n'.format(end_time),
	'-----------------------------------------------------------------------------------------------------------------\n\n',
	'Overall upgrade evaluation:  {}\n\n'.format(final_eval),
	'-----------------------------------------------------------------------------------------------------------------\n\n',
	'Check Results:\n',
	'        Total Checks Passed: {}\n'.format(checks_passed),
	'        Total Checks Failed: {}\n\n'.format(checks_failed),
	'-----------------------------------------------------------------------------------------------------------------\n\n',   
	'Detailed list of failed checks, and actions recommended\n\n' 
	]

	full_lst = [
	'-----------------------------------------------------------------------------------------------------------------\n\n',   
	'Detailed list of ALL checks, and actions recommended\n\n' 
	]

	report_file = open(report_file_path, 'r')
	Lines = report_file.readlines()
	Lines = Lines[:8] + meta_data + check_failed_lst + full_lst + Lines[8:]
	report_file.close() 

	report_file = open(report_file_path, "w")
	report_file.writelines(Lines)
	report_file.close()
	
	if cluster_size>1:
		critical_checks_count = len(critical_checks) + len(cluster_checks)
	else:
		critical_checks_count = len(critical_checks)
	warning_checks_count = len(warning_checks) 


	print('\n******\nCisco AURA SDWAN tool execution completed.\n')
	print('Overall Assessment: {} Critical errors, {} Warnings, please check report for details.'.format(critical_checks_count,warning_checks_count ))
	print ('    -- Full Results Report: {} '.format(report_file_path))
	print ('    -- Logs: {}\n'.format(log_file_path))
	print('Reach out to sure-tool@cisco.com if you have any questions or feedback\n')

