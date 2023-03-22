# -*- coding: utf-8 -*-

#!/usr/bin/env python

"""
------------------------------------------------------------------

April 2022, Rugvedi Kapse, Javier Contreras 

Copyright (c) 2022 by Cisco Systems, Inc.
All rights reserved.
------------------------------------------------------------------
"""

__sure_version =  "2.0.0"

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
import csv
import Queue


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



def generateSessionID(vManageIP,Username,Password,Port):
	if Port==None:
		command = "curl --insecure -i -s -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'j_username={}' --data-urlencode 'j_password={}' https://{}:8443/j_security_check".format(Username, Password,vManageIP)
		login = executeCommand(command)
	else:
		command = "curl --insecure -i -s -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'j_username={}' --data-urlencode 'j_password={}' https://{}:{}/j_security_check".format(Username, Password,vManageIP, Port)
		login = executeCommand(command)

	login = login.split(' ')
	try:
		if int(login[1]) == 200:
			jsessionid = (login[3].split('=')[1][0:-1])
			return jsessionid
	except:
		if int(login[1]) == 200:
			jsessionid = (login[5].split('=')[1][0:-1])
			return jsessionid
	else:
		print('  Error creating JsessionID, verify if  the information provided is correct')


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
	count = 1
	for device in controllers['data']:
		if device['deviceState'] == 'READY':
			if 'state_vedgeList' and 'timeRemainingForExpiration' not in device.keys():
				controllers_info[count] = [(device['deviceType']),(device['deviceIP']),(device['version']) ,(device['reachability']),(device['globalState']),'no-timeRemainingforExpiration', 'no-vedges']
				count += 1
			elif 'state_vedgeList' not in device.keys():
				controllers_info[count] = [(device['deviceType']),(device['deviceIP']),(device['version']) ,(device['reachability']),(device['globalState']),(device['timeRemainingForExpiration']), 'no-vedges']
				count += 1
			elif 'timeRemainingForExpiration' not in device.keys():
				controllers_info[count] = [(device['deviceType']),(device['deviceIP']),(device['version']) ,(device['reachability']),(device['globalState']),'no-timeRemainingforExpiration', (device['state_vedgeList'])]
				count += 1
			else:
				controllers_info[count] = [(device['deviceType']),(device['deviceIP']),(device['version']) ,(device['reachability']),(device['globalState']),(device['timeRemainingForExpiration']), (device['state_vedgeList'])]
				count += 1
	return controllers_info

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
	if 'data' in vedges.keys(): #Condition to on retrieve info if endpoint returns data
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

	if 'VMware' in server_type or 'Red Hat' in server_type:   #add red hat kvm type
		return 'on-prem'
	elif 'Amazon'in server_type or 'Microsoft' in server_type:
		return 'on-cloud'

#vManage: Validate server_configs.json
def validateServerConfigsUUID():
    success = False
    server_configs_file = '/opt/web-app/etc/server_configs.json'
    uuid_file = '/etc/viptela/uuid'
    if os.path.isfile(uuid_file) == True:
        with open(uuid_file) as uuid_f:
            uuid_val = uuid_f.read().strip()
    elif os.path.isfile(uuid_file) == False:
        check_analysis = uuid_file + " file not found."
        return success, check_analysis

    if os.path.isfile(server_configs_file) == True:
        with open(server_configs_file, 'r') as config_file:
            try:
                configs = json.load(config_file)
                uuid = configs['cluster']
                vmanageID = configs['vmanageID']
                if vmanageID == '0':
                   if uuid == uuid_val:
                        success = True
                        check_analysis = None
                   else:
                        success = False
                        check_analysis = "Failed to validate the uuid from server_configs.json."
                else:
                    success = True
                    check_analysis = "Validation of uuid from server_configs.json does not apply"
            except:
                success = False
                check_analysis = "Failed to validate uuid from server configs file."
    elif os.path.isfile(server_configs_file) == False :
        check_analysis = server_configs_file + " file not found."

    return success, check_analysis

#vManage: Parse server_configs.json
def _parse_local_server_config(services):
    server_configs_file = '/opt/web-app/etc/server_configs.json'
    server_config_dict = {}
    if os.path.isfile(server_configs_file) == True:
        try:
            with open(server_configs_file, 'r') as data_dict:
                server_configs_data = json.load(data_dict)
                server_config_dict['vmanageID'] = server_configs_data['vmanageID']
                server_config_dict['clusterUUID'] = server_configs_data['cluster']
                server_config_dict['mode'] = server_configs_data['mode']
                services_data_dict = server_configs_data["services"]
                for service in services:
                        serviceToDeviceIpMap = {}
                        serviceToDeviceIpMap['hosts'] = [node.split(":")[0] for node in services_data_dict[service]['hosts'].values()]
                        serviceToDeviceIpMap['clients'] = [node.split(":")[0] for node in services_data_dict[service]['clients'].values()]
                        serviceToDeviceIpMap['deviceIP'] = services_data_dict[service]["deviceIP"].split(":")[0]
                        server_config_dict[service] = serviceToDeviceIpMap
                success = True
                check_analysis = None
        except Exception:
            success = False
            check_analysis = "Error while processing read server_configs.json."
            log_file_logger.error("Error while processing read server_configs.json.")

    elif os.path.isfile(server_configs_file) == False:
        success = False
        check_analysis = server_configs_file + " file not found."

    return server_config_dict, success, check_analysis

def validateIps(serviceToDeviceIp, vmanage_ips):
	if len(serviceToDeviceIp) == len(vmanage_ips):
		check = all(item in serviceToDeviceIp for item in vmanage_ips)
		if check is True:
			return True

	return False

# vManage: Validate server_configs.json
def validateServerConfigsFile():
	if version_tuple[0:2] >= ('19', '2') and version_tuple[0:2] < ('20', '6'):
		services = ["nats", "neo4j", "elasticsearch", "zookeeper", "wildfly"]
	elif version_tuple[0:2] > ('20', '5'):
		services = ["messaging-server", "configuration-db", "statistics-db", "coordination-server", "application-server"]

	server_config_dict, success, check_analysis = _parse_local_server_config(services)
	vmanage_ips, vmanage_ids, vmanage_uuids = vmanage_service_list()

	if success:
		try:
			# Check vmanageID
			vmanageID = server_config_dict['vmanageID']
			if vmanageID not in vmanage_ids:
				success = False
				check_analysis = "Failed to validate the vmanageID from server_configs.json."
				check_action = "Check the correctness of vmanageID at server_configs.json."
				return success, check_analysis, check_action

			# Check cluster
			uuid = server_config_dict['clusterUUID']
			if uuid not in vmanage_uuids:
				success = False
				check_analysis = "Failed to validate cluster from server_configs.json."
				check_action = "Check the correctness of cluster at server_configs.json."
				return success, check_analysis, check_action

			# Check mode
			mode = server_config_dict['mode']
			tenant_mode = vmanage_tenancy_mode()
			if mode != tenant_mode:
				success = False
				check_analysis = "Failed to validate the tenant mode from server_configs.json."
				check_action = "Check the correctness of tenant mode at server_configs.json"
				return success, check_analysis, check_action

			# Check services
			for service_name in services:
				if (validateIps(server_config_dict[service_name]['hosts'], vmanage_ips) and validateIps(server_config_dict[service_name]['clients'], vmanage_ips) and server_config_dict[service_name]['deviceIP'] in vmanage_ips):
					success = True
					check_analysis = None
					check_action = None
				else:
					success = False
					check_analysis = "Failed to validate host/client/device IPs from server_configs.json for service_name:" + service_name
					check_action = "Check the correctness of host/client/device IPs at server_configs.json for service_name:" + service_name
					break

		except:
			success = False
			check_analysis = "Exception while validating server_configs.json."
			check_action = "Check the correctness of host/client/device IPs at server_configs.json."

	return success, check_analysis, check_action

def isValidUUID():
	success = False
	uuid_file = "/etc/viptela/uuid"
	if os.path.isfile(uuid_file) == True:
		with open(uuid_file) as uuid_f:
			uuid_val = uuid_f.read().strip()
			regex = "^[{]?[0-9a-fA-F]{8}" + "-([0-9a-fA-F]{4}-)" + "{3}[0-9a-fA-F]{12}[}]?$"
			p = re.compile(regex)
			if (re.search(p, uuid_val)):
				success = True
				check_analysis = None
			else:
				success = False
				check_analysis = "Investigate why the UUID is not valid."
	elif os.path.isfile(uuid_file) == False:
		check_analysis = uuid_file + " file not found."

	return success, check_analysis

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

#vManage Cluster/Interface Ips
def vmanage_cluster_ips(cluster_health_data):
	vmanage_cluster_ips = []
	if cluster_health_data['data']:
		for device in cluster_health_data['data']:
			vmanage_cluster_ips.append(device['deviceIP'])
	return vmanage_cluster_ips
### NOT SURE (20.5 issue)
#vManage service details for cluster checks
def vmanage_service_details(vmanage_cluster_ips):
	vmanage_service_details = {}
	for vmanage_cluster_ip in vmanage_cluster_ips:
		if version_tuple[0:2] < ('19','2'):
			service_details = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'clusterManagement/vManage/details/%s'%(vmanage_cluster_ip), args.vmanage_port))
		elif version_tuple[0:2] >= ('19','2') and version_tuple[0:2] < ('20','5'):
			service_details = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'clusterManagement/vManage/details/%s'%(vmanage_cluster_ip), args.vmanage_port, tokenid))
		vmanage_service_details[vmanage_cluster_ip] = service_details['data']
	return vmanage_service_details

def es_indices_details():
	try:
		es_indices = executeCommand('curl --connect-timeout 6 --silent -XGET localhost:9200/_cat/indices/ -u elasticsearch:s3cureElast1cPass')
	except:
		ip_add = (executeCommand("netstat -a -n -o |  grep tcp | awk '{print $4}'| grep :9200")).split()[0]
		pattern = "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):9200"
		match = re.search(pattern, ip_add)
		if match:
			es_indices = executeCommand('curl --connect-timeout 6 --silent -XGET {}/_cat/indices/ -u elasticsearch:s3cureElast1cPass'.format(ip_add))
	return es_indices

#vManage service list for cluster checks
def vmanage_service_list():
	if version_tuple[0:2] < ('19','2'):
		service_list = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port))
	elif version_tuple[0:2] >= ('19','2') and version_tuple[0:2] < ('20','5'):
		service_list = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'clusterManagement/list', args.vmanage_port, tokenid))
	vmanage_service_list = service_list['data'][0]['data']
	vmanage_ips,vmanage_ids, vmanage_uuids = [], [], []
	for vmanage in vmanage_service_list:
		vmanageID = vmanage['vmanageID']
		deviceIP = vmanage['configJson']['deviceIP']
		uuid = vmanage['configJson']['uuid']
		vmanage_ips.append(deviceIP)
		vmanage_ids.append(vmanageID)
		vmanage_uuids.append(uuid)

	return vmanage_ips, vmanage_ids, vmanage_uuids

#vManage tenancy mode
def vmanage_tenancy_mode():
	if version_tuple[0:2] < ('19','2'):
		service_details = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'clusterManagement/tenancy/mode', args.vmanage_port))
	elif version_tuple[0:2] >= ('19','2') and version_tuple[0:2] < ('20','5'):
		service_details = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'clusterManagement/tenancy/mode', args.vmanage_port, tokenid))
	mode = service_details['data']['mode']

	return mode
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
	if vmanage_version > 20.3 and vmanage_version < 20.6:
		#print('between 20.3 and 20.6')
		check_result = 'SUCCESSFUL'
		check_analysis = 'Direct Upgrade to next long life release 20.6 is possible and no intermediate upgrade is required'
		check_action = None
	elif vmanage_version == 20.3:
		#print('20.3')
		check_result = 'SUCCESSFUL'
		check_analysis = 'Controller is currently on recommended long life release branch, you can upgrade directly to latest release in 20.3.x'
		check_action = None
	elif vmanage_version >= 20.1 and vmanage_version < 20.3:
		#print('between 20.1 and 20.3')
		check_result = 'SUCCESSFUL'
		check_analysis = 'Direct Upgrade to next long life release 20.3 is possible and no intermediate upgrade is required'
		check_action = None
	elif vmanage_version >= 18.3 and    vmanage_version <= 19.2:
		#print('between 18.3 and 19.2')
		if boot_partition_size_Gig <= 2.0:
			#print(boot_partition_size_Gig)
			check_result = 'Failed'
			check_analysis = 'Current Disk Space is {}, it is less than 2GB and Direct Upgrade to next long life release 20.3 is not possible'.format(' '.join(boot_partition_size[0]))
			check_action = 'Upgrade through Version 20.1 is required'
		elif  boot_partition_size_Gig > 2.0:
			#print(boot_partition_size_Gig)
			check_result = 'SUCCESSFUL'
			check_analysis = 'Current Disk Space is {}, it is more than 2GB and Direct Upgrade to next long life release 20.3 is possible'.format(' '.join(boot_partition_size[0]))
			check_action = None
	elif vmanage_version < 18.3:
		#print('below 18.3')
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
		#memory_size_gb = executeCommand('free -g | grep Mem')
		memory_size_gb = executeCommand('free --giga | grep Mem')
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
		elif cpu_count >= 32:
			check_result = 'SUCCESSFUL'
			check_analysis = 'No. of Processors is sufficient for the upgrade,  CPU count is {}.'.format(cpu_count)
			check_action = None
	elif dpi_status != 'enable' and server_type == 'on-prem':
		if vedge_count > 250 and  cpu_count < 32:
			check_result = 'Failed'
			check_analysis = 'Based on device count, number of Processors is insufficient for the upgrade. CPU Count is {}, it should be 32 or higher.'.format(cpu_count)
			check_action = 'Allocate more processors'
		elif cpu_count < 16:
			check_result = 'Failed'
			check_analysis = 'Number of Processors is below the minimum supported size. CPU Count is {}, it should be 16 or higher.'.format(cpu_count)
			check_action = 'Allocate more processors'
		else:
			check_result = 'SUCCESSFUL'
			check_analysis = 'No. of Processors is sufficient for the upgrade,  CPU count is {}.'.format(cpu_count)
			check_action = None
	elif dpi_status != 'enable' and server_type == 'on-cloud':
		if vedge_count > 250 and  cpu_count < 32:
			check_result = 'Failed'
			check_analysis = 'Based on device count, number of Processors is insufficient for the upgrade. CPU Count is {}, it should be 32 or higher.'.format(cpu_count)
			check_action = 'Allocate more processors'
		elif vedge_count < 250 and  cpu_count < 16:
			check_result = 'Failed'
			check_analysis = 'Number of Processors is below the minimum supported size. CPU Count is {}, it should be 16 or higher.' .format(cpu_count)
			check_action = 'Allocate more processors'
		else:
			check_result = 'SUCCESSFUL'
			check_analysis = 'No. of Processors is sufficient for the upgrade,  CPU count is {}.'.format(cpu_count)
			check_action = None
	else:
		check_result = 'SUCCESSFUL'
		check_analysis = 'No. of Processors is sufficient for the upgrade,  CPU count is {}.'.format(cpu_count)
		check_action = None

	return check_result, check_analysis, check_action

#05:Check:vManage:ElasticSearch Indices status
def criticalCheckfive(es_indices):

	es_index_red = []
	'''
	if 'data' in es_indices.keys():
		for index in es_indices['data']:
			if index['status'] != 'GREEN':
				es_index_red.append(es_indices['indexName'])

		if len(es_index_red) != 0:
			check_result = 'Failed'
			check_analysis = 'There are Indices that have RED status'
			check_action = 'At least one StatsDB index is exhibiting problems. Please contact TAC  case to investigate and correct the issue'
		elif len(es_index_red) == 0:
			check_result = 'SUCCESSFUL'
			check_analysis = 'All the indices have GREEN status'
			check_action = None
	else:
		check_result = 'Failed'
		check_analysis = 'Error retrieving data from the API: https://<vManage-IPAddress>:<vManage-Port>/dataservice/management/elasticsearch/index/info '
		check_action = None
	return es_index_red, check_result, check_analysis, check_action
	'''
	if es_indices:
		es_indices = es_indices.split('\n')
		es_indices.pop()
		for index in es_indices:
			index = index.split(' ')
			if index[0] != 'green':
				print(index[0])
				print(index[2])
				es_index_red.append(index[2])
	else:
		es_indices = 'unknown'

	if es_indices == 'uknown':
		check_result = 'Failed'
		check_analysis = 'Error retrieving Elasticsearch Index Data using the curl command: curl  -XGET localhost:9200/_cat/indices/ -u elasticsearch:s3cureElast1cPass'
		check_action = None
	if len(es_index_red) != 0:
				check_result = 'Failed'
				check_analysis = 'There are Indices that have RED status'
				check_action = 'At least one StatsDB index is exhibiting problems. Please contact TAC  case to investigate and correct the issue'
	elif len(es_index_red) == 0:
				check_result = 'SUCCESSFUL'
				check_analysis = 'All the indices have GREEN status'
				check_action = None
	else:
		check_result = 'Failed'
		check_analysis = 'Error retrieving Elasticsearch Index Data using the curl command: curl  -XGET localhost:9200/_cat/indices/ -u elasticsearch:s3cureElast1cPass'
		check_action = None

	return es_index_red, check_result, check_analysis, check_action

#06:Check:vManage:Look for any neo4j exception errors
def criticalChecksix(version_tuple):
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
				date_time = datetime.strptime(match[0], '%Y-%m-%d %H:%M:%S')
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
		version_list = {}
		check_result = 'Failed'
		check_analysis = 'Failed to retrieve Elasticsearch Indices version data'
		check_action = 'It was not possible to obtain indices version data. Please check if there is any error on server, before attempting upgrade'
	return version_list, check_result, check_analysis, check_action



#09:Check:vManage:Evaluate incoming DPI data size
def criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count, total_devices, dpi_status):
	#es_indices = es_indices_details()
	try:
		api_returned_data = True
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
					appr_estimate_ondeday = None
					dpi_estimate_ondeday = None

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

	except:
		dpi_estimate_ondeday = None
		appr_estimate_ondeday = None
		api_returned_data = False

	if api_returned_data == False:
		check_result = 'Failed'
		check_analysis = 'Error retrieving data using the endpoint: https://<vManage-IPAddress>:<vManage-Port>/dataservice/management/elasticsearch/index/size/estimate'
		check_action = 'Investigate why the API is not returning appropriate data.'
	elif api_returned_data == True:
		if dpi_estimate_ondeday == None:
			check_result = 'Failed'
			check_analysis = 'The status of Index-DPI is not success'
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
				if 'data' not in ntp_data.keys() or ntp_data['data'] == []:
					ntp_nonworking.append(controllers_info[key][1])
				else:
					continue
	elif version_tuple[0:2] >= ('19','2') and version_tuple[0:2] < ('20','5'):
		for key in controllers_info:
			if controllers_info[key][0] != 'vbond':
				ntp_data = json.loads(getRequest(version_tuple, vmanage_lo_ip, jsessionid, 'device/ntp/associations?deviceId=%s'%(controllers_info[key][1]), args.vmanage_port, tokenid))
				if 'data' not in ntp_data.keys() or ntp_data['data'] == []:
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


#11:Check:vManage:Validate Neo4j Store version
def criticalCheckeighteen(version_tuple):

	if os.path.isfile('/var/log/nms/debug.log') == False:
		nodestore_version = 'unknown'
		check_result = 'Failed'
		check_analysis = '/var/log/nms/debug.log file not found'
		check_action = 'Investigate why the /var/log/nms/debug.log is missing'

	elif os.path.isfile('/var/log/nms/debug.log') == True:
		control_sum_tab = executeCommand('grep NodeStore /var/log/nms/debug.log')
		nodestore_version  = match(control_sum_tab,'(v\d|\D.\d)\.(\D|\d)\.(\d)' )
		if version_tuple[0:2] <= ('20','1') and 'v0.A.8' not in nodestore_version:
			check_result = 'Failed'
			check_analysis = 'The Neo4j Store version is {}, it should be v0.A.8.'.format(nodestore_version)
			check_action = 'Execute the following command to upgrade it: "request nms configuration-db upgrade"'
		elif version_tuple[0:2] >= ('20','3') and version_tuple[0:2] <= ('20','4') and 'v0.A.9' not in nodestore_version:
			check_result = 'Failed'
			check_analysis = 'The Neo4j Store version is {}, it should be v0.A.9.'.format(nodestore_version)
			check_action = 'Execute the following command to upgrade it: "request nms configuration-db upgrade"'
		elif version_tuple[0:2] >= ('20','5') and version_tuple[0:2] <= ('20','6') and 'SF4.0.0' not in nodestore_version:
			check_result = 'Failed'
			check_analysis = 'The Neo4j Store version is {}, it should be SF4.0.0.'.format(nodestore_version)
			check_action = 'Execute the following command to upgrade it: "request nms configuration-db upgrade"'
		else:
			check_result = 'SUCCESSFUL'
			check_analysis = 'The Neo4j Store version is {} and it is up to date.'.format(nodestore_version)
			check_action = None

	return nodestore_version, check_result, check_analysis, check_action

#12:Check:vManage:Validate ConfigDB Size is less than 5GB
def criticalChecknineteen():
	db_data = showCommand('request nms configuration-db diagnostics')
	if 'Disk space used by configuration' in db_data:
		db_size = db_data.split('\n')[-2]
		db_size = match(db_size, '\d+\.?\d*[BKMGT]')
		if db_size[-1] == 'M' and float(db_size[0:-1])/1000 >= 5.0:
			check_result = 'Failed'
			check_analysis = 'ConfigDB size is high, and that a DB clean up is needed'
			check_action = 'Contact TAC  to do DB cleanup'
		elif db_size[-1] == 'G' and float(db_size[0:-1]) >= 5.0:
			check_result = 'Failed'
			check_analysis = 'ConfigDB size is high, and that a DB clean up is needed'
			check_action = 'Contact TAC  to do DB cleanup'
		elif db_size[-1] == 'T' and float(db_size[0:-1])*1000 >= 5.0:
			check_result = 'Failed'
			check_analysis = 'ConfigDB size is high, and that a DB clean up is needed'
			check_action = 'Contact TAC  to do DB cleanup'
		else:
			check_result = 'SUCCESSFUL'
			check_analysis = 'The ConfigDB size is {} which is within limits i.e less than 5GB'.format(db_size)
			check_action = None
	else:
		db_size = 'unknown'
		check_result = 'Failed'
		check_analysis = 'Error retrieving the ConfigDB size.'
		check_action = 'Investigate why the command (request nms configuration-db diagnostics) is not returning appropriate data.'

	return db_size, check_result, check_analysis, check_action

#13:Check:Controllers:Validate vSmart/vBond CPU count for scale
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

#14:Check:Cluster:Version consistency
def criticalChecktwelve(vmanage_info):
	for vmanage in vmanage_info:
		version = []
		version.append(vmanage_info[vmanage][2])
	if len(set(version)) == 1:
		check_result = 'SUCCESSFUL'
		check_analysis = 'All the servers on the cluster have same version'
		check_action = 'None'
	else:
		check_result = 'Failed'
		check_analysis = 'Version in use across  all the servers in the cluster is not consistent'
		check_action = 'Evaluate if specific server should be upgraded before attempting overlay full upgrade'
	return check_result,check_analysis, check_action

#15:Check:Cluster:Cluster health
def criticalCheckthirteen(vmanage_service_details):
	services_down = []
	'''
	for device in cluster_health_data['data'][0]['data']:
		if 'deviceIP' in device['configJson'].keys(): (device['configJson'].pop('deviceIP'))
		if 'system-ip' in device['configJson'].keys(): (device['configJson'].pop('system-ip'))
		if 'uuid' in device['configJson'].keys(): (device['configJson'].pop('uuid'))
		if 'host-name' in device['configJson'].keys(): (device['configJson'].pop('host-name'))
		if 'state' in device['configJson'].keys(): (device['configJson'].pop('state'))

		for service in device['configJson']:
			if device['configJson'][service]['status'] != 'normal' and device['configJson'][service]['status'] != 'disabled':
				services_down.append('vManageID:{} service: {}'.format(device['vmanageID'], service))
	'''
	if vmanage_service_details:
		for vmanage_cluster_ip, service_details in vmanage_service_details.items():
			for service in service_details:
				if service['enabled'] == "true" and 'running' not in service['status']:
					services_down.append('vManage:{} service: {}'.format(vmanage_cluster_ip, service['service']))
				else:
					continue
	else:
		services_down = 'unknown'

	if services_down == 'unknown':
		check_result = 'Failed'
		check_analysis = 'Error retrieving vManage service details.'
		check_action = 'Troubleshoot why '
	elif len(services_down) != 0:
		check_result = 'Failed'
		check_analysis = 'The cluster has relevant services down'
		check_action = 'Troubleshoot why specific services are as down on a server'
	elif len(services_down) == 0:
		check_result = 'SUCCESSFUL'
		check_analysis = 'The cluster has all relevant services up and running'
		check_action = 'None'
	return services_down, check_result,check_analysis, check_action

#16:Check:Cluster:Cluster ConfigDB topology
def criticalCheckfourteen(vmanage_service_details):
	configDB_count = 0
	'''
	for device in cluster_health_data['data'][0]['data']:
		for service in device['configJson']:
			if (service == 'configuration-db'):
				configDB_count+=1
	'''
	if vmanage_service_details:
		for vmanage_cluster_ip, service_details in vmanage_service_details.items():
			for service in service_details:
				if ('configuration database' in service['service']) and service['enabled'] == "true" and 'running' in service['status']:
					configDB_count+=1
				else:
					continue
	else:
		configDB_count = 'unknown'

	if configDB_count == 'unkown':
		check_result = 'Failed'
		check_analysis = 'Error retrieving the number of configDB servers on the cluster'
		check_action = 'Investigate why the API is not returning vManage service information'
	elif (configDB_count % 2) == 0:
		check_result = 'Failed'
		check_analysis = 'The cluster has even number of configDB servers'
		check_action = ' Cluster is not on a supported configuration. Modify cluster to have odd number of configDB owners (1,3,5) '
	else:
		check_result = 'SUCCESSFUL'
		check_analysis = 'The cluster has odd number of configDB servers'
		check_action = None
	return configDB_count,check_result,check_analysis, check_action

#17:Check:Cluster:Messaging server
def criticalCheckfifteen(vmanage_service_details, cluster_size):
	cluster_msdown = []
	'''
	for device in cluster_health_data['data'][0]['data']:
		for service in device['configJson']:
			if (service == 'messaging-server') and device['configJson'][service]['status'] != 'normal' and device['configJson'][service]['status'] != 'disabled':
				cluster_msdown.append('vManageID: {}, Host-name: {}'.format(device['vmanageID'],device['configJson']['host-name']))
	'''
	if vmanage_service_details:
		for vmanage_cluster_ip, service_details in vmanage_service_details.items():
			for service in service_details:
				if 'messaging server' in service['service'] and service['enabled'] == "true" and 'running' in service['status']:
					cluster_msdown.append('vManage device IP: {}'.format(vmanage_cluster_ip))
				else:
					continue
	else:
		cluster_msdown = 'unknown'

	if cluster_msdown == 'unkown':
		check_result = 'Failed'
		check_analysis = 'Error retrieving the NMS Messaging server information'
		check_action = 'Investigate why the API is not returning vManage Messaging server information'
	if len(cluster_msdown) < cluster_size:
		check_result = 'Failed'
		check_analysis = 'All the servers in the cluster dont have message-service running'
		check_action = 'Cluster is not on a supported configuration. Modify cluster to have messaging server running '
	elif len(cluster_msdown) == cluster_size:
		check_result = 'SUCCESSFUL'
		check_analysis = 'All the servers in the cluster have message-service running'
		check_action = None
	return cluster_msdown,check_result,check_analysis, check_action


#18:Check:Cluster:DR replication status
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

#19:Check:Cluster:Intercluster communication
# 
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
		'''
		my_hostname = socket.gethostname()
		for device in cluster_health_data['data'][0]['data']:
			vmanage_cluster_ip = device['configJson']['deviceIP']
			vmanage_host_name = device['configJson']['host-name']
			#if vmanage_host_name != my_hostname:
		'''
		count = 0
		for device in cluster_health_data['data']:
			count += 1
			vmanage_system_ip = device['system-ip']
			vmanage_cluster_ip = device['deviceIP']
			if vmanage_system_ip != system_ip:
				output = executeCommand('ping -w 5 {} &'.format(vmanage_cluster_ip))
				output = output.split('\n')[-3:]
				xmit_stats = output[0].split(",")
				timing_stats = xmit_stats[3]
				packet_loss = float(xmit_stats[2].split("%")[0])
				ping_output[count] = vmanage_cluster_ip, packet_loss, timing_stats
				if packet_loss != 0:
					ping_output_failed[count] = vmanage_cluster_ip, packet_loss, timing_stats
			else:
				continue

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

#20:Check:vManage:Validate Server Configs file - uuid
def criticalChecktwenty(version):
	success, analysis = validateServerConfigsUUID()
	if not success:
		check_result = 'Failed'
		check_analysis = 'Failed to validate uuid from server configs file.'
		check_action = '{}'.format(analysis)
		check_action = '{}'.format(analysis)
	else:
		check_result = 'SUCCESSFUL'
		check_analysis = 'Validated the uuid from server configs file.'
		check_action = None
		log_file_logger.info('Validated the uuid from server configs file.')

	return check_result, check_analysis, check_action

#21:Check:vManage:Validate server_configs.json
def criticalChecktwentyone(version):
	success, analysis, action = validateServerConfigsFile()
	if not success:
		check_result = 'Failed'
		check_analysis = 'Failed to validate the server_configs.json.'
		check_action = '{}'.format(analysis)
	else:
		check_result = 'SUCCESSFUL'
		check_analysis = 'Validated the server_configs.json.'
		check_action = None
		log_file_logger.info('Validated the server_configs.json.')

	return check_result, check_analysis, check_action

#22:Check:vManage:Validate UUID
def criticalChecktwentytwo(version):
	success, analysis = isValidUUID()
	if not success:
		check_result = 'Failed'
		check_analysis = 'Failed to validate UUID at /etc/viptela/uuid.'
		check_action = '{}'.format(analysis)
	else:
		check_result = 'SUCCESSFUL'
		check_analysis = 'UUID is valid.'
		check_action = None
		log_file_logger.info('Validated the uuid at /etc/viptela/uuid.')

	return check_result, check_analysis, check_action

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
	if controllers_info != {}:
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
	else:
		check_result = 'Failed'
		check_analysis = 'No controllers found'
		check_action = None

	return check_result, check_analysis, check_action


#08:Check:Controllers:Confirm Certificate Expiration Dates
def warningCheckeight(controllers_info):
	controllers_exp = {}
	controllers_notexp = {}
	for controller in controllers_info:
		try:
			time_remaining = timedelta(seconds=controllers_info[controller][5])
			if timedelta(seconds=controllers_info[controller][5]) <= timedelta(seconds=2592000):
				controllers_exp[controller] = str(time_remaining)
			elif timedelta(seconds=controllers_info[controller][5]) > timedelta(seconds=2592000):
				controllers_notexp[controller] = str(time_remaining)
		except:
			controllers_exp[controller] = 'uknown'
	if len(controllers_exp) == 0:
		check_result = 'SUCCESSFUL'
		check_analysis = 'Certificates are ok'
		check_action = None
	elif 'unknown' in controllers_exp.values():
		check_result = 'Failed'
		check_analysis = 'Error retrieving in Certificates timeRemainingForExpiration details'
		check_action = 'Identify if certificates are installed on all controllers and if installed why the API is not returning Certificates timeRemainingForExpiration details'
	elif len(controllers_exp) != 0:
		check_result = 'Failed'
		check_analysis = 'Controllers with certificates close to expiration present'
		check_action = 'Renew respective certificates'
	return controllers_exp, controllers_notexp, check_result, check_analysis, check_action


#09:Check:Controllers:vEdge list sync
def warningChecknine(controllers_info):
	state_vedgeList = []
	novedge = []
	for controller in controllers_info:
		if controllers_info[controller][6] != 'Sync' and controllers_info[controller][6] != 'no-vedges':
			state_vedgeList.append([controller, controllers_info[controller][0], controllers_info[controller][1]])
		elif controllers_info[controller][6] == 'no-vedges':
			novedge.append([controller, controllers_info[controller][0], controllers_info[controller][1]])

	if novedge != [] and state_vedgeList == [] :
		check_result = 'SUCCESSFUL'
		check_analysis = 'No edge devices found and hence all the controllers do not have consistent state_vedgeList'
		check_action = None
	elif state_vedgeList == [] and novedge == [] :
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
		#only check vsmart count in first instance, and vbonds in all
		if (instance['instance'] ==0):
			if (instance['vbond_counts']) != vbond_count or (instance['vsmart_counts']) != vsmart_count:
				discrepancy.append(instance)
		else:
			if (instance['vbond_counts']) != vbond_count :
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
	else:
		check_result = 'Failed'
		check_analysis = 'Unable to identify the Disk controller type.'
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
	
# This function is not used in version less than 20.5
#04:Check:vManage:Persona type: COMPUTE/DATA/COMPUTE_AND_DATA
# def infoCheckfour(version):
# 	#vmanage version
# 	vmanage_version = float('.'.join((version.split('.'))[0:2]))
# 	check_result = 'SUCCESSFUL'
# 	check_analysis = 'Check is not required for the current version'
# 	check_action = None
# 	return check_result, check_analysis, check_action, persona_type

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

def pre_check(log_file_logger, check_name):
				log_file_logger.info('{}'.format(check_name))
				writeFile(report_file, '{}\n\n'.format(check_name))

def zfill_converter(check_count):
	check_count = str(check_count).zfill(2)
	return check_count

def check_error_logger(log_file_logger, check_result, check_analysis, check_count):
	log_file_logger.error('#{}: Check result:   {}'.format(check_count, check_result))
	log_file_logger.error('#{}: Check Analysis: {}'.format(check_count, check_analysis))

def check_info_logger(log_file_logger, check_result, check_analysis, check_count):
	log_file_logger.info('#{}: Check result:   {}'.format(check_count, check_result))
	log_file_logger.info('#{}: Check Analysis: {}'.format(check_count, check_analysis))


def check_error_report(check_analysis,check_action ):
	writeFile(report_file, 'Result: ERROR - {}\n'.format(check_analysis))
	writeFile(report_file, 'Action: {}\n\n'.format(check_action))
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>


if __name__ == "__main__":
	start_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
	json_final_result = {}
	result_log = {'Critical': {'SUCCESSFUL':'INFO', 'Failed':'ERROR'},
			  'Warning': {'SUCCESSFUL':'INFO', 'Failed':'WARNING'},
			  'Informational': {'SUCCESSFUL':'INFO', 'Failed':'WARNING'}}

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

	json_final_result = {}
	json_final_result['json_data_pdf'] = {}
	json_final_result['json_data_pdf']['title'] =  "AURA SDWAN Report"
	json_final_result['json_data_pdf']['information'] =  {"disclaimer":"Cisco SDWAN AURA command line tool performes a total of 26(Non Cluster Mode) or 32(Cluster Mode) checks at different levels of the SDWAN overlay.",
															"AURA Version":"{}".format(__sure_version)}
	json_final_result['json_data_pdf']['feedback'] = "sure-tool@cisco.com"

	writeFile(report_file, 'Cisco SDWAN AURA v{} Report\n\n'.format(__sure_version))
	writeFile(report_file,  '''Cisco SDWAN AURA command line tool performes a total of 26(Non Cluster Mode) or 32(Cluster Mode) checks at different levels of the SDWAN overlay.
							 \nReach out to sure-tool@cisco.com  if you have any questions or feedback\n\n''')
	writeFile(report_file, 'Summary of the Results:\n')
	writeFile(report_file, '-----------------------------------------------------------------------------------------------------------------\n\n\n')



	print('#########################################################')
	print('###      AURA SDWAN (SURE) - Version {}            ###'.format(__sure_version))
	print('#########################################################')
	print('###    Performing SD-WAN Audit & Upgrade Readiness    ###')
	print('#########################################################\n\n')

	check_count = 0
	json_final_result['json_data_pdf']['description'] = {}
	json_final_result['json_data_pdf']['description']['vManage'] = []
	json_final_result['json_data_pdf']['description']['Controllers'] = []
	json_final_result['json_data_pdf']['description']['Cluster'] = []

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
				#print(json.loads(getRequest(version_tuple, vmanage_lo_ip , jsessionid,'device/vmanage', args.vmanage_port)))
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
				json_final_result['json_data_pdf']['vmanage execution info'] = {"vManage Details":{
																					"Software Version":"{}".format(version),
																					"System IP Address":"{}".format(system_ip)

																		 }}
				if cluster_size > 1:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'clusterManagement/health/details', args.vmanage_port))
					vmanage_cluster_ips = vmanage_cluster_ips(cluster_health_data)
					vmanage_service_details = vmanage_service_details(vmanage_cluster_ips)
					log_file_logger.info('deviceIPs of vManages in the cluster: {}'.format(vmanage_cluster_ips))
					#log_file_logger.info('Service details of all vManages in the cluster: {}'.format(vmanage_service_details))

			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error Collecting Preliminary Data. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))

			print('*Starting Checks, this may take several minutes')



			#Critical Checks
			critical_checks = {}
			log_file_logger.info('*** Performing Critical Checks\n')
			print('\n**** Performing Critical checks\n')

			#Beginning #Check:Cluster:Intercluster communication  in the background
			if cluster_size>1:
				log_file_logger.info('Beginging Check:Cluster:Intercluster communication  in the background\n')
				try:
					criticalCheckseventeen =  criticalCheckseventeen(cluster_health_data,  system_ip, log_file_logger)
				except Exception as e:
					log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Validate current version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate current version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				boot_partition_size, check_result, check_analysis, check_action =  criticalCheckone(version)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: version: {}'.format(check_count_zfill, version))
					log_file_logger.error('#{}: Boot Partition Size: {}\n'.format(check_count_zfill, boot_partition_size))
					check_error_report(check_analysis,check_action )
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: version: {}'.format(check_count_zfill, version))
					log_file_logger.info('#{}: Boot Partition Size: {}\n'.format(check_count_zfill, boot_partition_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																	 'log type': '{}'.format(result_log['Critical'][check_result]),
																	 'result': '{}'.format(check_analysis),
																	 'action': '{}'.format(check_action),
																	 'status': '{}'.format(check_result),
																	 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:vManage:At minimum 20%  server disk space should be available
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:At minimum 20%  server disk space should be available'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				optdata_partition_size, rootfs_partition_size, check_result, check_analysis, check_action =  criticalCheckTwo()
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: /opt/data Used: {}'.format(check_count_zfill, optdata_partition_size))
					log_file_logger.error('#{}: /rootfs.rw Used: {}\n'.format(check_count_zfill, rootfs_partition_size))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: /opt/data Used: {}'.format(check_count_zfill, optdata_partition_size))
					log_file_logger.info('#{}: /rootfs.rw Used: {}\n'.format(check_count_zfill, rootfs_partition_size))
					writeFile(report_file, 'Result: INFO -  {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																	 'log type': '{}'.format(result_log['Critical'][check_result]),
																	 'result': '{}'.format(check_analysis),
																	 'action': '{}'.format(check_action),
																	 'status': '{}'.format(check_result),
																	 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#Check:vManage:Memory size
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Memory size'.format(check_count_zfill)
			pre_check(log_file_logger,check_name)
			writeFile(report_file, 'Link to the official documentation: \n https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html\n\n')
			try:
				memory_size, memory_size_str, dpi_status, server_type, check_result, check_analysis, check_action =  criticalCheckthree(vedge_count, dpi_status, server_type, cluster_size, version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Memory Size GB: {}'.format(check_count_zfill, memory_size_str))
					log_file_logger.error('#{}: /rootfs.rw Used: {}'.format(check_count_zfill, rootfs_partition_size))
					log_file_logger.error('#{}: Server Type: {}'.format(check_count_zfill, server_type))
					log_file_logger.error('#{}: vEdge Count: {}\n'.format(check_count_zfill, vedge_count))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																	 'log type': ''.format(result_log['Critical'][check_result]),
																	 'result': '{}'.format(check_analysis),
																	 'action': '{}'.format(check_action),
																	 'status': '{}'.format(check_result),
																	 'document': 'https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html'})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:CPU Count
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:CPU Count'.format(check_count_zfill)
			pre_check(log_file_logger,check_name)
			try:
				check_result, check_analysis, check_action = criticalCheckfour(cpu_count, vedge_count, dpi_status, server_type)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: CPU Count: {}\n'.format(check_count_zfill, cpu_count))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': '',})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:ElasticSearch Indices status
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:ElasticSearch Indices status'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)

			try:
				#es_indices_one = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'management/elasticsearch/index/info', args.vmanage_port))
				es_indices = es_indices_details()
				es_index_red_one, check_result_one, check_analysis_one, check_action_one = criticalCheckfive(es_indices)
				time.sleep(5)
				es_indices = es_indices_details()
				#es_indices_two = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'management/elasticsearch/index/info', args.vmanage_port))
				es_index_red_two, check_result_two, check_analysis_two, check_action_two = criticalCheckfive(es_indices)
				if check_result_one == 'Failed' and check_result_two == 'Failed':
					critical_checks[check_name] = [ check_analysis_two, check_action_two]
					check_error_logger(log_file_logger, check_result_two, check_analysis_two, check_count_zfill)
					check_error_report(check_analysis_two,check_action_two)
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																	 'log type': '{}'.format(result_log['Critical'][check_result_two]),
																	 'result': '{}'.format(check_analysis_two),
																	 'action': '{}'.format(check_action_two),
																	 'status': '{}'.format(check_result_two),
																	 'document': '',})
				elif check_result_one == 'SUCCESSFUL':
					check_info_logger(log_file_logger, check_result_one, check_analysis_one, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_one))
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																	 'log type': '{}'.format(result_log['Critical'][check_result_one]),
																	 'result': '{}'.format(check_analysis_one),
																	 'action': '{}'.format(check_action_one),
																	 'status': '{}'.format(check_result_one),
																	 'document': '',})
				elif check_result_two == 'SUCCESSFUL':
					check_info_logger(log_file_logger, check_result_two, check_analysis_two, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_two))
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																	 'log type': '{}'.format(result_log['Critical'][check_result_two]),
																	 'result': '{}'.format(check_analysis_two),
																	 'action': '{}'.format(check_action_two),
																	 'status': '{}'.format(check_result_two),
																	 'document': '',})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Look for any neo4j exception errors
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Look for any neo4j exception errors'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)

			try:
				check_result, check_analysis, check_action = criticalChecksix(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': '',})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Validate all services are up
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate all services are up'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				nms_data, nms_failed, check_result, check_analysis, check_action =   criticalCheckseven()
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: List of services that are enabled but not running:\n{}\n'.format(check_count_zfill, nms_failed))
					log_file_logger.error('#{}: Status of all services  :\n{}\n'.format(check_count_zfill, nms_data))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Status of all the services:\n{}\n'.format(check_count_zfill, nms_data))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name,log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Elasticsearch Indices version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Elasticsearch Indices version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				version_list, check_result, check_analysis, check_action = criticalCheckeight(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: List of indices with older versions  :\n{}\n'.format(check_count_zfill, version_list))
					check_error_report(check_analysis,check_action)

				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Evaluate incoming DPI data size
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Evaluate incoming DPI data size'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				es_indices_est = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'management/elasticsearch/index/size/estimate', args.vmanage_port))
				appr_estimate_ondeday, dpi_estimate_ondeday, check_result,check_analysis,check_action = criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count, total_devices, dpi_status)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Daily incoming DPI data : {}'.format(check_count_zfill, dpi_estimate_ondeday))
					log_file_logger.error('#{}: Daily incoming Approute data : {}\n'.format(check_count_zfill, appr_estimate_ondeday))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:NTP status across network
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:NTP status across network'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				ntp_nonworking, check_result, check_analysis, check_action = criticalCheckten(version_tuple, controllers_info)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Devices with invalid ntp associations:\n{}\n'.format(check_count_zfill, ntp_nonworking))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Validate Neo4j Store version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate Neo4j Store version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				nodestore_version, check_result, check_analysis, check_action = criticalCheckeighteen(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Neo4j Store version: {}\n'.format(check_count_zfill, nodestore_version))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Neo4j Store version: {}\n'.format(check_count_zfill, nodestore_version))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Validate ConfigDB Size is less than 5GB
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate ConfigDB Size is less than 5GB'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				db_size, check_result, check_analysis, check_action = criticalChecknineteen()
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: ConfigDB Size: {}\n'.format(check_count_zfill, db_size))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: ConfigDB Size: {}\n'.format(check_count_zfill, db_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers:Validate vSmart/vBond CPU count for scale
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Validate vSmart/vBond CPU count for scale'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				for vbond in vbond_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip, jsessionid,'device/system/synced/status?deviceId={}'.format(vbond_info[vbond][1]),args.vmanage_port ))
					if output['data'] != []:
							total_cpu_count = int(output['data'][0]['total_cpu_count'])
					else:
						total_cpu_count = 0
					vbond_info[vbond].append(total_cpu_count)

				for vsmart in vsmart_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip,jsessionid,'device/system/synced/status?deviceId={}'.format(vsmart_info[vsmart][1]), args.vmanage_port))
					if output['data'] != []:
							total_cpu_count = int(output['data'][0]['total_cpu_count'])
					else:
						total_cpu_count = 0
					vsmart_info[vsmart].append(total_cpu_count)

				failed_vbonds,failed_vsmarts,check_result,check_analysis, check_action = criticalCheckeleven(total_devices, vbond_info, vsmart_info)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: vBonds with insufficient CPU count: \n{}'.format(check_count_zfill, failed_vbonds))
					log_file_logger.error('#{}: vSmarts with insufficient CPU count: \n{}'.format(check_count_zfill, failed_vsmarts))
					log_file_logger.error('#{}: All vBonds info with total_cpu_count: \n{}'.format(check_count_zfill, vbond_info))
					log_file_logger.error('#{}: All vSmarts info with total_cpu_count: \n{}\n'.format(check_count_zfill, vsmart_info))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: All vBonds info with total_cpu_count:\n{}'.format(check_count_zfill, vbond_info))
					log_file_logger.info('#{}: All vSmarts info with total_cpu_count:\n{}\n'.format(check_count_zfill, vsmart_info))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Warning Checks
			print('\n**** Performing Warning checks\n')
			warning_checks = {}
			log_file_logger.info('*** Performing Warning Checks')

			#Check:vManage:CPU Speed
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Warning Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:CPU Speed'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result,check_analysis,check_action = warningCheckone(cpu_speed)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: CPU clock speed: {}\n'.format(check_count_zfill, cpu_speed))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Warning'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Network Card type
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Warning Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Network Card type'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				eth_drivers, check_action, check_analysis, check_result = warningChecktwo()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Ethercardswith e1000 card types: {}\n'.format(check_count_zfill, eth_drivers))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Warning'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Backup status
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Warning Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Backup status'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				date_time_obj, check_result, check_analysis, check_action = warningCheckthree()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Last Backup was performed on:{}\n'.format(check_count_zfill, date_time_obj))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Warning'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Evaluate Neo4j performance
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Warning Check:#16'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Evaluate Neo4j performance'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = warningCheckfour()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Warning'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Confirm there are no pending tasks
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Warning Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Confirm there are no pending tasks'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				tasks = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'device/action/status/tasks', args.vmanage_port))
				tasks_running, check_result, check_analysis, check_action  = warningCheckfive(tasks)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Tasks still running: {}\n'.format(check_count_zfill, tasks_running))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Warning'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Validate there are no empty password users
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Warning Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate there are no empty password users'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				users_emptypass, check_result, check_analysis, check_action = warningChecksix(version_tuple)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Users with empty passwords: {}\n'.format(check_count_zfill, users_emptypass))
					check_error_report(check_analysis,check_action)

				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Warning'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:Controller versions
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Warning Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Controller versions'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = warningCheckseven(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Warning'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers:Confirm Certificate Expiration Dates
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Warning Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Confirm Certificate Expiration Dates'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				controllers_exp, controllers_notexp, check_result, check_analysis, check_action = warningCheckeight(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Controllers with certificates close to expiration:\n{}\n'.format(check_count_zfill, controllers_exp))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Warning'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers:vEdge list sync
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Warning Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:vEdge list sync'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				state_vedgeList,check_result, check_analysis, check_action  = warningChecknine(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Controllers with inconsistent state_vedgeList: {}\n'.format(check_count_zfill, state_vedgeList))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Warning'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers: Confirm control connections
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Warning Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers: Confirm control connections'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)

			try:
				control_sum_tab, discrepancy,check_result, check_analysis, check_action = warningCheckten(vsmart_count, vbond_count)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Control Connections Summary\n{}\n'.format(check_count_zfill, control_sum_tab))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Warning'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Informational Checks
			print('\n**** Performing Informational checks\n')
			log_file_logger.info('*** Performing Informational Checks')

			#Check:vManage:Disk controller type
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Informational Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Disk controller type'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = infoCheckone(server_type, disk_controller)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Disk Controller type: {}\n'.format(check_count_zfill, disk_controller))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Disk Controller type: {}\n'.format(disk_controller))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Informational'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:Validate there is at minimum vBond, vSmart present
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Informational Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Validate there is at minimum vBond, vSmart present'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = infoChecktwo(vsmart_count,vbond_count)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: vSmart Count: {}'.format(check_count_zfill, vsmart_count))
					log_file_logger.error('#{}: vBond Count: {}\n'.format(check_count_zfill, vbond_count))
					check_error_report(check_analysis,check_action)

				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: vSmart Count: {}'.format(check_count_zfill, vsmart_count))
					log_file_logger.info('#{}: vBond Count: {}\n'.format(check_count_zfill, vbond_count))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Informational'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers:Validate all controllers are reachable
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Informational Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Validate all controllers are reachable'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				unreach_controllers,check_result, check_analysis, check_action = infoChecktthree(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Unreachable Controllers: {}\n'.format(check_count_zfill, unreach_controllers))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Informational'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			if cluster_size>1:
				cluster_checks = {}
				log_file_logger.info('*** Performing Cluster Checks')
				print('\n**** Performing Cluster checks\n')

				#Check:Cluster:Version consistency
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' Cluster Check:#{}'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Version consistency'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					check_result,check_analysis, check_action = criticalChecktwelve(vmanage_info)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: vManage info: {}\n'.format(check_count_zfill, vmanage_info))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.info('#{}: vManage info: {}\n'.format(check_count_zfill, vmanage_info))
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#Check:Cluster:Cluster health
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' Cluster Check:#{}'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Cluster health'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					services_down, check_result, check_analysis, check_action = criticalCheckthirteen(vmanage_service_details)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: Relevant cluster services that are down: {}\n'.format(check_count_zfill, services_down))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})

				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#Check:Cluster:Cluster ConfigDB topology
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' Cluster Check:#{}'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Cluster ConfigDB topology'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					configDB_count, check_result, check_analysis, check_action = criticalCheckfourteen(vmanage_service_details)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: No. of configDB servers in the cluster: {}\n'.format(check_count_zfill, configDB_count))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.info('#{}: No. of configDB servers in the cluster: {}\n'.format(check_count_zfill, configDB_count))
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})

				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#Check:Cluster:Messaging server
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' Cluster Check:#{}'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Messaging server'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					cluster_msdown,check_result,check_analysis, check_action = criticalCheckfifteen(vmanage_service_details, cluster_size)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: Servers with messaging service down: {}\n'.format(check_count_zfill, cluster_msdown))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})

				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#Check:Cluster:DR replication status
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' Cluster Check:#{}'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:DR replication status'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					dr_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'disasterrecovery/details', args.vmanage_port))
					dr_status, check_action, check_analysis, check_result = criticalChecksixteen(dr_data)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: DR Replication status: {}\n'.format(check_count_zfill, dr_status))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})

				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#Check:Cluster:Intercluster communication
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' Cluster Check:#{}'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Intercluster communication'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					if criticalCheckseventeen.is_alive():
						criticalCheckseventeen.join(10)

					if not criticalCheckseventeen.result_queue.empty():
						ping_output, ping_output_failed, check_result, check_analysis, check_action = criticalCheckseventeen.result_queue.get()
						if check_result == 'Failed':
							cluster_checks[check_name] = [ check_analysis, check_action]
							check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
							log_file_logger.error('#{}: Cluster nodes with ping failure: {}\n'.format(check_count_zfill, ping_output_failed))
							check_error_report(check_analysis,check_action)

						else:
							check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
							log_file_logger.info('#{}: Cluster nodes details: {}\n'.format(check_count_zfill, ping_output))

							writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})

				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
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
				json_final_result['json_data_pdf']['vmanage execution info'] = {"vManage Details":{
																					"Software Version":"{}".format(version),
																					"System IP Address":"{}".format(system_ip)
																				 }}
				if cluster_size > 1:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'clusterManagement/health/details', args.vmanage_port, tokenid))
					vmanage_cluster_ips = vmanage_cluster_ips(cluster_health_data)
					vmanage_service_details = vmanage_service_details(vmanage_cluster_ips)
					log_file_logger.info('deviceIPs of vManages in the cluster: {}'.format(vmanage_cluster_ips))
					#log_file_logger.info('Service details of all vManages in the cluster: {}'.format(vmanage_service_details))

			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error Collecting Preliminary Data. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))


			print('*Starting Checks, this may take several minutes\n\n')

			#Critical Checks
			print('\n**** Performing Critical checks\n')

			#Beginning #Check:Cluster:Intercluster communication  in the background
			if cluster_size>1:
				log_file_logger.info('Beginging #Check:Cluster:Intercluster communication  in the background\n')
				try:
					criticalCheckseventeen =  criticalCheckseventeen(cluster_health_data,  system_ip, log_file_logger)
				except Exception as e:
					log_file_logger.exception('{}\n'.format(e))

			critical_checks = {}
			log_file_logger.info('*** Performing Critical Checks\n')

			#Check:vManage:Validate current version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate current version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				boot_partition_size, check_result, check_analysis, check_action =  criticalCheckone(version)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: version: {}'.format(check_count_zfill, version))
					log_file_logger.error('#{}: Boot Partition Size: {}\n'.format(check_count_zfill, boot_partition_size))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: version: {}'.format(check_count_zfill, version))
					log_file_logger.info('#{}: Boot Partition Size: {}\n'.format(check_count_zfill, boot_partition_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:At minimum 20%  server disk space should be available
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:At minimum 20%  server disk space should be available'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				optdata_partition_size, rootfs_partition_size, check_result, check_analysis, check_action =  criticalCheckTwo()
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: /opt/data Used: {}'.format(check_count_zfill, optdata_partition_size))
					log_file_logger.error('#{}: /rootfs.rw Used: {}\n'.format(check_count_zfill, rootfs_partition_size))
					check_error_report(check_analysis,check_action)

				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: /opt/data Used: {}'.format(check_count_zfill, optdata_partition_size))
					log_file_logger.info('#{}: /rootfs.rw Used: {}\n'.format(check_count_zfill, rootfs_partition_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Memory size
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Memory size'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			writeFile(report_file, 'Link to the official documentation: \n https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html\n\n')
			try:
				memory_size, memory_size_str, dpi_status, server_type, check_result, check_analysis, check_action =  criticalCheckthree(vedge_count, dpi_status, server_type, cluster_size, version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Memory Size GB: {}'.format(check_count_zfill, memory_size_str))
					log_file_logger.error('#{}: /rootfs.rw Used: {}'.format(check_count_zfill, rootfs_partition_size))
					log_file_logger.error('#{}: Server Type: {}'.format(check_count_zfill, server_type))
					log_file_logger.error('#{}: vEdge Count: {}\n'.format(check_count_zfill, vedge_count))
					check_error_report(check_analysis,check_action)

				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': 'https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html'})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:CPU Count
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:CPU Count'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalCheckfour(cpu_count, vedge_count, dpi_status, server_type)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: CPU Count: {}\n'.format(check_count_zfill, cpu_count))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:ElasticSearch Indices status
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:ElasticSearch Indices status'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				#es_indices_one = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_indices = es_indices_details()
				es_index_red_one, check_result_one, check_analysis_one, check_action_one = criticalCheckfive(es_indices)
				time.sleep(5)
				#es_indices_two = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_indices = es_indices_details()
				es_index_red_two, check_result_two, check_analysis_two, check_action_two = criticalCheckfive(es_indices)

				if check_result_one == 'Failed' and check_result_two == 'Failed':
					critical_checks[check_name] = [ check_analysis_two, check_action_two]
					check_error_logger(log_file_logger, check_result_two, check_analysis_two, check_count_zfill)
					check_error_report(check_analysis_two,check_action_two)
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result_two]),
															 'result': '{}'.format(check_analysis_two),
															 'action': '{}'.format(check_action_two),
															 'status': '{}'.format(check_result_two),
															 'document': ''})
				elif check_result_one == 'SUCCESSFUL':
					check_info_logger(log_file_logger, check_result_one, check_analysis_one, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_one))
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result_one]),
															 'result': '{}'.format(check_analysis_one),
															 'action': '{}'.format(check_action_one),
															 'status': '{}'.format(check_result_one),
															 'document': ''})
				elif check_result_two == 'SUCCESSFUL':
					check_info_logger(log_file_logger, check_result_two, check_analysis_two, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_two))
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result_two]),
															 'result': '{}'.format(check_analysis_two),
															 'action': '{}'.format(check_action_two),
															 'status': '{}'.format(check_result_two),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Look for any neo4j exception errors
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Look for any neo4j exception errors'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalChecksix(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Validate all services are up
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate all services are up'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				nms_data, nms_failed, check_result, check_analysis, check_action = criticalCheckseven()
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: List of services that are enabled but not running:\n{}'.format(check_count_zfill, nms_failed))
					log_file_logger.error('#{}: Status of all services  :\n{}\n'.format(check_count_zfill, nms_data))
					check_error_report(check_analysis,check_action)

				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Status of all the services:\n{}\n'.format(check_count_zfill, nms_data))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Elasticsearch Indices version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Elasticsearch Indices version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				version_list, check_result, check_analysis, check_action = criticalCheckeight(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: List of indices with older versions  :\n{}\n'.format(check_count_zfill, version_list))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Evaluate incoming DPI data size
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Evaluate incoming DPI data size'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				es_indices_est = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'management/elasticsearch/index/size/estimate', args.vmanage_port, tokenid))
				appr_estimate_ondeday, dpi_estimate_ondeday, check_result, check_analysis,check_action = criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count , total_devices, dpi_status)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Daily incoming DPI data : {}'.format(check_count_zfill, dpi_estimate_ondeday))
					log_file_logger.error('#{}: Daily incoming Approute data : {}\n'.format(check_count_zfill, appr_estimate_ondeday))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:NTP status across network
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:NTP status across network'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				ntp_nonworking, check_result, check_analysis, check_action = criticalCheckten(version_tuple, controllers_info)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Devices with invalid ntp associations:\n{}\n'.format(check_count_zfill, ntp_nonworking))
					check_error_report(check_analysis,check_action)

				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Validate Neo4j Store version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate Neo4j Store version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				nodestore_version, check_result, check_analysis, check_action = criticalCheckeighteen(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Neo4j Store version: {}\n'.format(check_count_zfill, nodestore_version))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Neo4j Store version: {}\n'.format(check_count_zfill, nodestore_version))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing #{}:Check:vManage:Validate Neo4j Store version. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Validate ConfigDB Size is less than 5GB
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate ConfigDB Size is less than 5GB'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				db_size, check_result, check_analysis, check_action = criticalChecknineteen()
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: ConfigDB Size: {}\n'.format(check_count_zfill, db_size))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: ConfigDB Size: {}\n'.format(check_count_zfill, db_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:Validate vSmart/vBond CPU count for scale
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Validate vSmart/vBond CPU count for scale'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				for vbond in vbond_info:

					output = json.loads(getRequest( version_tuple,vmanage_lo_ip,jsessionid,'device/system/synced/status?deviceId={}'.format(vbond_info[vbond][1]),args.vmanage_port, tokenid))
					if output['data'] != []:
						total_cpu_count = int(output['data'][0]['total_cpu_count'])
					else:
						total_cpu_count = 0
					vbond_info[vbond].append(total_cpu_count)

				for vsmart in vsmart_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip,jsessionid,'device/system/synced/status?deviceId={}'.format(vsmart_info[vsmart][1]),args.vmanage_port,tokenid))
					if output['data'] != []:
						total_cpu_count = int(output['data'][0]['total_cpu_count'])
					else:
						total_cpu_count = 0
					vsmart_info[vsmart].append(total_cpu_count)

				failed_vbonds,failed_vsmarts,check_result,check_analysis, check_action = criticalCheckeleven(total_devices, vbond_info, vsmart_info)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: vBonds with insufficient CPU count:\n{}'.format(check_count_zfill, failed_vbonds))
					log_file_logger.error('#{}: vSmarts with insufficient CPU count:\n{}'.format(check_count_zfill, failed_vsmarts))
					log_file_logger.error('#{}: All vBonds info with total_cpu_count:\n{}'.format(check_count_zfill, vbond_info))
					log_file_logger.error('#{}: All vSmarts info with total_cpu_count:\n{}\n'.format(check_count_zfill, vsmart_info))
					check_error_report(check_analysis,check_action)

				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: All vBonds info with total_cpu_count:\n{}'.format(check_count_zfill, vbond_info))
					log_file_logger.info('#{}: All vSmarts info with total_cpu_count:\n{}\n'.format(check_count_zfill, vsmart_info))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			# Check:vManage:Validate server configs file - uuid
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate uuid from server configs file.'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalChecktwenty(version)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis, check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				json_final_result['json_data_pdf']['description']['vManage'].append(
					{'analysis type': '{}'.format(check_name.split(':')[-1]),
						'log type': '{}'.format(result_log['Critical'][check_result]),
						'result': '{}'.format(check_analysis),
						'action': '{}'.format(check_action),
						'status': '{}'.format(check_result),
						'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			# Check:vManage:Validate server_configs.json
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate server_configs.json'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalChecktwentyone(version)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis, check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				json_final_result['json_data_pdf']['description']['vManage'].append(
					{'analysis type': '{}'.format(check_name.split(':')[-1]),
						'log type': '{}'.format(result_log['Critical'][check_result]),
						'result': '{}'.format(check_analysis),
						'action': '{}'.format(check_action),
						'status': '{}'.format(check_result),
						'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			# Check:vManage:Validate UUID
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Critical Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate uuid at /etc/viptela/uuid'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalChecktwentytwo(version)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis, check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				json_final_result['json_data_pdf']['description']['vManage'].append(
					{'analysis type': '{}'.format(check_name.split(':')[-1]),
						'log type': '{}'.format(result_log['Critical'][check_result]),
						'result': '{}'.format(check_analysis),
						'action': '{}'.format(check_action),
						'status': '{}'.format(check_result),
						'document': ''})
			except Exception as e:
				print(
					'\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(
						check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Warning Checks
			print('\n**** Performing Warning checks\n')
			warning_checks = {}
			log_file_logger.info('*** Performing Warning Checks')

			#Check:vManage:CPU Speed
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Warning Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:CPU Speed'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result,check_analysis,check_action = warningCheckone(cpu_speed)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: CPU clock speed: {}\n'.format(check_count_zfill, cpu_speed))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Network Card type
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Warning Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Network Card type'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				eth_drivers, check_action, check_analysis, check_result = warningChecktwo()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Ethercardswith e1000 card types: {}\n'.format(check_count_zfill, eth_drivers))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Backup status
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Warning Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Backup status'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				date_time_obj, check_result, check_analysis, check_action = warningCheckthree()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Last Backup was performed on:{}\n'.format(check_count_zfill, date_time_obj))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Evaluate Neo4j performance
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Warning Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Evaluate Neo4j performance'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = warningCheckfour()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Confirm there are no pending tasks
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Warning Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Confirm there are no pending tasks'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				tasks = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'device/action/status/tasks', args.vmanage_port, tokenid))
				tasks_running, check_result, check_analysis, check_action  = warningCheckfive(tasks)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Tasks still running: {}\n'.format(check_count_zfill, tasks_running))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Validate there are no empty password users
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Warning Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate there are no empty password users'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				users_emptypass, check_result, check_analysis, check_action = warningChecksix(version_tuple)
				if check_result == 'Failed':
					warning_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Users with empty passwords: {}\n'.format(check_count_zfill, users_emptypass))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers:Controller versions
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Warning Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Controller versions'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = warningCheckseven(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers:Confirm Certificate Expiration Dates
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Warning Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Confirm Certificate Expiration Dates'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				controllers_exp, controllers_notexp, check_result, check_analysis, check_action = warningCheckeight(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Controllers with certificates close to expiration:\n{}\n'.format(check_count_zfill, controllers_exp))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:vEdge list sync
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Warning Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:vEdge list sync'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				state_vedgeList,check_result, check_analysis, check_action  = warningChecknine(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Controllers with inconsistent state_vedgeList: {}\n'.format(check_count_zfill, state_vedgeList))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing  {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers: Confirm control connections
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Warning Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers: Confirm control connections'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				control_sum_tab, discrepancy,check_result, check_analysis, check_action = warningCheckten(vsmart_count, vbond_count)
				if check_result == 'Failed':
					warning_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Control  Connections Summary:\n{}\n'.format(check_count_zfill, control_sum_tab))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Informational Checks
			print('\n**** Performing Informational checks\n')

			log_file_logger.info('*** Performing Informational Checks')

			#Check:vManage:Disk controller type
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Informational Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Disk controller type'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = infoCheckone(server_type, disk_controller)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Disk Controller type: {}\n'.format(check_count_zfill, disk_controller))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Disk Controller type: {}\n'.format(check_count_zfill, disk_controller))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Informational'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:Validate there is at minimum vBond, vSmart present
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Informational Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Validate there is at minimum vBond, vSmart present'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = infoChecktwo(vsmart_count,vbond_count)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: vSmart Count: {}'.format(check_count_zfill, vsmart_count))
					log_file_logger.error('#{}: vBond Count: {}\n'.format(check_count_zfill, vbond_count))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: vSmart Count: {}'.format(check_count_zfill, vsmart_count))
					log_file_logger.info('#{}: vBond Count: {}\n'.format(check_count_zfill, vbond_count))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Informational'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:Validate all controllers are reachable
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' Informational Check:#{}'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Validate all controllers are reachable'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				unreach_controllers,check_result, check_analysis, check_action = infoChecktthree(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Unreachable Controllers: {}\n'.format(check_count_zfill, unreach_controllers))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Informational'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			if cluster_size>1:
				cluster_checks = {}
				log_file_logger.info('*** Performing Cluster Checks')
				print('\n**** Performing Cluster checks\n')

				#Check:Cluster:Version consistency
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' Cluster Check:#{}'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Version consistency'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					check_result,check_analysis, check_action = criticalChecktwelve(vmanage_info)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: vManage info: {}\n'.format(check_count_zfill, vmanage_info))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.info('#{}: vManage info: {}\n'.format(check_count_zfill, vmanage_info))
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#Check:Cluster:Cluster health
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' Cluster Check:#{}'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Cluster health'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					services_down, check_result, check_analysis, check_action = criticalCheckthirteen(vmanage_service_details)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: Relevant cluster services that are down: {}\n'.format(check_count_zfill, services_down))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#Check:Cluster:Cluster ConfigDB topology
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' Cluster Check:#{}'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Cluster ConfigDB topology'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					configDB_count, check_result, check_analysis, check_action = criticalCheckfourteen(vmanage_service_details)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: No. of configDB servers in the cluster: {}\n'.format(check_count_zfill, configDB_count))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.info('#{}: No. of configDB servers in the cluster: {}\n'.format(check_count_zfill, configDB_count))
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#Check:Cluster:Messaging server
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' Cluster Check:#{}'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Messaging server'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					cluster_msdown,check_result,check_analysis, check_action = criticalCheckfifteen(vmanage_service_details, cluster_size)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: Servers with messaging service down: {}\n'.format(check_count_zfill, cluster_msdown))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#Check:Cluster:DR replication status
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' Cluster Check:#{}'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:DR replication status'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					dr_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'disasterrecovery/details', args.vmanage_port, tokenid))
					dr_status, check_action, check_analysis, check_result = criticalChecksixteen(dr_data)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: DR Replication status: {}\n'.format(check_count_zfill, dr_status))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#Check:Cluster:Intercluster communication
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' Cluster Check:#{}'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Intercluster communication'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					if criticalCheckseventeen.is_alive():
						criticalCheckseventeen.join(10)

					if not criticalCheckseventeen.result_queue.empty():
						ping_output, ping_output_failed, check_result, check_analysis, check_action = criticalCheckseventeen.result_queue.get()
						if check_result == 'Failed':
							cluster_checks[check_name] = [ check_analysis, check_action]
							check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
							log_file_logger.error('#{}: Cluster nodes with ping failure: {}\n'.format(check_count_zfill, ping_output_failed))
							check_error_report(check_analysis,check_action)
						else:
							check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
							log_file_logger.info('#{}: Cluster nodes details: {}\n'.format(check_count_zfill, ping_output))
							writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))

			#Logging out of the Session using jsessionid
			log_file_logger.info('Logging out of the Session')
			sessionLogout(vmanage_lo_ip, jsessionid, args.vmanage_port)
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
				json_final_result['json_data_pdf']['vmanage execution info'] = {"vManage Details":{
																					"Software Version":"{}".format(version),
																					"System IP Address":"{}".format(system_ip)
																				 }}
				if cluster_size > 1:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'clusterManagement/health/details', args.vmanage_port))
					vmanage_cluster_ips = vmanage_cluster_ips(cluster_health_data)
					vmanage_service_details = vmanage_service_details(vmanage_cluster_ips)
					log_file_logger.info('deviceIPs of vManages in the cluster: {}'.format(vmanage_cluster_ips))
					#log_file_logger.info('Service details of all vManages in the cluster: {}'.format(vmanage_service_details))

			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error Collecting Preliminary Data. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))


			print('*Starting Checks, this may take several minutes')

			#Critical Checks
			critical_checks = {}
			log_file_logger.info('*** Performing Critical Checks\n')

			#Beginning #Check:Cluster:Intercluster communication  in the background
			if cluster_size>1:
				log_file_logger.info('Beginging #Check:Cluster:Intercluster communication  in the background\n')
				try:
					criticalCheckseventeen =  criticalCheckseventeen(cluster_health_data,  system_ip, log_file_logger)
				except Exception as e:
					log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Validate current version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Validate current version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				boot_partition_size, check_result, check_analysis, check_action =  criticalCheckone(version)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: version: {}'.format(check_count_zfill, version))
					log_file_logger.error('#{}: Boot Partition Size: {}\n'.format(check_count_zfill, boot_partition_size))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: version: {}'.format(check_count_zfill, version))
					log_file_logger.info('#{}: Boot Partition Size: {}\n'.format(check_count_zfill, boot_partition_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:At minimum 20%  server disk space should be available
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:At minimum 20%  server disk space should be available'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				optdata_partition_size, rootfs_partition_size, check_result, check_analysis, check_action =  criticalCheckTwo()
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: /opt/data Used: {}'.format(check_count_zfill, optdata_partition_size))
					log_file_logger.error('#{}: /rootfs.rw Used: {}\n'.format(check_count_zfill, rootfs_partition_size))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: /opt/data Used: {}'.format(check_count_zfill, optdata_partition_size))
					log_file_logger.info('#{}: /rootfs.rw Used: {}\n'.format(check_count_zfill, rootfs_partition_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Memory size
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Memory size'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			writeFile(report_file, 'Link to the official documentation: \n https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html\n\n')
			try:
				memory_size, memory_size_str, dpi_status, server_type, check_result, check_analysis, check_action =  criticalCheckthree(vedge_count, dpi_status, server_type, cluster_size, version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Memory Size GB: {}'.format(check_count_zfill, memory_size_str))
					log_file_logger.error('#{}: /rootfs.rw Used: {}'.format(check_count_zfill, rootfs_partition_size))
					log_file_logger.error('#{}: Server Type: {}'.format(check_count_zfill, server_type))
					log_file_logger.error('#{}: vEdge Count: {}\n'.format(check_count_zfill, vedge_count))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': 'https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html'})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:CPU Count
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:CPU Count'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalCheckfour(cpu_count, vedge_count, dpi_status, server_type)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: CPU Count: {}\n'.format(check_count_zfill, cpu_count))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:ElasticSearch Indices status
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:ElasticSearch Indices status'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				#es_indices_one = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'management/elasticsearch/index/info', args.vmanage_port))
				es_indices = es_indices_details()
				es_index_red_one, check_result_one, check_analysis_one, check_action_one = criticalCheckfive(es_indices)
				time.sleep(5)
				#es_indices_two = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'management/elasticsearch/index/info', args.vmanage_port))
				es_indices = es_indices_details()
				es_index_red_two, check_result_two, check_analysis_two, check_action_two = criticalCheckfive(es_indices)

				if check_result_one == 'Failed' and check_result_two == 'Failed':
					critical_checks[check_name] = [ check_analysis_two, check_action_two]
					check_error_logger(log_file_logger, check_result_two, check_analysis_two, check_count_zfill)
					check_error_report(check_analysis_two, check_action_two)
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result_two]),
															 'result': '{}'.format(check_analysis_two),
															 'action': '{}'.format(check_action_two),
															 'status': '{}'.format(check_result_two),
															 'document': ''})
				elif check_result_one == 'SUCCESSFUL':
					check_info_logger(log_file_logger, check_result_one, check_analysis_one, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_one))
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result_one]),
															 'result': '{}'.format(check_analysis_one),
															 'action': '{}'.format(check_action_one),
															 'status': '{}'.format(check_result_one),
															 'document': ''})
				elif check_result_two == 'SUCCESSFUL':
					check_info_logger(log_file_logger, check_result_two, check_analysis_two, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_two))
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result_two]),
															 'result': '{}'.format(check_analysis_two),
															 'action': '{}'.format(check_action_two),
															 'status': '{}'.format(check_result_two),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Look for any neo4j exception errors
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Look for any neo4j exception errors'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalChecksix(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#Check:vManage:Validate all services are up
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Validate all services are up'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				nms_data, nms_failed, check_result, check_analysis, check_action =   criticalCheckseven()
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]

					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: List of services that are enabled but not running:\n\n {}\n\n'.format(check_count_zfill, nms_failed))
					log_file_logger.error('#{}: Status of all services  :\n{}\n'.format(check_count_zfill, nms_data))

					check_error_report(check_analysis,check_action)

				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Status of all the services:\n{}\n'.format(check_count_zfill, nms_data))

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Elasticsearch Indices version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Elasticsearch Indices version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				version_list, check_result, check_analysis, check_action = criticalCheckeight(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: List of indices with older versions  :\n{}\n'.format(check_count_zfill, version_list))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Evaluate incoming DPI data size
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Evaluate incoming DPI data size'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				es_indices_est = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid,'management/elasticsearch/index/size/estimate', args.vmanage_port))
				appr_estimate_ondeday, dpi_estimate_ondeday, check_result,check_analysis,check_action = criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count, total_devices, dpi_status)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Daily incoming DPI data : {}'.format(check_count_zfill, dpi_estimate_ondeday))
					log_file_logger.error('#{}: Daily incoming Approute data : {}\n'.format(check_count_zfill, appr_estimate_ondeday))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#Check:vManage:NTP status across network
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:NTP status across network'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				ntp_nonworking, check_result, check_analysis, check_action = criticalCheckten(version_tuple, controllers_info)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Devices with invalid ntp associations:\n{}\n'.format(check_count_zfill, ntp_nonworking))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Validate Neo4j Store version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Validate Neo4j Store version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				nodestore_version, check_result, check_analysis, check_action = criticalCheckeighteen(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Neo4j Store version: {}\n'.format(check_count_zfill, nodestore_version))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Neo4j Store version: {}\n'.format(check_count_zfill, nodestore_version))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Validate ConfigDB Size is less than 5GB
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Validate ConfigDB Size is less than 5GB '.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				db_size, check_result, check_analysis, check_action = criticalChecknineteen()
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: ConfigDB Size: {}\n'.format(check_count_zfill, db_size))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: ConfigDB Size: {}\n'.format(check_count_zfill, db_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers:Validate vSmart/vBond CPU count for scale
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:Controllers:Validate vSmart/vBond CPU count for scale'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				for vbond in vbond_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip, jsessionid,'device/system/synced/status?deviceId={}'.format(vbond_info[vbond][1]),args.vmanage_port ))
					if output['data'] != []:
						total_cpu_count = int(output['data'][0]['total_cpu_count'])
					else:
						total_cpu_count = 0
					vbond_info[vbond].append(total_cpu_count)

				for vsmart in vsmart_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip, jsessionid,'device/system/synced/status?deviceId={}'.format(vsmart_info[vsmart][1]), args.vmanage_port))
					if output['data'] != []:
						total_cpu_count = int(output['data'][0]['total_cpu_count'])
					else:
						total_cpu_count = 0
					vsmart_info[vsmart].append(total_cpu_count)

				failed_vbonds,failed_vsmarts,check_result,check_analysis, check_action = criticalCheckeleven(total_devices, vbond_info, vsmart_info)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]

					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: vBonds with insufficient CPU count: \n{}'.format(check_count_zfill, failed_vbonds))
					log_file_logger.error('#{}: vSmarts with insufficient CPU count: \n{}'.format(check_count_zfill, failed_vsmarts))
					log_file_logger.error('#{}: All vBonds info with total_cpu_count: \n{}'.format(check_count_zfill, vbond_info))
					log_file_logger.error('#{}: All vSmarts info with total_cpu_count: \n{}\n'.format(check_count_zfill, vsmart_info))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: All vBonds info with total_cpu_count: \n{}'.format(check_count_zfill, vbond_info))
					log_file_logger.info('#{}: All vSmarts info with total_cpu_count: \n{}\n'.format(check_count_zfill, vsmart_info))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Warning Checks
			warning_checks = {}
			log_file_logger.info('*** Performing Warning Checks')


			#Check:vManage:CPU Speed
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:CPU Speed'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result,check_analysis,check_action = warningCheckone(cpu_speed)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: CPU clock speed: {}\n'.format(check_count_zfill, cpu_speed))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Network Card type
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Network Card type'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				eth_drivers, check_action, check_analysis, check_result = warningChecktwo()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Ethercards with e1000 card types: {}\n'.format(check_count_zfill, eth_drivers))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Backup status
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Backup status'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				date_time_obj, check_result, check_analysis, check_action = warningCheckthree()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Last Backup was performed on: {}\n'.format(check_count_zfill, date_time_obj))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Evaluate Neo4j performance
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Evaluate Neo4j performance'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = warningCheckfour()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Confirm there are no pending tasks
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Confirm there are no pending tasks'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				tasks = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'device/action/status/tasks', args.vmanage_port))
				tasks_running, check_result, check_analysis, check_action  = warningCheckfive(tasks)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Tasks still running: {}\n'.format(check_count_zfill, tasks_running))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#Check:vManage:Validate there are no empty password users
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Validate there are no empty password users'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				users_emptypass, check_result, check_analysis, check_action = warningChecksix(version_tuple)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Users with empty passwords: {}\n'.format(check_count_zfill, users_emptypass))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing  {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:Controller versions
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:Controllers:Controller versions'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = warningCheckseven(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers:Confirm Certificate Expiration Dates
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:Controllers:Confirm Certificate Expiration Dates'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				controllers_exp, controllers_notexp, check_result, check_analysis, check_action = warningCheckeight(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Controllers with certificates close to expiration:\n{}\n'.format(check_count_zfill, controllers_exp))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:vEdge list sync
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:Controllers:vEdge list sync'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				state_vedgeList,check_result, check_analysis, check_action  = warningChecknine(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Controllers with inconsistent state_vedgeList: {}\n'.format(check_count_zfill, state_vedgeList))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers: Confirm control connections
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:Controllers: Confirm control connections'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				control_sum_tab, discrepancy,check_result, check_analysis, check_action = warningCheckten(vsmart_count, vbond_count)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Control  Connections Summary:\n{}\n'.format(check_count_zfill, control_sum_tab))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Informational Checks
			log_file_logger.info('*** Performing Informational Checks')

			#Check:vManage:Disk controller type
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Disk controller type'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = infoCheckone(server_type, disk_controller)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Disk Controller type: {}\n'.format(check_count_zfill, disk_controller))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Disk Controller type: {}\n'.format(check_count_zfill, disk_controller))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Informational'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:Validate there is at minimum vBond, vSmart present
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:Controllers:Validate there is at minimum vBond, vSmart present'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = infoChecktwo(vsmart_count,vbond_count)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: vSmart Count: {}'.format(check_count_zfill, vsmart_count))
					log_file_logger.error('#{}: vBond Count: {}\n'.format(check_count_zfill, vbond_count))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: vSmart Count: {}'.format(check_count_zfill, vsmart_count))
					log_file_logger.info('#{}: vBond Count: {}\n'.format(check_count_zfill, vbond_count))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Informational'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:Validate all controllers are reachable
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:Controllers:Validate all controllers are reachable'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				unreach_controllers,check_result, check_analysis, check_action = infoChecktthree(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Unreachable Controllers: {}\n'.format(check_count_zfill, unreach_controllers))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Informational'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			if cluster_size>1:
				cluster_checks = {}
				log_file_logger.info('*** Performing Cluster Checks')

				#Check:Cluster:Version consistency
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				check_name = '#{}:Check:Cluster:Version consistency'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					check_result,check_analysis, check_action = criticalChecktwelve(vmanage_info)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: vManage info: {}\n'.format(check_count_zfill, vmanage_info))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.info('#{}: vManage info: {}\n'.format(check_count_zfill, vmanage_info))
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#Check:Cluster:Cluster health
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				check_name = '#{}:Check:Cluster:Cluster health'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					services_down, check_result, check_analysis, check_action = criticalCheckthirteen(vmanage_service_details)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: Relevant cluster services that are down: {}\n'.format(check_count_zfill, services_down))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#Check:Cluster:Cluster ConfigDB topology
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				check_name = '#{}:Check:Cluster:Cluster ConfigDB topology'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					configDB_count, check_result, check_analysis, check_action = criticalCheckfourteen(vmanage_service_details)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: No. of configDB servers in the cluster: {}\n'.format(check_count_zfill, configDB_count))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.info('#{}: No. of configDB servers in the cluster: {}\n'.format(check_count_zfill, configDB_count))
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#Check:Cluster:Messaging server
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				check_name = '#{}:Check:Cluster:Messaging server'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					cluster_msdown,check_result,check_analysis, check_action = criticalCheckfifteen(vmanage_service_details, cluster_size)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: Servers with messaging service down: {}\n'.format(check_count_zfill, cluster_msdown))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#Check:Cluster:DR replication status
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				check_name = '#{}:Check:Cluster:DR replication status'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					dr_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'disasterrecovery/details', args.vmanage_port))
					dr_status, check_action, check_analysis, check_result = criticalChecksixteen(dr_data)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: DR Replication status: {}\n'.format(check_count_zfill, dr_status))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#Check:Cluster:Intercluster communication
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				check_name = '#{}:Check:Cluster:Intercluster communication'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					if criticalCheckseventeen.is_alive():
						criticalCheckseventeen.join(10)

					if not criticalCheckseventeen.result_queue.empty():
						ping_output, ping_output_failed, check_result, check_analysis, check_action = criticalCheckseventeen.result_queue.get()
						if check_result == 'Failed':
							cluster_checks[check_name] = [ check_analysis, check_action]
							check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
							log_file_logger.error('#{}: Cluster nodes with ping failure: {}\n'.format(check_count_zfill, ping_output_failed))
							check_error_report(check_analysis,check_action)
						else:
							check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
							log_file_logger.info('#{}: Cluster nodes details: {}\n'.format(check_count_zfill, ping_output))
							writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
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
				json_final_result['json_data_pdf']['vmanage execution info'] = {"vManage Details":{
																					"Software Version":"{}".format(version),
																					"System IP Address":"{}".format(system_ip)
																				 }}
				if cluster_size > 1:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'clusterManagement/health/details', args.vmanage_port, tokenid))
					vmanage_cluster_ips = vmanage_cluster_ips(cluster_health_data)
					vmanage_service_details = vmanage_service_details(vmanage_cluster_ips)
					log_file_logger.info('deviceIPs of vManages in the cluster: {}'.format(vmanage_cluster_ips))
					#log_file_logger.info('Service details of all vManages in the cluster: {}'.format(vmanage_service_details))
			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error Collecting Preliminary Data. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))


			print('*Starting Checks, this may take several minutes\n\n')

			#Critical Checks
			critical_checks = {}
			log_file_logger.info('*** Performing Critical Checks\n')

			#Beginning #Check:Cluster:Intercluster communication  in the background
			if cluster_size>1:
				log_file_logger.info('Beginging #Check:Cluster:Intercluster communication  in the background\n')
				try:
					criticalCheckseventeen =  criticalCheckseventeen(cluster_health_data,  system_ip, log_file_logger)
				except Exception as e:
					log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Validate current version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Validate current version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				boot_partition_size, check_result, check_analysis, check_action =  criticalCheckone(version)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: version: {}'.format(check_count_zfill, version))
					log_file_logger.error('#{}: Boot Partition Size: {}\n'.format(check_count_zfill, boot_partition_size))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: version: {}'.format(check_count_zfill, version))
					log_file_logger.info('#{}: Boot Partition Size: {}\n'.format(check_count_zfill, boot_partition_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:At minimum 20%  server disk space should be available
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:At minimum 20%  server disk space should be available'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				optdata_partition_size, rootfs_partition_size, check_result, check_analysis, check_action =  criticalCheckTwo()
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: /opt/data Used: {}'.format(check_count_zfill, optdata_partition_size))
					log_file_logger.error('#{}: /rootfs.rw Used: {}\n'.format(check_count_zfill, rootfs_partition_size))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: /opt/data Used: {}'.format(check_count_zfill, optdata_partition_size))
					log_file_logger.info('#{}: /rootfs.rw Used: {}\n'.format(check_count_zfill, rootfs_partition_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#Check:vManage:Memory size
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Memory size '.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			writeFile(report_file, 'Link to the official documentation: \n https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html\n\n')
			try:
				memory_size, memory_size_str, dpi_status, server_type, check_result, check_analysis, check_action =  criticalCheckthree(vedge_count, dpi_status, server_type, cluster_size, version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Memory Size GB: {}'.format(check_count_zfill, memory_size_str))
					log_file_logger.error('#{}: /rootfs.rw Used: {}'.format(check_count_zfill, rootfs_partition_size))
					log_file_logger.error('#{}: Server Type: {}'.format(check_count_zfill, server_type))
					log_file_logger.error('#{}: vEdge Count: {}\n'.format(check_count_zfill, vedge_count))
					check_error_report(check_analysis,check_action)

				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)

					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': 'https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html'})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}\033[0;0m. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:CPU Count
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:CPU Count'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalCheckfour(cpu_count, vedge_count, dpi_status, server_type)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: CPU Count: {}\n'.format(check_count_zfill, cpu_count))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {} \033[0;0m. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:ElasticSearch Indices status
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:ElasticSearch Indices status'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				#es_indices_one = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_indices = es_indices_details()
				es_index_red_one, check_result_one, check_analysis_one, check_action_one = criticalCheckfive(es_indices)
				time.sleep(5)
				#es_indices_two = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_indices = es_indices_details()
				es_index_red_two, check_result_two, check_analysis_two, check_action_two = criticalCheckfive(es_indices)


				if check_result_one == 'Failed' and check_result_two == 'Failed':
					critical_checks[check_name] = [ check_analysis_two, check_action_two]
					check_error_logger(log_file_logger, check_result_two, check_analysis_two, check_count_zfill)
					check_error_report(check_analysis_two,check_action_two)
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result_two]),
															 'result': '{}'.format(check_analysis_two),
															 'action': '{}'.format(check_action_two),
															 'status': '{}'.format(check_result_two),
															 'document': ''})
				elif check_result_one == 'SUCCESSFUL':
					check_info_logger(log_file_logger, check_result_one, check_analysis_one, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_one))
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result_one]),
															 'result': '{}'.format(check_analysis_one),
															 'action': '{}'.format(check_action_one),
															 'status': '{}'.format(check_result_one),
															 'document': ''})
				elif check_result_two == 'SUCCESSFUL':
					check_info_logger(log_file_logger, check_result_two, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_two))
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result_two]),
															 'result': '{}'.format(check_analysis_two),
															 'action': '{}'.format(check_action_two),
															 'status': '{}'.format(check_result_two),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Look for any neo4j exception errors
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Look for any neo4j exception errors'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalChecksix(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Validate all services are up
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Validate all services are up'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				nms_data, nms_failed, check_result, check_analysis, check_action =   criticalCheckseven()
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: List of services that are enabled but not running:\n{}'.format(check_count_zfill, nms_failed))
					log_file_logger.error('#{}: Status of all services  :\n{}\n'.format(check_count_zfill, nms_data))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Status of all the services:\n{}\n'.format(check_count_zfill, nms_data))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Elasticsearch Indices version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Elasticsearch Indices version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				version_list, check_result, check_analysis, check_action = criticalCheckeight(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: List of indices with older versions:\n{}\n'.format(check_count_zfill, version_list))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Evaluate incoming DPI data size
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Evaluate incoming DPI data size'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				es_indices_est = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'management/elasticsearch/index/size/estimate', args.vmanage_port, tokenid))
				appr_estimate_ondeday, dpi_estimate_ondeday, check_result, check_analysis,check_action = criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count, total_devices, dpi_status)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Daily incoming DPI data : {}'.format(check_count_zfill, dpi_estimate_ondeday))
					log_file_logger.error('#{}: Daily incoming Approute data : {}\n'.format(check_count_zfill, appr_estimate_ondeday))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:NTP status across network
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:NTP status across network'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				ntp_nonworking, check_result, check_analysis, check_action = criticalCheckten(version_tuple, controllers_info)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Devices with invalid ntp associations:\n{}\n'.format(check_count_zfill, ntp_nonworking))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Validate Neo4j Store version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Validate Neo4j Store version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				nodestore_version, check_result, check_analysis, check_action = criticalCheckeighteen(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Neo4j Store version: {}\n'.format(check_count_zfill, nodestore_version))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Neo4j Store version: {}\n'.format(check_count_zfill, nodestore_version))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Validate ConfigDB Size is less than 5GB
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Validate ConfigDB Size is less than 5GB '.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				db_size, check_result, check_analysis, check_action = criticalChecknineteen()
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: ConfigDB Size: {}\n'.format(check_count_zfill, db_size))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: ConfigDB Size: {}\n'.format(check_count_zfill, db_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers:Validate vSmart/vBond CPU count for scale
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:Controllers:Validate vSmart/vBond CPU count for scale'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				for vbond in vbond_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip, jsessionid, 'device/system/synced/status?deviceId={}'.format(vbond_info[vbond][1]),args.vmanage_port, tokenid))
					if output['data'] != []:
						total_cpu_count = int(output['data'][0]['total_cpu_count'])
					else:
						total_cpu_count = 0
					vbond_info[vbond].append(total_cpu_count)

				for vsmart in vsmart_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip,jsessionid, 'device/system/synced/status?deviceId={}'.format(vsmart_info[vsmart][1]),args.vmanage_port,tokenid))
					if output['data'] != []:
							total_cpu_count = int(output['data'][0]['total_cpu_count'])
					else:
						total_cpu_count = 0
					vsmart_info[vsmart].append(total_cpu_count)

				failed_vbonds,failed_vsmarts,check_result,check_analysis, check_action = criticalCheckeleven(total_devices, vbond_info, vsmart_info)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: vBonds with insufficient CPU count: \n{}'.format(check_count_zfill, failed_vbonds))
					log_file_logger.error('#{}: vSmarts with insufficient CPU count: \n{}'.format(check_count_zfill, failed_vsmarts))
					log_file_logger.error('#{}: All vBonds info with total_cpu_count: \n{}'.format(check_count_zfill, vbond_info))
					log_file_logger.error('#{}: All vSmarts info with total_cpu_count: \n{}\n'.format(check_count_zfill, vsmart_info))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: All vBonds info with total_cpu_count:\n{}'.format(check_count_zfill, vbond_info))
					log_file_logger.info('#{}: All vSmarts info with total_cpu_count: \n{}\n'.format(check_count_zfill, vsmart_info))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			# Check:vManage:Validate server configs file - uuid
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Validate uuid from server configs file.'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalChecktwenty(version)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis, check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				json_final_result['json_data_pdf']['description']['vManage'].append(
					{'analysis type': '{}'.format(check_name.split(':')[-1]),
						'log type': '{}'.format(result_log['Critical'][check_result]),
						'result': '{}'.format(check_analysis),
						'action': '{}'.format(check_action),
						'status': '{}'.format(check_result),
						'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			# Check:vManage:Validate server_configs.json
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Validate server_configs.json.'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalChecktwentyone(version)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis, check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				json_final_result['json_data_pdf']['description']['vManage'].append(
					{'analysis type': '{}'.format(check_name.split(':')[-1]),
						'log type': '{}'.format(result_log['Critical'][check_result]),
						'result': '{}'.format(check_analysis),
						'action': '{}'.format(check_action),
						'status': '{}'.format(check_result),
						'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			# Check:vManage:Validate UUID
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Validate uuid at /etc/viptela/uuid.'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalChecktwentytwo(version)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis, check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				json_final_result['json_data_pdf']['description']['vManage'].append(
					{'analysis type': '{}'.format(check_name.split(':')[-1]),
						'log type': '{}'.format(result_log['Critical'][check_result]),
						'result': '{}'.format(check_analysis),
						'action': '{}'.format(check_action),
						'status': '{}'.format(check_result),
						'document': ''})
			except Exception as e:
				print(
					'\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(
						check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Warning Checks
			warning_checks = {}
			log_file_logger.info('*** Performing Warning Checks')

			#Check:vManage:CPU Speed
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:CPU Speed'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result,check_analysis,check_action = warningCheckone(cpu_speed)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: CPU clock speed: {}\n'.format(check_count_zfill, cpu_speed))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Network Card type
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Network Card type'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				eth_drivers, check_action, check_analysis, check_result = warningChecktwo()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Ethercardswith e1000 card types: {}\n'.format(check_count_zfill, eth_drivers))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Backup status
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Backup status'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				date_time_obj, check_result, check_analysis, check_action = warningCheckthree()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Last Backup was performed on:{}\n'.format(check_count_zfill, date_time_obj))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Evaluate Neo4j performance
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Evaluate Neo4j performance'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = warningCheckfour()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Confirm there are no pending tasks
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Confirm there are no pending tasks'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				tasks = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'device/action/status/tasks', args.vmanage_port, tokenid))
				tasks_running, check_result, check_analysis, check_action  = warningCheckfive(tasks)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Tasks still running: {}\n'.format(check_count_zfill, tasks_running))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Validate there are no empty password users
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Validate there are no empty password users'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				users_emptypass, check_result, check_analysis, check_action = warningChecksix(version_tuple)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Users with empty passwords: {}\n'.format(check_count_zfill, users_emptypass))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:Controller versions
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:Controllers:Controller versions'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = warningCheckseven(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers:Confirm Certificate Expiration Dates
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:Controllers:Confirm Certificate Expiration Dates'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				controllers_exp, controllers_notexp, check_result, check_analysis, check_action = warningCheckeight(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Controllers with certificates close to expiration:\n{}\n'.format(check_count_zfill, controllers_exp))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:vEdge list sync
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:Controllers:vEdge list sync'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				state_vedgeList,check_result, check_analysis, check_action  = warningChecknine(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Controllers with inconsistent state_vedgeList: {}\n'.format(check_count_zfill, state_vedgeList))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers: Confirm control connections
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:Controllers: Confirm control connections'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				control_sum_tab, discrepancy,check_result, check_analysis, check_action = warningCheckten(vsmart_count, vbond_count)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Control  Connections Summary: \n{}\n'.format(check_count_zfill, control_sum_tab))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Informational Checks
			log_file_logger.info('*** Performing Informational Checks')

			#Check:vManage:Disk controller type
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:vManage:Disk controller type'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = infoCheckone(server_type, disk_controller)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Disk Controller type: {}\n'.format(check_count_zfill, disk_controller))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Disk Controller type: {}\n'.format(check_count_zfill, disk_controller))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Informational'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:Validate there is at minimum vBond, vSmart present
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:Controllers:Validate there is at minimum vBond, vSmart present'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = infoChecktwo(vsmart_count,vbond_count)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: vSmart Count: {}'.format(check_count_zfill, vsmart_count))
					log_file_logger.error('#{}: vBond Count: {}\n'.format(check_count_zfill, vbond_count))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: vSmart Count: {}'.format(check_count_zfill, vsmart_count))
					log_file_logger.info('#{}: vBond Count: {}\n'.format(check_count_zfill, vbond_count))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Informational'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#Check:Controllers:Validate all controllers are reachable
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			check_name = '#{}:Check:Controllers:Validate all controllers are reachable'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				unreach_controllers,check_result, check_analysis, check_action = infoChecktthree(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Unreachable Controllers: {}\n'.format(check_count_zfill, unreach_controllers))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Informational'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			if cluster_size>1:
				cluster_checks = {}
				log_file_logger.info('*** Performing Cluster Checks')

				#Check:Cluster:Version consistency
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				check_name = '#{}:Check:Cluster:Version consistency'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					check_result,check_analysis, check_action = criticalChecktwelve(vmanage_info)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: vManage info: {}\n'.format(check_count_zfill, vmanage_info))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.info('#{}: vManage info: {}\n'.format(check_count_zfill, vmanage_info))
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#Check:Cluster:Cluster health
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				check_name = '#{}:Check:Cluster:Cluster health'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					services_down, check_result, check_analysis, check_action = criticalCheckthirteen(vmanage_service_details)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: Relevant cluster services that are down: {}\n'.format(check_count_zfill, services_down))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#Check:Cluster:Cluster ConfigDB topology
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				check_name = '#{}:Check:Cluster:Cluster ConfigDB topology'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					configDB_count, check_result, check_analysis, check_action = criticalCheckfourteen(vmanage_service_details)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: No. of configDB servers in the cluster: {}\n'.format(check_count_zfill, configDB_count))
						check_error_report(check_analysis,check_action)

					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.info('#{}: No. of configDB servers in the cluster: {}\n'.format(check_count_zfill, configDB_count))
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#Check:Cluster:Messaging server
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				check_name = '#{}:Check:Cluster:Messaging server'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					cluster_msdown,check_result,check_analysis, check_action = criticalCheckfifteen(vmanage_service_details, cluster_size)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: Servers with messaging service down: {}\n'.format(check_count_zfill, cluster_msdown))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': ''.format(check_name.split(':')[-1]),
															 'log type': ''.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#Check:Cluster:DR replication status
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				check_name = '#{}:Check:Cluster:DR replication status'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					dr_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'disasterrecovery/details', args.vmanage_port, tokenid))
					dr_status, check_action, check_analysis, check_result = criticalChecksixteen(dr_data)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: DR Replication status: {}\n'.format(check_count_zfilldr_status))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#Check:Cluster:Intercluster communication
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				check_name = '#{}:Check:Cluster:Intercluster communication'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					if criticalCheckseventeen.is_alive():
						criticalCheckseventeen.join(10)

					if not criticalCheckseventeen.result_queue.empty():
						ping_output, ping_output_failed, check_result, check_analysis, check_action = criticalCheckseventeen.result_queue.get()
						if check_result == 'Failed':
							cluster_checks[check_name] = [ check_analysis, check_action]
							check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
							log_file_logger.error('#{}: Cluster nodes with ping failure: {}\n'.format(check_count_zfill, ping_output_failed))
							check_error_report(check_analysis,check_action)
						else:
							check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
							log_file_logger.info('#{}: Cluster nodes details: {}\n'.format(check_count_zfill, ping_output))
							writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))


			#Logging out of the Session using jsessionid
			log_file_logger.info('Logging out of the Session')
			sessionLogout(vmanage_lo_ip, jsessionid, args.vmanage_port)
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
				json_final_result['json_data_pdf']['vmanage execution info'] = {"vManage Details":{
																					"Software Version":"{}".format(version),
																					"System IP Address":"{}".format(system_ip)
																				 }}
				if cluster_size > 1:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'clusterManagement/health/details', args.vmanage_port))
					vmanage_cluster_ips = vmanage_cluster_ips(cluster_health_data)
					vmanage_service_details = vmanage_service_details(vmanage_cluster_ips)
					log_file_logger.info('deviceIPs of vManages in the cluster: {}'.format(vmanage_cluster_ips))
					#log_file_logger.info('Service details of all vManages in the cluster: {}'.format(vmanage_service_details))

			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error Collecting Preliminary Data. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))


			print('*Starting Checks, this may take several minutes\n\n')

			#Critical Checks
			print('\n**** Performing Critical checks\n')
			critical_checks = {}
			log_file_logger.info('*** Performing Critical Checks\n')

			#Beginning #Check:Cluster:Intercluster communication  in the background
			if cluster_size>1:
				log_file_logger.info('Beginging #Check:Cluster:Intercluster communication  in the background\n')
				try:
					criticalCheckseventeen =  criticalCheckseventeen(cluster_health_data,  system_ip, log_file_logger)
				except Exception as e:
					log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Validate current version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Validate current version'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate current version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				boot_partition_size, check_result, check_analysis, check_action =  criticalCheckone(version)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: version: {}'.format(check_count_zfill, version))
					log_file_logger.error('#{}: Boot Partition Size: {}\n'.format(check_count_zfill, boot_partition_size))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: version: {}'.format(check_count_zfill, version))
					log_file_logger.info('#{}: Boot Partition Size: {}\n'.format(check_count_zfill, boot_partition_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:At minimum 20%  server disk space should be available
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:vManage sever disk space'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:At minimum 20%  server disk space should be available'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				optdata_partition_size, rootfs_partition_size, check_result, check_analysis, check_action =  criticalCheckTwo()
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: /opt/data Used: {}'.format(check_count_zfill, optdata_partition_size))
					log_file_logger.error('#{}: /rootfs.rw Used: {}\n'.format(check_count_zfill, rootfs_partition_size))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: /opt/data Used: {}'.format(check_count_zfill, optdata_partition_size))
					log_file_logger.info('#{}: /rootfs.rw Used: {}\n'.format(check_count_zfill, rootfs_partition_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Memory size
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Memory size'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Memory size'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			writeFile(report_file, 'Link to the official documentation: \n https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html\n\n')

			try:
				memory_size, memory_size_str, dpi_status, server_type, check_result, check_analysis, check_action =  criticalCheckthree(vedge_count, dpi_status, server_type, cluster_size, version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Memory Size GB: {}'.format(check_count_zfill, memory_size_str))
					log_file_logger.error('#{}: /rootfs.rw Used: {}'.format(check_count_zfill, rootfs_partition_size))
					log_file_logger.error('#{}: Server Type: {}'.format(check_count_zfill, server_type))
					log_file_logger.error('#{}: vEdge Count: {}\n'.format(check_count_zfill, vedge_count))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': 'https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html'})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:CPU Count
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:CPU Count'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:CPU Count'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalCheckfour(cpu_count, vedge_count, dpi_status, server_type)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: CPU Count: {}\n'.format(check_count_zfill, cpu_count))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:ElasticSearch Indices status
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:ElasticSearch Indices status'.format(check_count_zfill))
			check_name = '#{}:Checking:vManage:ElasticSearch Indices status'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				#es_indices_one = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/info', args.vmanage_port))
				es_indices = es_indices_details()
				es_index_red_one, check_result_one, check_analysis_one, check_action_one = criticalCheckfive(es_indices)
				time.sleep(5)
				#es_indices_two = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/info', args.vmanage_port))
				es_indices = es_indices_details()
				es_index_red_two, check_result_two, check_analysis_two, check_action_two = criticalCheckfive(es_indices)

				if check_result_one == 'Failed' and check_result_two == 'Failed':
					critical_checks[check_name] = [ check_analysis_two, check_action_two]
					check_error_logger(log_file_logger, check_result_two, check_analysis_two, check_count_zfill)
					check_error_report(check_analysis_two,check_action_two)
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result_two]),
															 'result': '{}'.format(check_analysis_two),
															 'action': '{}'.format(check_action_two),
															 'status': '{}'.format(check_result_two),
															 'document': ''})

				elif check_result_one == 'SUCCESSFUL':
					check_info_logger(log_file_logger, check_result_one, check_analysis_one, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_one))
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result_one]),
															 'result': '{}'.format(check_analysis_one),
															 'action': '{}'.format(check_action_one),
															 'status': '{}'.format(check_result_one),
															 'document': ''})

				elif check_result_two == 'SUCCESSFUL':
					check_info_logger(log_file_logger, check_result_two, check_analysis_two, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_two))
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result_two]),
															 'result': '{}'.format(check_analysis_two),
															 'action': '{}'.format(check_action_two),
															 'status': '{}'.format(check_result_two),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Look for any neo4j exception errors
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Look for any neo4j exception errors'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Look for any neo4j exception errors'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalChecksix(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Validate all services are up
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Validate all services are up'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate all services are up'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				nms_data, nms_failed, check_result, check_analysis, check_action =   criticalCheckseven()
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: List of services that are enabled but not running:\n{}'.format(check_count_zfill, nms_failed))
					log_file_logger.error('#{}: Status of all services  :\n{}\n'.format(check_count_zfill, nms_data))
					check_error_report(check_analysis,check_action)

				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Status of all the services:\n{}\n'.format(check_count_zfill, nms_data))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Elasticsearch Indices version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Elasticsearch Indices version'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Elasticsearch Indices version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				version_list, check_result, check_analysis, check_action = criticalCheckeight(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: List of indices with older versions  :\n{}\n'.format(check_count_zfill, version_list))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Evaluate incoming DPI data size
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Evaluate incoming DPI data size'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Evaluate incoming DPI data size'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				es_indices_est = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/size/estimate', args.vmanage_port))
				appr_estimate_ondeday, dpi_estimate_ondeday, check_result,check_analysis,check_action = criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count, total_devices, dpi_status)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Daily incoming DPI data : {}'.format(check_count_zfill, dpi_estimate_ondeday))
					log_file_logger.error('#{}: Daily incoming Approute data : {}\n'.format(check_count_zfill, appr_estimate_ondeday))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:NTP status across network
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:NTP status across network'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:NTP status across network'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				ntp_nonworking, check_result, check_analysis, check_action = criticalCheckten(version_tuple, controllers_info)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Devices with invalid ntp associations: \n{}\n'.format(check_count_zfill, ntp_nonworking))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Validate Neo4j Store version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Validate Neo4j Store version'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate Neo4j Store version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				nodestore_version, check_result, check_analysis, check_action = criticalCheckeighteen(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Neo4j Store version: {}\n'.format(check_count_zfill, nodestore_version))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Neo4j Store version: {}\n'.format(check_count_zfill, nodestore_version))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Validate ConfigDB Size is less than 5GB
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Validate ConfigDB Size is less than 5GB'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate ConfigDB Size is less than 5GB'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				db_size, check_result, check_analysis, check_action = criticalChecknineteen()
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: ConfigDB Size: {}\n'.format(check_count_zfill, db_size))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: ConfigDB Size: {}\n'.format(check_count_zfill, db_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers:Validate vSmart/vBond CPU count for scale
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:Controllers:Validate vSmart/vBond CPU count for scale'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Validate vSmart/vBond CPU count for scale'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				for vbond in vbond_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip, jsessionid,'device/system/synced/status?deviceId={}'.format(vbond_info[vbond][1]),args.vmanage_port ))
					if output['data'] != []:
							total_cpu_count = int(output['data'][0]['total_cpu_count'])
					else:
						total_cpu_count = 0
					vbond_info[vbond].append(total_cpu_count)

				for vsmart in vsmart_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip,jsessionid, 'device/system/synced/status?deviceId={}'.format(vsmart_info[vsmart][1]), args.vmanage_port))
					if output['data'] != []:
							total_cpu_count = int(output['data'][0]['total_cpu_count'])
					else:
						total_cpu_count = 0
					vsmart_info[vsmart].append(total_cpu_count)

				failed_vbonds,failed_vsmarts,check_result,check_analysis, check_action = criticalCheckeleven(total_devices, vbond_info, vsmart_info)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: vBonds with insufficient CPU count: \n{}'.format(check_count_zfill, failed_vbonds))
					log_file_logger.error('#{}: vSmarts with insufficient CPU count: \n{}'.format(check_count_zfill, failed_vsmarts))
					log_file_logger.error('#{}: All vBonds info with total_cpu_count: \n{}'.format(check_count_zfill, vbond_info))
					log_file_logger.error('#{}: All vSmarts info with total_cpu_count: \n{}\n'.format(check_count_zfill, vsmart_info))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: All vBonds info with total_cpu_count: \n{}'.format(check_count_zfill, vbond_info))
					log_file_logger.info('#{}: All vSmarts info with total_cpu_count: \n{}\n'.format(check_count_zfill, vsmart_info))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing  {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Warning Checks
			print('\n**** Performing Warning checks\n')

			warning_checks = {}
			log_file_logger.info('*** Performing Warning Checks')

			#Check:vManage:CPU Speed
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:CPU Speed'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:CPU Speed'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result,check_analysis,check_action = warningCheckone(cpu_speed)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: CPU clock speed: {}\n'.format(check_count_zfill, cpu_speed))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Network Card type
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Network Card type'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Network Card type'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				eth_drivers, check_action, check_analysis, check_result = warningChecktwo()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Ethercardswith e1000 card types: {}\n'.format(check_count_zfill, eth_drivers))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Backup status
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Backup status'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Backup status'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				date_time_obj, check_result, check_analysis, check_action = warningCheckthree()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Last Backup was performed on: {}\n'.format(check_count_zfill, date_time_obj))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Evaluate Neo4j performance
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Evaluate Neo4j performance'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Evaluate Neo4j performance'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = warningCheckfour()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Confirm there are no pending tasks
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Confirm there are no pending tasks'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Confirm there are no pending tasks'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				tasks = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'device/action/status/tasks', args.vmanage_port))
				tasks_running, check_result, check_analysis, check_action  = warningCheckfive(tasks)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Tasks still running: {}\n'.format(check_count_zfill, tasks_running))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Validate there are no empty password users
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Validate there are no empty password users'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate there are no empty password users'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				users_emptypass, check_result, check_analysis, check_action = warningChecksix(version_tuple)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Users with empty passwords: {}\n'.format(check_count_zfill, users_emptypass))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:Controller versions
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:Controllers:Controller versions'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Controller versions'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = warningCheckseven(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:Confirm Certificate Expiration Dates
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:Controllers:Confirm Certificate Expiration Dates'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Confirm Certificate Expiration Dates'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				controllers_exp, controllers_notexp, check_result, check_analysis, check_action = warningCheckeight(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Controllers with certificates close to expiration: \n{}\n'.format(check_count_zfill, controllers_exp))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:vEdge list sync
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:Controllers:vEdge list sync'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:vEdge list sync'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				state_vedgeList,check_result, check_analysis, check_action  = warningChecknine(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Controllers with inconsistent state_vedgeList: {}\n'.format(check_count_zfill, state_vedgeList))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers: Confirm control connections
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:Controllers: Confirm control connections'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers: Confirm control connections'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				control_sum_tab, discrepancy,check_result, check_analysis, check_action = warningCheckten(vsmart_count, vbond_count)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Control  Connections Summary: \n{}\n'.format(check_count_zfill, control_sum_tab))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Informational Checks
			print('\n**** Performing Informational checks\n')
			log_file_logger.info('*** Performing Informational Checks')

			#Check:vManage:Disk controller type
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Disk controller type'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Disk controller type'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = infoCheckone(server_type, disk_controller)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Disk Controller type: {}\n'.format(check_count_zfill, disk_controller))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Disk Controller type: {}\n'.format(check_count_zfill, disk_controller))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Informational'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:Validate there is at minimum vBond, vSmart present
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:Controllers:Validate there is at minimum vBond, vSmart present'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Validate there is at minimum vBond, vSmart present'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = infoChecktwo(vsmart_count,vbond_count)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: vSmart Count: {}'.format(check_count_zfill, vsmart_count))
					log_file_logger.error('#{}: vBond Count: {}\n'.format(check_count_zfill, vbond_count))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: vSmart Count: {}'.format(check_count_zfill, vsmart_count))
					log_file_logger.info('#{}: vBond Count: {}\n'.format(check_count_zfill, vbond_count))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Informational'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers:Validate all controllers are reachable
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:Controllers:Validate all controllers are reachable'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Validate all controllers are reachable'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				unreach_controllers,check_result, check_analysis, check_action = infoChecktthree(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Unreachable Controllers: {}\n'.format(check_count_zfill, unreach_controllers))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Informational'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			if cluster_size>1:
				cluster_checks = {}

				log_file_logger.info('*** Performing Cluster Checks')
				print('\n**** Performing Cluster checks\n')

				#Check:Cluster:Version consistency
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print('  #{}:Checking:Cluster:Version consistency'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Version consistency'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					check_result,check_analysis, check_action = criticalChecktwelve(vmanage_info)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: vManage info: {}\n'.format(check_count_zfill, vmanage_info))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.info('#{}: vManage info: {}\n'.format(check_count_zfill, vmanage_info))
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#Check:Cluster:Cluster health
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print('  #{}:Checking:Cluster:Cluster health'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Cluster health'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					services_down, check_result, check_analysis, check_action = criticalCheckthirteen(vmanage_service_details)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: Relevant cluster services that are down: {}\n'.format(check_count_zfill, services_down))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#Check:Cluster:Cluster ConfigDB topology
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print('  #{}:Checking:Cluster:Cluster ConfigDB topology'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Cluster ConfigDB topology'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					configDB_count, check_result, check_analysis, check_action = criticalCheckfourteen(vmanage_service_details)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: No. of configDB servers in the cluster: {}\n'.format(check_count_zfill, configDB_count))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.info('#{}: No. of configDB servers in the cluster: {}\n'.format(check_count_zfill, configDB_count))
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#Check:Cluster:Messaging server
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print('  #{}:Checking:Cluster:Messaging server'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Messaging server'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					cluster_msdown,check_result,check_analysis, check_action = criticalCheckfifteen(vmanage_service_details, cluster_size)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: Servers with messaging service down: {}\n'.format(check_count_zfill, cluster_msdown))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#Check:Cluster:DR replication status
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print('  #{}:Checking:Cluster:DR replication status'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:DR replication status'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					dr_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'disasterrecovery/details', args.vmanage_port))
					dr_status, check_action, check_analysis, check_result = criticalChecksixteen(dr_data)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: DR Replication status: {}\n'.format(check_count_zfill, dr_status))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#Check:Cluster:Intercluster communication
				check_count += 1
				check_count_zfill = zfill_converter(check_count)

				print('  #{}:Checking:Cluster:Intercluster communication'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Intercluster communication'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					if criticalCheckseventeen.is_alive():
						criticalCheckseventeen.join(10)

					if not criticalCheckseventeen.result_queue.empty():
						ping_output, ping_output_failed, check_result, check_analysis, check_action = criticalCheckseventeen.result_queue.get()
						if check_result == 'Failed':
							cluster_checks[check_name] = [ check_analysis, check_action]
							check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
							log_file_logger.error('#{}: Cluster nodes with ping failure: {}\n'.format(check_count_zfill, ping_output_failed))
							check_error_report(check_analysis,check_action)
						else:
							check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
							log_file_logger.info('#{}: Cluster nodes details: {}\n'.format(check_count_zfill, ping_output))

							writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
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
				json_final_result['json_data_pdf']['vmanage execution info'] = {"vManage Details":{
																					"Software Version":"{}".format(version),
																					"System IP Address":"{}".format(system_ip)
																				 }}
				if cluster_size > 1:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid,'clusterManagement/health/details', args.vmanage_port, tokenid))
					vmanage_cluster_ips = vmanage_cluster_ips(cluster_health_data)
					vmanage_service_details = vmanage_service_details(vmanage_cluster_ips)
					log_file_logger.info('deviceIPs of vManages in the cluster: {}'.format(vmanage_cluster_ips))
					#log_file_logger.info('Service details of all vManages in the cluster: {}'.format(vmanage_service_details))

			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error Collecting Preliminary Data. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))

			print('*Starting Checks, this may take several minutes\n\n')

			#Critical Checks
			critical_checks = {}
			log_file_logger.info('*** Performing Critical Checks\n')

			#Beginning #Check:Cluster:Intercluster communication  in the background
			if cluster_size>1:
				log_file_logger.info('Beginging #Check:Cluster:Intercluster communication  in the background\n')
				try:
					criticalCheckseventeen =  criticalCheckseventeen(cluster_health_data,  system_ip, log_file_logger)
				except Exception as e:
					log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Validate current version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Validate current version'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate current version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				boot_partition_size, check_result, check_analysis, check_action =  criticalCheckone(version)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: version: {}'.format(check_count_zfill, version))
					log_file_logger.error('#{}: Boot Partition Size: {}\n'.format(check_count_zfill, boot_partition_size))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: version: {}'.format(check_count_zfill, version))
					log_file_logger.info('#{}: Boot Partition Size: {}\n'.format(check_count_zfill, boot_partition_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:At minimum 20%  server disk space should be available
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:At minimum 20%  server disk space should be available'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:At minimum 20%  server disk space should be available'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				optdata_partition_size, rootfs_partition_size, check_result, check_analysis, check_action =  criticalCheckTwo()
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: /opt/data Used: {}'.format(check_count_zfill, optdata_partition_size))
					log_file_logger.error('#{}: /rootfs.rw Used: {}\n'.format(check_count_zfill, rootfs_partition_size))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: /opt/data Used: {}'.format(check_count_zfill, optdata_partition_size))
					log_file_logger.info('#{}: /rootfs.rw Used: {}\n'.format(check_count_zfill, rootfs_partition_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Memory size
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Memory size'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Memory size'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			writeFile(report_file, 'Link to the official documentation: \n https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html\n\n')
			try:
				memory_size, memory_size_str, dpi_status, server_type, check_result, check_analysis, check_action =  criticalCheckthree(vedge_count, dpi_status, server_type, cluster_size, version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Memory Size GB: {}'.format(check_count_zfill, memory_size_str))
					log_file_logger.error('#{}: /rootfs.rw Used: {}'.format(check_count_zfill, rootfs_partition_size))
					log_file_logger.error('#{}: Server Type: {}'.format(check_count_zfill, server_type))
					log_file_logger.error('#{}: vEdge Count: {}\n'.format(check_count_zfill, vedge_count))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': 'https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html'})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:CPU Count
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:CPU Count'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:CPU Count'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalCheckfour(cpu_count, vedge_count, dpi_status, server_type)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: CPU Count: {}\n'.format(check_count_zfill, cpu_count))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:ElasticSearch Indices status
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:ElasticSearch Indices status'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:ElasticSearch Indices status'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				#es_indices_one = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_indices = es_indices_details()
				es_index_red_one, check_result_one, check_analysis_one, check_action_one = criticalCheckfive(es_indices)
				time.sleep(5)
				#es_indices_two = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_indices = es_indices_details()
				es_index_red_two, check_result_two, check_analysis_two, check_action_two = criticalCheckfive(es_indices)

				if check_result_one == 'Failed' and check_result_two == 'Failed':
					critical_checks[check_name] = [ check_analysis_two, check_action_two]
					check_error_logger(log_file_logger, check_result_two, check_analysis_two, check_count_zfill)
					check_error_report(check_analysis_two,check_action_two)
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result_two]),
															 'result': '{}'.format(check_analysis_two),
															 'action': '{}'.format(check_action_two),
															 'status': '{}'.format(check_result_two),
															 'document': ''})
				elif check_result_one == 'SUCCESSFUL':
					check_info_logger(log_file_logger, check_result_one, check_analysis_one, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_one))
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result_one]),
															 'result': '{}'.format(check_analysis_one),
															 'action': '{}'.format(check_action_one),
															 'status': '{}'.format(check_result_one),
															 'document': ''})
				elif check_result_two == 'SUCCESSFUL':
					check_info_logger(log_file_logger, check_result_two, check_analysis_two, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_two))
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result_two]),
															 'result': '{}'.format(check_analysis_two),
															 'action': '{}'.format(check_action_two),
															 'status': '{}'.format(check_result_two),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Look for any neo4j exception errors
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Look for any neo4j exception errors'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Look for any neo4j exception errors'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalChecksix(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Validate all services are up
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Validate all services are up'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate all services are up'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				nms_data, nms_failed, check_result, check_analysis, check_action =   criticalCheckseven()
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: List of services that are enabled but not running:\n{}'.format(check_count_zfill, nms_failed))
					log_file_logger.error('#{}: Status of all services  :\n{}\n'.format(check_count_zfill, nms_data))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Status of all the services: \n{}\n'.format(check_count_zfill, nms_data))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Elasticsearch Indices version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Elasticsearch Indices version '.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Elasticsearch Indices version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				version_list, check_result, check_analysis, check_action = criticalCheckeight(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: List of indices with older versions  :\n{}\n'.format(check_count_zfill, version_list))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Evaluate incoming DPI data size
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Evaluate incoming DPI data size'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Evaluate incoming DPI data size'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				es_indices_est = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'management/elasticsearch/index/size/estimate', args.vmanage_port, tokenid))
				appr_estimate_ondeday, dpi_estimate_ondeday, check_result, check_analysis,check_action = criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count, total_devices, dpi_status)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Daily incoming DPI data : {}'.format(check_count_zfill, dpi_estimate_ondeday))
					log_file_logger.error('#{}: Daily incoming Approute data : {}\n'.format(check_count_zfill, appr_estimate_ondeday))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:NTP status across network
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:NTP status across network'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:NTP status across network'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				ntp_nonworking, check_result, check_analysis, check_action = criticalCheckten(version_tuple, controllers_info)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Devices with invalid ntp associations: \n{}\n'.format(check_count_zfill, ntp_nonworking))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Validate Neo4j Store version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Validate Neo4j Store version'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate Neo4j Store version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				nodestore_version, check_result, check_analysis, check_action = criticalCheckeighteen(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Neo4j Store version: {}\n'.format(check_count_zfill, nodestore_version))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Neo4j Store version: {}\n'.format(check_count_zfill, nodestore_version))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Validate ConfigDB Size is less than 5GB
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Validate ConfigDB Size is less than 5GB'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate ConfigDB Size is less than 5GB'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				db_size, check_result, check_analysis, check_action = criticalChecknineteen()
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: ConfigDB Size: {}\n'.format(check_count_zfill, db_size))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: ConfigDB Size: {}\n'.format(check_count_zfill, db_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers:Validate vSmart/vBond CPU count for scale
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:Controllers:Validate vSmart/vBond CPU count for scale'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Validate vSmart/vBond CPU count for scale'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				for vbond in vbond_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip, jsessionid,'device/system/synced/status?deviceId={}'.format(vbond_info[vbond][1]),args.vmanage_port, tokenid))
					if output['data'] != []:
							total_cpu_count = int(output['data'][0]['total_cpu_count'])
					else:
						total_cpu_count = 0
					vbond_info[vbond].append(total_cpu_count)

				for vsmart in vsmart_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip,jsessionid, 'device/system/synced/status?deviceId={}'.format(vsmart_info[vsmart][1]),args.vmanage_port,tokenid))
					if output['data'] != []:
							total_cpu_count = int(output['data'][0]['total_cpu_count'])
					else:
						total_cpu_count = 0
					vsmart_info[vsmart].append(total_cpu_count)

				failed_vbonds,failed_vsmarts,check_result,check_analysis, check_action = criticalCheckeleven(total_devices, vbond_info, vsmart_info)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: vBonds with insufficient CPU count: \n{}'.format(check_count_zfill, failed_vbonds))
					log_file_logger.error('#{}: vSmarts with insufficient CPU count: \n{}'.format(check_count_zfill, failed_vsmarts))
					log_file_logger.error('#{}: All vBonds info with total_cpu_count: \n{}'.format(check_count_zfill, vbond_info))
					log_file_logger.error('#{}: All vSmarts info with total_cpu_count: \n{}\n'.format(check_count_zfill, vsmart_info))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: All vBonds info with total_cpu_count: \n{}'.format(check_count_zfill, vbond_info))
					log_file_logger.info('#{}: All vSmarts info with total_cpu_count: \n{}\n'.format(check_count_zfill, vsmart_info))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			# Check:vManage:Validate server configs file - uuid
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Validate uuid from server configs file.'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate uuid from server configs file.'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalChecktwenty(version)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis, check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				json_final_result['json_data_pdf']['description']['vManage'].append(
					{'analysis type': '{}'.format(check_name.split(':')[-1]),
						'log type': '{}'.format(result_log['Critical'][check_result]),
						'result': '{}'.format(check_analysis),
						'action': '{}'.format(check_action),
						'status': '{}'.format(check_result),
						'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			# Check:vManage:Validate server_configs.json
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Validate server_configs.json.'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate server_configs.json'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalChecktwentyone(version)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis, check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				json_final_result['json_data_pdf']['description']['vManage'].append(
					{'analysis type': '{}'.format(check_name.split(':')[-1]),
						'log type': '{}'.format(result_log['Critical'][check_result]),
						'result': '{}'.format(check_analysis),
						'action': '{}'.format(check_action),
						'status': '{}'.format(check_result),
						'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			# Check:vManage:Validate UUID
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Validate uuid at /etc/viptela/uuid'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate uuid at /etc/viptela/uuid'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalChecktwentytwo(version)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis, check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

				json_final_result['json_data_pdf']['description']['vManage'].append(
					{'analysis type': '{}'.format(check_name.split(':')[-1]),
					 'log type': '{}'.format(result_log['Critical'][check_result]),
					 'result': '{}'.format(check_analysis),
					 'action': '{}'.format(check_action),
					 'status': '{}'.format(check_result),
					 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(
							check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Warning Checks
			print('\n**** Performing Warning checks\n')
			warning_checks = {}
			log_file_logger.info('*** Performing Warning Checks')

			#Check:vManage:CPU Speed
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:CPU Speed'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:CPU Speed'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result,check_analysis,check_action = warningCheckone(cpu_speed)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: CPU clock speed: {}\n'.format(check_count_zfill, cpu_speed))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Network Card type
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Network Card type'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Network Card type'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				eth_drivers, check_action, check_analysis, check_result = warningChecktwo()
				if check_result == 'Failed':
					warning_checks['#{}:Check:vManage:Network Card type'] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Ethercardswith e1000 card types: {}\n'.format(check_count_zfill, eth_drivers))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Backup status
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Backup status'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Backup status'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				date_time_obj, check_result, check_analysis, check_action = warningCheckthree()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Last Backup was performed on:{}\n'.format(check_count_zfill, date_time_obj))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Evaluate Neo4j performance
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Evaluate Neo4j performance'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Evaluate Neo4j performance'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = warningCheckfour()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Confirm there are no pending tasks
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Confirm there are no pending tasks'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Confirm there are no pending tasks'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				tasks = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid,'device/action/status/tasks', args.vmanage_port, tokenid))
				tasks_running, check_result, check_analysis, check_action  = warningCheckfive(tasks)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Tasks still running: {}\n'.format(check_count_zfill, tasks_running))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Validate there are no empty password users
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Validate there are no empty password users'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate there are no empty password users'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				users_emptypass, check_result, check_analysis, check_action = warningChecksix(version_tuple)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Users with empty passwords: {}\n'.format(check_count_zfill, users_emptypass))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:Controller versions
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:Controllers:Controller versions'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Controller versions'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = warningCheckseven(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:Confirm Certificate Expiration Dates
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:Controllers:Confirm Certificate Expiration Dates'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Confirm Certificate Expiration Dates'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				controllers_exp, controllers_notexp, check_result, check_analysis, check_action = warningCheckeight(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Controllers with certificates close to expiration: \n{}\n'.format(check_count_zfill, controllers_exp))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing  {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#Check:Controllers:vEdge list sync
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:Controllers:vEdge list sync'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:vEdge list sync'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				state_vedgeList,check_result, check_analysis, check_action  = warningChecknine(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Controllers with inconsistent state_vedgeList: {}\n'.format(state_vedgeList))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers: Confirm control connections
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:Controllers: Confirm control connections'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers: Confirm control connections'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				control_sum_tab, discrepancy,check_result, check_analysis, check_action = warningCheckten(vsmart_count, vbond_count)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Control  Connections Summary: \n{}\n'.format(check_count_zfill, control_sum_tab))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#Informational Checks
			print('\n**** Performing Informational checks\n')
			log_file_logger.info('*** Performing Informational Checks')

			#Check:vManage:Disk controller type
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Disk controller type'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Disk controller type'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = infoCheckone(server_type, disk_controller)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Disk Controller type: {}\n'.format(check_count_zfill, disk_controller))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Disk Controller type: {}\n'.format(check_count_zfill, disk_controller))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Informational'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:Validate there is at minimum vBond, vSmart present
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:Controllers:Validate there is at minimum vBond, vSmart present '.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Validate there is at minimum vBond, vSmart present'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = infoChecktwo(vsmart_count,vbond_count)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: vSmart Count: {}'.format(check_count_zfill, vsmart_count))
					log_file_logger.error('#{}: vBond Count: {}\n'.format(check_count_zfill, vbond_count))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: vSmart Count: {}'.format(check_count_zfill, vsmart_count))
					log_file_logger.info('#{}: vBond Count: {}\n'.format(check_count_zfill, vbond_count))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Informational'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#Check:Controllers:Validate all controllers are reachable
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:Controllers:Validate all controllers are reachable'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Validate all controllers are reachable'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				unreach_controllers,check_result, check_analysis, check_action = infoChecktthree(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Unreachable Controllers: {}\n'.format(check_count_zfill, unreach_controllers))
					check_error_report(check_analysis,check_action)
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Informational'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			if cluster_size>1:
				cluster_checks = {}

				log_file_logger.info('*** Performing Cluster Checks')
				print('\n**** Performing Cluster checks\n')

				#Check:Cluster:Version consistency
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print('  #{}:Checking:Cluster:Version consistency'.format(check_count_zfill))
				check_name = '#{}:Checking:Cluster:Version consistency'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					check_result,check_analysis, check_action = criticalChecktwelve(vmanage_info)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: vManage info: {}\n'.format(check_count_zfill, vmanage_info))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.info('#{}: vManage info: {}\n'.format(check_count_zfill, vmanage_info))
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#Check:Cluster:Cluster health
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print('  #{}:Checking:Cluster:Cluster health'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Cluster health'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					services_down, check_result, check_analysis, check_action = criticalCheckthirteen(vmanage_service_details)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: Relevant cluster services that are down: {}\n'.format(check_count_zfill, services_down))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))



				#Check:Cluster:Cluster ConfigDB topology
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print('  #{}:Checking:Cluster:Cluster ConfigDB topology'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Cluster ConfigDB topology'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					configDB_count, check_result, check_analysis, check_action = criticalCheckfourteen(vmanage_service_details)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: : No. of configDB servers in the cluster: {}\n'.format(check_count_zfill, configDB_count))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.info('#{}: : No. of configDB servers in the cluster: {}\n'.format(check_count_zfill, configDB_count))
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#Check:Cluster:Messaging server
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print('  #{}:Checking:Cluster:Messaging server'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Messaging server'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					cluster_msdown,check_result,check_analysis, check_action = criticalCheckfifteen(vmanage_service_details, cluster_size)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: Servers with messaging service down: {}\n'.format(check_count_zfill, cluster_msdown))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#Check:Cluster:DR replication status
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print('  #{}:Checking:Cluster:DR replication status'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:DR replication status'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					dr_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'disasterrecovery/details', args.vmanage_port, tokenid))
					dr_status, check_action, check_analysis, check_result = criticalChecksixteen(dr_data)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: DR Replication status: {}\n'.format(check_count_zfill, dr_status))
						check_error_report(check_analysis,check_action)
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#Check:Cluster:Intercluster communication
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print('  #{}:Checking:Cluster:Intercluster communication'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Intercluster communication'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					if criticalCheckseventeen.is_alive():
						criticalCheckseventeen.join(10)

					if not criticalCheckseventeen.result_queue.empty():
						ping_output, ping_output_failed, check_result, check_analysis, check_action = criticalCheckseventeen.result_queue.get()
						if check_result == 'Failed':
							cluster_checks[check_name] = [ check_analysis, check_action]
							check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
							log_file_logger.error('#{}: Cluster nodes with ping failure: {}\n'.format(check_count_zfill, ping_output_failed))
							check_error_report(check_analysis,check_action)
						else:
							check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
							log_file_logger.info('#{}: Cluster nodes details: {}\n'.format(check_count_zfill, ping_output))
							writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
					log_file_logger.exception('{}\n'.format(e))

			#Logging out of the Session using jsessionid
			log_file_logger.info('Logging out of the Session')
			sessionLogout(vmanage_lo_ip, jsessionid, args.vmanage_port)
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
				json_final_result['json_data_pdf']['vmanage execution info'] = {"vManage Details":{
																					"Software Version":"{}".format(version),
																					"System IP Address":"{}".format(system_ip)
																				 }}
				if cluster_size > 1:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/health/details', args.vmanage_port))
					vmanage_cluster_ips = vmanage_cluster_ips(cluster_health_data)
					vmanage_service_details = vmanage_service_details(vmanage_cluster_ips)
					log_file_logger.info('deviceIPs of vManages in the cluster: {}'.format(vmanage_cluster_ips))
					#log_file_logger.info('Service details of all vManages in the cluster: {}'.format(vmanage_service_details))

			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error Collecting Preliminary Data. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))

			print('*Starting Checks, this may take several minutes\n\n')

			#Critical Checks
			critical_checks = {}
			log_file_logger.info('*** Performing Critical Checks\n')

			#Beginning #Check:Cluster:Intercluster communication  in the background
			if cluster_size>1:
				log_file_logger.info('Beginging #Check:Cluster:Intercluster communication  in the background')
				try:
					criticalCheckseventeen =  criticalCheckseventeen(cluster_health_data,  system_ip, log_file_logger)
				except Exception as e:
					log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Validate current version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Validate current version'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate current version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				boot_partition_size, check_result, check_analysis, check_action =  criticalCheckone(version)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: version: {}'.format(check_count_zfill, version))
					log_file_logger.error('#{}: Boot Partition Size: {}\n'.format(check_count_zfill, boot_partition_size))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: version: {}'.format(check_count_zfill, version))
					log_file_logger.info('#{}: Boot Partition Size: {}\n'.format(check_count_zfill, boot_partition_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO: {}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:At minimum 20%  server disk space should be available
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:vManage sever disk space'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:At minimum 20%  server disk space should be available'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				optdata_partition_size, rootfs_partition_size, check_result, check_analysis, check_action =  criticalCheckTwo()
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: /opt/data Used: {}'.format(check_count_zfill, optdata_partition_size))
					log_file_logger.error('#{}: /rootfs.rw Used: {}\n'.format(check_count_zfill, rootfs_partition_size))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: /opt/data Used: {}'.format(check_count_zfill, optdata_partition_size))
					log_file_logger.info('#{}: /rootfs.rw Used: {}\n'.format(check_count_zfill, rootfs_partition_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Memory size
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Memory size'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Memory size'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			writeFile(report_file, 'Link to the official documentation: \n https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html\n\n')
			try:
				memory_size, memory_size_str, dpi_status, server_type, check_result, check_analysis, check_action =  criticalCheckthree(vedge_count, dpi_status, server_type, cluster_size, version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Memory Size GB: {}'.format(check_count_zfill, memory_size_str))
					log_file_logger.error('#{}: /rootfs.rw Used: {}'.format(check_count_zfill, rootfs_partition_size))
					log_file_logger.error('#{}: Server Type: {}'.format(check_count_zfill, server_type))
					log_file_logger.error('#{}: vEdge Count: {}\n'.format(check_count_zfill, vedge_count))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': 'https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html'})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:CPU Count
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:CPU Count'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:CPU Count'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalCheckfour(cpu_count, vedge_count, dpi_status, server_type)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: CPU Count: {}\n'.format(check_count_zfill, cpu_count))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:ElasticSearch Indices status
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:ElasticSearch Indices status'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:ElasticSearch Indices status'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				#es_indices_one = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/info', args.vmanage_port))
				es_indices = es_indices_details()
				es_index_red_one, check_result_one, check_analysis_one, check_action_one = criticalCheckfive(es_indices)
				time.sleep(5)
				#es_indices_two = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/info', args.vmanage_port))
				es_indices = es_indices_details()
				es_index_red_two, check_result_two, check_analysis_two, check_action_two = criticalCheckfive(es_indices)


				if check_result_one == 'Failed' and check_result_two == 'Failed':
					critical_checks[check_name] = [ check_analysis_two, check_action_two]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis_two))
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

				elif check_result_one == 'SUCCESSFUL':
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_one))
					print(' INFO:{}\n\n'.format(check_analysis_one))
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

				elif check_result_two == 'SUCCESSFUL':
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_two))
					print(' INFO:{}\n\n'.format(check_analysis_two))
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Look for any neo4j exception errors
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Look for any neo4j exception errors'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Look for any neo4j exception errors'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalChecksix(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing  {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Validate all services are up
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Validate all services are up'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate all services are up'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				nms_data, nms_failed, check_result, check_analysis, check_action =   criticalCheckseven()
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: List of services that are enabled but not running:\n{}'.format(check_count_zfill, nms_failed))
					log_file_logger.error('#{}: Status of all services  :\n{}\n'.format(check_count_zfill, nms_data))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Status of all the services:\n{}\n'.format(check_count_zfill, nms_data))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name,log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Elasticsearch Indices version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Elasticsearch Indices version'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Elasticsearch Indices version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				version_list, check_result, check_analysis, check_action = criticalCheckeight(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: List of indices with older versions  :\n{}\n'.format(check_count_zfill, version_list))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Evaluate incoming DPI data size
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Evaluate incoming DPI data size'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Evaluate incoming DPI data size'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				es_indices_est = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'management/elasticsearch/index/size/estimate', args.vmanage_port))
				appr_estimate_ondeday, dpi_estimate_ondeday, check_result,check_analysis,check_action = criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count, total_devices, dpi_status)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Daily incoming DPI data : {}'.format(check_count_zfill, dpi_estimate_ondeday))
					log_file_logger.error('#{}: Daily incoming Approute data : {}\n'.format(check_count_zfill, appr_estimate_ondeday))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:NTP status across network
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:NTP status across network'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:NTP status across network'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				ntp_nonworking, check_result, check_analysis, check_action = criticalCheckten(version_tuple, controllers_info)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Devices with invalid ntp associations: \n{}\n'.format(check_count_zfill, ntp_nonworking))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file.  \033[0;0m \n\n'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Validate Neo4j Store version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Validate Neo4j Store version'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate Neo4j Store version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				nodestore_version, check_result, check_analysis, check_action = criticalCheckeighteen(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Neo4j Store version: {}\n'.format(check_count_zfill, nodestore_version))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Neo4j Store version: {}\n'.format(check_count_zfill, nodestore_version))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Validate ConfigDB Size is less than 5GB
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Validate ConfigDB Size is less than 5GB'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate ConfigDB Size is less than 5GB'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				db_size, check_result, check_analysis, check_action = criticalChecknineteen()
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: ConfigDB Size: {}\n'.format(check_count_zfill, db_size))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: ConfigDB Size: {}\n'.format(check_count_zfill, db_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers:Validate vSmart/vBond CPU count for scale
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:Controllers:Validate vSmart/vBond CPU count for scale'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Validate vSmart/vBond CPU count for scale'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				for vbond in vbond_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip, jsessionid,'device/system/synced/status?deviceId={}'.format(vbond_info[vbond][1]),args.vmanage_port ))
					if output['data'] != []:
							total_cpu_count = int(output['data'][0]['total_cpu_count'])
					else:
						total_cpu_count = 0
					vbond_info[vbond].append(total_cpu_count)

				for vsmart in vsmart_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip, jsessionid,'device/system/synced/status?deviceId={}'.format(vsmart_info[vsmart][1]), args.vmanage_port))
					if output['data'] != []:
							total_cpu_count = int(output['data'][0]['total_cpu_count'])
					else:
						total_cpu_count = 0
					vsmart_info[vsmart].append(total_cpu_count)

				failed_vbonds,failed_vsmarts,check_result,check_analysis, check_action = criticalCheckeleven(total_devices, vbond_info, vsmart_info)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: vBonds with insufficient CPU count: \n{}'.format(check_count_zfill, failed_vbonds))
					log_file_logger.error('#{}: vSmarts with insufficient CPU count: \n{}'.format(check_count_zfill, failed_vsmarts))
					log_file_logger.error('#{}: All vBonds info with total_cpu_count: \n{}'.format(check_count_zfill, vbond_info))
					log_file_logger.error('#{}: All vSmarts info with total_cpu_count: \n{}\n'.format(check_count_zfill, vsmart_info))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: All vBonds info with total_cpu_count: \n{}'.format(check_count_zfill, vbond_info))
					log_file_logger.info('#{}: ll vSmarts info with total_cpu_count: \n{}\n'.format(check_count_zfill, vsmart_info))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name,log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Warning Checks
			print('\n**** Performing Warning checks\n')
			warning_checks = {}
			log_file_logger.info('*** Performing Warning Checks')

			#Check:vManage:CPU Speed
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:CPU Speed'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:CPU Speed'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result,check_analysis,check_action = warningCheckone(cpu_speed)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: CPU clock speed: {}\n'.format(check_count_zfill, cpu_speed))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})

			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Network Card type
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Network Card type'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Network Card type'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				eth_drivers, check_action, check_analysis, check_result = warningChecktwo()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Ethercardswith e1000 card types: {}\n'.format(check_count_zfill, eth_drivers))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name,log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Backup status
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Backup status'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Backup status'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				date_time_obj, check_result, check_analysis, check_action = warningCheckthree()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Last Backup was performed on: {}\n'.format(check_count_zfill, date_time_obj))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name,log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Evaluate Neo4j performance
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Evaluate Neo4j performance'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Evaluate Neo4j performance'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = warningCheckfour()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name,log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Confirm there are no pending tasks
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Confirm there are no pending tasks'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Confirm there are no pending tasks'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				tasks = json.loads(getRequest(version_tuple,vmanage_lo_ip,  jsessionid,'device/action/status/tasks', args.vmanage_port))
				tasks_running, check_result, check_analysis, check_action  = warningCheckfive(tasks)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Tasks still running: {}\n'.format(check_count_zfill, tasks_running))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name,log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Validate there are no empty password users
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Validate there are no empty password users'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate there are no empty password users'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				users_emptypass, check_result, check_analysis, check_action = warningChecksix(version_tuple)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Users with empty passwords: {}\n'.format(check_count_zfill, users_emptypass))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name,log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers:Controller versions
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:Controllers:Controller versions'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Controller versions'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = warningCheckseven(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers:Confirm Certificate Expiration Dates
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:Controllers:Confirm Certificate Expiration Dates'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Confirm Certificate Expiration Dates'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				controllers_exp, controllers_notexp, check_result, check_analysis, check_action = warningCheckeight(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Controllers with certificates close to expiration:\n{}\n'.format(controllers_exp))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name,log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers:vEdge list sync
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:Controllers:vEdge list sync'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:vEdge list sync'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				state_vedgeList,check_result, check_analysis, check_action  = warningChecknine(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Controllers with inconsistent state_vedgeList: {}\n'.format(check_count_zfill, state_vedgeList))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers: Confirm control connections
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:Controllers: Confirm control connections'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers: Confirm control connections'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				control_sum_tab, discrepancy,check_result, check_analysis, check_action = warningCheckten(vsmart_count, vbond_count)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Control  Connections Summary: \n{}\n'.format(check_count_zfill, control_sum_tab))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name,log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Informational Checks
			print('\n**** Performing Informational checks\n' )
			log_file_logger.info('*** Performing Informational Checks')

			#Check:vManage:Disk controller type
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Check:vManage:Disk controller type'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Disk controller type'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = infoCheckone(server_type, disk_controller)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Disk Controller type: {}\n'.format(check_count_zfill, disk_controller))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Disk Controller type: {}\n'.format(check_count_zfill, disk_controller))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:Validate there is at minimum vBond, vSmart present
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Check:Controllers:Validate there is at minimum vBond, vSmart present '.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Validate there is at minimum vBond, vSmart present'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = infoChecktwo(vsmart_count,vbond_count)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: vSmart Count: {}'.format(check_count_zfill, vsmart_count))
					log_file_logger.error('#{}: vBond Count: {}\n'.format(check_count_zfill, vbond_count))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: vSmart Count: {}'.format(check_count_zfill, vsmart_count))
					log_file_logger.info('#{}: vBond Count: {}\n'.format(check_count_zfill, vbond_count))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name,log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers:Validate all controllers are reachable
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Check:Controllers:Validate all controllers are reachable'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Validate all controllers are reachable'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				unreach_controllers,check_result, check_analysis, check_action = infoChecktthree(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Unreachable Controllers: {}\n'.format(check_count_zfill, unreach_controllers))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			if cluster_size>1:
				cluster_checks = {}

				log_file_logger.info('*** Performing Cluster Checks')
				print('\n**** Performing Cluster checks\n')

				#Check:Cluster:Version consistency
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' #{}:Checking:Cluster:Version consistency'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Version consistency'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					check_result,check_analysis, check_action = criticalChecktwelve(vmanage_info)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: vManage info: {}\n'.format(check_count_zfill, vmanage_info))
						check_error_report(check_analysis,check_action)
						print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.info('#{}: vManage info: {}\n'.format(check_count_zfill, vmanage_info))
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						print(' INFO:{}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name,log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#Check:Cluster:Cluster health
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' #{}:Checking:Cluster:Cluster health'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Cluster health'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					services_down, check_result, check_analysis, check_action = criticalCheckthirteen(vmanage_service_details)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: Relevant cluster services that are down: {}\n'.format(check_count_zfill, services_down))
						check_error_report(check_analysis,check_action)
						print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						print(' INFO:{}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name,log_file_path))
					log_file_logger.exception('{}\n'.format(e))



				#Check:Cluster:Cluster ConfigDB topology
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' #{}:Checking:Cluster:Cluster ConfigDB topology'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Cluster ConfigDB topology'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					configDB_count, check_result, check_analysis, check_action = criticalCheckfourteen(vmanage_service_details)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: No. of configDB servers in the cluster: {}\n'.format(check_count_zfill, configDB_count))
						check_error_report(check_analysis,check_action)
						print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.info('#{}: No. of configDB servers in the cluster: {}\n'.format(check_count_zfill, configDB_count))
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						print(' INFO:{}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name,log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#Check:Cluster:Messaging server
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' #{}:Checking:Cluster:Messaging server'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Messaging server'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					cluster_msdown,check_result,check_analysis, check_action = criticalCheckfifteen(vmanage_service_details, cluster_size)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: Servers with messaging service down: {}\n'.format(check_count_zfill, cluster_msdown))
						check_error_report(check_analysis,check_action)
						print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						print(' INFO:{}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name,log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#Check:Cluster:DR replication status
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' #{}:Checking:Cluster:DR replication status'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:DR replication status'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					dr_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'disasterrecovery/details', args.vmanage_port))
					dr_status, check_action, check_analysis, check_result = criticalChecksixteen(dr_data)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: DR Replication status: {}\n'.format(check_count_zfill, dr_status))
						check_error_report(check_analysis,check_action)
						print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						print(' INFO:{}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name,log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#Check:Cluster:Intercluster communication
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' #{}:Checking:Cluster:Intercluster communication'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Intercluster communication'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					if criticalCheckseventeen.is_alive():
						criticalCheckseventeen.join(10)

					if not criticalCheckseventeen.result_queue.empty():
						ping_output, ping_output_failed, check_result, check_analysis, check_action = criticalCheckseventeen.result_queue.get()
						if check_result == 'Failed':
							cluster_checks[check_name] = [ check_analysis, check_action]
							check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
							log_file_logger.error('#{}: Cluster nodes with ping failure: {}\n'.format(check_count_zfill, ping_output_failed))
							check_error_report(check_analysis,check_action)
							print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
						else:
							check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
							log_file_logger.info('#{}: Cluster nodes details: {}\n'.format(check_count_zfill, ping_output))
							writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
							print(' INFO:{}\n\n'.format(check_analysis))
						json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
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
				json_final_result['json_data_pdf']['vmanage execution info'] = {"vManage Details":{
																					"Software Version":"{}".format(version),
																					"System IP Address":"{}".format(system_ip)
																				 }}
				if cluster_size > 1:
					cluster_health_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid, 'clusterManagement/health/details', args.vmanage_port, tokenid))
					vmanage_cluster_ips = vmanage_cluster_ips(cluster_health_data)
					vmanage_service_details = vmanage_service_details(vmanage_cluster_ips)
					log_file_logger.info('deviceIPs of vManages in the cluster: {}'.format(vmanage_cluster_ips))
					#log_file_logger.info('Service details of all vManages in the cluster: {}'.format(vmanage_service_details))

			except Exception as e:
				log_file_logger.exception('{}\n'.format(e))
				raise SystemExit('\033[1;31m ERROR: Error Collecting Preliminary Data. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))


			print('*Starting Checks, this may take several minutes\n\n')

			#Critical Checks
			print('\n**** Performing Critical checks\n')

			#Beginning #Check:Cluster:Intercluster communication  in the background
			if cluster_size>1:
				log_file_logger.info('Beginging #Check:Cluster:Intercluster communication  in the background\n')
				try:
					criticalCheckseventeen =  criticalCheckseventeen(cluster_health_data,  system_ip, log_file_logger)
				except Exception as e:
					log_file_logger.exception('{}\n'.format(e))

			critical_checks = {}
			log_file_logger.info('*** Performing Critical Checks\n')

			#Check:vManage:Validate current version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Validate current version'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate current version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				boot_partition_size, check_result, check_analysis, check_action =  criticalCheckone(version)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: version: {}'.format(check_count_zfill, version))
					log_file_logger.error('#{}: Boot Partition Size: {}\n'.format(check_count_zfill, boot_partition_size))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: version: {}'.format(check_count_zfill, version))
					log_file_logger.info('#{}: Boot Partition Size: {}\n'.format(check_count_zfill, boot_partition_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:At minimum 20%  server disk space should be available
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:vManage sever disk space')
			check_name = '#{}:Check:vManage:At minimum 20%  server disk space should be available'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				optdata_partition_size, rootfs_partition_size, check_result, check_analysis, check_action =  criticalCheckTwo()
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: /opt/data Used: {}'.format(check_count_zfill, optdata_partition_size))
					log_file_logger.error('#{}: /rootfs.rw Used: {}\n'.format(check_count_zfill, rootfs_partition_size))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: /opt/data Used: {}'.format(check_count_zfill, optdata_partition_size))
					log_file_logger.info('#{}: /rootfs.rw Used: {}\n'.format(check_count_zfill, rootfs_partition_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Memory size
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Memory size'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Memory size'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			writeFile(report_file, 'Link to the official documentation: \n https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html\n\n')
			try:
				memory_size, memory_size_str, dpi_status, server_type, check_result, check_analysis, check_action =  criticalCheckthree(vedge_count, dpi_status, server_type, cluster_size, version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Memory Size GB: {}'.format(check_count_zfill, memory_size_str))
					log_file_logger.error('#{}: /rootfs.rw Used: {}'.format(check_count_zfill, rootfs_partition_size))
					log_file_logger.error('#{}: Server Type: {}'.format(check_count_zfill, server_type))
					log_file_logger.error('#{}: vEdge Count: {}\n'.format(check_count_zfill, vedge_count))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis) )
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': 'https://www.cisco.com/c/en/us/td/docs/routers/sdwan/release/notes/compatibility-and-server-recommendations/ch-server-recs-20-3.html'})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:CPU Count
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:CPU Count'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:CPU Count'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalCheckfour(cpu_count, vedge_count, dpi_status, server_type)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: CPU Count: {}\n'.format(check_count_zfill, cpu_count))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:ElasticSearch Indices status
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:ElasticSearch Indices status'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:ElasticSearch Indices status'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				#es_indices_one = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_indices = es_indices_details()
				es_index_red_one, check_result_one, check_analysis_one, check_action_one = criticalCheckfive(es_indices)
				time.sleep(5)
				#es_indices_two = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'management/elasticsearch/index/info', args.vmanage_port, tokenid))
				es_indices = es_indices_details()
				es_index_red_two, check_result_two, check_analysis_two, check_action_two = criticalCheckfive(es_indices)

				if check_result_one == 'Failed' and check_result_two == 'Failed':
					critical_checks[check_name] = [ check_analysis_two, check_action_two]
					check_error_logger(log_file_logger, check_result_two, check_action_two, check_count_zfill)
					check_error_report(check_analysis_two,check_action_two)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis_two))
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result_two]),
															 'result': '{}'.format(check_analysis_two),
															 'action': '{}'.format(check_action_two),
															 'status': '{}'.format(check_result_two),
															 'document': ''})
				elif check_result_one == 'SUCCESSFUL':
					check_info_logger(log_file_logger, check_result_one, check_analysis_one, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_one))
					print(' INFO:{}\n\n'.format(check_analysis_one))
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result_one]),
															 'result': '{}'.format(check_analysis_one),
															 'action': '{}'.format(check_action_one),
															 'status': '{}'.format(check_result_one),
															 'document': ''})
				elif check_result_two == 'SUCCESSFUL':
					check_info_logger(log_file_logger, check_result_two, check_analysis_two, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis_two))
					print(' INFO:{}\n\n'.format(check_analysis_two))
					json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result_two]),
															 'result': '{}'.format(check_analysis_two),
															 'action': '{}'.format(check_action_two),
															 'status': '{}'.format(check_result_two),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name,log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Look for any neo4j exception errors
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Look for any neo4j exception errors'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Look for any neo4j exception errors'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalChecksix(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Validate all services are up
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Validate all services are up'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate all services are up'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				nms_data, nms_failed, check_result, check_analysis, check_action =   criticalCheckseven()
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: List of services that are enabled but not running:\n{}\n'.format(check_count_zfill, nms_failed))
					log_file_logger.error('#{}: Status of all services  :\n{}\n'.format(check_count_zfill, nms_data))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Status of all the services:\n{}\n'.format(check_count_zfill, nms_data))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))

					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name,log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Elasticsearch Indices version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Elasticsearch Indices version'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Elasticsearch Indices version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				version_list, check_result, check_analysis, check_action = criticalCheckeight(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: List of indices with older versions  :\n{}\n'.format(check_count_zfill, version_list))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Evaluate incoming DPI data size
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Evaluate incoming DPI data size'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Evaluate incoming DPI data size'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				es_indices_est = json.loads(getRequest(version_tuple,vmanage_lo_ip,jsessionid, 'management/elasticsearch/index/size/estimate', args.vmanage_port, tokenid))
				appr_estimate_ondeday, dpi_estimate_ondeday, check_result, check_analysis,check_action = criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count, total_devices, dpi_status)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Daily incoming DPI data : {}'.format(check_count_zfill, dpi_estimate_ondeday))
					log_file_logger.error('#{}: Daily incoming Approute data : {}\n'.format(check_count_zfill, appr_estimate_ondeday))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#Check:vManage:NTP status across network
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:NTP status across network'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:NTP status across network'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				ntp_nonworking, check_result, check_analysis, check_action = criticalCheckten(version_tuple, controllers_info)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Devices with invalid ntp associations: \n{}\n'.format(check_count_zfill, ntp_nonworking))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name,log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Validate Neo4j Store version
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Validate Neo4j Store version'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate Neo4j Store version'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				nodestore_version, check_result, check_analysis, check_action = criticalCheckeighteen(version_tuple)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Neo4j Store version: {}\n'.format(check_count_zfill, nodestore_version))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Neo4j Store version: {}\n'.format(check_count_zfill, nodestore_version))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:vManage:Validate ConfigDB Size is less than 5GB
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print('  #{}:Checking:vManage:Validate ConfigDB Size is less than 5GB'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate ConfigDB Size is less than 5GB'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				db_size, check_result, check_analysis, check_action = criticalChecknineteen()
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: ConfigDB Size: {}\n'.format(check_count_zfill, db_size))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: ConfigDB Size: {}\n'.format(check_count_zfill, db_size))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
																 'log type': '{}'.format(result_log['Critical'][check_result]),
																 'result': '{}'.format(check_analysis),
																 'action': '{}'.format(check_action),
																 'status': '{}'.format(check_result),
																 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers:Validate vSmart/vBond CPU count for scale
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:Controllers:Validate vSmart/vBond CPU count for scale'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Validate vSmart/vBond CPU count for scale'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				for vbond in vbond_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip, jsessionid, 'device/system/synced/status?deviceId={}'.format(vbond_info[vbond][1]),args.vmanage_port, tokenid))
					if output['data'] != []:
							total_cpu_count = int(output['data'][0]['total_cpu_count'])
					else:
						total_cpu_count = 0
					vbond_info[vbond].append(total_cpu_count)

				for vsmart in vsmart_info:
					output = json.loads(getRequest( version_tuple,vmanage_lo_ip,jsessionid, 'device/system/synced/status?deviceId={}'.format(vsmart_info[vsmart][1]),args.vmanage_port,tokenid))
					if output['data'] != []:
							total_cpu_count = int(output['data'][0]['total_cpu_count'])
					else:
						total_cpu_count = 0
					vsmart_info[vsmart].append(total_cpu_count)

				failed_vbonds,failed_vsmarts,check_result,check_analysis, check_action = criticalCheckeleven(total_devices, vbond_info, vsmart_info)
				if check_result == 'Failed':
					critical_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: vBonds with insufficient CPU count: \n{}'.format(check_count_zfill, failed_vbonds))
					log_file_logger.error('#{}: vSmarts with insufficient CPU count: \n{}'.format(check_count_zfill, failed_vsmarts))
					log_file_logger.error('#{}: All vBonds info with total_cpu_count: \n{}'.format(check_count_zfill, vbond_info))
					log_file_logger.error('#{}: All vSmarts info with total_cpu_count: \n{}\n'.format(check_count_zfill, vsmart_info))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: All vBonds info with total_cpu_count:  \n{}'.format(check_count_zfill, vbond_info))
					log_file_logger.info('#{}: All vSmarts info with total_cpu_count: \n{}\n'.format(check_count_zfill, vsmart_info))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			# Check:vManage:Validate server configs file - uuid
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Validate uuid from server configs file.'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate uuid from server configs file.'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalChecktwenty(version)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis, check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))

				json_final_result['json_data_pdf']['description']['vManage'].append(
					{'analysis type': '{}'.format(check_name.split(':')[-1]),
						'log type': '{}'.format(result_log['Critical'][check_result]),
						'result': '{}'.format(check_analysis),
						'action': '{}'.format(check_action),
						'status': '{}'.format(check_result),
						'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			# Check:vManage:Validate server_configs.json
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Validate server_configs.json'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate server_configs.json'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalChecktwentyone(version)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis, check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))

				json_final_result['json_data_pdf']['description']['vManage'].append(
					{'analysis type': '{}'.format(check_name.split(':')[-1]),
						'log type': '{}'.format(result_log['Critical'][check_result]),
						'result': '{}'.format(check_analysis),
						'action': '{}'.format(check_action),
						'status': '{}'.format(check_result),
						'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			# Check:vManage:Validate UUID
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Validate uuid at /etc/viptela/uuid'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate uuid at /etc/viptela/uuid'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = criticalChecktwentytwo(version)
				if check_result == 'Failed':
					critical_checks[check_name] = [check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis, check_action)
					print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))

				json_final_result['json_data_pdf']['description']['vManage'].append(
					{'analysis type': '{}'.format(check_name.split(':')[-1]),
					'log type': '{}'.format(result_log['Critical'][check_result]),
					'result': '{}'.format(check_analysis),
					'action': '{}'.format(check_action),
					'status': '{}'.format(check_result),
					'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m'.format(
						check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Warning Checks
			print('\n**** Performing Warning checks\n')
			warning_checks = {}
			log_file_logger.info('*** Performing Warning Checks')

			#Check:vManage:CPU Speed
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:CPU Speed'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:CPU Speed'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result,check_analysis,check_action = warningCheckone(cpu_speed)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: CPU clock speed: {}\n'.format(check_count_zfill, cpu_speed))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Network Card type
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Network Card type'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Network Card type'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				eth_drivers, check_action, check_analysis, check_result = warningChecktwo()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Ethercardswith e1000 card types: {}\n'.format(check_count_zfill, eth_drivers))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Backup status
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Backup status'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Backup status'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				date_time_obj, check_result, check_analysis, check_action = warningCheckthree()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Last Backup was performed on:{}\n'.format(check_count_zfill, date_time_obj))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Evaluate Neo4j performance
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Evaluate Neo4j performance'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Evaluate Neo4j performance'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = warningCheckfour()
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:vManage:Confirm there are no pending tasks
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Confirm there are no pending tasks'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Confirm there are no pending tasks'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				tasks = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'device/action/status/tasks', args.vmanage_port, tokenid))
				tasks_running, check_result, check_analysis, check_action  = warningCheckfive(tasks)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Tasks still running: {}\n'.format(check_count_zfill, tasks_running))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#Check:vManage:Validate there are no empty password users
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:vManage:Validate there are no empty password users'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Validate there are no empty password users'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				users_emptypass, check_result, check_analysis, check_action = warningChecksix(version_tuple)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Users with empty passwords: {}\n'.format(check_count_zfill, users_emptypass))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n '.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:Controller versions
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:Controllers:Controller versions'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Controller versions'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = warningCheckseven(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:Confirm Certificate Expiration Dates
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:Controllers:Confirm Certificate Expiration Dates'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Confirm Certificate Expiration Dates'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				controllers_exp, controllers_notexp, check_result, check_analysis, check_action = warningCheckeight(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Controllers with certificates close to expiration: \n{}\n'.format(check_count_zfill, controllers_exp))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))

				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m  \n\n'.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:vEdge list sync
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:Controllers:vEdge list sync'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:vEdge list sync'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				state_vedgeList,check_result, check_analysis, check_action  = warningChecknine(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Controllers with inconsistent state_vedgeList: {}\n'.format(check_count_zfill, state_vedgeList))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#Check:Controllers: Confirm control connections
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Checking:Controllers: Confirm control connections'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers: Confirm control connections'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				control_sum_tab, discrepancy,check_result, check_analysis, check_action = warningCheckten(vsmart_count, vbond_count)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Control  Connections Summary: \n{}\n'.format(check_count_zfill, control_sum_tab))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Warning'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))



			#Informational Checks
			print('\n**** Performing Informational checks\n' )
			log_file_logger.info('*** Performing Informational Checks')

			#Check:vManage:Disk controller type
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Check:vManage:Disk controller type'.format(check_count_zfill))
			check_name = '#{}:Check:vManage:Disk controller type'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = infoCheckone(server_type, disk_controller)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Disk Controller type: {}\n'.format(check_count_zfill, disk_controller))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m\n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: Disk Controller type: {}\n'.format(check_count_zfill, disk_controller))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['vManage'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Informational'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))

			#Check:Controllers:Validate there is at minimum vBond, vSmart present
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Check:Controllers:Validate there is at minimum vBond, vSmart present '.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Validate there is at minimum vBond, vSmart present'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				check_result, check_analysis, check_action = infoChecktwo(vsmart_count,vbond_count)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: vSmart Count: {}'.format(check_count_zfill, vsmart_count))
					log_file_logger.error('#{}: vBond Count: {}\n'.format(check_count_zfill, vbond_count))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.info('#{}: vSmart Count: {}'.format(check_count_zfill, vsmart_count))
					log_file_logger.info('#{}: vBond Count: {}\n'.format(check_count_zfill, vbond_count))
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Informational'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			#Check:Controllers:Validate all controllers are reachable
			check_count += 1
			check_count_zfill = zfill_converter(check_count)
			print(' #{}:Check:Controllers:Validate all controllers are reachable'.format(check_count_zfill))
			check_name = '#{}:Check:Controllers:Validate all controllers are reachable'.format(check_count_zfill)
			pre_check(log_file_logger, check_name)
			try:
				unreach_controllers,check_result, check_analysis, check_action = infoChecktthree(controllers_info)
				if check_result == 'Failed':
					warning_checks[check_name] = [ check_analysis, check_action]
					check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					log_file_logger.error('#{}: Unreachable Controllers: {}\n'.format(check_count_zfill, unreach_controllers))
					check_error_report(check_analysis,check_action)
					print('\033[1;31m WARNING: {} \033[0;0m \n\n'.format(check_analysis))
				else:
					check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
					writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
					print(' INFO:{}\n\n'.format(check_analysis))
				json_final_result['json_data_pdf']['description']['Controllers'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Informational'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
			except Exception as e:
				print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(check_name, log_file_path))
				log_file_logger.exception('{}\n'.format(e))


			if cluster_size>1:
				cluster_checks = {}

				log_file_logger.info('*** Performing Cluster Checks')
				print('\n**** Performing Cluster checks\n')

				#Check:Cluster:Version consistency
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' #{}:Checking:Cluster:Version consistency'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Version consistency'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					check_result,check_analysis, check_action = criticalChecktwelve(vmanage_info)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: vManage info: {}\n'.format(check_count_zfill, vmanage_info))
						check_error_report(check_analysis,check_action)
						print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.info('#{}: vManage info: {}\n'.format(check_count_zfill, vmanage_info))
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						print(' INFO:{}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#Check:Cluster:Cluster health
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' #{}:Checking:Cluster:Cluster health'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Cluster health'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					services_down, check_result, check_analysis, check_action = criticalCheckthirteen(vmanage_service_details)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: Relevant cluster services that are down: {}\n'.format(check_count_zfill, services_down))
						check_error_report(check_analysis,check_action)
						print('\033[1;31m ERROR: {} \033[0;0m\n\n'.format(check_analysis))
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						print(' INFO:{}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#Check:Cluster:Cluster ConfigDB topology
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' #{}:Checking:Cluster:Cluster ConfigDB topology'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Cluster ConfigDB topology'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					configDB_count, check_result, check_analysis, check_action = criticalCheckfourteen(vmanage_service_details)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: No. of configDB servers in the cluster: {}\n'.format(check_count_zfill, configDB_count))
						check_error_report(check_analysis,check_action)
						print('\033[1;31m ERROR: {} \033[0;0m\n\n'.format(check_analysis))
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.info('#{}: No. of configDB servers in the cluster: {}\n'.format(check_count_zfill, configDB_count))
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						print(' INFO:{}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n'.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))

				#Check:Cluster:Messaging server
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' #{}:Checking:Cluster:Messaging server'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Messaging server'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					cluster_msdown,check_result,check_analysis, check_action = criticalCheckfifteen(vmanage_service_details, cluster_size)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: Servers with messaging service down: {}\n'.format(check_count_zfill, cluster_msdown))
						print('\033[1;31m ERROR: {} \033[0;0m\n\n'.format(check_analysis))
					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						print(' INFO:{}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))


				#Check:Cluster:DR replication status
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' #{}:Checking:Cluster:DR replication status'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:DR replication status'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					dr_data = json.loads(getRequest(version_tuple,vmanage_lo_ip, jsessionid,'disasterrecovery/details', args.vmanage_port, tokenid))
					dr_status, check_action, check_analysis, check_result = criticalChecksixteen(dr_data)
					if check_result == 'Failed':
						cluster_checks[check_name] = [ check_analysis, check_action]
						check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						log_file_logger.error('#{}: DR Replication status: {}\n'.format(check_count_zfill, dr_status))
						check_error_report(check_analysis,check_action)
						print('\033[1;31m ERROR: {} \033[0;0m\n\n'.format(check_analysis))

					else:
						check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
						writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
						print(' INFO:{}\n\n'.format(check_analysis))
					json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))



				#Check:Cluster:Intercluster communication
				check_count += 1
				check_count_zfill = zfill_converter(check_count)
				print(' #{}:Checking:Cluster:Intercluster communication'.format(check_count_zfill))
				check_name = '#{}:Check:Cluster:Intercluster communication'.format(check_count_zfill)
				pre_check(log_file_logger, check_name)
				try:
					if criticalCheckseventeen.is_alive():
						criticalCheckseventeen.join(10)

					if not criticalCheckseventeen.result_queue.empty():
						ping_output, ping_output_failed, check_result, check_analysis, check_action = criticalCheckseventeen.result_queue.get()
						if check_result == 'Failed':
							cluster_checks[check_name] = [ check_analysis, check_action]
							check_error_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
							log_file_logger.error('#{}: Cluster nodes with ping failure: {}\n'.format(check_count_zfill, ping_output_failed))
							check_error_report(check_analysis,check_action)
							print('\033[1;31m ERROR: {} \033[0;0m \n\n'.format(check_analysis))

						else:
							check_info_logger(log_file_logger, check_result, check_analysis, check_count_zfill)
							log_file_logger.info('#{}: Cluster nodes details: {}\n'.format(ping_output))
							writeFile(report_file, 'Result: INFO - {}\n\n'.format(check_analysis))
							print(' INFO:{}\n\n'.format(check_analysis))
						json_final_result['json_data_pdf']['description']['Cluster'].append({'analysis type': '{}'.format(check_name.split(':')[-1]),
															 'log type': '{}'.format(result_log['Critical'][check_result]),
															 'result': '{}'.format(check_analysis),
															 'action': '{}'.format(check_action),
															 'status': '{}'.format(check_result),
															 'document': ''})
				except Exception as e:
					print('\033[1;31m ERROR: Error performing {}. \n Please check error details in log file: {}.\n If needed, please reach out to tool support at: sure-tool@cisco.com, with your report and log file. \033[0;0m \n\n '.format(check_name, log_file_path))
					log_file_logger.exception('{}\n'.format(e))


			#Logging out of the Session using jsessionid
			log_file_logger.info('Logging out of the Session')
			sessionLogout(vmanage_lo_ip, jsessionid, args.vmanage_port)
			log_file_logger.info('Successfully closed the connection')


	report_file.close()


	end_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

	json_final_result['json_data_pdf']['vmanage execution info'].update({'Script Execution Time': {'Start Time': '{}'.format(start_time),'End Time': '{}'.format(end_time)}})

	#Final evaluation
	if len(critical_checks) == 0:
		final_eval = 'No critical issues found'
	elif len(critical_checks) != 0:
		final_eval = 'Critical issues found that need to be resolved before an upgrade'

	#Failed Check Count
	if cluster_size>1:
		checks_failed = len(critical_checks) + len(cluster_checks)
		checks_passed = check_count - checks_failed
	else:
		checks_failed = len(critical_checks)
		checks_passed = check_count - checks_failed

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



	if cluster_size>1:
		critical_checks_count = len(critical_checks) + len(cluster_checks)
	else:
		critical_checks_count = len(critical_checks)
	warning_checks_count = len(warning_checks)

	meta_data = [
	'AURA SDWAN Version:          {}\n\n'.format(__sure_version),
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
	'        Total Checks Performed:     {}\n'.format(check_count),
	'        Total Checks Passed:        {} out of {}\n'.format(checks_passed, check_count),
	'        Total Checks Failed:        {} out of {}\n'.format(checks_failed, check_count),
	'        Total Checks with Errors:   {}\n'.format(critical_checks_count),
	'        Total Checks with Warnings: {}\n\n'.format(warning_checks_count),
	'-----------------------------------------------------------------------------------------------------------------\n\n',
	'Detailed list of failed checks, and actions recommended\n\n'
	]

	full_lst = [
	'-----------------------------------------------------------------------------------------------------------------\n\n',
	'Detailed list of ALL checks, and actions recommended\n\n'
	]

	json_final_result['json_data_pdf']['result summary'] = {'Overall upgrade evaluation': '{}'.format(final_eval),
															'Result': {'Passed': '{}'.format(checks_passed), 'Failed': '{}'.format(checks_failed)}}

	report_file = open(report_file_path, 'r')
	Lines = report_file.readlines()
	Lines = Lines[:8] + meta_data + check_failed_lst + full_lst + Lines[8:]
	report_file.close()

	report_file = open(report_file_path, "w")
	report_file.writelines(Lines)
	report_file.close()

	json_file_path =  '{}/sure_json_summary_{}.json'.format(dir_path, datetime.now().strftime("%d_%m_%Y_%H_%M_%S"))
	with open(json_file_path, 'w') as json_file:
		json.dump(json_final_result, json_file, indent=2)


	print('\n******\nCisco AURA SDWAN tool execution completed.\n')
	print('Total Checks Performed: {}'.format(check_count))
	print('Overall Assessment: {} Critical errors, {} Warnings, please check report for details.'.format(critical_checks_count,warning_checks_count ))
	print ('    -- Full Results Report: {} '.format(report_file_path))
	print ('    -- Logs: {}'.format(log_file_path))
	print ('    -- Json Summary: {}\n'.format(json_file_path))
	print('Reach out to sure-tool@cisco.com if you have any questions or feedback\n')
