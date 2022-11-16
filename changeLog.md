# AURA-SDWAN (SURE)
Cisco AURA-SDWAN (SURE) Command Line tool performs a total of 26(Non Cluster Mode) or 32(Cluster Mode) checks at different levels of the SDWAN overlay. The purpose of the tool is to prevent potential failures and recommend corrective actions for a seamless upgrade process. The tool retrieves data using GET API Calls and show/shell commands.<br>

The objective is to execute without impact the performance of the vManage or other devices.

## Features:

- Simple and straighfroward, uses default python modules that are already available on the vManage server 
- Automatically generates TXT report.
- Only requires – vManage <username> and password.
- To Execute, simply copy the file to the vManage and run it on the server.
- Not Intrusive
- Run Time - usually less than 60 seconds, depending on your deployment size
- Root access is not required to perform any check.
- No data is collected or shared to anyone. All information used by the tool, remains in the provided report and logs

**IF YOU HAVE ANY QUESTIONS OR FEEDBACK, reach out to sure-tool@cisco.com**

## To Download the script on vManage
This script needs to be downloaded onto Cisco vManage.  <br>
**Note: The application can be downloaded under any desired directory, typically it is downloaded under the user home directory.**

**Option 1. Isolated environment.** <br>
Obtain file content from this site, then copy via SCP to the server. <br>

>scp source_file.py {user}@{vManageIP}:/home/{user}<br>

**Option 2. Paste Method.** <br>

* Open sure_script.py file, select all and copy to clipboard
* SSH to the vManage, and do vshell command
* Open vi, press Esc i (letter i), then paste the content
* Press Esc, :wq (symbol : and letters w,q) to save it


## How to Run


### Step 1: <br>

Go to the install directory where you put the file.<br>
Either change directory to sure.<br>
```sh 
cd ./sure
python sure.py
```
For 20.5, 20.6:  <br>
```sh 
cd ./sure
python3 sure.py
 ```
**OR** <br>

Run directly from the home directory.  <br>
```sh
python ./sure/sure.py
```
For 20.5, 20.6:  <br>
```sh
python3 ./sure/sure.py
```

### Step2 : Command Line Options <br>

```sh
usage: sure.py [-h] [-q] [-v] [-d] -u USERNAME 

SURE - SDWAN Uprade Readiness Engine - v2.0.0

optional arguments:
  -h, --help            show this help message and exit
  -q, --quiet           Quiet execution of the script
  -v, --verbose         Verbose execution of the script
  -d, --debug           Debug execution of the script
  -u USERNAME, --username USERNAME
                        vManage Username
  -vp VMANAGE_PORT, --vmanage_port VMANAGE_PORT
                        vManage Password
```
##  REQUIRED: You must provide the vManage <username>.<br>
**- OPTIONAL: Enter the vManage Port.**<br>

- -p --vmanage_port (Optional): <br>
> Note: The default vmanage_port is 8443, <br>
> https://{vManage_localip}:***8443***//dataservice system/device/vedges <br>
> if the port has been changed from 8443 to another port, use --vmanage_port/-p argument. <br>
> https://{vManage_localip}:***{vmanage_port}***//dataservice system/device/vedges <br>

###  OPTIONAL: Execution Ouput levels <br>

> 1. Quiet Execution Mode -q/--quiet <br>
> 2. Verbose Execution Mode -v/--verbose <br>
> 3. Debug Execution Mode -d/--debug <br>

> By default the script runs in the normal execution mode <br>
> In order to change the execution mode enter the desired flag.  <br>

**Example:** <br>

```sh 
python sure.py -u <vManageUsername> 
python sure.py -q -u <vManageUsername> 
python sure.py -v -u <vManageUsername>
python sure.py -d -u <vManageUsername> 
python sure.py -u <vManageUsername> -vp <vManagePort>
```
> vManage version 20.5.x onwards, python3 is supported hence enter the following python3 commands. 
```sh 
python3 sure.py -u <vManageUsername> 
python3 sure.py -q -u <vManageUsername> 
python3 sure.py -v -u <vManageUsername> 
python3 sure.py -d -u <vManageUsername> 
python3 sure.py -d -u <vManageUsername>  -vp <vManagePort>
 ```

### Step3 :vManagae Password <br>
After executing the python/python3 command, there will be a input prompt to enter the vManage Password. 
```sh 
vmanage-cluster1:~$ python sure.py -u <username>
vManage Password:
```
User can be operator/readonly,  no special privileges required

## Output
**Normal Execution:**<br>
CLI Output on executing the script in normal mode.
```sh
vmanage-cluster1:~$ python sure.py -u <username> 
vManage Password:
#########################################################
###         SURE – Version 2.0.0                      ###
#########################################################
###     Performing SD-WAN Upgrade Readiness Check     ###
#########################################################




*Starting Checks, this may take several minutes


**** Performing Critical checks

 Critical Check:#01
 Critical Check:#02
 Critical Check:#03
```
**Quiet Execution mode**<br>
In the quiet execution mode it quietly performs all the checks and on completion it provides the locations of the report and logs files that were generated. 
```sh
vmanage-cluster1:~$ python sure.py -q -u <username> 
vManage Password:
#########################################################
###         SURE – Version 2.0.0                      ###
#########################################################
###     Performing SD-WAN Upgrade Readiness Check     ###
#########################################################



*Starting Checks, this may take several minutes

******
Cisco SDWAN SURE tool execution completed. 
```

**Verbose Execution mode**<br>
In this mode the progress of the checks being performed can be monitored from the cli. 
```sh
vmanage-cluster1:~$ python sure.py -v -u <username> 
vManage Password:
#########################################################
###         SURE – Version 2.0.0                      ###
#########################################################
###     Performing SD-WAN Upgrade Readiness Check     ###
#########################################################




*Starting Checks, this may take several minutes

**** Performing Critical checks

  #01:Checking:vManage:Validate current version
  #02:Checking:vManage:vManage sever disk space
  #03:Checking:vManage:Memory size
  #04:Checking:vManage:CPU Count
```
 **3. Debug Execution mode**<br>
 In the debug mode you can monitor the check performed and check analysis from the cli. 
```sh
vmanage-cluster1:~$ python sure.py -d -u <username> 
vManage Password:
#########################################################
###         SURE – Version 2.0.0                      ###
#########################################################
###     Performing SD-WAN Upgrade Readiness Check     ###
#########################################################




*Starting Checks, this may take several minutes

**** Performing Critical checks

 #01:Checking:vManage:Validate current version
 INFO:Direct Upgrade to 20.5 is possible


 #02:Checking:vManage:vManage sever disk space
 INFO:Enough Disk space available to perform the upgrade
 
```
## After the script finishes the report, logs and json summary will be available.

```sh
******
Cisco SDWAN SURE tool execution completed.

Total Checks Performed: 32
Overall Assessment: 4 Critical errors, 2 Warnings, please check report for details.
    -- Full Results Report: sdwan_sure/sure_report_03_09_2021_11_35_56.txt 
    -- Logs: sdwan_sure/sure_logs_03_09_2021_11_35_56.log
    -- Json Summary: sdwan_sure/sure_json_summary_03_09_2021_11_35_56.json

Reach out to sure-tool@cisco.com if you have any questions or feedback


```

criticalChecknine(es_indices_est, server_type, cluster_size, cpu_count, total_devices, dpi_status)

## The tool retrieves data using the following resources:
- **GET API Calls**
    1.  https://{vManage_localip}:{Port}/dataservice/system/device/controllers
    2.  https://{vManage_localip}:{Port}/dataservice/system/device/vedges
    3.  https://{vManage_localip}:{Port}/dataservice/statistics/settings/status
    4.  https://{vManage_localip}:{Port}/dataservice/management/elasticsearch/index/size/estimate
    5.  https://{vManage_localip}:{Port}/dataservice/device/system/synced/status?deviceId={}
    6.  https://{vManage_localip}:{Port}/dataservice/clusterManagement/list
    7.  https://{vManage_localip}:{Port}/dataservice/disasterrecovery/details
    8.  https://{vManage_localip}:{Port}/dataservice/device/action/status/tasks
    9.  https://{vManage_localip}:{Port}/dataservice/device/vmanage
    10. https://{vManage_localip}:{Port}/dataservice/device/ntp/associations?deviceId={deviceIP}
- **show/shell commands**

## Performs the following checks:

**_Checks with severity level: CRITICAL_**<br>
\#01:Check:vManage:Validate current version <br>
\#02:Check:vManage:vManage:At minimum 20%  server disk space should be available <br>
\#03:Check:vManage:Memory size <br>
\#04:Check:vManage:CPU Count<br>
\#05:Check:vManage:ElasticSearch Indices status<br>
\#06:Check:vManage:Look for any neo4j exception errors<br>
\#07:Check:vManage:Validate all services are up<br>
\#08:Check:vManage:Elasticsearch Indices version<br>
\#09:Check:vManage:Evaluate incoming DPI data size<br>
\#10:Check:vManage:NTP status across network<br>
\#11:Check:vManage:Validate Neo4j Store version<br>
\#12:Check:vManage:Validate ConfigDB Size is less than 5GB<br>
\#13:Check:Controllers:Validate vSmart/vBond CPU count for scale<br>

**_Checks with severity level: WARNING_**<br>
\#14:Check:vManage:CPU Speed<br>
\#15:Check:vManage:Network Card type<br>
\#16:Check:vManage:Backup status<br>
\#17:Check:vManage:Evaluate Neo4j performance<br>
\#18:Check:vManage:Confirm there are no pending tasks<br>
\#19:Check:vManage:Validate there are no empty password users<br>
\#20:Check:Controllers:Controller versions<br>
\#21:Check:Controllers:Confirm Certificate Expiration Dates<br>
\#22:Check:Controllers:vEdge list sync<br>
\#22:Check:Controllers: Confirm control connections<br>

**_Checks with severity level: INFORMATIONAL_**<br>
\#24:Check:vManage:Disk controller type<br>
\#25:Check:Controllers:Validate there is at minimum vBond, vSmart present<br> 
\#26:Check:Controllers:Validate all controllers are reachable<br>

**_Cluster Checks with severity level: CRITICAL_**<br>
\#27:Check:Cluster:Version consistency<br>
\#28:Check:Cluster:Cluster health<br>
\#29:Check:Cluster:Cluster ConfigDB topology<br>
\#30:Check:Cluster:Messaging server<br>
\#31:Check:Cluster:DR replication status<br>
\#32:Check:Cluster:Intercluster communication<br>
