# SDWAN-SURE 
Cisco SDWAN SURE Command Line tool performs a total of 30 checks at different levels of the SDWAN overlay. The purpose of the tool is to prevent potential failures and recommend corrective actions for a seamless upgrade process. The tool retrieves data using GET API Calls and show/shell commands.<br>

The objective is to execute without impact the performance of the vManage or other devices.

## Features:

- Simple and straighfroward, uses default python modules that are already available on the vManage server 
- Automatically generates TXT report.
- Only requires – vManage username and password.
- To Execute, simply copy the file to the vManage and run it on the server.
- Not Intrusive
- Run Time - usually less than 60 seconds, depending on your deployment size
- Root access is not required to perform any check.
- No data is collected or shared to anyone. All information used by the tool, remains in the provided report and logs

**IF YOU HAVE ANY QUESTIONS OR FEEDBACK, reach out to sure-tool@cisco.com**

## To Download the script on vManage
This script needs to be downloaded onto Cisco vManage.  <br>

**Option 1. git clone direct** <br>
First ssh to vManage. <br>
>ssh {user}@{ManageIP}

The next step is to get the script onto Cisco vManage.  <br>
Depending on access from vManage to the internet <br>

If you have access to the internet from vManage, can clone the repository (containing the executable) <br>
> git clone https://github.com/CiscoDevNet/sure.git<br>


**Option 2. Isolated environment.** <br>
You will need to clone (using method 1) to an intermediate machine and copy to vManage, using scp. <br>

>scp source_file.py {user}@{vManageIP}:/home/{user}<br>

**Option 3. Paste Method.** <br>

* Open sure_script.py file, select all and copy to clipboard
* SSH to the vManage, and do vshell command
* Open vi, press Esc i (letter i), then paste the content
* Press Esc, :wq (symbol : and letters w,q) to save it


## To get the latest version
We are adding new features regularly. If you have downloaded an older version, it is very easy to get the latest. If you used option #1, you can simply change directory into the jamun directory and use git pull, to update to latest

>$ cd ./jamun<br>
>$ git pull<br>

## How to Run


### Step 1: <br>

Go to the install directory where you put the file.<br>
Either change directory to jamun.<br>
```sh 
cd ./jamun
python sure.py
```
For 20.5, 20.6:  <br>
```sh 
cd ./jamun
python3 sure.py
 ```
**OR** <br>

Run directly from the home directory.  <br>
```sh
python ./jamun/sure.py
```
For 20.5, 20.6:  <br>
```sh
python3 ./jamun/sure.py
```

### Step2 : Command Line Options <br>

```sh
usage: sure.py [-h] [-q] [-v] [-d] -u USERNAME 

SURE - SDWAN Uprade Readiness Engine - v1.0.5

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
##  REQUIRED: You must provide the vManage username.<br>
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
vmanage-cluster1:~$ python sure.py -u admin
vManage Password:
```
User can be operator/readonly,  no special privileges required

## Output
**Normal Execution:**<br>
CLI Output on executing the script in normal mode.
```sh
vmanage-cluster1:~$ python sure.py -u username 
vManage Password:
#########################################################
###         SURE – Version 1.0.5                      ###
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
vmanage-cluster1:~$ python sure.py -q -u username 
vManage Password:
#########################################################
###         SURE – Version 1.0.5                      ###
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
vmanage-cluster1:~$ python sure.py -v -u username 
vManage Password:
#########################################################
###         SURE – Version 1.0.5                      ###
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
vmanage-cluster1:~$ python sure.py -d -u username 
vManage Password:
#########################################################
###         SURE – Version 1.0.5                      ###
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
## After the script finishes the report and logs will be available.

```sh
******
Cisco SDWAN SURE tool execution completed.

Overall Assessment: 4 Critical errors, 2 Warnings, please check report for details.
    -- Full Results Report: sdwan_sure/sure_report_03_09_2021_11_35_56.txt 
    -- Logs: sdwan_sure/sure_logs_03_09_2021_11_35_56.log

Reach out to sure-tool@cisco.com if you have any questions or feedback


```

## The tool retrieves data using the following resources:
- **GET API Calls**
    1.  https://{vManage_localip}:{Port}/dataservice/system/device/controllers
    2.  https://{vManage_localip}:{Port}//dataservice system/device/vedges
    3.  https://{vManage_localip}:{Port}//dataservice statistics/settings/status
    4.  https://{vManage_localip}:{Port}/dataservice/management/elasticsearch/index/size/estimate
    5.  https://{vManage_localip}:{Port}/dataservice device/system/synced/status?deviceId={}
    6.  https://{vManage_localip}:{Port}/dataservice clusterManagement/list
    7.  https://{vManage_localip}:{Port}/dataservice disasterrecovery/details
    8.  https://{vManage_localip}:{Port/dataservice device/action/status/tasks
- **show/shell commands**

## Performs the following checks :

**_Checks with severity level: CRITICAL_**<br>
\#01:Check:vManage:Validate current version <br>
\#02:Check:vManage:vManage sever disk space <br>
\#03:Check:vManage:Memory size <br>
\#04:Check:vManage:CPU Count<br>
\#05:Check:vManage:ElasticSearch Indices status<br>
\#06:Check:vManage:Look for any neo4j exception errors<br>
\#07:Check:vManage:Validate all services are up<br>
\#08:Check:vManage:Elasticsearch Indices version<br>
\#09:Check:vManage:Evaluate incoming DPI data size<br>
\#10:Check:vManage:NTP status across network<br>
\#11:Check:Controllers:Validate vSmart/vBond CPU count for scale<br>

**_Checks with severity level: WARNING_**<br>
\#12:Check:vManage:CPU Speed<br>
\#13:Check:vManage:Network Card type<br>
\#14:Check:vManage:Backup status<br>
\#15:Check:vManage:Evaluate Neo4j performance<br>
\#16:Check:vManage:Confirm there are no pending tasks<br>
\#17:Check:vManage:Validate there are no empty password users<br>
\#18:Check:Controllers:Controller versions<br>
\#19:Check:Controllers:Confirm Certificate Expiration Dates<br>
\#20:Check:Controllers:vEdge list sync<br>
\#21:Check:Controllers: Confirm control connections<br>

**_Checks with severity level: INFORMATIONAL_**<br>
\#22:Check:vManage:Disk controller type<br>
\#23:Check:Controllers:Validate there is at minimum vBond, vSmart present<br> 
\#24:Check:Controllers:Validate all controllers are reachable<br>

**_Cluster Checks with severity level: CRITICAL_**<br>
\#25:Check:Cluster:Version consistency<br>
\#26:Check:Cluster:Cluster health<br>
\#27:Check:Cluster:Cluster ConfigDB topology<br>
\#28:Check:Cluster:Messaging server<br>
\#29:Check:Cluster:DR replication status<br>
\#30:Check:Cluster:Intercluster communication<br>



