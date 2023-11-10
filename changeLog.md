- v3.2.1 (10th November 2023)
  - Total Issues Fixed:
    - Server Type 'QEMU' Not known
      https://github.com/CiscoDevNet/sure/issues/114
    - Included Check Type in the JSON Summary of each check
      https://github.com/CiscoDevNet/sure/issues/117
    - Added -p argument for passing password as an argument 
      https://github.com/CiscoDevNet/sure/issues/116 
    - Removed Critical Check: CPU Clock Speed (Not required)

- v3.2.0 (4th October 2023)
  - Total Checks Added: 1
    - Critical Check - Verify if stale entry of vManage+vSmart UUID present on any one cEdge 
      https://github.com/CiscoDevNet/sure/issues/106
      
  - Total Issues Fixed: 9
    - Error Collecting Prelimiary Data- vEdge information
      https://github.com/CiscoDevNet/sure/issues/103
      https://github.com/CiscoDevNet/sure/issues/104 (Duplicate)
    - #01:CPU Speed - Permit lower speed for Azure Infrastructure
      https://github.com/CiscoDevNet/sure/issues/101
    - checkUtilization failing where wildfly. neo4j and elasticache not in the top 5 processes
      https://github.com/CiscoDevNet/sure/issues/100
    - py3 Library Errors on 20.5
      https://github.com/CiscoDevNet/sure/issues/99
    - py2 script error for 20.5.x versions
      https://github.com/CiscoDevNet/sure/issues/98
    - Text Discrepancy in Critical Check Nineteen
      https://github.com/CiscoDevNet/sure/issues/97
    - Preliminary Data: elasticSearch_data IndexError: list index out of range
      https://github.com/CiscoDevNet/sure/issues/88
    - KeyError: 'version' when collecting ControllersInfo - Preliminary Data
      https://github.com/CiscoDevNet/sure/issues/43
    - Tool fails with ERROR:'version'
      https://github.com/CiscoDevNet/sure/issues/3

- v3.0.0 (30th March 2023)
  - Total Enhancements: 6
    - Split the script into Python2 and Python3 versions
      https://github.com/CiscoDevNet/sure/issues/44
    - Enhance the script for version above 20.6 
      https://github.com/CiscoDevNet/sure/issues/46
    - Change SUCCESS to SUCCESSFUL throughout the script, for uniformity with NMS team
      https://github.com/CiscoDevNet/sure/issues/52 
    - Move Execution mode conditions within the check to shorten the length of script
      https://github.com/CiscoDevNet/sure/issues/68
    - Tabulate report file instead of sequential data 
      https://github.com/CiscoDevNet/sure/issues/69
    - Collecting Preliminary Data - Monitor RSS consumer JAVA process - wildfly, statsdb and neo4j
      https://github.com/CiscoDevNet/sure/issues/31

  - Total Checks Added : 3
    
    - Critical Check - Validate UUID from server configs file
    - Critical Check - Validate server configs file on vManage
    - Critical Check - Validate UUID at /etc/viptela/uuid

  - Total Issues Fixed: 5
    - Need to sanitize user input & perform error handling 
      https://github.com/CiscoDevNet/sure/issues/24
    - Keyerror exception on 'timeRemainingForExpiration' 
      https://github.com/CiscoDevNet/sure/issues/29
    - Tabulate the preliminary data 
      https://github.com/CiscoDevNet/sure/issues/30
    - Add warning incase DB Slicing is required. 
      https://github.com/CiscoDevNet/sure/issues/32
    - Return the roundtrip delay for intercluster comm. 
      https://github.com/CiscoDevNet/sure/issues/33

- v2.0.0 (23th September 2022)
  - 2 new vManage checks added:
    Check:vManage:Validate ConfigDB Size is less than 5GB
    Check:vManage:Validate Neo4j Store version
  - Generates summary report in JSON format for vDoctor integration.
  - Modified the script and Readme.md to reflect the exact check count 
  - Using is_alive in favour of isAlive for Python 3.9 compatibility.
  - Removed the Git option from the installation instructions in the readme.md 
  - Summary in the Report also indicates the Total Errors and Total Warnings
  - Added exceptions incase the script is executed on a multi-tenant vManage server
  - Fixed the upgrade path recommended for version 19.2 

- v1.0.8 (20th January 2022)
  - Check: Incorrect validation of vSmart count.
  
- v1.0.7 (22nd October 2021)
  - Check: Exception if index was on failed state caused by typo in code.
  
- v1.0.6 (22nd October 2021)
  - Check: Scan only errors(not warnings) within last 14 days in neo4j output file.
  - CSRF Token generation failure, not storing the cookies in a file.
  - Preliminary Data: Skip controllers if deviceState not READY.
  - Changed the name from SURE TO AURA-SDWAN.

 - v1.0.5 
  - Authentication successful using passwords with special characters. Exclamation marks ('!'), only work from 20.3 due to vManage software dependencies to support that character.

 - v1.0.4
    - Error handling for thread execution.
    - Added version notice on script run.
    - Improved message at the end of run.
    - Improved error reporting, exception data collection.
    - Cookie file is deleted.
    - Other cosmetic changes.
    
 - v1.0.3
    - Added handler for python import error in 20.5/20.6.
  
 - v1.0.2
    - Minor cosmetic changes.
    
- v1.0.1 
  - Check:vManage:Evaluate incoming DPI data size<br>
    Modified the check to include the daily incoming Approute data in the daily incoming DPI data to evaluate if data within limits.
  - Check:vManage:ElasticSearch Indices status<br>
    Performing the check twice at 5 seconds apart, to get rid of false positives.
  - Retrieving the system-ip using API.
  - Prompt the user for a password without echoing.
  - If unable to retrieve localhost IP, customer to verify if there were config changes and use static '127.0.0.1' instead.
  - Added mailer details to the tool.

- v1.0.0 (20th August 2021)
    - first release.
