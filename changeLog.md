# Change Log 
 
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
