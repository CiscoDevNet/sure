## Change Log

 - v1.0.6 (22nd October 2021)
 	- Check #06: Scan only errors(not warnings) within last 14 days in neo4j output file.
 	- CSRF Token generation failure, not storing the cookies in a file.
 	- Preliminary Data: Skip controllers if deviceState not READY.
 	- Changed the name from SURE TO AURA-SDWAN

 - v1.0.5 
 	- Authentication successful using passwords with special characters. Exclamation marks ('!'), only work from 20.3 due to vManage software dependencies to support that character

 - v1.0.4
  	- Error handling for thread execution
  	- Added version notice on script run
  	- Improved message at the end of run
  	- Improved error reporting, exception data collection
  	- Cookie file is deleted
  	- Other cosmetic changes
  	
 - v1.0.3
  	- Added handler for python import error in 20.5/20.6
	
 - v1.0.2
  	- Minor cosmeric changes
  	
- v1.0.1 
	- #09:Check:vManage:Evaluate incoming DPI data size<br>
		Modified the check to include the daily incoming Approute data in the daily incoming DPI data to evaluate if data within limits.
	- #05:Check:vManage:ElasticSearch Indices status<br>
	 	Performing the check twice at 5 seconds apart, to get rid of false positives.
	- Retrieving the system-ip using API.
	- Prompt the user for a password without echoing.
	- If unable to retrieve localhost IP, customer to verify if there were config changes and use static '127.0.0.1' instead.
	- Added mailer details to the tool.

- v1.0.0 (20th August 2021)
    - first release 
