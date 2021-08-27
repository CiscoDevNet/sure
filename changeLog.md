## Change Log
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
