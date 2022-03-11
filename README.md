# Appthreat for SAST 
[App Threat](https://github.com/AppThreat/sast-scan) is a fully open-source SAST scanner supporting a range of languages and frameworks. This tool is used with GitHub actions using this [action](https://github.com/marketplace/actions/sast-scan).

## How to scan files 
* Add files to the **/AppThreat/files** directory.

**Thats it !!!**

## What's next ? 
* The scan will result in the creation of an "artifact" which will contain the scan results in different formats. 
* The artifact created is uploaded to github.
* The workflow file is configured in such a way that a python script stored in the repo itself (in the /AppThreat/script directory) is triggered.
* The python script in the **/AppThreat/script** folder uses the config file in the **/AppThreat/scirpt/config** directory to upload the artifact created to **RiskSense**.

## Python scipt functioning 
* Convert the scan result from json to csv.
* Get the network ID from Risk Sense using the network name from the config file. 
* Create an assessment in Risk Sense using the name AppThreat_\<Date\>_\<Time\>.
* Get an upload id. 
* Upload the csv file using the upload id to Risk Sense.
* Start parsing the uploaded file. 
