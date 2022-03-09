import json
from datetime import datetime
import os
import sys
import toml
import requests
from urllib3 import Retry
from requests.adapters import HTTPAdapter
from zipfile import ZipFile


def jsontocsv(json_filename,folder):
  try:
    with open(folder+json_filename) as json_format_file: 
      j = json.load(json_format_file)
    csv_filename = "AppThreatReport.csv"
    csv = open("AppThreatReport.csv","w")
    csvdata = "Pluginid,Locaiton,Address,Name,Title,Severity,Description,Solution\n"
    csv.write(csvdata)
  except:
    print("Error while creating the CSV file")
    print("Exiting...")
    sys.exit(0)
  for i in j['results']:
    res=dict(i)
    csvdata=res['test_id'] + "," #REQUIRED
    csvdata += res['filename'] + ": Line no."+str(res['line_number'])+ "," #REQUIRED
    csvdata += res['filename'] + "," #REQUIRED
    csvdata += res['filename'] + "," #REQUIRED
    csvdata += res['test_name'] + "," #REQUIRED

    if res['issue_severity'] == 'HIGH':
      csvdata +=  "10" + "," #REQUIRED
    elif res['issue_severity'] == 'MEDIUM':
      csvdata += "6" + "," #REQUIRED
    else:
      csvdata += "3" + "," #REQUIRED

    csvdata += "\"" + res["issue_text"] + "\"" + "," # HIGHLY RECOMMENDED 
    csvdata += res["more_info"] + "," # HIGHLY RECOMMENDED 
    csvdata += "\n"
    csv.write(csvdata)
  csv.close()

  return csv_filename


def read_config_file(filename):

    try:
        data = toml.loads(open(filename).read())
        return data
    except (Exception, FileNotFoundError, toml.TomlDecodeError) as ex:
        print("Error reading configuration file.")
        print(ex)
        print()
        input("Please press ENTER to close.")
        exit(1)

def process_config(config):
  try:
    platform_url = config['platform_url']
    api_key = os.getenv('RS_API_KEY')
    json_filename = config['json_filename']
    client_id = config['client_id']
    folder = config['folder']
#     network_id = config['network_id']
    network_name = config['network_name']
  except:
    print("Error accessing/using data from the config file.")
    print("The config file must contain the following values")
    print("[+] platform_url \n[+] api_key\n[+] client_id\n[+] network_id\n[+] json_filename")
  return platform_url, api_key, client_id, network_name, json_filename, folder 


def __requests_retry_session(max_retries=5, backoff_factor=0.5,
                             status_forcelist=(429, 502, 503)):

    session = requests.Session()
    retry = Retry(total=max_retries,
                  read=max_retries,
                  connect=max_retries,
                  backoff_factor=backoff_factor,
                  status_forcelist=status_forcelist)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    return session


#CREATING A NEW ASSESSMENT 
#THE ASSESSMENT NAME IS OF THE FORMAT APPTHREAT_<DATE>_<TIME>
def create_assessment(platform_url,api_key,client_id):

  startDate = str(datetime.now().strftime('%Y-%m-%d'))
  startTime = str(datetime.now().strftime('%H:%M'))
  assess_name = "AppThreat_"+ startDate + "_" + startTime
  url = "{}//api/v1/client/{}/assessment".format(
      platform_url, client_id)

  header = {
      "content-type": "application/json",
      "x-api-key": api_key}
 
  body = {
      "name": assess_name,
      "startDate": startDate,
      "notes": "",
      "startTime": startTime
  }

  try:
      raw_response = __requests_retry_session().post(
          url, headers=header, data=json.dumps(body))
  except TimeoutError as ex:
      print(ex)
  response = json.loads(raw_response.text)
  if raw_response and raw_response.status_code == 201:
      response = json.loads(raw_response.text)
      print("Assessment successfully created ")
      print("[+] Assessment Name : ",assess_name)
      return response['id']
  else:
      print(response)
      print(response.content)
      print('Error while creating the assessment')
      sys.exit(0)


# GET THE UPLOAD ID  
def get_upload_id(platform_url, api_key, client_id, assessment_id, network_id):

  url = "{}//api/v1/client/{}/upload".format(
      platform_url, client_id)
  header = {
      "content-type": "application/json",
      "x-api-key": api_key}
  body = {
      "assessmentId": assessment_id,
      "name":str(datetime.now().strftime('%Y-%m-%d')),
      "networkId":network_id
  }

  try:
      raw_response = __requests_retry_session().post(
          url, headers=header, data=json.dumps(body))
  except TimeoutError as ex:
      print(ex)

  if raw_response and raw_response.status_code == 201:
      response = json.loads(raw_response.text)
      return response['id']
  else:
      print('Error while getting upload id...')
      print("Exiting...")
      sys.exit(0)


# UPLOAD FILE USING UPLOAD ID 
def upload_file(upload_id,platform_url,client_id,api_key,csv_filename):

  url = "{}//api/v1/client/{}/upload/{}/file".format(
      platform_url, client_id, upload_id)
  header = {
      "x-api-key": api_key,
      "Content-Disposition": "form-data",
      "filename": csv_filename,
       }
  scanFile={'scanFile': open(csv_filename,'rb')}

  try:
      raw_response = __requests_retry_session().post(
          url, files=scanFile, headers=header)
  except TimeoutError as ex:
      print(ex)

  if raw_response and raw_response.status_code == 201:
      return
  else:
      print("Error while uploading the file ")
      print("Exiting...")
      sys.exit(0)


  
#PARSE THE UPLOADED FILE
def start_parsing(upload_id, platform_url, client_id, api_key ):

  url = "{}//api/v1/client/{}/upload/{}/start".format(
      platform_url, client_id,upload_id)
  header = {
      "content-type": "application/json",
      "x-api-key": api_key
      }
  body = {
      "autoUrba": False 
  }

  try:
      raw_response = __requests_retry_session().post(
          url, headers=header, data=json.dumps(body))
  except TimeoutError as ex:
      print(ex)

  if raw_response and raw_response.status_code == 200:
      print("Successfully started parsing the uploaded file :)")
  else:
      print("Couldnt start parsing the file")
      print("Exiting...")
      sys.exit(0)

# SEARCH FOR THE NETWORK AND GET THE NETWORK ID
def get_network_id(platform_url, api_key, client_id, network_name):

  url = "{}//api/v1/client/{}/network/search".format(
      platform_url, client_id)

  header = {
      "content-type": "application/json",
      "x-api-key": api_key}
 
  body = {
  "filters": [
    {
      "field": "name",
      "exclusive": False ,
      "operator": "EXACT",
      "value": network_name
    }
  ],
  "projection": "basic",
  "sort": [
    {
      "field": "name",
      "direction": "ASC"
    }
  ],
  "page": 0,
  "size": 1
  }

  try:
      raw_response = __requests_retry_session().post(
          url, headers=header, data=json.dumps(body))
  except TimeoutError as ex:
      print(ex)

  if raw_response and raw_response.status_code == 200:
      response = json.loads(raw_response.text)
      if(response['page']['totalElements'] != 1):
        print("Couldnt find the specified network.\nPlease update the config file... ")
        print("Exiting...")
        sys.exit(0)
      else:
        return (response['_embedded']['networks'][0]['id'])

  else:
    print('Error while finding the network')

#MAIN
def main():

  #READING THE CONFIG FILE 
  conf_file = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'conf', 'config.toml')
  config = read_config_file(conf_file)
  platform_url, api_key, client_id, network_name, json_filename, folder= process_config(config)
  #CHECKING FOR MISSING VARIABLES
  if (json_filename == "" or network_name == "" or client_id == "" or platform_url == "" or api_key == ""):
    print("Missing one or more of the following values ")
    print("\n[+] JsonFile Name (Report) \n[+] API kay \n[+] Client ID \n[+] Platform URL \n[+] Network Name \n[+] Report Folder Name")
    sys.exit(0)
  

  #CONVERTING THE JSON FILE TO CSV
  csv_filename = jsontocsv(json_filename,folder)

  #BUCKLE UP...
  network_id = get_network_id(platform_url, api_key, client_id,network_name)
  assessment_id = create_assessment(platform_url, api_key, client_id)
  upload_id = get_upload_id(platform_url, api_key, client_id, assessment_id, network_id)
  upload_file(upload_id,platform_url,client_id,api_key,csv_filename)
  start_parsing(upload_id, platform_url, client_id, api_key)
  
#  Execute the script
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print("KeyboardInterrupt detected.  Exiting...")
        print()
        sys.exit(0)
