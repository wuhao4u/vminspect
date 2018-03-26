import os
import os.path 
import zipfile
import json
import requests
import re
import errno
from collections import defaultdict

def dl_remote(local_path):
    if not os.path.exists(local_path):
        try:
            os.makedirs(local_path)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
    r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
    for filename in re.findall("nvdcve-1.0-.*\.json\.zip", r.text):
        r_file = requests.get("https://static.nvd.nist.gov/feeds/json/cve/1.0/" + filename, stream=True)
        with open(local_path + filename, 'wb+') as f:
            for chunk in r_file:
                f.write(chunk)
     #       print(local_path + filename)
        archive = zipfile.ZipFile(local_path + filename, 'r')
        archive.extractall(local_path)
        archive.close()
        os.remove(local_path + filename)

def load_local(cvepath):
    files = [f for f in os.listdir(cvepath) if os.path.isfile(os.path.join(cvepath, f))]
    files.sort()
    
    cve_dict = defaultdict(list)
    for file in files:            
        jsonfile = open(cvepath + "/" + file)
        file_dict = json.loads(jsonfile.read()) 
        for k,v in file_dict.items():
            cve_dict[k] += v
        jsonfile.close()
    ##print([item['cve']['CVE_data_meta']['ID'] for item in cve_dict['CVE_Items']])
    #print([item['impact'] for item in cve_dict['CVE_Items'] 
    #        if item['cve']['CVE_data_meta']['ID']=='CVE-2017-3738'])
    return cve_dict

