from __future__ import absolute_import

from .celery import app
import time
import json
from inspector_chi import vulnscan_command


#@app.task
#def longtime_add(x, y):
#    print('long time task begins')
#    # sleep 5 seconds
#    time.sleep(5)
#    print('long time task finished')
#    return x + y

@app.task
def run_vulnscan(image_path='/mnt/store/image1'):
    arguments = {}
    arguments['disk'] = image_path
    arguments['url'] = 'http://cve.circl.lu/api/search'
    arguments['concurrency'] = 50
    result = vulnscan_command(arguments)
    image_name = image_path[image_path.rfind('/') + 1 :]
    result_file_name = '/home/ubuntu/vminspect-our-github/vminspect/scanning_result/' + image_name + '_' + str(int(time.time()))
    with open(result_file_name, 'w') as file:
        file.write(json.dumps(result, indent=2))

if __name__ == '__main__':
    run_vulnscan()
