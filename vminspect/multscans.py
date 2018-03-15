from remote import longtime_add,scanOS
import time

SCAN_LIST = ['/mnt/store/workload_52395c9b-e7a9-4e0c-a4a2-4578d105bff1/snapshot_1a04bb46-de77-4511-909f-2eacaf562592/vm_id_56e22431-d49c-41d3-8fa9-7846a9ea1e1b/vm_res_id_dc9a1d3f-3c68-492f-9da1-7ae161af648a_vda/195f6d48-fa65-4895-b48e-af203b82836c']

CVE_URL = "http://cve.circl.lu/api/search"

if __name__ == '__main__':
    SCAN_LIST.extend(SCAN_LIST)
    for img in SCAN_LIST :
        in_args = {}
        in_args["abs_path"] = img
        in_args["cve_url"] = CVE_URL
        result = scanOS.delay(in_args)
        # at this time, our task is not finished, so it will return False
        print('Task finished? ', result.ready())
        print('Task result: ', result.result)
        # sleep 10 seconds to ensure the task has been finished
        time.sleep(10)
        # now the task should be finished and ready method will return True
        print('Task finished? ', result.ready())
        print('Task result: ', result.result)
