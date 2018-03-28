from .tasks import run_vulnscan 
import time

if __name__ == '__main__':
    #image_files = ['image1', 'image2', 'image3', 'image4', 'image5']
    image_files = ['image1', 'image2', 'image1']
    #image_files = ['/mnt/store/' + file for file in image_files] * 2
    image_files = ['/mnt/store/' + file for file in image_files]

    for image_file in image_files:
        run_vulnscan.delay(image_file)
        #result = longtime_add.delay(1,2)
    # at this time, our task is not finished, so it will return False
        #print('Task finished? ', result.ready())
        #print('Task result: ', result.result)
    # sleep 10 seconds to ensure the task has been finished
        #time.sleep(10)
    # now the task should be finished and ready method will return True
        #print('Task finished? ', result.ready())
        #print('Task result: ', result.result)
