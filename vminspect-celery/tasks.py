from __future__ import absolute_import
from celery import app
import time
import subprocess

@app.task
def vminspect_scan(image):
    print("#########################################################")
    print("perform security scanning on " + image)
    subprocess.run(["sudo", "vminspect", 
        "vulnscan", "-c", 
        "50", "http://cve.circl.lu/api/search",
        image]) 
