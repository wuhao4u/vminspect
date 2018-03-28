from .tasks import vminspect_scan 
import time
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("images", help="the images you are performing security scan")
    args = parser.parse_args()
    images = args.images
    for image in images.split(","):
        vminspect_scan.delay(images.strip())

