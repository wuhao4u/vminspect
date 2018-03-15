from __future__ import absolute_import
from celery import Celery
import time
from inspector import performTask

app = Celery('tasks',
             broker='amqp://jimmy:jimmy123@localhost/jimmy_vhost',
             backend='rpc://',
        )

@app.task
def longtime_add(x, y):
    print('long time task begins')
    # sleep 5 seconds
    time.sleep(5)
    print('long time task finished')
    return x + y

@app.task
def scanOS(args1):
    return performTask(args1)
