from __future__ import absolute_import
from celery import Celery

app = Celery('vminspect-celery',
             broker='amqp://jimmy:jimmy123@10.0.0.10/jimmy_vhost',
             backend='rpc://',
             include=['vminspect-celery.tasks'])
