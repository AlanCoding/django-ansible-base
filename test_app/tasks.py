import time

from ansible_base.task.publish import durable_tasktask


@durable_tasktask()
def hello_world():
    print('hello world')


@durable_tasktask()
def sleep(seconds=2):
    print(f'about to sleep for {seconds} seconds')
    time.sleep(seconds)
    print(f'finished sleeping for {seconds} seconds')
