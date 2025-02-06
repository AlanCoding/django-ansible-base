import time

from ansible_base.task.publish import task


@task()
def hello_world():
    print('hello world')


@task()
def sleep(seconds=2):
    print(f'about to sleep for {seconds} seconds')
    time.sleep(seconds)
    print(f'finished sleeping for {seconds} seconds')
