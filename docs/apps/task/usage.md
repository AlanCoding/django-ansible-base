## DAB Task

This app "dab_task" provides a tasking system (it can run tasks in the background).
This is an overlay on top of the dispatcher library:

https://github.com/ansible/dispatcher

The key differences of using dab_task as opposed to the dispatcher directly are:

 - Tasks are submitted to a true queue backed by postgres
 - Formal message ACK de-duplicates submissions based on its UUID
 - Rollbacks for database changes are possible, allowing for a number of retries

The dispatcher library, itself, is intended to be lower-level,
to accomidate cases where an app implements these things on its own.

Obtaining these things come at a cost, mainly that almost all interactions
require an additional database interaction.

### Configuration

Decorate tasks to allow them to be ran as background tasks.

```python
from ansible_base.dispatcher.publish import task

@task()
def hello_world():
    print('hello world')
```

### Service

To run the service, use the management command

```
python manage.py run_dispatcher
```

### Publisher

Submit a task by importing it and using the interface from celery.

```python
from test_app.tasks import hello_world

hello_world.delay()
```

This will print "hello world" in the dispatcher service.
