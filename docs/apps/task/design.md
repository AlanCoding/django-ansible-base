## DAB Task System Design

The closest analog to the goals of this project may be the pulpcore task system

https://github.com/pulp/pulpcore/tree/main/pulpcore/tasking

The main loop is in the `worker` module under that. Like AWX, they use `select.select`,
and combined with `add_notify_handler`.

This accomplishes the goal of getting timely "wakeups" when a task is submitted.

https://www.psycopg.org/psycopg3/docs/advanced/async.html

> Alternatively, you can use add_notify_handler() to register a callback function, which will be invoked whenever a notification is received, during the normal query processing; you will be then able to use the connection normally. Please note that in this case notifications will not be received immediately, but only during a connection operation, such as a query.

After control is returned, `unblock_tasks` loops over `Task` objects in order of created time.
Based on the `Task` `status` field, it will take an action.

Since uuid primary keys are standard in pulp, the default `pulp_id` field is a valid uuid for the task.

While doing this, postgres advisory locks are used significantly to avoid errors from multiple simultaneous processes doing something.
