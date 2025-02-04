import asyncio
import contextlib
import multiprocessing
import time
from uuid import uuid4

import pytest
from dispatcher.main import DispatcherMain


async def asyncio_target(queue_in, queue_out, config, this_uuid):
    try:
        dispatcher = DispatcherMain(config)

        await dispatcher.connect_signals()
        await dispatcher.start_working()
        await dispatcher.wait_for_producers_ready()
        queue_out.put('ready')

        print(f'{this_uuid} dispatcher server listening on queue_in')
        loop = asyncio.get_event_loop()
        message = await loop.run_in_executor(None, queue_in.get)

        print(f'{this_uuid} got message, will shut down: {message}')
    finally:
        await dispatcher.shutdown()
        await dispatcher.cancel_tasks()


def subprocess_target(queue_in, queue_out, config, this_uuid):
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(asyncio_target(queue_in, queue_out, config, this_uuid))
    except Exception:
        import traceback

        traceback.print_exc()
        # We are in a subprocess here, so even if we handle the exception
        # the main process will not know and still wait forever
        # so give them a kick on our way out
        print(f'{this_uuid} sending error message after error')
        queue_out.put('error')
    finally:
        print(f'{this_uuid} closing asyncio loop')
        loop.close()


class SubprocessRunner:

    def __init__(self):
        self.queue_in = multiprocessing.Queue()
        self.queue_out = multiprocessing.Queue()

    def start_in_subprocess(self, config, server_uuid):
        process = multiprocessing.Process(target=subprocess_target, args=(self.queue_in, self.queue_out, config, server_uuid))
        process.start()
        return process

    @contextlib.contextmanager
    def with_server(self, config, server_uuid=None):
        if server_uuid is None:
            server_uuid = str(uuid4())
        process = self.start_in_subprocess(config, server_uuid)
        msg = self.queue_out.get()
        if msg != 'ready':
            raise RuntimeError('never got ready message from subprocess')
        try:
            yield self
        finally:
            self.queue_in.put('stop')
            process.join(timeout=2)
            if not process.is_alive():
                return  # exited because we told it to

            # Subprocess did not behave
            process.terminate()  # SIGTERM
            # Poll to close process resources, due to race condition where it is not still running
            for i in range(3):
                time.sleep(0.1)
                try:
                    process.close()
                    break
                except Exception:
                    if i == 2:
                        raise


@pytest.fixture
def dispatcher_subprocess():
    server = SubprocessRunner()
    return server.with_server
