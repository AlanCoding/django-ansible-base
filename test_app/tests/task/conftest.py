import asyncio
import multiprocessing
import contextlib
import time

import pytest


from dispatcher.main import DispatcherMain



async def asyncio_target(queue_in, queue_out, config):
    try:
        dispatcher = DispatcherMain(config)

        await dispatcher.connect_signals()
        await dispatcher.start_working()
        await dispatcher.wait_for_producers_ready()
        queue_out.put('ready')


        print('dispatcher server listening on queue_in')
        loop = asyncio.get_event_loop()
        message = await loop.run_in_executor(None, queue_in.get)

        print(f'got message, will shut down: {message}')
    finally:
        await dispatcher.shutdown()
        await dispatcher.cancel_tasks()


def subprocess_target(queue_in, queue_out, config):
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(asyncio_target(queue_in, queue_out, config))
    except Exception:
        import traceback

        traceback.print_exc()
        # We are in a subprocess here, so even if we handle the exception
        # the main process will not know and still wait forever
        # so give them a kick on our way out
        print('sending error message after error')
        queue_out.put('error')
    finally:
        print('closing asyncio loop')
        loop.close()


class SubprocessRunner:

    def __init__(self):
        self.queue_in = multiprocessing.Queue()
        self.queue_out = multiprocessing.Queue()

    def start_in_subprocess(self, config):
        process = multiprocessing.Process(target=subprocess_target, args=(self.queue_in, self.queue_out, config))
        process.start()
        return process

    @contextlib.contextmanager
    def with_server(self, config):
        process = self.start_in_subprocess(config)
        msg = self.queue_out.get()
        if msg != 'ready':
            raise RuntimeError('never got ready message from subprocess')
        try:
            yield self
        finally:
            self.queue_in.put('stop')
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
