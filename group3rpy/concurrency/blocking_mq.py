"""Port of LibSnaffle/Concurrency/BlockingMq.cs.

Class to provide an API for the BlockingCollection queue.
This class should be used for queuing output to be printed or written to file.

This class stores the queue, and methods for adding different QueueMessages.
This class can be extended to enqueue custom QueueMessage subclasses.

PORT NOTE: `BlockingCollection<QueueMessage>` becomes a `queue.Queue`, which has
the same blocking-take semantics that `Pop()` relies on.
"""

import datetime
import queue
from typing import Optional

from .messages import (
    DebugMessage,
    ErrorMessage,
    FatalMessage,
    FinishMessage,
    InfoMessage,
    QueueMessage,
    TraceMessage,
)


class BlockingMq:
    """Port of LibSnaffle.Concurrency.BlockingMq."""

    def __init__(self):
        """Default constructor."""
        #: The queue of QueueMessages
        self.q: queue.Queue[QueueMessage] = queue.Queue()

    def is_empty(self) -> bool:
        """Checks if the queue is empty. Returns true if the queue is empty."""
        return self.q.qsize() == 0

    def pop(self) -> QueueMessage:
        """Removes a message from the queue and returns is."""
        return self.q.get()

    def try_take(self) -> Optional[QueueMessage]:
        """PORT NOTE: stands in for `BlockingCollection.TryTake`, which
        Group3rRunner.DumpQueue uses to drain the queue without blocking."""
        try:
            return self.q.get_nowait()
        except queue.Empty:
            return None

    def terminate(self) -> None:
        """Enqueues a FatalMessage with a termination message."""
        self.q.put(
            FatalMessage(
                msg_date_time=datetime.datetime.now(),
                message_string="Terminate was called",
            )
        )

    def trace(self, message: str) -> None:
        """Enqueues a TraceMessage."""
        self.q.put(TraceMessage(msg_date_time=datetime.datetime.now(), message_string=message))

    def degub(self, message: str) -> None:
        """Enqueues a DebugMessage."""
        self.q.put(DebugMessage(msg_date_time=datetime.datetime.now(), message_string=message))

    def debug(self, message: str) -> None:
        self.q.put(DebugMessage(msg_date_time=datetime.datetime.now(), message_string=message))

    def info(self, message: str) -> None:
        """Enqueues a InfoMessage."""
        self.q.put(InfoMessage(msg_date_time=datetime.datetime.now(), message_string=message))

    def error(self, message: str) -> None:
        """Enqueues a ErrorMessage."""
        self.q.put(ErrorMessage(msg_date_time=datetime.datetime.now(), message_string=message))

    def fatal(self, message: str) -> None:
        """PORT NOTE: addition. The C# only reaches FatalMessage through
        `Terminate()`, which hardcodes its text; the runner needs to be able to
        enqueue a fatal with a real reason, so this method does that and nothing
        else."""
        self.q.put(FatalMessage(msg_date_time=datetime.datetime.now(), message_string=message))

    def finish(self) -> None:
        """Enqueues a FinishMessage with no content."""
        self.q.put(FinishMessage(msg_date_time=datetime.datetime.now()))
