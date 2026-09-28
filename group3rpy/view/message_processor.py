"""Port of Group3r/View/MessageProcessor/IMessageProcessor.cs and
Group3r/View/MessageProcessor/CliMessageProcessor.cs.

PORT NOTE: NLog becomes the standard library's `logging`. NLog has Trace and
Fatal levels that `logging` does not, so TRACE is registered at 5 and Fatal maps
onto CRITICAL; the level *names* are kept so a log line still reads the same.
"""

import logging
import sys
from abc import ABC, abstractmethod

from ..concurrency.messages import (
    DebugMessage,
    ErrorMessage,
    FatalMessage,
    FileResultMessage,
    FinishMessage,
    GpoResultMessage,
    InfoMessage,
    QueueMessage,
    TraceMessage,
)

# PORT NOTE: NLog's Trace level sits below Debug.
TRACE = 5
logging.addLevelName(TRACE, "Trace")


class IMessageProcessor(ABC):
    """Defines the interface for msg processing behaviour."""

    @abstractmethod
    def process_message(self, message: QueueMessage, options) -> bool:
        ...


class CliMessageProcessor(IMessageProcessor):
    """Implementation of IMessageProcessor which prints to stdout/stderr via Nlog."""

    def __init__(self):
        """Summary: constructor
        Arguments: string containing the control flag for the outputter factory.
        Returns: CliMessageProcessor instance
        """
        self.logger = logging.getLogger("Group3r.View.CliMessageProcessor")

    def process_message(self, message: QueueMessage, options) -> bool:
        """Summary: Implementation of ProcessMessage which sends strings to a logger.
        TODO: Inspecting the type of an instance created via the template
        pattern to decide behaviour is not awesome. Probaly should do a better thing.
        Arguments: Group3rMessage containing the message from the queue, GroupCoreOptions for config options
        Returns: None
        """
        if isinstance(message, TraceMessage):
            self.logger.log(TRACE, message.get_message())
        elif isinstance(message, DebugMessage):
            self.logger.debug(message.get_message())
        elif isinstance(message, InfoMessage):
            self.logger.info(message.get_message())
        # Handle file result messages from snafflin'.
        elif isinstance(message, FileResultMessage):
            self.logger.warning(message.get_message())
        elif isinstance(message, GpoResultMessage):
            self.logger.warning(message.get_message())
        elif isinstance(message, ErrorMessage):
            self.logger.error(message.get_message())
        elif isinstance(message, FatalMessage):
            self.logger.critical(message.get_message())
            if _debugger_is_attached():
                sys.stdout.write("Press any key to exit." + "\r\n")
                sys.stdin.readline()
            return True
        elif isinstance(message, FinishMessage):
            self.logger.info(message.get_message())
            if _debugger_is_attached():
                sys.stdout.write("Press any key to exit." + "\r\n")
                sys.stdin.readline()
            return True
        return False


def _debugger_is_attached() -> bool:
    """PORT NOTE: `System.Diagnostics.Debugger.IsAttached`. A trace function being
    installed is the closest Python equivalent."""
    return sys.gettrace() is not None
