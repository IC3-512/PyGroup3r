"""Port of Group3r/Concurrency/GrouperMq.cs.

The two Group3r-specific message types it enqueues (GpoResultMessage and
FileResultMessage, ported from Group3r/Concurrency/) live in
`group3rpy/concurrency/messages.py` alongside the LibSnaffle ones.
"""

import datetime
from typing import Any

from .blocking_mq import BlockingMq
from .messages import FileResultMessage, GpoResultMessage


class GrouperMq(BlockingMq):
    """Port of Group3r.Concurrency.GrouperMq."""

    def gpo_result(self, gpo_result: Any, message_text: str) -> None:
        self.q.put(
            GpoResultMessage(
                msg_date_time=datetime.datetime.now(),
                message_string=message_text,
                gpo_result=gpo_result,
            )
        )

    def file_result(self, message: str, result: Any) -> None:
        """A file result message to handle snaffler output"""
        self.q.put(
            FileResultMessage(
                msg_date_time=datetime.datetime.now(),
                message_string=message,
                result=result,
            )
        )
