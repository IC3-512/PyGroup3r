"""Port of Group3r/View/JsonGpoPrinter.cs.

PORT NOTE: the whole C# file is commented out (it depended on Newtonsoft.Json,
which was dropped from the project), so there is no live original to copy. Per
CONVENTIONS.md the commented-out C# is reproduced verbatim as comments below and
stays inert; the live Python class beneath it is a *port addition* that
reproduces what the commented C# described, using the standard library:

    NullValueHandling = NullValueHandling.Ignore   -> None fields are omitted
    Formatting = Formatting.Indented               -> indent of 2
    Converters = { new StringEnumConverter() }     -> enums serialise as names

Property names are the Python attribute names (snake_case) rather than the C#
PascalCase ones, because the rest of this port addresses the model that way.
"""

# using Newtonsoft.Json;
# using Newtonsoft.Json.Converters;
#
#    /*
#     * Summary: Implementation of IGpoOutputter which just serializes the GPO as JSON and returns it.
#     */
#    /*
#    class JsonGpoPrinter : IGpoPrinter
#    {
#        private JsonSerializerSettings jSettings;
#        private GrouperOptions grouperOptions;
#        /**
#         * Summary: constructor
#         * Arguments: none
#         * Returns: JsonGpoPrinter instance
#         */
#        public JsonGpoPrinter(GrouperOptions options)
#        {
#            grouperOptions = options;
#            // Set up the Json serializer
#            jSettings = new JsonSerializerSettings
#            {
#                NullValueHandling = NullValueHandling.Ignore,
#                Formatting = Formatting.Indented,
#                Converters = new List<JsonConverter>() { new StringEnumConverter() }
#            };
#        }
#
#
#        /**
#         * Summary: Implementation of OutputGPO which returns the serialized GPO as a Json string.
#         * Arguments: GPO object to be outputted
#         * Returns: string representation of GPO
#         */
#        public string OutputGPO(GPO gpo)
#        {
#            return JsonConvert.SerializeObject(gpo, jSettings);
#        }
#
#        public string OutputGpoResult(GpoResult gpoResult)
#        {
#            return JsonConvert.SerializeObject(gpoResult, jSettings);
#        }
#    }
#    */

import dataclasses
import datetime
import json
import uuid
from enum import Enum
from typing import Any

from ..ad.gpo import GPO
from ..assessment.finding import GpoResult
from .gpo_printer import IGpoPrinter


def _serialisable(value: Any) -> Any:
    """Turn a ported model object into something json.dumps can eat.

    Mirrors the three serializer settings the commented-out C# asked for.
    """
    if value is None:
        return None
    if isinstance(value, Enum):
        # StringEnumConverter: the member name, exactly as .NET would write it.
        # Checked before the scalar case because Triage and RegKeyValType are
        # IntEnums, and would otherwise serialise as bare numbers.
        return value.name
    if isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, (datetime.datetime, datetime.date)):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(k): _serialisable(v) for k, v in value.items() if v is not None}
    if isinstance(value, (list, tuple, set)):
        return [_serialisable(item) for item in value]
    if dataclasses.is_dataclass(value):
        return {
            field.name: _serialisable(getattr(value, field.name))
            for field in dataclasses.fields(value)
            if getattr(value, field.name) is not None
        }
    if hasattr(value, "__dict__"):
        return {
            key: _serialisable(item)
            for key, item in vars(value).items()
            if item is not None and not key.startswith("_")
        }
    return str(value)


class JsonGpoPrinter(IGpoPrinter):
    """Implementation of IGpoOutputter which just serializes the GPO as JSON and
    returns it."""

    def __init__(self, options):
        """Summary: constructor
        Arguments: none
        Returns: JsonGpoPrinter instance
        """
        self.grouper_options = options
        # Set up the Json serializer
        self.j_settings = {"indent": 2}

    def output_gpo(self, gpo: GPO) -> str:
        """Summary: Implementation of OutputGPO which returns the serialized GPO as a Json string.
        Arguments: GPO object to be outputted
        Returns: string representation of GPO
        """
        return json.dumps(_serialisable(gpo), **self.j_settings)

    def output_gpo_result(self, gpo_result: GpoResult) -> str:
        return json.dumps(_serialisable(gpo_result), **self.j_settings)
