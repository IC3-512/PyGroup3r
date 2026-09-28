"""Port of Group3r/View/GpoPrinterFactory.cs.

Factory to create GpoPrinter given the control flag.
"""

from typing import Optional

from .gpo_printer import IGpoPrinter
from .nice_gpo_printer import NiceGpoPrinter


def get_printer(setting: Optional[str], options) -> IGpoPrinter:
    """Summary: Returns a GpoPrinter given the setting.
    Arguments: string containing the control flag.
    Returns: IGpoPrinter instance.
    """
    # Currently only JSON exists which is the default.
    # switch (setting)
    # {
    #    case "json":
    #        processor = new JsonGpoPrinter(options);
    #        break;
    #    case "nice":
    #        processor = new NiceGpoPrinter(options);
    #        break;
    #    default:
    #        processor = new NiceGpoPrinter(options);
    #        break;
    # }
    processor: IGpoPrinter = NiceGpoPrinter(options)

    return processor


class GpoPrinterFactory:
    """Static class in the C#; kept as a namespace so call sites can read the
    same as the original (`GpoPrinterFactory.get_printer(...)`)."""

    get_printer = staticmethod(get_printer)
