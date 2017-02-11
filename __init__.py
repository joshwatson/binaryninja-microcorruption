import struct
import traceback

from binaryninja import Architecture, BinaryView, SegmentFlag, log_error


class MicrocorruptionView(BinaryView):
    name = "Microcorruption"
    long_name = "Microcorruption Memory Dump"

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.raw = data

    @classmethod
    def is_valid_for_data(self, data):
        if len(data) == 0x10000:
            return True
        else:
            return False

    def init(self):
        try:
            self.platform = Architecture['msp430'].standalone_platform
            self.arch = Architecture['msp430']

            self.entry_addr = struct.unpack('<H', self.raw.read(0xfffe, 2))[0]
            self.add_entry_point(self.entry_addr)
            self.add_auto_segment(
                0, self.entry_addr, 0, self.entry_addr,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
            )
            self.add_auto_segment(
                self.entry_addr, 0x10000 - self.entry_addr,
                self.entry_addr, 0x10000 - self.entry_addr,
                SegmentFlag.SegmentExecutable | SegmentFlag.SegmentReadable
            )
        except:
            log_error(traceback.format_exc())
            return False

        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.entry_addr


MicrocorruptionView.register()
