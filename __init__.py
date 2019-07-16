import os
import struct
import traceback

from binaryninja import (Architecture, BinaryView, SegmentFlag, Symbol,
                         SymbolType, log_error, Platform)

class MicrocorruptionPlatform(Platform):
    name = 'microcorruption-msp430'


mc = MicrocorruptionPlatform(Architecture['msp430'])
mc.register('microcorruption')
mc.default_calling_convention = Architecture['msp430'].standalone_platform.default_calling_convention
mc.system_call_convention = Architecture['msp430'].standalone_platform.calling_conventions[1]

class MicrocorruptionView(BinaryView):
    name = "Microcorruption"
    long_name = "Microcorruption Memory Dump"
    address_size = 2

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
            self.platform = Platform['microcorruption-msp430']
            self.arch = Architecture['msp430']

            self.entry_addr = struct.unpack('<H', self.raw.read(0xfffe, 2))[0]
            
            self.add_auto_segment(
                0, self.entry_addr, 0, self.entry_addr,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
            )
            self.add_auto_segment(
                self.entry_addr, 0x10000 - self.entry_addr,
                self.entry_addr, 0x10000 - self.entry_addr,
                SegmentFlag.SegmentExecutable | SegmentFlag.SegmentReadable
            )

            self.add_entry_point(self.entry_addr)

            path = os.path.dirname(self.file.original_filename)
            filename = os.path.basename(self.file.original_filename)
            sym_path = os.path.join(path, os.path.splitext(filename)[0] + '.sym')

            if os.path.exists(sym_path) and not self.symbols:
                with open(sym_path, 'r') as f:
                    for line in f:
                        addr, symbol = line.split(' ')[:2]
                        addr = int(addr, 16)
                        symbol = symbol.strip()
                        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, addr, symbol))

        except:
            log_error(traceback.format_exc())
            return False

        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.entry_addr

    def perform_get_address_size(self):
        return 2

MicrocorruptionView.register()
