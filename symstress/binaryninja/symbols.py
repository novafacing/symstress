"""
Add symbols to a binary with binaryninja.
"""

from collections import defaultdict
from json import loads
from operator import itemgetter
from pathlib import Path
from typing import Any, Dict

from binaryninja import BinaryViewType


class BinjaSymbols:
    """
    Add symbols to a binary with binaryninja.
    """

    def __init__(self, binary: Path, symbols: str, options: Dict[str, Any]) -> None:
        """
        Add symbols to a binary with binaryninja.
        """
        self.binary = binary
        self.symbols = loads(symbols)
        self.bv = BinaryViewType.get_view_of_file_with_options(
            str(self.binary.resolve()), options
        )
        self.bv.update_analysis_and_wait()

    def add_symbols(self, match: float) -> None:
        """
        Add symbols to a binary with binaryninja.

        :param match: The minimum similarity of a symbol to add to the binary.
        """
        bin_strings = self.bv.get_strings()

        function_string_refs = defaultdict(set)
        for bstr in bin_strings:
            for ref in self.bv.get_code_refs(bstr.start):
                print(ref, bstr)
                function_string_refs[ref.function.start].add(bstr.raw)

        metrics = defaultdict(set)
        for fname, strs in self.symbols.items():
            for addr, bstrs in function_string_refs.items():
                strs_ = set(map(lambda s: s.encode("utf-8"), strs))
                overlap = set()
                for s in strs_:
                    for b in bstrs:
                        if s in b or b in s:
                            overlap.add((s, b))
                if len(overlap) > 0:
                    metrics[addr].add(
                        (float(len(overlap)) / len(bstrs), fname, tuple(overlap))
                    )

        likely = {}
        for addr, overlaps in metrics.items():
            print(addr, overlaps)
            try:
                top = next(iter(sorted(overlaps, key=itemgetter(0))))
                likely[addr] = top[1]
            except StopIteration:
                continue

        print(likely)
