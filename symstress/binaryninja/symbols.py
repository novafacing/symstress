"""
Add symbols to a binary with binaryninja.
"""

from collections import defaultdict
from json import loads
from operator import itemgetter
from pathlib import Path
from typing import Any, Dict, List

from binaryninja import BinaryViewType, Symbol
from binaryninja.filemetadata import SaveSettings

from symstress.matcher.matcher import StringMatcher


class BinjaSymbols:
    """
    Add symbols to a binary with binaryninja.
    """

    def __init__(
        self, binary: Path, symbols: Dict[str, List[str]], options: Dict[str, Any]
    ) -> None:
        """
        Add symbols to a binary with binaryninja.
        """
        self.binary = binary
        self.symbols = symbols
        self.bv = BinaryViewType.get_view_of_file_with_options(
            str(self.binary.resolve()), options
        )
        self.bv.update_analysis_and_wait()

    def add_symbols(
        self, match: float = 0.85, prefix: str = "", include_confidence: bool = False
    ) -> None:
        """
        Add symbols to a binary with binaryninja.

        :param match: The minimum similarity of a symbol to add to the binary.
        :param prefix: The prefix to add to the symbol name.
        """
        bin_strings = self.bv.get_strings()

        function_string_refs = defaultdict(set)
        for bstr in bin_strings:
            for ref in self.bv.get_code_refs(bstr.start):
                st = bstr.raw
                if isinstance(st, str):
                    st = st.encode("utf-8")
                function_string_refs[ref.function.start].add(st)

        matched = StringMatcher.match(self.symbols, function_string_refs)

        for likely_name in sorted(matched.items(), key=lambda i: i[1][1], reverse=True):
            confidence = f"_{int(likely_name[1][1]*100)}%" if include_confidence else ""

            print(
                f"Definining {prefix + likely_name[1][0] + confidence}@{likely_name[0]}"
            )

            self.bv.define_user_symbol(
                Symbol(
                    "FunctionSymbol",
                    likely_name[0],
                    prefix + likely_name[1][0] + confidence,
                )
            )

        self.bv.update_analysis_and_wait()
        self.bv.create_database(
            str(self.binary.resolve()) + ".bndb", None, SaveSettings()
        )
