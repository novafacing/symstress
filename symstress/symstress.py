"""
Main entrypoint for symstress.
"""

from json import loads

from symstress.parse.cparse import CParse


def main(args) -> None:
    """
    Main entrypoint for symstress.
    """
    cparser = CParse()
    for sfile in args.source.rglob("**/*.c"):
        cparser.parse(sfile)
        cparser.update_mapping()

    if args.binary is not None:
        if args.backend == "binaryninja":
            from symstress.binaryninja.symbols import BinjaSymbols

            bsymbols = BinjaSymbols(
                args.binary, cparser.serialized_map(), loads(args.options)
            )
            bsymbols.add_symbols(args.match)
    else:
        print(cparser.serialized_map())
