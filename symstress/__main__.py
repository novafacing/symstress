from argparse import ArgumentParser
from pathlib import Path

from symstress.symstress import main

if __name__ == "__main__":
    parser = ArgumentParser(prog="symstress")
    parser.add_argument(
        "source",
        type=Path,
        help="The source directory to acquire symbols for.",
    )
    parser.add_argument(
        "--binary",
        type=Path,
        required=False,
        help="The binary to add symbols to.",
    )
    parser.add_argument(
        "--backend",
        choices=("binaryninja",),
        required=False,
        help="The backend to add symbols in.",
    )
    parser.add_argument(
        "--match",
        type=float,
        required=False,
        default=0.75,
        help="The minimum similarity of a symbol to add to the binary.",
    )
    parser.add_argument(
        "--options",
        type=str,
        required=False,
        default="{}",
        help="Options to pass to BinaryViewType.get_view_of_file_with_options().",
    )

    args = parser.parse_args()
    main(args)
