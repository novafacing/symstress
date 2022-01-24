"""
Initializer for C parser. Compiles the parser library if necessary and makes the
language module available.
"""

from pathlib import Path
from typing import Optional

from tree_sitter import Language, Parser

PARSER_LIB_PATH = Path(__file__).parents[2] / "third_party" / "tree-sitter-c"
PARSER_BUILD_PATH = Path(__file__).parents[2] / "build" / "parsers.so"


class CParseInit:
    """
    Set up the C language parser and compile it if necessary.
    """

    lang: Optional[Language] = None

    @classmethod
    def init(cls) -> None:
        """
        Check the source tree for the C language parser.
        If it is not present, compile it.
        """
        assert (
            PARSER_LIB_PATH.exists() and (PARSER_LIB_PATH / "src" / "parser.c").exists()
        ), "C parser source not found. Please ensure you have initialized submodules."
        Language.build_library(
            str(PARSER_BUILD_PATH.resolve()), [str(PARSER_LIB_PATH.resolve())]
        )

        cls.lang = Language(PARSER_BUILD_PATH.resolve(), "c")

    @classmethod
    def get_parser(cls) -> Parser:
        """
        Get a parser for the C language.
        """
        parser = Parser()
        parser.set_language(cls.lang)
        return parser
