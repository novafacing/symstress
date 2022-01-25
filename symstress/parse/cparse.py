from collections import defaultdict
from itertools import chain
from json import dumps
from operator import itemgetter
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Union

from tree_sitter import Language, Node, Parser

from symstress.parse.cparse_init import CParseInit


class CParse:
    """
    Wrapper for the C language parser.
    """

    def __init__(self) -> None:
        """
        Initialize the C language parser.
        """
        CParseInit.init()
        self.parser: Parser = CParseInit.get_parser()
        self.lang: Language = CParseInit.lang
        self.mapping: Dict[str, Set[str]] = defaultdict(set)

    def parse(self, inp: Union[bytes, Path]) -> None:
        """
        Parse some source code.
        """

        if isinstance(inp, bytes):
            text = inp
        elif isinstance(inp, Path):
            with inp.open("rb") as f:
                text = f.read()
        else:
            raise TypeError(f"Input must be bytes or Path, not {type(inp)}")

        self.tree = self.parser.parse(text)

    def dump(self) -> None:
        """
        Dump the parse tree.
        """
        print(self.tree.root_node.sexp())

    @classmethod
    def find_enclosing(cls, node: Node, enc: Iterable[str]) -> List[Node]:
        """
        Find the enclosing function of a node.

        :param node: The node to find the enclosing function of.
        :param enc: The types of enclosing constructs to look for.
        """
        enclosing = []
        while node.parent is not None:
            if node.type in enc:
                enclosing.append(node)
            node = node.parent

        return enclosing

    @classmethod
    def child_by_type(cls, node: Node, typ: str) -> Optional[Node]:
        """
        Find a child node by type.
        """
        for child in node.children:
            if child.type == typ:
                return child
        return None

    def find_string_literals(self) -> List[Node]:
        """
        Find any strings in the parse tree that could show up in the compiled
        binary.

        This assists the strongest assumption we can make: direct assignment or use of
        a string literal inside a function.
        """
        string_query = self.lang.query(
            """
            (string_literal) @str
            """
        )

        return list(map(itemgetter(0), string_query.captures(self.tree.root_node)))

    def function_defn_name(self, defn: Node) -> Optional[str]:
        """
        Get the name of a function definition.
        """
        declarator = self.child_by_type(defn, "function_declarator")
        if declarator is None:
            return None
        fun_name = self.child_by_type(declarator, "identifier")
        if fun_name is None:
            return None

        return self.node_text(fun_name)

    def find_identifiers(self) -> List[Node]:
        """
        Find all identifiers in the parse tree.
        """
        id_query = self.lang.query(
            """
            (identifier) @ident
            """
        )

        return list(map(itemgetter(0), id_query.captures(self.tree.root_node)))

    @classmethod
    def node_text(cls, node: Node) -> str:
        """
        Ge the text of a node.

        :param node: The node to get the text of.
        """
        if node.type == "string_literal":
            return node.text.decode("utf-8")[1:-1]

        return node.text.decode("utf-8")

    def map_identifier_access(self, assign: Node, string: Node) -> Dict[str, Set[str]]:
        """
        Map an identifier access to a variable assignment and find uses of
        the variable.

        :param assign: The variable assignment node.
        :param string: The string literal node.
        """
        mapping: Dict[str, Set[str]] = defaultdict(set)
        varname = self.child_by_type(assign, "identifier")
        if varname is None:
            return mapping
        for ident in filter(
            lambda i: self.node_text(i) == self.node_text(varname),
            self.find_identifiers(),
        ):
            ef = self.find_enclosing(ident, ("function_definition",))
            for enc in ef:
                if len(self.node_text(string)) >= 2:
                    mapping[self.function_defn_name(enc)].add(self.node_text(string))

        return mapping

    def map_symbols(self) -> Dict[str, Set[str]]:
        """
        Map each node we thing has data we care about to the function
        that contains the node.
        """
        mapping = defaultdict(set)
        locs = self.find_string_literals()
        for string in chain(locs):
            for enc in self.find_enclosing(
                string,
                (
                    "function_definition",
                    "assignment_expression",
                ),
            ):

                if enc.type == "function_definition":
                    fun_name = self.function_defn_name(enc)

                    if fun_name is None:
                        continue

                    if len(self.node_text(string)) >= 2:
                        mapping[fun_name].add(self.node_text(string))
                elif enc.type == "assignment_expression":
                    # See if we can get an identifier this is part of
                    for fn, strs in self.map_identifier_access(enc, string).items():
                        if fn is None:
                            continue
                        mapping[fn] |= strs
                else:
                    pass

        return mapping

    def update_mapping(self) -> None:
        """
        Update the object mapping attribute with a mapping.

        :param mapping: The mapping to update with.
        """
        for fn, strs in self.map_symbols().items():
            self.mapping[fn] |= set(
                map(
                    lambda s: s.encode("utf-8")
                    .decode("unicode_escape")
                    .encode("utf-8"),
                    strs,
                )
            )

    def serialized_map(self) -> str:
        """
        Serialize the parser's mapping.
        """
        mp = {}
        for fn, strs in self.mapping.items():
            mp[fn] = list(strs)
        return dumps(mp)
