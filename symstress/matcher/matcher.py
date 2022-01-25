"""
Implements the levenshtein likelihood matcher for string to function name correlation.
"""

from typing import Dict, List
from Levenshtein import ratio


class StringMatcher:
    """
    Implements the levenshtein likelihood matcher for string to function name
    correlation.
    """

    CUTOFF = 0.85  # TODO: Make this a parameter

    DENYLIST = (
        "main",
        "__libc_start_main",
        "__libc_csu_init",
        "usage",
    )

    @classmethod
    def match(
        cls,
        source_map: Dict[str, List[str]],
        bin_map: Dict[int, List[str]],
        cutoff: float = CUTOFF,
    ) -> Dict[int, str]:
        """
        Matches strings to function names.

        :param source_map: A dictionary mapping function names to a list of strings.
        :param bin_map: A dictionary mapping function addresses to a list of strings.
        :return: A dictionary mapping function addresses to a string.
        """
        # NOTE: this is not a particularly efficient algorithm, but it is accurate.

        matched = {}

        for baddr, bstrings in bin_map.items():
            best_score = 0
            best_matches = []
            best_sname = ""
            for sname, sstrings in source_map.items():

                if sname in cls.DENYLIST:
                    continue

                best_matches = []
                for bstr in bstrings:
                    best_match = {"score": 0, "string": ""}
                    for sstr in sstrings:
                        try:
                            score = ratio(bstr, sstr)
                        except TypeError as e:
                            print(e)
                            print(type(bstr), type(sstr))
                            raise e
                        if score > best_match["score"]:
                            best_match["score"] = score
                            best_match["string"] = sstr

                    # best_match contains the string out of the current set
                    # that matches best
                    best_matches.append(best_match)

                avg_score = sum([match["score"] for match in best_matches]) / len(
                    best_matches
                )

                if avg_score > best_score:
                    best_score = avg_score
                    best_matches = sstrings
                    best_sname = sname
            # if best_score > cutoff:
            # TODO: Uncomment to enable cutoff
            matched[baddr] = (best_sname, best_score)
            # else:
            #    print(f"No match for {baddr}")
        return matched
