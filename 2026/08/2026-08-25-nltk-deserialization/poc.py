#!/usr/bin/env python3
# PoC for CVE-2026-78683 (NLTK <= 3.9.4)
#
# The differential lives in nltk/tree/tree.py::Tree.fromstring. The fix adds a
# "token_char" that recognises a backslash-escaped bracket ( \(  or  \) ) as a
# single literal character inside a node/leaf token:
#
#     token_char = (?:\\[()] | [^\s()])
#     node_pattern = leaf_pattern = token_char+      # patched
#     node_pattern = leaf_pattern = [^\s()]+         # vulnerable (pre-patch)
#
# Pre-patch, the tokenizer cannot represent an escaped bracket. Feeding it the
# input  (S \))  makes it read a bare "\" leaf followed by a *stray* close
# bracket, which raises a parse error (and can never round-trip). Post-patch the
# escaped ")" is kept verbatim: the tree carries the leaf "\)" and str(tree)
# reproduces the source exactly (this is precisely what the patch's own
# test_fromstring_allows_escaped_brackets / _roundtrips_escaped_bracket_leaf
# assert).
#
# So: exact round-trip  => patched (safe, canary NOT printed)
#     raise / mismatch  => vulnerable pre-patch tokenizer path taken.
# The canary is emitted only inside that vulnerable branch.

import os
from nltk.tree import Tree

# An escaped close bracket embedded in a leaf. On a fixed build this parses and
# round-trips byte-for-byte; on a vulnerable build the un-escaped tokenizer
# mis-handles it.
SRC = r"(S \))"


def vulnerable_behaviour_observed():
    try:
        tree = Tree.fromstring(SRC)
    except Exception:
        # Pre-patch tokenizer: "\)" is split into a lone "\" leaf plus an extra
        # unmatched ")" -> parse error. This code path only exists on the
        # vulnerable build.
        return True
    # Patched build guarantees an exact round-trip of the escaped bracket.
    return str(tree) != SRC


if vulnerable_behaviour_observed():
    # Reached only as a direct consequence of the pre-patch tokenizer behaviour.
    print(os.environ["POC_CANARY"])