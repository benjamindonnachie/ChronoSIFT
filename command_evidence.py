"""Conservative command-position extraction, never a shell interpreter.

Policy supplies wrapper/script grammars and all executable vocabulary. This
module only handles literal quoting and command separators. It does not expand
variables, substitutions, aliases or functions, or assert successful execution.
"""
from functools import lru_cache
import re


def literal_path_references(text):
    """Literal absolute path operands, including quoted/escaped spaces.

    Input must already be source/operation-qualified by policy. No path is
    extracted from inside a URL, flag value, larger word, or shell expansion.
    """
    for match in re.finditer(r'''"([^"\n]*)"|'([^'\n]*)'|((?:\\[ \t]|[^\s"'])+)''', text):
        value = next(item for item in match.groups() if item is not None).replace(r'\ ', ' ')
        if (value.startswith('/') or re.match(r'^[A-Za-z]:[\\/]',value)) and not re.search(r'[$`\x00-\x1f]',value):
            yield value


def _segments(text):
    quote = None
    start = 0
    escaped = False
    comment = False
    parentheses = 0
    backtick = False
    parts = []
    for i, char in enumerate(text):
        if comment:
            if char == "\n":
                comment = False
                start = i + 1
            continue
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote != "'" and i + 1 < len(text) and text[i + 1] in "\"';&|$`\\\n ":
            escaped = True
            continue
        if quote is None and char == "#" and (i == 0 or text[i - 1].isspace()):
            parts.append(text[start:i].strip())
            comment = True
            continue
        if quote is None and char == "`":
            backtick = not backtick
            continue
        if backtick:
            continue
        if quote is None and char == "(":
            parentheses += 1
        elif quote is None and char == ")":
            parentheses = max(0, parentheses - 1)
        if char in "\"'":
            if quote == char:
                quote = None
            elif quote is None:
                quote = char
        elif quote is None and not parentheses and char in ";&|\n":
            parts.append(text[start:i].strip())
            start = i + 1
    if quote is not None or escaped or parentheses or backtick:
        return []
    if not comment:
        parts.append(text[start:].strip())
    return [part for part in parts if part]


def _head(segment):
    match = re.match(r'''^(?:"([^"\n]+)"|'([^'\n]+)'|([^\s"']+))(.*)$''', segment, re.S)
    if not match:
        return None
    executable = next(value for value in match.groups()[:3] if value is not None)
    # Unexpanded names and shell constructs are not literal executable names.
    if re.search(r"[$`(){}<>]", executable):
        return None
    return executable.replace("\\", "/").rsplit("/", 1)[-1] + match.group(4)


@lru_cache(maxsize=4096)
def command_invocations(text, wrappers=(), scripts=()):
    """Return newline-delimited literal invocations with basename-only heads.

    Wrappers and scripts are compiled regexes with a named ``command`` group.
    A wrapper delegates to its operand; a script retains the shell invocation
    and recursively examines its literal payload. Bounds prevent pathological
    nesting from consuming unbounded CPU. Arguments remain quoted/raw.
    """
    result = []

    def visit(value, depth):
        if depth > 8 or len(result) >= 256:
            return
        for segment in _segments(value):
            invocation = _head(segment)
            if invocation is None:
                continue
            delegated = False
            for pattern in wrappers:
                match = pattern.fullmatch(invocation)
                if match:
                    visit(match.group("command"), depth + 1)
                    delegated = True
                    break
            if delegated:
                continue
            result.append(invocation)
            if len(result) >= 256:
                return
            for pattern in scripts:
                match = pattern.fullmatch(invocation)
                if match:
                    payload = match.group("command").strip()
                    if len(payload) >= 2 and payload[0] == payload[-1] and payload[0] in "\"'":
                        payload = payload[1:-1]
                    visit(payload, depth + 1)
                    break

    visit(text, 0)
    return "\n".join(result) or None
