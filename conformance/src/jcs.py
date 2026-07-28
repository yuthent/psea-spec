"""RFC 8785 JSON Canonicalization Scheme, integers-only subset.

draft-yossif-psea-02 restricts the action payload to integers, which removes
the need for the ES6 number-serialization algorithm.  A float anywhere in the
payload is a profile violation and is rejected rather than serialized.
"""


class NonConformingPayload(Exception):
    pass


def _esc(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _key(s: str):
    # RFC 8785 sorts by UTF-16 code units.
    return s.encode("utf-16-be")


def canonicalize(obj) -> bytes:
    def ser(o):
        if o is True:
            return "true"
        if o is False:
            return "false"
        if o is None:
            return "null"
        if isinstance(o, float):
            raise NonConformingPayload(
                "float in action payload; draft-yossif-psea-02 restricts to integers"
            )
        if isinstance(o, int):
            return str(o)
        if isinstance(o, str):
            return _esc(o)
        if isinstance(o, list):
            return "[" + ",".join(ser(x) for x in o) + "]"
        if isinstance(o, dict):
            items = sorted(o.items(), key=lambda kv: _key(kv[0]))
            return "{" + ",".join(_esc(k) + ":" + ser(v) for k, v in items) + "}"
        raise NonConformingPayload(f"unserializable type {type(o).__name__}")

    return ser(obj).encode("utf-8")
