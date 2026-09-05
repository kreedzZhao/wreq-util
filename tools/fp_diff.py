import json, sys

def load(path):
    return [json.loads(l) for l in open(path)]

wreq, chrome = load(sys.argv[1]), load(sys.argv[2])
for name, recs in (("wreq", wreq), ("chrome", chrome)):
    errs = [r for r in recs if "error" in r]
    print("%s: %d connections, %d errors" % (name, len(recs), len(errs)))
    for r in errs:
        print("   error:", r["error"])

wreq = [r for r in wreq if "error" not in r]
chrome = [r for r in chrome if "error" not in r]

def uniq(recs, get):
    return sorted({json.dumps(get(r), sort_keys=True) for r in recs})

print("\n== stable-across-runs check (each line = one distinct value seen) ==")
FIELDS = [
    ("ja4", lambda r: r["ja4"]),
    ("akamai", lambda r: r["akamai"]),
    ("ciphers (ordered)", lambda r: r["client_hello"]["ciphers"]),
    ("extensions (sorted)", lambda r: sorted(r["client_hello"]["extensions"])),
    ("extensions (ordered)", lambda r: r["client_hello"]["extensions"]),
    ("curves", lambda r: r["client_hello"]["curves"]),
    ("sigalgs", lambda r: r["client_hello"]["sigalgs"]),
    ("alpn", lambda r: r["client_hello"]["alpn"]),
    ("supported_versions", lambda r: r["client_hello"]["supported_versions"]),
    ("key_share_groups", lambda r: r["client_hello"]["key_share_groups"]),
    ("compress_cert", lambda r: r["client_hello"]["compress_cert"]),
    ("point_formats", lambda r: r["client_hello"]["point_formats"]),
    ("ech", lambda r: r["client_hello"]["ech"]),
    ("session_id_len", lambda r: r["client_hello"]["session_id_len"]),
    ("sni", lambda r: r["client_hello"]["sni"]),
    ("h2 settings", lambda r: r["h2"]["settings"]),
    ("h2 window_update", lambda r: r["h2"]["window_update"]),
    ("h2 priority_frames", lambda r: r["h2"]["priority_frames"]),
    ("h2 headers_priority", lambda r: r["h2"]["headers_priority"]),
    ("h2 pseudo_order", lambda r: r["h2"]["pseudo_order"]),
]
for label, get in FIELDS:
    w, c = uniq(wreq, get), uniq(chrome, get)
    variable = " (varies per conn)" if len(w) > 1 or len(c) > 1 else ""
    verdict = "MATCH" if set(w) == set(c) else ("MATCH-AS-SET" if label.endswith("(ordered)") and False else "DIFF")
    print("\n[%s] %s%s" % (verdict, label, variable))
    if verdict != "MATCH":
        for v in w: print("  wreq:   %s" % v[:400])
        for v in c: print("  chrome: %s" % v[:400])
    else:
        print("  both:   %s" % w[0][:400])
