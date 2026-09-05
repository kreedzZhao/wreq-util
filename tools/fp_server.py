"""Local TLS+h2 fingerprint endpoint.

Per connection: peek the raw ClientHello off the TCP socket (MSG_PEEK, so the TLS
layer still sees it), parse the fingerprint-relevant fields, finish the handshake
with a self-signed cert (ALPN h2 only), then read the client's h2 frames and record
the Akamai-fingerprint elements (SETTINGS in order, WINDOW_UPDATE, PRIORITY frames,
pseudo-header order). One JSON line per connection.

Usage: fp_server.py <port> <out.jsonl> <cert> <key>
"""
import hashlib
import json
import socket
import ssl
import struct
import sys
import threading
import time

import hpack


def is_grease(v):
    return (v & 0xff) == (v >> 8) and (v & 0x0f) == 0x0a


def norm(v):
    return "GREASE" if is_grease(v) else "0x%04x" % v


def peek_client_hello(sock):
    """Peek until the full first handshake message is buffered, return raw bytes."""
    sock.settimeout(5.0)
    data = b""
    for _ in range(200):
        data = sock.recv(65536, socket.MSG_PEEK)
        if len(data) >= 5:
            rec_len = struct.unpack(">H", data[3:5])[0]
            if len(data) >= 5 + rec_len:
                return data[: 5 + rec_len]
        time.sleep(0.01)
    raise TimeoutError("client hello never completed")


def parse_client_hello(raw):
    """The fingerprint-relevant fields of one ClientHello, GREASE normalized."""
    assert raw[0] == 0x16, "not a handshake record"
    body = raw[5:]
    assert body[0] == 0x01, "not a ClientHello"
    p = 4  # handshake header
    p += 2 + 32  # legacy_version + random
    sid_len = body[p]; p += 1 + sid_len
    n = struct.unpack(">H", body[p:p+2])[0]; p += 2
    ciphers = [struct.unpack(">H", body[p+i:p+i+2])[0] for i in range(0, n, 2)]; p += n
    comp_len = body[p]; p += 1 + comp_len
    ext_total = struct.unpack(">H", body[p:p+2])[0]; p += 2
    end = p + ext_total

    out = {
        "ciphers": [norm(c) for c in ciphers],
        "extensions": [],
        "sni": None, "alpn": [], "curves": [], "point_formats": [],
        "sigalgs": [], "supported_versions": [], "key_share_groups": [],
        "compress_cert": [], "ech": False, "padding_len": None,
        "session_id_len": sid_len,
    }
    while p + 4 <= end:
        et, el = struct.unpack(">HH", body[p:p+4]); p += 4
        d = body[p:p+el]; p += el
        out["extensions"].append(norm(et))
        if et == 0 and el >= 5:
            out["sni"] = d[5:5 + struct.unpack(">H", d[3:5])[0]].decode("ascii", "replace")
        elif et == 10:
            cn = struct.unpack(">H", d[:2])[0]
            out["curves"] = [norm(struct.unpack(">H", d[2+i:4+i])[0]) for i in range(0, cn, 2)]
        elif et == 11:
            out["point_formats"] = list(d[1:1 + d[0]])
        elif et == 13:
            sn = struct.unpack(">H", d[:2])[0]
            out["sigalgs"] = ["0x%04x" % struct.unpack(">H", d[2+i:4+i])[0] for i in range(0, sn, 2)]
        elif et == 16:
            q = 2
            while q < len(d):
                ln = d[q]; q += 1
                out["alpn"].append(d[q:q+ln].decode("ascii", "replace")); q += ln
        elif et == 43:
            vn = d[0]
            out["supported_versions"] = [norm(struct.unpack(">H", d[1+i:3+i])[0]) for i in range(0, vn, 2)]
        elif et == 51:
            q = 2
            while q + 4 <= len(d):
                g, gl = struct.unpack(">HH", d[q:q+4])
                out["key_share_groups"].append(norm(g)); q += 4 + gl
        elif et == 27:
            out["compress_cert"] = ["0x%04x" % struct.unpack(">H", d[1+i:3+i])[0] for i in range(0, d[0], 2)]
        elif et == 65037:
            out["ech"] = True
        elif et == 21:
            out["padding_len"] = el
    return out


def ja4(ch):
    """JA4 computed from the parsed hello -- same code for both clients, so the
    comparison holds even where this deviates from the reference implementation."""
    ciphers = sorted(c[2:] for c in ch["ciphers"] if c != "GREASE")
    exts_all = [e for e in ch["extensions"] if e != "GREASE"]
    exts_hash = sorted(e[2:] for e in exts_all if e not in ("0x0000", "0x0010"))
    sig = [s[2:] for s in ch["sigalgs"]]
    ver = "13" if "0x0304" in ch["supported_versions"] else "12"
    sni = "d" if ch["sni"] else "i"
    alpn = ch["alpn"][0] if ch["alpn"] else "00"
    a = "t%s%s%02d%02d%s%s" % (ver, sni, len(ciphers), len(exts_all), alpn[0], alpn[-1])
    b = hashlib.sha256(",".join(ciphers).encode()).hexdigest()[:12]
    c = hashlib.sha256((",".join(exts_hash) + "_" + ",".join(sig)).encode()).hexdigest()[:12]
    return "%s_%s_%s" % (a, b, c)


def read_exact(tls, n, deadline):
    data = b""
    while len(data) < n:
        tls.settimeout(max(0.05, deadline - time.monotonic()))
        chunk = tls.recv(n - len(data))
        if not chunk:
            raise ConnectionError("peer closed")
        data += chunk
    return data


def frame(ftype, flags, stream, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack(">I", stream) + payload


HTML = (b"<html><body>ok<script>"
        b"var x=new XMLHttpRequest();x.open('GET','/xhr');x.send();"
        b"fetch('/fetch');"
        b"var s=new XMLHttpRequest();s.open('GET','/xhr-sync',false);"
        b"try{s.send();}catch(e){}"
        b"</script></body></html>")


def read_h2(tls):
    """Serve h2 until the deadline, recording every request's HEADERS priority."""
    deadline = time.monotonic() + 8.0
    out = {"settings": [], "window_update": None, "priority_frames": [], "requests": []}
    preface = read_exact(tls, 24, deadline)
    assert preface == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", preface
    tls.sendall(frame(4, 0, 0))  # server SETTINGS, empty
    decoder, encoder = hpack.Decoder(), hpack.Encoder()
    cur = None  # (stream, priority, fragments) of an unfinished HEADERS
    while time.monotonic() < deadline:
        try:
            h = read_exact(tls, 9, deadline)
        except (TimeoutError, socket.timeout, ConnectionError):
            break
        ln = struct.unpack(">I", b"\x00" + h[:3])[0]
        ftype, flags = h[3], h[4]
        stream = struct.unpack(">I", h[5:9])[0] & 0x7fffffff
        payload = read_exact(tls, ln, deadline) if ln else b""
        if ftype == 4 and not flags & 0x1:
            out["settings"] = [(struct.unpack(">H", payload[i:i+2])[0],
                                struct.unpack(">I", payload[i+2:i+6])[0])
                               for i in range(0, len(payload), 6)]
            tls.sendall(frame(4, 0x1, 0))  # ack
        elif ftype == 8 and stream == 0 and out["window_update"] is None:
            out["window_update"] = struct.unpack(">I", payload)[0] & 0x7fffffff
        elif ftype == 2:
            dep, weight = struct.unpack(">I", payload[:4])[0], payload[4]
            out["priority_frames"].append({"stream": stream, "excl": bool(dep >> 31),
                                           "dep": dep & 0x7fffffff, "weight": weight})
        elif ftype in (1, 9):  # HEADERS / CONTINUATION
            q, pad, prio = 0, 0, None
            if ftype == 1:
                pad = payload[0] if flags & 0x8 else 0
                if flags & 0x8:
                    q += 1
                if flags & 0x20:
                    dep, weight = struct.unpack(">I", payload[q:q+4])[0], payload[q+4]
                    prio = {"excl": bool(dep >> 31), "dep": dep & 0x7fffffff,
                            "weight": weight}
                    q += 5
                cur = [stream, prio, b""]
            if cur is None:
                continue
            cur[2] += payload[q:len(payload) - pad]
            if flags & 0x4:  # END_HEADERS
                pairs = [(k.decode("ascii", "replace"), v.decode("ascii", "replace"))
                         for k, v in decoder.decode(cur[2], raw=True)]
                names = [k for k, _ in pairs]
                path = dict(pairs).get(":path")
                out["requests"].append({
                    "stream": cur[0], "path": path, "priority": cur[1],
                    "pseudo_order": [n for n in names if n.startswith(":")]})
                body = HTML if path == "/" else b"ok"
                ctype = "text/html" if path == "/" else "text/plain"
                tls.sendall(frame(1, 0x4, cur[0], encoder.encode(
                    [(":status", "200"), ("content-type", ctype),
                     ("content-length", str(len(body)))])))
                tls.sendall(frame(0, 0x1, cur[0], body))  # DATA, END_STREAM
                cur = None
    return out
def akamai(h2):
    s = ";".join("%d:%d" % kv for kv in h2["settings"])
    wu = h2["window_update"] or 0
    pr = ",".join("%d:%d:%d:%d" % (p["stream"], int(p["excl"]), p["dep"], p["weight"])
                  for p in h2["priority_frames"]) or "0"
    first = h2["requests"][0] if h2["requests"] else {"pseudo_order": []}
    po = ",".join(n[1] for n in first["pseudo_order"])
    return "|".join([s, str(wu), pr, po])
def handle(conn, addr, out_path, ctx):
    try:
        raw = peek_client_hello(conn)
        ch = parse_client_hello(raw)
        record = {"peer": addr[1], "ja4": ja4(ch), "client_hello": ch}
        tls = ctx.wrap_socket(conn, server_side=True)
        record["alpn_selected"] = tls.selected_alpn_protocol()
        h2 = read_h2(tls)
        record["h2"] = h2
        record["akamai"] = akamai(h2)
    except Exception as error:
        record = {"peer": addr[1], "error": "%s: %s" % (type(error).__name__, error)}
    with open(out_path, "a") as f:
        f.write(json.dumps(record) + "\n")
    try:
        conn.close()
    except OSError:
        pass


def main():
    port, out_path, cert, key = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["h2"])
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    print("ready", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr, out_path, ctx), daemon=True).start()


if __name__ == "__main__":
    main()
