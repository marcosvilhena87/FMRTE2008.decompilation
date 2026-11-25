"""Cooperative CPython audit-event guard for this synthetic runner."""
import sys

PREFIXES = ("socket.", "os.exec", "os.fork", "os.posix_spawn", "os.spawn",
            "os.system", "subprocess.")
LIMITS = [
    "Only matching CPython audit events in this interpreter are intercepted.",
    "The hook starts at runner entry, after interpreter startup and standard-library imports.",
    "Filesystem access and nonmatching events are outside this policy.",
    "Native code and unaudited actions require external containment and observation.",
    "A clean event log covers the observed policy only.",
]


class AuditGuard:
    def __init__(self):
        self.events = []
        self.probe_event = "dc002_r1.audit_probe"
        self.probe_seen = False

    def hook(self, event, args):
        if event == self.probe_event:
            self.probe_seen = True
        if event.startswith(PREFIXES):
            self.events.append(event)
            raise PermissionError(f"Synthetic runner denied {event}")

    def install(self):
        if sys.implementation.name != "cpython":
            raise RuntimeError("The audit guard requires CPython")
        sys.addaudithook(self.hook)
        sys.audit(self.probe_event)
        if not self.probe_seen:
            raise RuntimeError("CPython audit hook registration could not be verified")

    def verify(self):
        import socket

        probes = {"socket.__new__": socket.socket}
        for event in ("os.exec", "os.fork", "os.posix_spawn", "os.spawn", "os.system",
                      "subprocess.Popen"):
            probes[event] = lambda event=event: sys.audit(event)

        checks = []
        for event, probe in probes.items():
            start = len(self.events)
            denied = False
            try:
                result = probe()
                if event == "socket.__new__":
                    result.close()
            except PermissionError:
                denied = True
            checks.append({"event": event, "probe": "api" if event.startswith("socket.") else "synthetic",
                           "passed": denied and self.events[start:] == [event]})
        start = len(self.events)
        with open(__file__, "rb") as file:
            read_succeeded = bool(file.read(1))
        checks.append({"event": "open", "probe": "api",
                       "passed": read_succeeded and self.events[start:] == []})
        return checks
