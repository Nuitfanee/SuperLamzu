"""Shared SLZ1 request/reply matching for runtime configuration queries."""
from . import cfg, protocol as P


class RuntimeLink(cfg.Link):
    """Match operation, target and idempotent SET values before accepting an ACK."""

    @staticmethod
    def _ok(reply, request, strict):
        if len(reply) < 6 or not cfg.native.Link._ok(reply, request, strict):
            return False
        if reply[2] != request[2]:
            return False
        if request[4] != P.GROUP or request[5] not in (P.GET, P.SET):
            return True
        op = request[7]
        if op == P.CAPS:
            return reply[3] == 12 and reply[6:10] == b"SLZ1"
        if op == P.DEBOUNCE:
            return (reply[3] == 5 and len(reply) >= 11 and reply[6] == request[6]
                    and (request[5] != P.SET or reply[7:11] == request[8:12]))
        if len(reply) < 6 + reply[3] or reply[6:8] != request[6:8]:
            return False
        if request[5] == P.SET:
            if op == P.FPS:
                return reply[3] == 6 and reply[8] == request[8]
            if op == P.FPS_CUSTOM:
                return reply[3] == 12 and reply[8] == P.CUSTOM_FPS_ID and reply[11:14] == request[8:11]
            if op == P.SENSOR_SNAPSHOT:
                return reply[3] == 26 and reply[12:14] == request[8:10]
            if op == P.LOCK:
                return reply[3] == 7 and reply[8:11] == request[8:11]
            if op == P.STATS and request[8] < 2:
                return reply[3] == 3 and reply[8] == request[8]
        elif op == P.STATS:
            return reply[8] == request[8]
        return True

    def xfer(self, req, strict=True, rounds=3, poll=8):
        return super().xfer(req, strict=strict, rounds=rounds, poll=poll)
