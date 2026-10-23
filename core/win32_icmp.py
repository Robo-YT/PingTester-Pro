"""
Native 64-bit Windows ICMP Implementation using Win32 Iphlpapi.dll.
Requires NO administrative privileges and delivers sub-millisecond precision.
"""

import ctypes
from ctypes import wintypes
import socket
import struct
import time
import subprocess
import threading
from typing import Optional, Dict, Any

# Windows Sockets & ICMP Constants
IP_STATUS_CODES = {
    0: "SUCCESS",
    11001: "BUFFER_TOO_SMALL",
    11002: "DEST_NET_UNREACHABLE",
    11003: "DEST_HOST_UNREACHABLE",
    11004: "DEST_PROT_UNREACHABLE",
    11005: "DEST_PORT_UNREACHABLE",
    11006: "NO_RESOURCES",
    11007: "BAD_OPTION",
    11008: "HW_ERROR",
    11009: "PACKET_TOO_BIG",
    11010: "REQ_TIMED_OUT",
    11011: "BAD_REQ",
    11012: "BAD_ROUTE",
    11013: "TTL_EXPIRED_TRANSIT",
    11014: "TTL_EXPIRED_REASSEM",
    11015: "PARAM_PROBLEM",
    11016: "SOURCE_QUENCH",
    11017: "OPTION_TOO_BIG",
    11018: "BAD_DESTINATION",
    11050: "GENERAL_FAILURE",
}


class IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


class ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [
        ("Address", wintypes.DWORD),
        ("Status", wintypes.ULONG),
        ("RoundTripTime", wintypes.ULONG),
        ("DataSize", wintypes.USHORT),
        ("Reserved", wintypes.USHORT),
        ("Data", ctypes.c_void_p),
        ("Options", IP_OPTION_INFORMATION),
    ]


class Win32ICMPEngine:
    """Thread-safe native Win32 ICMP wrapper using IcmpSendEcho."""

    _tls = threading.local()

    def __init__(self):
        self._iphlpapi = ctypes.windll.Iphlpapi

        # Setup ctypes signatures
        self._iphlpapi.IcmpCreateFile.restype = wintypes.HANDLE
        self._iphlpapi.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
        self._iphlpapi.IcmpCloseHandle.restype = wintypes.BOOL

        self._iphlpapi.IcmpSendEcho.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.WORD,
            ctypes.POINTER(IP_OPTION_INFORMATION),
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        self._iphlpapi.IcmpSendEcho.restype = wintypes.DWORD

    def _get_thread_handle(self) -> wintypes.HANDLE:
        """Get or create an ICMP handle for the current thread."""
        handle = getattr(self._tls, "handle", None)
        if handle is None or handle == 0 or handle == wintypes.HANDLE(-1).value:
            handle = self._iphlpapi.IcmpCreateFile()
            self._tls.handle = handle
        return handle

    def close_thread_handle(self):
        """Clean up handle for current thread."""
        handle = getattr(self._tls, "handle", None)
        if handle:
            self._iphlpapi.IcmpCloseHandle(handle)
            self._tls.handle = None

    @staticmethod
    def resolve_ip(target: str) -> Optional[str]:
        """Resolve a hostname or IP string to an IPv4 string."""
        try:
            return socket.gethostbyname(target)
        except Exception:
            return None

    @staticmethod
    def get_default_gateway() -> Optional[str]:
        """Detect the local default gateway (router IP)."""
        try:
            out = subprocess.check_output(
                ["route", "print", "0.0.0.0"],
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            )
            for line in out.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gateway = parts[2]
                    # Validate IP format
                    socket.inet_aton(gateway)
                    return gateway
        except Exception:
            pass

        # Secondary fallback: socket connect probe
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            # Most common gateway is .1 on the same subnet
            octets = local_ip.split(".")
            return f"{octets[0]}.{octets[1]}.{octets[2]}.1"
        except Exception:
            return None

    def ping(
        self,
        target_ip: str,
        timeout_ms: int = 1000,
        ttl: int = 128,
        payload: bytes = b"PingTesterRealtimePacketProbe32B",
    ) -> Dict[str, Any]:
        """
        Send a single ICMP echo packet to target_ip.
        Uses time.perf_counter for sub-millisecond precision.
        Returns a detailed dictionary of the result.
        """
        try:
            dest_packed = socket.inet_aton(target_ip)
            ip_dest = ctypes.c_uint32.from_buffer_copy(dest_packed).value
        except Exception as e:
            return {
                "success": False,
                "rtt_ms": None,
                "status": -1,
                "status_text": f"INVALID_IP: {e}",
                "from_ip": None,
                "ttl_reply": 0,
                "timestamp": time.time(),
            }

        handle = self._get_thread_handle()
        if not handle or handle == wintypes.HANDLE(-1).value:
            return {
                "success": False,
                "rtt_ms": None,
                "status": -2,
                "status_text": "FAILED_TO_CREATE_HANDLE",
                "from_ip": None,
                "ttl_reply": 0,
                "timestamp": time.time(),
            }

        reply_size = ctypes.sizeof(ICMP_ECHO_REPLY) + len(payload) + 64
        reply_buf = ctypes.create_string_buffer(reply_size)

        opt = IP_OPTION_INFORMATION()
        opt.Ttl = ttl
        opt.Tos = 0
        opt.Flags = 0
        opt.OptionsSize = 0
        opt.OptionsData = None

        t_start = time.perf_counter()
        ret = self._iphlpapi.IcmpSendEcho(
            handle,
            ip_dest,
            payload,
            len(payload),
            ctypes.byref(opt),
            reply_buf,
            reply_size,
            timeout_ms,
        )
        t_end = time.perf_counter()
        measured_rtt = (t_end - t_start) * 1000.0

        if ret > 0:
            reply = ICMP_ECHO_REPLY.from_buffer_copy(reply_buf)
            raw_addr = reply.Address
            try:
                from_ip = socket.inet_ntoa(raw_addr.to_bytes(4, "little"))
            except Exception:
                from_ip = "Unknown"

            status = reply.Status
            status_text = IP_STATUS_CODES.get(status, f"CODE_{status}")

            # If Win32 reports 0 ms, use measured_rtt to provide sub-ms fidelity
            reported_rtt = float(reply.RoundTripTime)
            final_rtt = measured_rtt if (reported_rtt == 0 and measured_rtt < 1.0) else (reported_rtt if reported_rtt > 0 else measured_rtt)

            is_success = (status == 0)

            return {
                "success": is_success,
                "rtt_ms": round(final_rtt, 2),
                "status": status,
                "status_text": status_text,
                "from_ip": from_ip,
                "ttl_reply": reply.Options.Ttl if hasattr(reply.Options, "Ttl") else 0,
                "timestamp": time.time(),
            }
        else:
            return {
                "success": False,
                "rtt_ms": None,
                "status": 11010,
                "status_text": "REQ_TIMED_OUT",
                "from_ip": None,
                "ttl_reply": 0,
                "timestamp": time.time(),
            }
