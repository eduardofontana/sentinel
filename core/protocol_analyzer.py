import re
import urllib.parse
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum


class ProtocolType(Enum):
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    FTP = "ftp"
    SMTP = "smtp"
    SSH = "ssh"
    UNKNOWN = "unknown"


@dataclass
class HTTPAnalysis:
    method: str
    url: str
    path: str
    query_params: Dict[str, str]
    headers: Dict[str, str]
    user_agent: Optional[str] = None
    host: Optional[str] = None
    content_type: Optional[str] = None
    referer: Optional[str] = None
    is_sql_injection: bool = False
    is_xss: bool = False
    is_path_traversal: bool = False
    is_command_injection: bool = False


@dataclass
class DNSAnalysis:
    query_name: str
    query_type: str
    is_suspicious: bool = False
    suspicious_reason: Optional[str] = None


@dataclass
class FTPAnalysis:
    command: str
    argument: str
    is_suspicious: bool = False
    suspicious_reason: Optional[str] = None


class ProtocolAnalyzer:
    DNS_QUERY_TYPES = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
    }

    FTP_COMMANDS = [
        "USER", "PASS", "CWD", "CDUP", "DELE", "LIST", "MDTM", "MKD",
        "NLIST", "PASS", "PASV", "PORT", "PWD", "QUIT", "RETR",
        "RMD", "RNFR", "RNTO", "SITE", "SIZE", "STOR", "TYPE",
    ]

    SUSPICIOUS_PATTERNS = {
        "sql_injection": [
            r"' OR '1'='1",
            r"UNION ALL SELECT",
            r"DROP TABLE",
            r"INSERT INTO",
            r"UPDATE .* SET",
            r"DELETE FROM",
            r"EXEC\(",
            r"';--",
        ],
        "xss": [
            r"<script",
            r"javascript:",
            r"onerror=",
            r"onload=",
            r"<iframe",
        ],
        "path_traversal": [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e/",
            r"\.\.%2f",
        ],
        "command_injection": [
            r";\s*/bin/sh",
            r";\s*cmd\.exe",
            r"\|",
            r"`",
            r"\$\(",
            r"eval\(",
        ],
    }

    def __init__(self):
        self.http_patterns_by_category = {
            category: self._compile_patterns(category)
            for category in self.SUSPICIOUS_PATTERNS
        }

    def _compile_patterns(self, category: str) -> List[re.Pattern]:
        return [
            re.compile(p, re.IGNORECASE)
            for p in self.SUSPICIOUS_PATTERNS.get(category, [])
        ]

    def detect_protocol(self, packet) -> ProtocolType:
        if not hasattr(packet, "destination_port"):
            return ProtocolType.UNKNOWN

        port = packet.destination_port

        if port == 80:
            return ProtocolType.HTTP
        elif port == 443:
            return ProtocolType.HTTPS
        elif port == 53:
            return ProtocolType.DNS
        elif port == 21:
            return ProtocolType.FTP
        elif port == 22:
            return ProtocolType.SSH
        elif port == 25:
            return ProtocolType.SMTP

        return ProtocolType.UNKNOWN

    def analyze_http(self, payload: bytes) -> Optional[HTTPAnalysis]:
        if not payload:
            return None

        try:
            text = payload.decode("utf-8", errors="ignore")
        except Exception:
            return None

        lines = text.split("\r\n")
        if not lines:
            return None

        request_line = lines[0]
        parts = request_line.split(" ", 2)
        if len(parts) < 2:
            return None

        method = parts[0]
        if method not in ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"]:
            return None

        url = parts[1]
        parsed = urllib.parse.urlparse(url)
        path = parsed.path
        query = parsed.query

        headers = {}
        for line in lines[1:]:
            if ":" not in line:
                break
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

        params = urllib.parse.parse_qs(query)

        analysis = HTTPAnalysis(
            method=method,
            url=url,
            path=path,
            query_params=params,
            headers=headers,
            user_agent=headers.get("user-agent"),
            host=headers.get("host"),
            content_type=headers.get("content-type"),
            referer=headers.get("referer"),
        )

        self._check_http_threats(analysis, text)
        return analysis

    def _check_http_threats(self, analysis: HTTPAnalysis, text: str) -> None:
        combined = analysis.url + analysis.path
        if analysis.query_params:
            combined += "&".join(analysis.query_params.values())

        combined_lower = combined.lower()

        for category, patterns in self.http_patterns_by_category.items():
            if not any(pattern.search(combined_lower) for pattern in patterns):
                continue
            if category == "sql_injection":
                analysis.is_sql_injection = True
            elif category == "xss":
                analysis.is_xss = True
            elif category == "path_traversal":
                analysis.is_path_traversal = True
            elif category == "command_injection":
                analysis.is_command_injection = True

    def analyze_dns(self, packet) -> Optional[DNSAnalysis]:
        return DNSAnalysis(
            query_name="unknown",
            query_type="A",
        )

    def analyze_ftp(self, payload: bytes) -> Optional[FTPAnalysis]:
        if not payload:
            return None

        try:
            text = payload.decode("utf-8", errors="ignore").strip()
        except Exception:
            return None

        parts = text.split(" ", 1)
        command = parts[0].upper() if parts else ""
        argument = parts[1] if len(parts) > 1 else ""

        is_suspicious = command in ["DELE", "RMD", "RNFR"] or (
            command == "USER" and argument.startswith("root")
        )

        return FTPAnalysis(
            command=command,
            argument=argument,
            is_suspicious=is_suspicious,
            suspicious_reason="Dangerous FTP command" if is_suspicious else None,
        )

    def analyze(self, packet) -> Dict[str, Any]:
        if not hasattr(packet, "payload"):
            return {"protocol": ProtocolType.UNKNOWN.value}

        protocol = self.detect_protocol(packet)
        result = {"protocol": protocol.value}

        if protocol == ProtocolType.HTTP:
            result["http"] = self.analyze_http(packet.payload)
        elif protocol == ProtocolType.DNS:
            result["dns"] = self.analyze_dns(packet)
        elif protocol == ProtocolType.FTP:
            result["ftp"] = self.analyze_ftp(packet.payload)

        return result
