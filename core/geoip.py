import ipaddress
import socket
from typing import Optional, Dict
from dataclasses import dataclass


@dataclass
class GeoInfo:
    country: str
    country_code: str
    city: Optional[str] = None
    isp: Optional[str] = None
    is_private: bool = False


class GeoIPLookup:
    PRIVATE_IP_RANGES = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    ]

    COUNTRY_MAP = {
        "US": ("United States", "US"),
        "BR": ("Brazil", "BR"),
        "CN": ("China", "CN"),
        "RU": ("Russia", "RU"),
        "DE": ("Germany", "DE"),
        "GB": ("United Kingdom", "GB"),
        "FR": ("France", "FR"),
        "JP": ("Japan", "JP"),
        "KR": ("South Korea", "KR"),
        "IN": ("India", "IN"),
        "AU": ("Australia", "AU"),
        "CA": ("Canada", "CA"),
        "MX": ("Mexico", "MX"),
        "AR": ("Argentina", "AR"),
        "NL": ("Netherlands", "NL"),
        "SG": ("Singapore", "SG"),
    }

    def __init__(self, use_dns: bool = True):
        self.use_dns = use_dns
        self._cache: Dict[str, GeoInfo] = {}
        self._private_networks = [
            ipaddress.ip_network(range_, strict=False)
            for range_ in self.PRIVATE_IP_RANGES
        ]

    def lookup(self, ip_address: str) -> Optional[GeoInfo]:
        if ip_address in self._cache:
            return self._cache[ip_address]

        info = self._do_lookup(ip_address)
        self._cache[ip_address] = info
        return info

    def _do_lookup(self, ip_address: str) -> GeoInfo:
        if self._is_private_ip(ip_address):
            return GeoInfo(
                country="Private Network",
                country_code="XX",
                is_private=True,
            )

        if self.use_dns:
            return self._reverse_dns_lookup(ip_address)

        return GeoInfo(
            country="Unknown",
            country_code="XX",
        )

    def _is_private_ip(self, ip_address: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_address)
            for network in self._private_networks:
                if ip in network:
                    return True
        except ValueError:
            pass
        return False

    def _reverse_dns_lookup(self, ip_address: str) -> GeoInfo:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)

            if hostname:
                domain = hostname.lower()

                if ".br" in domain:
                    return GeoInfo(country="Brazil", country_code="BR")
                elif ".us" in domain or ".com" in domain or ".net" in domain:
                    return GeoInfo(country="United States", country_code="US")
                elif ".cn" in domain:
                    return GeoInfo(country="China", country_code="CN")
                elif ".ru" in domain:
                    return GeoInfo(country="Russia", country_code="RU")
                elif ".de" in domain:
                    return GeoInfo(country="Germany", country_code="DE")
                elif ".uk" in domain:
                    return GeoInfo(country="United Kingdom", country_code="GB")
                elif ".jp" in domain:
                    return GeoInfo(country="Japan", country_code="JP")
                elif ".kr" in domain:
                    return GeoInfo(country="South Korea", country_code="KR")
                elif ".in" in domain:
                    return GeoInfo(country="India", country_code="IN")
                elif ".au" in domain:
                    return GeoInfo(country="Australia", country_code="AU")
                elif ".ca" in domain:
                    return GeoInfo(country="Canada", country_code="CA")
                elif ".mx" in domain:
                    return GeoInfo(country="Mexico", country_code="MX")
                elif ".ar" in domain:
                    return GeoInfo(country="Argentina", country_code="AR")
                elif ".nl" in domain:
                    return GeoInfo(country="Netherlands", country_code="NL")
                elif ".sg" in domain:
                    return GeoInfo(country="Singapore", country_code="SG")

                if "localhost" in hostname:
                    return GeoInfo(country="Localhost", country_code="LO")

        except socket.herror:
            pass

        return GeoInfo(country="Unknown", country_code="XX")

    def get_country_code(self, ip_address: str) -> str:
        info = self.lookup(ip_address)
        return info.country_code if info else "XX"

    def get_country(self, ip_address: str) -> str:
        info = self.lookup(ip_address)
        return info.country if info else "Unknown"

    def clear_cache(self) -> None:
        self._cache.clear()