import socket
from ipaddress import ip_network, collapse_addresses

WHOIS_HOST = "whois.radb.net"
WHOIS_PORT = 43
WHOIS_TIMEOUT = 30

TARGET_ASNS = ["AS134963", "AS45102"]


def query_whois(query: str, host: str = WHOIS_HOST, port: int = WHOIS_PORT, timeout: int = WHOIS_TIMEOUT) -> str:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(query.encode("utf-8") + b"\r\n")
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def get_asn_prefixes(asn: str = "AS134963"):
    text = query_whois(f"-i origin {asn}")
    prefixes = []

    for line in text.splitlines():
        if line.startswith("route:") or line.startswith("route6:"):
            prefix = line.split()[-1].strip()
            if prefix:
                prefixes.append(prefix)

    return prefixes


def get_prefixes_for_asns(asns: list[str]) -> list[str]:
    """複数ASNのプレフィックスを取得し、重複を除いて返す。"""
    prefixes: list[str] = []
    for asn in asns:
        asn_prefixes = get_asn_prefixes(asn)
        print(f"{asn} のプレフィックス数: {len(asn_prefixes)}")
        prefixes.extend(asn_prefixes)
    return list(dict.fromkeys(prefixes))


def summarize_prefixes(prefixes: list[str]) -> list[str]:
    """重複・隣接するプレフィックスを最小のCIDR集合にサマライズする。"""
    networks = []
    for prefix in prefixes:
        try:
            networks.append(ip_network(prefix, strict=False))
        except ValueError:
            continue

    ipv4 = [net for net in networks if net.version == 4]
    ipv6 = [net for net in networks if net.version == 6]

    summarized = list(collapse_addresses(ipv4)) + list(collapse_addresses(ipv6))
    return [str(net) for net in summarized]


if __name__ == "__main__":
    prefixes = get_prefixes_for_asns(TARGET_ASNS)
    summarized = summarize_prefixes(prefixes)
    print(f"取得プレフィックス数(重複除去後): {len(prefixes)}")
    print(f"サマライズ後のプレフィックス数: {len(summarized)}")
    print("\n".join(summarized[:20]))  # 先頭20個表示
    # 保存例
    with open("alibaba_sg_as134963.txt", "w") as f:
        f.write("\n".join(summarized))
