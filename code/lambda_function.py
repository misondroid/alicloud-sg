#! /usr/bin/env python3
from boto3 import client,Session
from os import environ, path
from datetime import datetime, timezone
from ipaddress import IPv4Address, ip_network, summarize_address_range, collapse_addresses
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

import json
import socket
from typing import Dict, Iterator, List

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


is_local = environ.get("IS_LOCAL", "false").lower() == "true"
aws_region = environ.get("AWS_REGION", "ap-northeast-1")
aws_profile = environ.get("AWS_PROFILE", None)
cidr_url = environ.get("ALIBABA_CIDR_URL", "https://sourcecidr.com/feeds/alibaba-cloud.json")
country = environ.get("COUNTRY", "SG")
apnic_cidr_url = environ.get("APNIC_CIDR_URL", "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest")
timeout = int(environ.get("TIMEOUT", "30"))

# BGP(WHOIS)からAlibaba CloudのASNプレフィックスを取得するための設定
whois_host = environ.get("WHOIS_HOST", "whois.radb.net")
whois_port = int(environ.get("WHOIS_PORT", "43"))
target_asns = [asn.strip() for asn in environ.get("TARGET_ASNS", "AS134963,AS45102").split(",") if asn.strip()]

# Cloudflare 配下の sourcecidr.com は Python 標準 UA を 403 で弾く
DEFAULT_HTTP_HEADERS = {
  "User-Agent": "curl/8.7.1",
  "Accept": "*/*",
}

def build_request(url: str) -> Request:
  return Request(url, headers=DEFAULT_HTTP_HEADERS)

# IP Set操作用のパラメータ
ipset_name = environ.get("IPSET_NAME", "alibaba-sg")
ipset_id = environ.get("IPSET_ID", "alibaba-sg")
ipset_scope = environ.get("IPSET_SCOPE", "regional")

# AWSのクライアントを取得
def get_aws_client(service_name: str):
  if aws_profile is not None:
    return (Session(profile_name=aws_profile)
     .client(service_name, region_name=aws_region))
  else:
    return client(service_name, region_name=aws_region)

# Source CIDRからAlibaba CloudのCIDR一覧を取得
def get_alibaba_cidr_from_source_cidr(local_file: str=None)->list[str]:
  print(f'local_file: {local_file}')
  if local_file is not None:
    try:  # ローカルファイルからCIDRを取得
      with open(local_file, "r") as file:
        data = json.load(file)["prefixes"]
        print(f'got {len(data)} cidrs for alibaba cloud from local file')
        return [prefix["ipv4Prefix"] for prefix in data]
    except Exception as e:
      logger.error(e)
      return []
  else:
    try:  # Source CIDR からCIDRを取得
      with urlopen(build_request(cidr_url), timeout=timeout) as response:
        data = json.load(response)["prefixes"]
        print(f'got {len(data)} cidrs for alibaba cloud from source cidr url')
        return [prefix["ipv4Prefix"] for prefix in data]
    except HTTPError as e:
      raise e
    except Exception as e:
      raise e

# WHOIS(TCP/43)へクエリを送信し、応答本文を返す
def query_whois(query: str, host: str = None, port: int = None) -> str:
  host = host or whois_host
  port = port or whois_port
  with socket.create_connection((host, port), timeout=timeout) as sock:
    sock.sendall(query.encode("utf-8") + b"\r\n")
    chunks = []
    while True:
      data = sock.recv(4096)
      if not data:
        break
      chunks.append(data)
  return b"".join(chunks).decode("utf-8", errors="replace")

# 単一ASNのルートプレフィックス一覧をWHOISから取得
def get_asn_prefixes(asn: str = "AS134963") -> list[str]:
  text = query_whois(f"-i origin {asn}")
  prefixes = []
  for line in text.splitlines():
    if line.startswith("route:") or line.startswith("route6:"):
      prefix = line.split()[-1].strip()
      if prefix:
        prefixes.append(prefix)
  print(f'got {len(prefixes)} prefixes for {asn} from whois')
  return prefixes

# WHOISから複数ASNのAlibaba CloudのCIDR一覧(IPv4)を取得
def get_alibaba_cidr_from_whois(asns: list[str] = None) -> list[str]:
  asns = asns or target_asns
  prefixes: list[str] = []
  for asn in asns:
    prefixes.extend(get_asn_prefixes(asn))
  # 既存パイプラインはIPv4前提のため、IPv4のみ抽出して重複除去
  ipv4 = [p for p in dict.fromkeys(prefixes) if ip_network(p, strict=False).version == 4]
  print(f'got {len(ipv4)} ipv4 cidrs for alibaba cloud from whois')
  return ipv4

# アドレス数をCIDRに変換
def count_to_cidrs(start_ip: str, count: int) -> list[str]:
  start = IPv4Address(start_ip)
  end = IPv4Address(int(start) + count - 1)
  return [str(net) for net in summarize_address_range(start, end)]

# APNICのCIDR一覧を取得し、各行をIteratorで返す
def iter_apnic_lines(local_file: str | None = None) -> Iterator[str]:
  if local_file is not None:
    print(f'getting apnic cidrs from local file')
    with open(local_file, "r", encoding="utf-8", errors="ignore") as f:
      for line in f:
        yield line.strip()
  else:
    with urlopen(build_request(apnic_cidr_url), timeout=timeout) as res:
      for raw in res:
        yield raw.decode("utf-8", errors="ignore").strip()

# APNICのCIDR一覧を解析し、IPv4とIPv6のCIDR一覧を返す
def parse_apnic_delegated(lines: Iterator[str]) -> tuple[list[str], list[str]]:
  ipv4: list[str] = []
  ipv6: list[str] = []

  for line in lines:
    if not line or line.startswith("#") or line.startswith("2|"):
      continue

    parts = line.split("|")
    if len(parts) < 7:
      continue

    registry, cc, typ, start, value, date, status = parts[:7]

    if cc != country:
      continue

    if typ == "ipv4":
      # value はアドレス数。例: 16384 => /18
      ipv4.extend(count_to_cidrs(start, int(value)))

    elif typ == "ipv6":
      # value はプレフィックス長。例: 32
      ipv6.append(f"{start}/{value}")

  return ipv4, ipv6

# APNICのCIDR一覧を取得
def get_apnic_cidr_from_apnic_cidr_url(
  ip_type: str="ipv4", local_file: str=None) -> Dict:
  source = local_file or apnic_cidr_url
  print(f'getting {ip_type} cidrs from {source}')
  try:
    ipv4, ipv6 = parse_apnic_delegated(iter_apnic_lines(local_file))
  except Exception as e:
    logger.error(e)
    return {}

  data: Dict = {
    "country": country,
    "source": source,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "ipv4": sorted(set(ipv4), key=lambda x: int(ip_network(x).network_address)),
    "ipv6": sorted(set(ipv6), key=lambda x: int(ip_network(x).network_address)),
  }
  return data[ip_type] if ip_type in ["ipv4", "ipv6"] else data

# IP Setを取得
def get_current_ip_set(ipset_name: str, ipset_id: str, ipset_scope: str) -> Dict:
  waf_client = get_aws_client("wafv2")
  response = waf_client.get_ip_set(
    Name=ipset_name,
    Id=ipset_id,
    Scope=ipset_scope
  )
  return response["IPSet"]["Addresses"]

# IP SetのLockTokenを取得
def get_ip_set_lock_token(ipset_name: str, ipset_id: str, ipset_scope: str) -> str:
  waf_client = get_aws_client("wafv2")
  response = waf_client.get_ip_set(
    Name=ipset_name,
    Id=ipset_id,
    Scope=ipset_scope
  )
  return response["LockToken"]
# IP Setを更新
def update_ip_set(ipset_name: str, ipset_id: str, ipset_scope: str, new_ip_set: list[str], lock_token: str):
  waf_client = get_aws_client("wafv2")
  try:
    waf_client.update_ip_set(
      Name=ipset_name,
      Id=ipset_id,
      Scope=ipset_scope,
      Addresses=new_ip_set,
      LockToken=lock_token
    )
    logger.info(f'IPセットの更新に成功しました。')
    return True
  except Exception as e:
    logger.error(e)
    return False
# IP Setを比較し、追加になるCIDRを返す
def filter_new_ip_set(current_ip_set: Dict, new_ip_set: Dict) -> Dict:
  return [cidr for cidr in new_ip_set if cidr not in current_ip_set]

# 重複するCIDRを返す
def build_overlapped_cidrs(
    target_cidrs: list[str],
    reference_cidrs: list[str],
) -> list[str]:
    results = []

    targets = [ip_network(cidr, strict=False) for cidr in target_cidrs]
    refs = [ip_network(cidr, strict=False) for cidr in reference_cidrs]

    for ref in refs:
        for target in targets:
            if not ref.overlaps(target):
                continue

            start = max(ref.network_address, target.network_address)
            end = min(ref.broadcast_address, target.broadcast_address)

            results.extend(summarize_address_range(start, end))

    return [str(cidr) for cidr in collapse_addresses(results)]


# メイン関数(Lambda実行時)
def lambda_handler(event, context):
  sg_cidrs = get_apnic_cidr_from_apnic_cidr_url()
  alibaba_cidrs = get_alibaba_cidr_from_whois()
  current_ip_set = get_current_ip_set(ipset_name, ipset_id, ipset_scope)
  overlapped_cidrs = build_overlapped_cidrs(alibaba_cidrs, sg_cidrs)
  new_ip_set = filter_new_ip_set(current_ip_set, overlapped_cidrs)
  lock_token = get_ip_set_lock_token(ipset_name, ipset_id, ipset_scope)
  logger.info(f'追加 CIDR数: {len(new_ip_set)}')
  logger.info(f'追加 CIDR: {",".join(new_ip_set)}')
  logger.info(f'削除 CIDR数: {len(current_ip_set)-len(new_ip_set)}')
  update_ip_set(ipset_name, ipset_id, ipset_scope, new_ip_set, lock_token)
  return {
    "statusCode": 200,
    "body": "Hello, World!"
  }
# メイン関数(コマンドライン実行時)
def main():
  print(f'is_local: {is_local}')
  sg_cidrs = (get_apnic_cidr_from_apnic_cidr_url(
    local_file="data/delegated-apnic-latest", 
    ip_type="ipv4")
    if is_local else get_apnic_cidr_from_apnic_cidr_url(ip_type="ipv4"))
  alibaba_cidrs = get_alibaba_cidr_from_whois()
  current_ip_set = get_current_ip_set(ipset_name, ipset_id, ipset_scope)
  filtered_cidrs = build_overlapped_cidrs(alibaba_cidrs, sg_cidrs)
  new_ip_set = filter_new_ip_set(current_ip_set, filtered_cidrs)
  print(f'追加 CIDR数: {len(new_ip_set)}')
  print(f'追加 CIDR: {",".join(new_ip_set)}')
  print(f'削除 CIDR数: {len(current_ip_set)-len(new_ip_set)}')
  lock_token = get_ip_set_lock_token(ipset_name, ipset_id, ipset_scope)
  update_ip_set(ipset_name, ipset_id, ipset_scope, new_ip_set, lock_token)

def get_logger():
  script_name = (path.basename(__file__)).split(".")[0]
  logger = logging.getLogger(script_name)
  logger.setLevel(logging.INFO)
  logger.addHandler(logging.FileHandler(f"{script_name}.log"))
  return logger

if __name__ == "__main__":
  logger=get_logger()
  main()