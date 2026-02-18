#!/usr/bin/env python3
import argparse
import sys
from datetime import datetime

from utils.helpers import create_output_dir, read_config
from utils.logger import log



try:
    from modules.module_whois import WhoisModule

except ImportError as e:
    log.critical(f"gagal import module {str(e)}")
    sys.exit(1)


def processTarget(domain, config):

    log.info(f"scanning {domain}")

    outputDir = create_output_dir(domain)
    finalReport = {
        "target": domain,
        "start_time": str(datetime.now()),
        "results": {}
    }

    #whois
    try:
        whoisScan = WhoisModule(domain,config)
        finalReport["results"]["WHOIS"] = whoisScan.run()
    except Exception as e:
        log.error(f"Modul whois error parah : {str(e)}")
        finalReport["results"]["WHOIS"] = {"error":str(e)}

def main():

    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d","--domain", help="Target domain tunggal(contoh :bugcrowd.com)")
    group.add_argument("-l","--list", help="Daftar target domain dalam bentuk file")

    args= parser.parse_args()

    config = read_config()

    targets = []
    if args.domain:
        for d in args.domain.split(","):
            targets.append(d.strip())
    elif args.list:
