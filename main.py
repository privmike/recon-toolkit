#!/usr/bin/env python3
import argparse
import os.path
import sys
from datetime import datetime

from utils.helpers import create_output_dir, read_config, save_json_report
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


    finalReport["finish_time"] = str(datetime.now())
    savedPath = save_json_report(finalReport,outputDir)
    if savedPath:
        log.info(f"laporan berhasil dibuat : {savedPath}")

    log.info(f"scan selesai")

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
        if os.path.exists(args.list):
            with open(args.list,'r') as file:
                for line in file:
                    line = line.strip()
                    if line:
                        targets.append(line)

        else:
            log.critical(f"File list domain tidak ditemukan : {args.list}")
            sys.exit(1)

    if not targets:
        log.critical(f"Tidak ada target valid yang ditemukan")
        sys.exit(1)

    log.info(f"total target : {len(targets)}")

    for t in targets:
        processTarget(t,config)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log.critical(f"Error di running main : {str(e)}")
        sys.exit(1)

    except KeyboardInterrupt:
        print("\n")
        log.warning("Tool diberhentikan manual oleh user")
        sys.exit(0)




