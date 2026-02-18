#!/usr/bin/env python3
import sys
from datetime import datetime

from utils.helpers import create_output_dir
from utils.logger import log
import utils.helpers



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

    #whoisss
    try:
        whoisScan = WhoisModule(domain,config)
        finalReport["results"]["WHOIS"] = whoisScan.run()
    except Exception as e:
        log.error(f"Modul whois error parah : {str(e)}")
        finalReport["results"]["WHOIS"] = {"error":str(e)}

def main():