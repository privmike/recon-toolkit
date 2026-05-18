#!/usr/bin/env python3
import argparse
import os.path
import sys
from datetime import datetime

from modules.module_dorking import DorkingModule
from modules.module_nmap import NmapModule
from modules.module_subdomain_enumeration import SubdomainEnumerationModule
from modules.module_subdomain_status_check import SubdomainStatusCheckModule
from utils.helpers import create_output_dir, read_config, save_json_report
from utils.logger import log



try:
    from modules.module_whois import WhoisModule
    from modules.module_dns import DnsModule
    from modules.module_email_breach import EmailBreachModule
    from modules.module_find_email import FindEmailModule
    from modules.module_ip import IPModule

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

    #dns
    try:
        dnsScan = DnsModule(domain,config)
        finalReport["results"]["DNS"] = dnsScan.run()
    except Exception as e:
        log.error(f"Modul dns error parah : {str(e)}")
        finalReport["results"]["DNS"] = {"error" : str(e)}

    #ip
    try:
        ipscan = IPModule(domain,config)
        tmp = ipscan.run()
        if tmp == None:
            tmp = "No IP Found"
        finalReport["results"]["IP"] = tmp
    except Exception as e:
        log.error(f"Modul IP error parah : {str(e)}")
        finalReport["results"]["IP"] = {"error" : str(e)}

    #find email
    # emailresult = None
    # try:
    #     findemail = FindEmailModule(domain,config)
    #     emailresult = findemail.run()
    #     finalReport["results"]["Email"] =emailresult
    # except Exception as e:
    #     log.error(f"Modul Find Email error parah : {str(e)}")
    #     finalReport["results"]["Email"] = {"error" : str(e)}
    #
    # #email breach check
    # try:
    #     emailfinal =set()
    #     if isinstance(emailresult, dict) and "error" not in emailresult:
    #         for tool, emaillist in emailresult.items():
    #             if isinstance(emaillist, list):
    #                 for email in emaillist:
    #                     emailfinal.add(email)
    #
    #     targetemail = list(emailfinal)
    #     if targetemail:
    #         log.info(f"{len(targetemail)} email diterima ke modul breach check")
    #         breachcheck = EmailBreachModule(targetemail,config)
    #         finalReport["results"]["EmailBreach"] = breachcheck.run()
    #     # else:
    #     #     log.info(f"No email found. No email ran though breach check module")
    #     #     finalReport["results"]["EmailBreach"] = {"status":"safe", "message":"No target email to check"}
    # except Exception as e:
    #     log.error(f"Modul Breach Check error parah : {str(e)}")
    #     finalReport["results"]["EmailBreach"] = {"error": str(e)}
    #
    # #google dorking
    # try:
    #     module_dorking = DorkingModule(domain,config)
    #     dorks_result = module_dorking.run()
    #     finalReport["results"]["Google_Dorking"] = dorks_result
    #     if not dorks_result:
    #         finalReport["results"]["Google_Dorking"] = {"message":"No dorking result found"}
    # except Exception as e:
    #     log.error(f"Modul Google_Dorking error parah : {str(e)}")
    #     finalReport["results"]["Google_Dorking"] = {"error": str(e)}
    #


    #subdomain enumeration
    subdomains = []
    try:
        module_subdomain = SubdomainEnumerationModule(domain,config)
        subdomain_result = module_subdomain.run()
        finalReport["results"]["Subdomain_Enumeration"] = subdomain_result
        subdomains = subdomain_result.get("subdomains",[])
    except Exception as e:
        log.error(f"Modul Subdomain_Enumeration error parah : {str(e)}")
        finalReport["results"]["Subdomain_Enumeration"] = {"error": str(e)}

    #subdomain status check
    subdomain_active = []
    if subdomains:
        try:
            module_subdomain_status_check = SubdomainStatusCheckModule(domain,config,subdomains)
            status_check_result = module_subdomain_status_check.run()
            finalReport["results"]["Subdomain_Status_Check"] = status_check_result
            if isinstance(status_check_result,dict):
                if "method_httpx_toolkit" in status_check_result and isinstance(status_check_result["method_httpx_toolkit"],list):
                    subdomain_active.extend(status_check_result["method_httpx_toolkit"])
                elif "method_httprobe" in status_check_result and isinstance(status_check_result["method_httprobe"],list):
                    subdomain_active.extend(status_check_result["method_httprobe"])
        except Exception as e:
            log.error(f"Modul Subdomain_Status_Check error parah : {str(e)}")
            finalReport["results"]["Subdomain_Status_Check"] = {"error": str(e)}
    else:
        log.info(f"Tidak ada subdomain yang ditemukan")
        finalReport["results"]["Subdomain_Status_Check"] = {"message":"No Subdomain Found"}

    #nmap
    if subdomain_active:
        try:
            log.info(f"({len(subdomain_active)}) subdomain aktif diterima modul nmap")
            module_nmap = NmapModule(domain,config,subdomain_active)
            nmap_result = module_nmap.run()
            finalReport['results']['Nmap'] = nmap_result
        except Exception as e:
            log.error(f"Modul Nmap error parah : {str(e)}")
            finalReport['results']['Nmap'] = {"error": str(e)}
    else:
        log.info(f"Tidak ada subdomain aktif yang diterima nmap")
        finalReport['results']['Nmap'] = {"message":"No Subdomain Found to scan with Nmap"}



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




