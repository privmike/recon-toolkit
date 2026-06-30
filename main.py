#!/usr/bin/env python3
import argparse
import os.path
import sys
from datetime import datetime

from modules.module_dns import DnsModule
from modules.module_dorking import DorkingModule
from modules.module_email_breach import EmailBreachModule
from modules.module_extended_find_email import module_extended_find_email
from modules.module_find_email import FindEmailModule
from modules.module_github_check import GithubCheckModule
from modules.module_ip import IPModule
from modules.module_nmap import NmapModule
from modules.module_subdomain_enumeration import SubdomainEnumerationModule
from modules.module_subdomain_status_check import SubdomainStatusCheckModule
from modules.module_waf_detection import WafDetectionModule
from modules.module_whois import WhoisModule
from utils.helpers import create_output_dir, read_config, save_json_report
from utils.logger import log
from utils.json_to_html import generate_html_final_report


# try:
#     from modules.module_whois import WhoisModule
#     from modules.module_dns import DnsModule
#     from modules.module_email_breach import EmailBreachModule
#     from modules.module_find_email import FindEmailModule
#     from modules.module_ip import IPModule
#
# except ImportError as e:
#     log.critical(f"gagal import module {str(e)}")
#     sys.exit(1)


def processTarget(domain, config, github_repo=None):

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
    emailresult = None
    try:
        findemail = FindEmailModule(domain,config)
        emailresult = findemail.run()
        finalReport["results"]["Email"] =emailresult
    except Exception as e:
        log.error(f"Modul Find Email error parah : {str(e)}")
        finalReport["results"]["Email"] = {"error" : str(e)}

    # #email breach check
    try:
        emailfinal =set()
        if isinstance(emailresult, dict) and "error" not in emailresult:
            for tool, emaillist in emailresult.items():
                if isinstance(emaillist, list):
                    for email in emaillist:
                        emailfinal.add(email)

        targetemail = list(emailfinal)
        if targetemail:
            log.info(f"{len(targetemail)} email diterima ke modul breach check")
            breachcheck = EmailBreachModule(targetemail,config)
            finalReport["results"]["EmailBreach"] = breachcheck.run()
            # else:
            #     log.info(f"No email found. No email ran though breach check module")
            #     finalReport["results"]["EmailBreach"] = {"status":"safe", "message":"No target email to check"}
    except Exception as e:
        log.error(f"Modul Breach Check error parah : {str(e)}")
        finalReport["results"]["EmailBreach"] = {"error": str(e)}

    # #google dorking
    try:
        module_dorking = DorkingModule(domain,config)
        dorks_result = module_dorking.run()
        finalReport["results"]["Google_Dorking"] = dorks_result
        if not dorks_result:
            finalReport["results"]["Google_Dorking"] = {"message":"No dorking result found"}
    except Exception as e:
        log.error(f"Modul Google_Dorking error parah : {str(e)}")
        finalReport["results"]["Google_Dorking"] = {"error": str(e)}

    dorks_result = None
    try:
        module_dorking = DorkingModule(domain, config)
        dorks_result = module_dorking.run()
        finalReport["results"]["Google_Dorking"] = dorks_result
        if not dorks_result:
            finalReport["results"]["Google_Dorking"] = {"message": "No dorking result found"}
    except Exception as e:
        log.error(f"Modul Google_Dorking error parah : {str(e)}")
        finalReport["results"]["Google_Dorking"] = {"error": str(e)}

    if dorks_result and isinstance(dorks_result, dict) and "error" not in dorks_result:
        try:
            dork_email_scanner = module_extended_find_email(domain, config, dorks_result)

            finalReport["results"]["Emails_From_Dorked_Paths"] = dork_email_scanner.run()
        except Exception as e:
            log.error(f"Modul Dork Email Scanner error parah : {str(e)}")
            finalReport["results"]["Emails_From_Dorked_Paths"] = {"error": str(e)}

    # subdomain enumeration
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
                #
                # tmp = []
                #ganti elif jadi if
                #tmp.exted(statuscheckresult["adfsd"]
                #sub active = list(set(tmp))
        except Exception as e:
            log.error(f"Modul Subdomain_Status_Check error parah : {str(e)}")
            finalReport["results"]["Subdomain_Status_Check"] = {"error": str(e)}
    else:
        log.info(f"Tidak ada subdomain yang ditemukan")
        finalReport["results"]["Subdomain_Status_Check"] = {"message":"No Subdomain Found"}

    #nmap
    if subdomain_active:
        try:
            log.info(f"{len(subdomain_active)} subdomain aktif diterima modul nmap")
            module_nmap = NmapModule(domain,config,subdomain_active)
            nmap_result = module_nmap.run()
            finalReport['results']['Nmap'] = nmap_result
        except Exception as e:
            log.error(f"Modul Nmap error parah : {str(e)}")
            finalReport['results']['Nmap'] = {"error": str(e)}
    else:
        log.info(f"Tidak ada subdomain aktif yang diterima nmap")
        finalReport['results']['Nmap'] = {"message":"No Subdomain Found to scan with Nmap"}


    # waf detection
    if subdomain_active:
        try:
            log.info(f"{len(subdomain_active)} subdomain aktif diterima modul waf detection")
            module_waf = WafDetectionModule(domain,config,subdomain_active)
            waf_result = module_waf.run()
            finalReport['results']['WAF'] = waf_result
        except Exception as e:
            log.error(f"Modul WAF error parah : {str(e)}")
            finalReport['results']['WAF'] = {"error": str(e)}
    else:
        log.info(f"Tidak ada subdomain aktif yang diterima waf detection")
        finalReport['results']['WAF'] = {"message":"No Subdomain Found to scan with WAF"}

    #github check
    if github_repo:
        try:
            log.info(f"github check diterima")
            module_github = GithubCheckModule(domain,config, github_repo)
            github_result = module_github.run()
            finalReport['results']['Github'] = github_result
        except Exception as e:
            log.error(f"Modul Github Check error parah : {str(e)}")
            finalReport['results']['Github'] = {"error": str(e)}
    else:
        log.info(f"Tidak ada github repo yang ditemukan")
        finalReport['results']['Github'] = {"message":"No Github Repo Found"}

    finalReport["finish_time"] = str(datetime.now())
    savedPath = save_json_report(finalReport,outputDir)
    if savedPath:
        log.info(f"laporan JSON berhasil dibuat : {savedPath}")
        try:
            html_path = savedPath.replace('.json','.html')
            generate_html_final_report(savedPath,html_path)
            log.info(f"HTML report successfully : {html_path}")
        except Exception as e:
            log.error(f"Error generating HTML report : {str(e)}")

    log.info(f"scan selesai")


def main():

    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d","--domain", help="Target domain tunggal(contoh :bugcrowd.com)")
    group.add_argument("-l","--list", help="Daftar target domain dalam bentuk file")

    parser.add_argument("-g","--github", help="Github Repository Target", default=None)

    args= parser.parse_args()

    config = read_config()

    targets = []
    if args.domain:
        domain = args.domain.strip()
        repogithub = args.github.strip() if args.github else None
        if domain:
            targets.append((domain,repogithub))

    elif args.list:
        if os.path.exists(args.list):
            with open(args.list,'r') as file:
                for line in file:
                    line = line.strip()
                    if not line: #baris kosong di sekip
                        continue
                    if ',' in line: #domain mbk github repo d,g
                        part = line.split(',')
                        domain = part[0].strip()
                        repogithub = part[1].strip()
                        targets.append((domain,repogithub))
                    else: #isine cuman domain tok line e
                        targets.append((line,None))

        else:
            log.critical(f"File list domain tidak ditemukan : {args.list}")
            sys.exit(1)

    if not targets:
        log.critical(f"Tidak ada target valid yang ditemukan")
        sys.exit(1)

    log.info(f"total target : {len(targets)}")


    for domain, repogitub in targets:
        processTarget(domain,config, repogitub)

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




