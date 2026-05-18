import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from xml.sax.handler import version

from utils.logger import log




class NmapModule:
    def __init__(self, domain, config, subdomain):
        self.domain = domain
        self.config = config
        self.mode = self.config.get('settings',{}).get('execution_mode','default')
        self.subdomain = subdomain

    def run(self):
        log.info(f"Running Module Nmap dengan mode {self.mode} untuk {self.domain}")
        if not self.subdomain:
            return {"error":f"Input subdomain cannot be empty"}


        method = [
            ("method_nmap", self.method_nmap)
        ]

        results = {}
        for tool, func in method:
            data = func()
            if data:
                results[tool] = data
                isError = isinstance(data, dict) and 'error' in data
                if self.mode == 'default' and not isError:
                    return results

        if not results:
            log.error(f"No Nmap result found")
            return {"message": "No Nmap result found"}

        return results

    def method_nmap(self):
        log.debug(f"Running Module Nmap dengan method nmap")

        tmp_input_file =""
        tmp_xml_file = ""
        host_list = set()

        for item in self.subdomain:
            hostname = item.get('url','')
            if hostname:
                host_list.add(hostname) #harus hati2 karena ini berati url subdomain yg msuk harus sudah bersih dari protocol http/https


        if not host_list:
            return {"error":"No active Subdomain extracted from previous module"}

        try:
            with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".txt") as file_input:
                file_input.write("\n".join(host_list))
                tmp_input_file = file_input.name

            with tempfile.NamedTemporaryFile(mode="w+",delete=False, suffix=".xml") as file_xml:
                tmp_xml_file = file_xml.name

            cmd = ["nmap", "-sV","-Pn", "-O","--script","vulners","-F","-iL",tmp_input_file,"-oX",tmp_xml_file]

            process = subprocess.run(cmd, capture_output=True, text=True, timeout=6000)

            if process.returncode == 0:
                log.info(f"Nmap scan completed successfully")
                return self.parse_nmap_xml(tmp_xml_file)
            else:
                log.error(f"Error running nmap: {process.stderr}")
                return {"error":f"Error running nmap: {process.stderr}"}

        except subprocess.TimeoutExpired:
            log.error(f"Nmap Timeout")
            return {"error":"Nmap Timeout"}
        except Exception as e:
            log.error(f"Error running nmap: {str(e)}")
            return {"error":f"nmap error {str(e)}"}
        finally:
            if tmp_input_file and os.path.exists(tmp_input_file):
                os.remove(tmp_input_file)
            if tmp_xml_file and os.path.exists(tmp_xml_file):
                os.remove(tmp_xml_file)

    def parse_nmap_xml(self, file_xml):
        log.debug(f"Parsing Nmap XML file")
        results = []
        try:
            if not os.path.exists(file_xml) or os.path.getsize(file_xml) == 0:
                log.error(f"Nmap XML file is empty or does not exist")
                return results

            tree = ET.parse(file_xml)
            root = tree.getroot()

            for host in root.findall('host'):
                status = host.find('status')
                if status is None or status.get('state') != 'up':
                    continue

                host_data= {
                    "ip": "",
                    "hostname":"",
                    "os":"Unknown",
                    "open_ports":[]
                }
                # parse ip
                for address in host.findall('address'):
                    if address.get('addrtype') == 'ipv4':
                        host_data['ip'] = address.get('addr')

                #parse hostnam
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    hostname = hostnames.find('hostname')
                    if hostname is not None:
                        host_data['hostname'] = hostname.get('name')

                #parse os detect
                os_detect = host.find('os')
                if os_detect is not None:
                    os_match = os_detect.find('osmatch')
                    if os_match is not None:
                        host_data['os'] = os_match.get('name')

                #parse port dkk
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        state = port.find('state')
                        if state is None or state.get('state') != 'open':
                            continue

                        port_data = {
                            "port": port.get('portid'),
                            "protocol" : port.get('protocol'),
                            "service" : "Unknown",
                            "version" : "Unknown",
                            "cve" :[]
                        }

                        #parse service bs
                        service = port.find('service')
                        if service is not None:
                            port_data['service'] = service.get('name','Name Unknown')
                            product = service.get('product','Product Unknown')
                            version = service.get('version','Version Unknown')
                            extrainfo = service.get('extrainfo','Extrainfo Unknown')
                            full_version = f"{product} {version} {extrainfo}".strip()
                            if full_version:
                                port_data['version'] = full_version

                        #parse cve
                        vulnerability = [] #isine cve2 yang ad
                        curr_cve = None

                        for script in port.findall('script'):
                            if script.get('id') == 'vulners':
                                output_raw = script.get('output','')
                                for line in output_raw.split('\n'):
                                    line = line.strip()
                                    if not line or line.endswith(':'):
                                        continue
                                    splited_line= line.split('\t')

                                    if len(splited_line) >=3:
                                        vuln_id = splited_line[0].strip()
                                        cvss_str = splited_line[1].strip()
                                        cvss_score = float(cvss_str) if cvss_str else 0.0
                                        url = splited_line[2].strip()
                                        isExploit = False
                                        if len(splited_line) >=4 and '*EXPLOIT*' in splited_line[3]:
                                            isExploit = True

                                        vulnerability.append({
                                            'id':vuln_id,
                                            'cvss':cvss_score,
                                            'url':url,
                                            'type': 'Exploit' if isExploit else 'Vulnerability/CVE'
                                        })

                                        # if not isExploit:
                                        #     curr_cve = {
                                        #         'id': vuln_id,
                                        #         'cvss': cvss_score,
                                        #         'url': url,
                                        #         'exploits': []
                                        #     }
                                        #     vulnerability.append(curr_cve)
                                        # else:
                                        #     exploit_data = {
                                        #         'id': vuln_id,
                                        #         'url': url
                                        #     }
                                        #     if curr_cve is not None:
                                        #         curr_cve['exploits'].append(exploit_data)
                                        #     else: #siap2 edge case aneh klo bug exploit tanpa parent cve
                                        #         curr_cve= {
                                        #             'id':f'Unknown CVE Parent - {vuln_id}',
                                        #             'cvss': cvss_score,
                                        #             'url':url,
                                        #             'exploits': [exploit_data]
                                        #         }
                                        #         vulnerability.append(curr_cve)



                        port_data['cve'] = vulnerability
                        host_data['open_ports'].append(port_data)

                results.append(host_data)
        except Exception as e:
            log.error(f"Error parsing Nmap XML: {str(e)}")
            return {"error":f"Error parsing Nmap XML: {str(e)}"}
        return results






