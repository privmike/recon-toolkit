
import dns.resolver
import requests

from utils.logger import log



class DnsModule:
    def __init__(self,domain, config):
        self.domain= domain
        self.config = config
        self.mode = self.config.get('settings',{}).get('execution_mode','default')
        self.timeout = 5

    def run(self):
        log.info(f"Running Module DNS dengan mode {self.mode} untuk {self.domain}")
        recordTypes = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]
        method = [
            ("dns-python", self.method_dns_python),
            ("cloudflare-dns", self.method_dns_cloudflare)
        ]
        result ={}

        for tool, func in method:
            toolResult ={}
            for record in recordTypes:
                data = func(record)
                if data:
                    toolResult[record] = data

            if toolResult:
                result[tool] = toolResult
                if self.mode =="default":
                    return result

        if not result :
            return {"error": "semua metode modul dns gagal"}
        return result

    def method_dns_python(self, recordType):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            answers = resolver.resolve(self.domain,recordType)
            result =[]
            for r in answers:
                result.append(r.to_text())
            return result
        except dns.resolver.NXDOMAIN :
            log.debug(f"dns-python error di record {recordType}, dengan error : domain tidak ditemukan ")
            return None #domain tidak ditemukan
        except dns.resolver.NoAnswer:
            log.debug(f"dns-python error di record {recordType}, dengan error : record domain tidak ditemukan ")
            return None #tidak ditemukan record tipe ini
        except Exception as e:
            log.debug(f"dns-python error di record {recordType}, dengan error : {str(e)} ")
            return None

    def method_dns_cloudflare(self, recordType):

        try:
            url = "https://cloudflare-dns.com/dns-query"
            params = {
                "name": self.domain,
                "type": recordType
            }
            header = {"Accept": "application/dns-json"}

            timeout = 5
            response = requests.get(url,params=params, headers=header,timeout=timeout)

            if response.status_code ==200:
                data = response.json()
                result =[]
                if "Answer" in data:
                    for a in data["Answer"]:
                        result.append(a["data"])
                    return result
            else :
                log.debug(f"error di modul dns, metode backup bagian request : {response.status_code}  - {response.text}")
        except Exception as e:
            log.debug(f"modul dns cloudflare error L {str(e)}")
            return None




