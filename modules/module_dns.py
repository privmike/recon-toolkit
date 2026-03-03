
import dns.resolver
from utils.logger import log



class DnsModule:
    def __init__(self,domain, config):
        self.domain= domain
        self.result = {}
        self.config = config
        self.mode = self.config['settings'].get('execution_mode','default')

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
            answers = dns.resolver.resolve(self.domain,recordType)
            result =[]
            for r in answers:
                result.append(r.to_text())
            return result
        except dns.resolver.NXDOMAIN:
            return None #domain tidak ditemukan
        except dns.resolver.NoAnswer:
            return None #tidak ditemukan record tipe ini
        except Exception as e:
            log.debug(f"dns-python error di record {recordType}, dengan error : {str(e)} ")
            return None

    def method_dns_cloudflare:
