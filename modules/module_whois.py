import whois
from utils.logger import log
import requests
class WhoisModule:
    def __init__(self, domain, config):
        self.domain = domain
        self.config = config
        self.mode = self.config['settings'].get('execution_mode','default')

    def run(self):
        log.info(f"Running WHOIS dengan mode {self.mode} untuk {self.domain}")

        method = [
            ("python-whois", self.method_python_whois),
            ("WHOIS API", self.method_WHOIS_API)
        ]

        results = {}

        for tool, func in method:
            data = func()
            if data:
                results[tool] = data

                if self.mode == "default":
                    return results

        if not results:
            return {"error": "semua metode whois gagal"}
        return results

    def method_python_whois(self):
        try:
            whoisData = whois.whois(self.domain)
            if whoisData:
                return dict(whoisData)
        except Exception as e:
            log.debug(f"python-library gagal : {str(e)}")
        return None

    def method_WHOIS_API(self):

        apiKey = self.config['api_keys'].get('apilayer_whois')
        if not apiKey:
            log.debug(f"api key whois tidak ditemukan")
            return None
        try:
            headers = {"apikey": apiKey}
            url = f"https://api.apilayer.com/whois/query?domain={self.domain}"
            response = requests.get(url,headers=headers, timeout=10)

            if response.status_code ==200:
                return response.json()
            else:
                log.debug(f"API whois error {response.status_code}  - {response.text}")

        except Exception as e:
            log.debug(f"API WHOIS error : {str(e)}")
        return  None

