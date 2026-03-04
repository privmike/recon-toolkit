import socket

import requests

from utils.logger import log

class IPModule:
    def __init__(self, domain,config):
        self.domain = domain
        self.config = config
        self.mode = self.config.get('settings',{}).get('execution_mode','default')
        self.timeout = 5
    def run(self):
        log.info(f"Running IP dengan mode {self.mode} untuk {self.domain}")

        method = [
            ("IP-API", self.method_ip_api),
            ("freeipapi", self.method_freeipapi)
        ]
        results ={}

        for tool, func in method:
            data = func()
            if data:
                results[tool] = data
                if self.mode =="default":
                    return results

        if not results:
            log.debug(f"semua metode ip gagal")
        return None

    def method_ip_api(self):
        try:
            url = f"http://ip-api.com/json/{self.domain}?fields=status,message,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,isp,org,as,query"
            response = requests.get(url, timeout=self.timeout)
            if response.status_code ==200:
                data = response.json()
                if data.get("status") == "success":
                    return data
            else:
                log.debug(f"error di modul ip, metode ipapi, ada masalah dengan request: {response.status_code}  - {response.text}")
            return None
        except Exception as e :
            log.debug(f"error di modul ip , metode ip-api: {str(e)}")
            return None

    def method_freeipapi(self):
        try:
            try:
                ip = socket.gethostbyname(self.domain)
            except Exception as e:
                log.debug(f"error di modul ip, metode backup bagian resolver hostname to ip : {str(e)}")
                return None
            url = f"https://free.freeipapi.com/api/json/{ip}"
            response = requests.get(url, timeout=self.timeout)

            if response.status_code == 200:
                data= response.json()
                return data
            else:
                log.debug(f"error di modul ip, metode backup, ada masalah dengan request : {response.status_code}  - {response.text}")
            return None
        except Exception as e :
            log.debug(f"error di modul ip, metode backup {str(e)}")
            return None