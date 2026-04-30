from http.client import responses

import requests

from utils.logger import log


class EmailBreachModule:
    def __init__(self,emails,config):
        self.emails= emails
        self.config = config
        self.mode = self.config.get('settings',{}).get('execution_mode','default')

    def run(self):
        log.info(f"Running Module Breach Email dengan mode {self.mode} untuk {self.domain}")

        method = [
            ("xposedornot",self.method_xposedornot(self.emails)),
            ("leakcheck",self.method_leakcheck(self.emails))
        ]
        result = {}

        for tool,func in method:
            data = func()

            if data:
                result[tool] = data
                if self.mode =="default":
                    return result

        if not result:
            log.debug(f"semua metode breach check gagal")
        return None

    def method_xposedornot(self, emails):
        try:
            for email in emails:
                url = f"https://api.xposedornot.com/v1/check-email/{email}"
                responses = requests.get(url, timeout=10)
                if responses.status_code ==200:
                    data = responses.json()
                    breach = data.get('breaches',[])
                    if breach:
                        return breach
                    else:
                        return None

        except Exception as e:
            log.debug(f"xposedornot error {str(e)}")

        return None
    def method_leakcheck(self,emails):

        try:
            for email in emails:
                url = f"https://leakcheck.io/api/public?check={email}"
                responses = requests.get(url,timeout=10)
                if responses.status_code ==200:
                    data =responses.json()
                    if data.get("success") is True:
                        breach = data.get('sources',[])
                        return [src.get("name","unknown") for src in breach]
                    else:
                        log.debug(f"leakcheck error when parsing response")
        except Exception as e:
            log.debug(f"leakcheck error {str(e)}")
        return None