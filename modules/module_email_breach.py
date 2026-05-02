from http.client import responses

import requests

from utils.logger import log


class EmailBreachModule:
    def __init__(self,emails,config):
        self.emails= emails
        self.config = config
        self.mode = self.config.get('settings',{}).get('execution_mode','default')

    def run(self):
        log.info(f"Running Module Breach Email dengan mode {self.mode}")

        if not self.emails:
            return {"status" : "safe", "message" :"No targeted email"}
        method = [
            ("xposedornot",self.method_xposedornot),
            ("leakcheck",self.method_leakcheck)
        ]
        result = {}

        for tool,func in method:
            data = func(self.emails)

            if data:
                result[tool] = data
                if self.mode =="default":
                    return result

        if not result:
            log.debug(f"No Breached Email Found")
            return {"status":"safe", "message":"No Breached Email Found"}
        return None

    def method_xposedornot(self, emails):
        result = {}
        for email in emails:
            try:
                url = f"https://api.xposedornot.com/v1/check-email/{email}"
                responses = requests.get(url, timeout=10)
                if responses.status_code == 200:
                    data = responses.json()
                    breach = data.get('breaches', [])
                    if breach:
                        result[email] = breach
            except Exception as e:
                log.error(f"xposedornot error {str(e)}")
        return result if result else None



    def method_leakcheck(self,emails):
        result={}
        for email in emails:
            try:
                url = f"https://leakcheck.io/api/public?check={email}"
                responses = requests.get(url, timeout=10)
                if responses.status_code == 200:
                    data = responses.json()
                    if data.get("success") is True:
                        breach = data.get('sources', [])
                        if breach:
                            result[email] = [src.get("name", "unknown") for src in breach]
                    else:
                        log.error(f"leakcheck error when parsing response")
            except Exception as e:
                log.error(f"leakcheck error {str(e)}")
        return result if result else None

