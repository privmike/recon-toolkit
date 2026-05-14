import time


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
                isError= isinstance(data,dict) and "error" in data
                if self.mode =="default" and not isError:
                    return result

        if not result:
            log.debug(f"No Breached Email Found")
            return {"status":"safe", "message":"No Breached Email Found"}
        return result

    def method_xposedornot(self, emails):
        log.debug(f"Running Module Breach Email dengan method xposedornot")
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
                elif responses.status_code == 404:
                    None
                else:
                    log.error(f"xposedornot error http status code {responses.status_code}")
                    return {"error":f"xposedornot error http status code {responses.status_code}"}
            except Exception as e:
                log.error(f"xposedornot error {str(e)}")
                return {"error":f"xposedornot error {str(e)}"}
        return result if result else {"message":"No Breached Email Found"}



    def method_leakcheck(self,emails):
        log.debug(f"Running Module Breach Email dengan method leakcheck")
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
                    elif data.get("error") == "Not found":
                            None
                    else:
                        log.error(f"leakcheck error when parsing response")
                        return {"error":f"leakcheck error when parsing response"}
                else:
                    log.error(f"leakcheck error http status code {responses.status_code}")
                    return {"error":f"leakcheck error http status code {responses.status_code}"}
                time.sleep(0.75) #rate limiting
            except Exception as e:
                log.error(f"leakcheck error {str(e)}")
                return {"error":f"leakcheck error {str(e)}"}
        return result if result else {"message":"No Breached Email Found"}

