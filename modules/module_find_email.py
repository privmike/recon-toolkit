import re
import shutil
import subprocess

from utils.logger import log

class FindEmailModule:
    def __init__(self, domain, config):
        self.domain= domain
        self.config = config
        self.mode = self.config.get('settings',{}).get('execution_mode','default')
        self.email_regex = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

    def run(self):
        log.info(f"Running Module Find Email dengan mode {self.mode} untuk {self.domain}")

        method = [
            ("theharvester" , self.method_theharvester),
            ("emailharvester",self.method_emailharvester)
        ]

        result = {}
        for tool,func in method:
            checkTool = "theHarvester" if "theharvester" in tool.lower() else "emailharvester"
            if not shutil.which(checkTool) and not shutil.which(tool.lower()):
                log.warning(f"Tool {tool} Not Found.")
                continue

            log.info(f"Running tool {tool}")
            data = func()

            if data:
                result[tool] = data
                if self.mode == "default":
                    return result

        if not result:
            log.warning(f"Semua metode gagal untuk modul find email")
            return {"error":"Semua metode find email gagal"}

        return result


    def extract_email(self,input):
        emailr = re.findall(self.email_regex,input)
        emails = list(set([e.lower() for e in emailr]))
        return emails

    def method_theharvester(self):
        try:
            cmd = ["theHarvester", "-d", self.domain, "-b", "all"]

            process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if process.returncode == 0 or process.stdout:
                return self.extract_email(process.stdout)

            else:
                log.debug(f"theHarvester error {process.stderr}")

        except subprocess.TimeoutExpired:
            log.debug(f"theHarvester Timeout")
        except Exception as e:
            log.debug(f"theHarvester error {str(e)}")

        return None

    def method_emailharvester(self):
        try:
            cmd = ["emailharvester", "-d", self.domain, "-e", "all", "-r","ask"]

            process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if process.returncode == 0 or process.stdout:
                return self.extract_email(process.stdout)

            else:
                log.debug(f"emailharvester error {process.stderr}")
        except subprocess.TimeoutExpired:
            log.debug(f"emailharvester timeout")
        except Exception as e:
            log.debug(f"emailharvester error {str(e)}")
        return None



