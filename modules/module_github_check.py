import json
import subprocess
from typing import Text

from utils.logger import log



class GithubCheckModule:
    def __init__(self, domain, config, github_repo):
        self.domain = domain
        self.config = config
        self.mode = self.config.get('settings',{}).get('execution_mode','default')
        self.github_repo = github_repo

    def run(self):
        log.info(f"Running Module Github Check dengan mode {self.mode} untuk {self.domain}")

        results={}

        if not self.github_repo:
            return {"error":"Input github repo cannot be empty"}

        method = [
            ("method_trufflehog",self.methid_trufflehog),
            ("method_gitleaks",self.method_gitleaks)
        ]

        for tool,func in method:
            data = func()
            if data:
                results[tool] = data
                isError = isinstance(data, dict) and 'error' in data
                if self.mode == 'default' and not isError:
                    return results

        if not results:
            log.debug(f"No Github Check Found")
            return {"message":"No Github Check Found"}


        return results


    def methid_trufflehog(self):
        log.debug(f"Running Module Github Check dengan method trufflehog")

        cmd = ['trufflehog', 'github','--result=verified','repo',self.github_repo,'-j','--no-color']

        try:
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if process.returncode == 0:
                findings = []
                raw_output = process.stdout

                if not raw_output:
                    log.debug(f"Trufflehog output is Empty")
                    return []

                lines = raw_output.splitlines()

                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if "SourceMetadata" in data or "DetectorName" in data:
                            findings.append(data)
                    except json.JSONDecodeError:
                        log.debug(f"failed to parse json output from trufflehog")
                        return {"error":"failed to parse json output from trufflehog"}
                log.debug(f"Trufflehog output: {len(findings)} findings")
                return findings
        except subprocess.TimeoutExpired:
            log.error(f"Trufflehog Timeout")
            return {"error":"Trufflehog Timeout"}
        except Exception as e:
            log.error(f"Error running trufflehog: {str(e)}")
            return {"error":f"trufflehog error {str(e)}"}


    def method_gitleaks(self):
        log.debug(f"Running Module Github Check dengan method gitleaks")


