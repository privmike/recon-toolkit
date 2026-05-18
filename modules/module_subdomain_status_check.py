import os
import subprocess
import tempfile

from utils.logger import log



class SubdomainStatusCheckModule:
    def __init__(self, domain, config,subdomain):
        self.domain = domain
        self.config = config
        self.mode = self.config.get('settings',{}).get('execution_mode','default')
        self.subdomain = subdomain

    def run(self):
        log.info(f"Running Module Subdomain Status Check dengan mode {self.mode} untuk {self.domain}")
        if not self.subdomain:
            return {"error":f"Input subdomain cannot be empty"}

        method = [
            ("method_httpx_toolkit", self.method_httpx_toolkit),
            ("method_httprobe", self.method_httprobe)
        ]

        results = {}
        for tool, func in method:
            data = func()
            if data:
                results[tool] = data
                isError= isinstance(data,dict) and "error" in data
                if self.mode == "default" and not isError:
                    return results
        if not results:
            log.debug(f"No Subdomain Status Found")
            return {"message":"No Subdomain Status Found"}
        return results

    def method_httpx_toolkit(self):
        log.debug(f"Running Module Subdomain Status Check dengan method http-toolkit")

        subdomain_online = []
        temp_file_input = ""

        try:
            with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".txt") as temp_file: #ini digunakan supaya proses pembuatan dan pembukaan file sekaligus handle proses penutupannya sehingga clean
                temp_file.write("\n".join(self.subdomain))
                temp_file_input = temp_file.name
            cmd = ["httpx-toolkit","-silent","-no-color","-tech-detect","-l",temp_file_input]

            process = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if process.returncode ==0:
                if process.stdout:
                    for line in process.stdout.splitlines():
                        clear_text = line.strip()
                        if clear_text:
                            split = clear_text.split(" [")
                            url = split[0]
                            tech = []
                            if len(split)>1:
                                tech_string = split[1].replace("]","")
                                tech = [tech.strip() for tech in tech_string.split(",")]
                            split_protocol = url.split("//")
                            clear_url = split_protocol[1]
                            subdomain_online.append({"url":clear_url,"technologies":tech})
                return subdomain_online
            else:
                log.error(f"Error running http-toolkit: {process.stderr}")
                return {"error":f"Error running http-toolkit: {process.stderr}"}
        except subprocess.TimeoutExpired:
            log.error(f"http-toolkit Timeout")
            return {"error":"http-toolkit Timeout"}
        except Exception as e:
            log.error(f"Error running http-toolkit: {str(e)}")
            return {"error":f"http-toolkit error {str(e)}"}

        finally:
            if os.path.exists(temp_file_input) and temp_file_input:
                os.remove(temp_file_input)


    def method_httprobe(self):
        log.debug(f"Running Module Subdomain Status Check dengan method httprobe")

        subdomain_online = []
        temp_file_input = ""
        cmd = ["httprobe"]
        tmp_sub = set()
        try:
            with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".txt") as temp_file:
                temp_file.write("\n".join(self.subdomain))
                temp_file_input = temp_file.name
            with open(temp_file_input,'r') as file:
                process = subprocess.run(cmd, stdin=file, capture_output=True, text=True, timeout=180)
                if process.returncode ==0:
                    if process.stdout:
                        for line in process.stdout.splitlines():
                            clear_text = line.strip()
                            if clear_text:
                                split = clear_text.split("//")
                                subdomains = split[1]
                                if subdomains not in tmp_sub:
                                    tmp_sub.add(subdomains)
                                    subdomain_online.append({"url":subdomains, "technologies":[]})

                    else:
                        return {"error":"No Subdomain Found"}

                    return subdomain_online
                else:
                    log.error(f"Error running httprobe: {process.stderr}")
                    return {"error":f"Error running httprobe: {process.stderr}"}
        except subprocess.TimeoutExpired:
            log.error(f"httprobe Timeout")
            return {"error":"httprobe Timeout"}
        except Exception as e:
            log.error(f"Error running httprobe: {str(e)}")
            return {"error":f"httprobe error {str(e)}"}

        finally:
            if os.path.exists(temp_file_input) and temp_file_input:
                os.remove(temp_file_input)