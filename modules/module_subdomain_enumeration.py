import subprocess
from utils.logger import log

class SubdomainEnumerationModule:
    def __init__(self, domain, config):
        self.domain = domain
        self.config = config
        self.mode = self.config.get('settings',{}).get('execution_mode','default')

    def run(self):
        log.info(f"Running Module Subdomain Enumeration dengan mode {self.mode} untuk {self.domain}")

        method = [
            ("method_subfinder",self.method_subfinder),
            ("method_amass",self.method_amass)
        ]

        all_subdomains = set() #buat memastikan kalo subdomainnya tidak ada yg doble
        tool_counter = 0
        # tool_count = 2
        error_msg ={}
        for tool,func in method:
            log.info(f"Running {tool} for subdomain enumeration")
            data = func()
            isError = isinstance(data,dict) and "error" in data
            if isError:
                log.error(f"Error running {tool}: {data.get('error')}")
                error_msg[tool] = data.get('error')
            elif data:
                all_subdomains.update(data)
                tool_counter += 1
                log.info(f"Found {len(data)} subdomains using {tool}")
            else:
                log.error(f"No subdomains found using {tool}")
        if not all_subdomains:
            if tool_counter > 0:
                return {"message":f"No subdomains found by {tool_counter} method"}
            else:
                return {"error":"No result, All method failed"}

        sort_subdomains = sorted(list(all_subdomains))
        log.info(f"Found {len(sort_subdomains)} subdomains")
        results= {
            "total_subdomains": len(sort_subdomains),
            "subdomains": sort_subdomains
        }
        if error_msg:
            results["error"] = error_msg
        return results



    def method_amass(self):
        log.info(f"Running Module Subdomain Enumeration dengan method amass")
        subdomain = set()
        cmd_enum = ["amass", "enum","-active","-d",self.domain,"--nocolor","-timeout","10","-brute"]
        cmd_sub = ["amass","subs","-names","-d",self.domain,"-nocolor"]
        try:
            process = subprocess.run(cmd_enum, capture_output=True, text=True, timeout=1200)
            if process.returncode == 0:
                process_sub = subprocess.run(cmd_sub, capture_output=True, text=True, timeout=60)
                if process_sub.returncode == 0:
                    for line in process_sub.stdout.splitlines():
                        clear_text = line.strip()
                        if clear_text:
                            subdomain.add(clear_text)
                else:
                    log.error(f"Error running amass internal database query: {process_sub.stderr}")
                    return {"error":f"Error running amass internal database query: {process_sub.stderr}"}
            else:
                log.error(f"Error running amass: {process.stderr}")
                return {"error":f"Error running amass: {process.stderr}"}
            return subdomain
        except subprocess.TimeoutExpired:
            log.error(f"Amass Timeout")
            return {"error":"Amass Timeout"}

        except Exception as e:
            log.error(f"Error running amass: {str(e)}")
            return {"error":f"amass error {str(e)}"}



    def method_subfinder(self):
        log.info(f"Running Module Subdomain Enumeration dengan method subfinder")
        subdomain = set()
        cmd = ["subfinder","-d",self.domain, "-silent", "-no-color", "-active"]
        try:
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if process.returncode == 0:
                for line in process.stdout.splitlines():
                    clear_text = line.strip()
                    if clear_text: #and clear_text.endwith(self.domain)
                        subdomain.add(clear_text)
            else:
                log.error(f"Error running subfinder: {process.stderr}")
                return {"error":f"Error running subfinder: {process.stderr}"}
        except subprocess.TimeoutExpired:
            log.error(f"Subfinder Timeout")
            return {"error":"Subfinder Timeout"}
        except Exception as e:
            log.error(f"Error running subfinder: {str(e)}")
            return {"error":f"subfinder error {str(e)}"}
        return subdomain







