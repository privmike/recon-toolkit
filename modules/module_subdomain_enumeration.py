

from logging import log

class SubdomainEnumerationModule:
    def __init__(self, domain, config):
        self.domain = domain
        self.config = config
        self.mode = self.config.get('settings',{}).get('execution_mode','default')

    def run(self):
        log.info(f"Running Module Subdomain Enumeration dengan mode {self.mode} untuk {self.domain}")

        method = [

        ]

        all_subdomains = set() #buat memastikan kalo subdomainnya tidak ada yg doble
        tool_counter = 0
        # tool_count = 2
        for tool,func in method:
            log.info(f"Running {tool} for subdomain enumeration")
            data = func()
            if data:
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
        return {
            "total_subdomains": len(sort_subdomains),
            "subdomains": sort_subdomains
        }






