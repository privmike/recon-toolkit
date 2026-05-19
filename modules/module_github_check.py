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
            (),
            ()
        ]

        for tool,func in method:
            data = func(self.github_repo)
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




    def method_gitleaks(self):
        log.debug(f"Running Module Github Check dengan method gitleaks")


