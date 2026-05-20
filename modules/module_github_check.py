import json
import os.path
import subprocess
import tempfile


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
            ("trufflehog",self.methid_trufflehog),
            ("gitleaks",self.method_gitleaks)
        ]

        for tool,func in method:
            data = func()
            if data:
                results[tool] = data
                isError = isinstance(data, dict) and 'error' in data
                if self.mode == 'default' and not isError:
                    return results

        if not results:
            log.debug(f"No exposed secret found")
            return {"message":"No exposed secret found"}


        return results


    def methid_trufflehog(self):
        log.debug(f"Running Module Github Check dengan method trufflehog")

        cmd = ['trufflehog', 'github','--results=verified','--repo',self.github_repo,'-j','--no-color']

        try:
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if process.returncode == 0:
                findings = []
                raw_output = process.stdout

                if not raw_output:
                    log.debug(f"Trufflehog output is Empty")
                    return {'message': 'trufferhog output is Empty'}

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
                if not findings:
                    log.debug(f"Trufflehog finding is Empty")
                    return {'message': 'No exposed secret found'}
                return findings
        except subprocess.TimeoutExpired:
            log.error(f"Trufflehog Timeout")
            return {"error":"Trufflehog Timeout"}
        except Exception as e:
            log.error(f"Error running trufflehog: {str(e)}")
            return {"error":f"trufflehog error {str(e)}"}


    def method_gitleaks(self):
        log.debug(f"Running Module Github Check dengan method gitleaks")

        with tempfile.TemporaryDirectory() as temp_repo_dir:
            github_clone_cmd = ['git','clone', self.github_repo, temp_repo_dir]

            try:
                log.debug(f"running git clone")
                gitclone_process = subprocess.run(github_clone_cmd, capture_output=True, text=True, timeout=600)
                if gitclone_process.returncode != 0:
                    log.error(f"Error cloning github repository stderr: {gitclone_process.stderr}")
                    return {"error":f"Error cloning github repository: {gitclone_process.stderr}"}
            except subprocess.TimeoutExpired:
                log.error(f"Github Clone Timeout")
                return {"error":"Github Clone Timeout"}
            except Exception as e:
                log.error(f"Error cloning github repository: {str(e)}")
                return {"error":f"Error cloning github repository: {str(e)}"}

            temp_gitleaks_output_file = tempfile.NamedTemporaryFile(suffix='.json', delete=False)

            temp_gitleaks_output_file_path = temp_gitleaks_output_file.name #ngambil asbsoute path dari file tmp

            temp_gitleaks_output_file.close()

            gitleaks_cmd = ['gitleaks','dir',temp_repo_dir, '--report-path', temp_gitleaks_output_file_path,'--report-format','json']

            try:
                log.debug(f"running gitleaks")
                gitleaks_process = subprocess.run(gitleaks_cmd, capture_output=True, text=True, timeout=6000)
                if gitleaks_process.returncode  not in [0,1]: #1 berati ketemu , 0 berati tidak ada
                    if not os.path.exists(temp_gitleaks_output_file_path) or os.path.getsize(temp_gitleaks_output_file_path) <=0:
                        log.debug(f"gitleaks output is Empty")
                        return {'message': 'gitleaks output is Empty'}
                    with open(temp_gitleaks_output_file_path, 'r') as file:
                        findings = json.load(file)
                    log.debug(f"gitleaks output: {len(findings)} findings")

                    if not findings:
                        log.debug(f"gitleaks finding is Empty")
                        return {'message': 'No exposed secret found'}
                    return findings

            except subprocess.TimeoutExpired:
                log.error(f"Gitleaks Timeout")
                return {"error":"Gitleaks Timeout"}
            except json.JSONDecodeError:
                log.error(f"failed to parse json output from gitleaks")
                return {"error":"failed to parse json output from gitleaks"}
            except Exception as e:
                log.error(f"Error running gitleaks: {str(e)}")
                return {"error":f"Error running gitleaks: {str(e)}"}
            finally:
                if os.path.exists(temp_gitleaks_output_file_path):
                    os.remove(temp_gitleaks_output_file_path)




