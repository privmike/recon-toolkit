import json
import os.path
import subprocess
import tempfile

from utils.logger import log


class WafDetectionModule:
    def __init__(self, domain, config,subdomains):
        self.domain = domain
        self.config = config
        self.mode = self.config.get('settings',{}).get('execution_mode','default')
        self.subdomains = subdomains

    def run(self):
        log.info(f"Running Module WAF Detection dengan mode {self.mode} untuk {self.domain}")

        if not self.subdomains:
            return {"error":f"Input subdomain cannot be empty"}

        host_list = []
        for item in self.subdomains:
            if isinstance(item, dict):
                hostname = item.get('url','')
                if hostname:
                    if not hostname.startswith('http://','https://'):
                        hostname = f'http://{hostname}'
                    host_list.append(hostname)
        if not host_list:
            return {"error":"No active Subdomain extracted from previous module to run WAF Detection"}

        tmp_input_file = ''
        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.txt') as input_file:
                input_file.write('\n'.join(host_list))
                tmp_input_file = input_file.name
        except Exception as e:
            log.error(f"Error creating temporary file: {str(e)}")
            return {"error":f"Error creating temporary file: {str(e)}"}

        method =[
            ("method_whatw00f",self.method_whatw00f),
            ("method_whatwaf", self.method_whatwaf)
        ]
        result = {}

        for tool,func in method:
            data = func()
            if data:
                isError= isinstance(data, dict) and 'error' in data
                if self.mode == 'default' and not isError:
                    return result
        if not result:
            log.debug(f"No WAF Found")
            return {"message":"No WAF Found"}

        return result


    def method_whatw00f(self, tmp_input_file):
        log.debug(f"Running Module WAF Detection dengan method whatw00f")

        result = {}

        temp_json_output_file = ''
        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as json_output_file:
                temp_json_output_file = json_output_file.name

            cmd = ['whatw00f', '-i', tmp_input_file, '-o', temp_json_output_file, '-f','json','-a','--no-colors']
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if process.returncode == 0:
                if os.path.exists(temp_json_output_file) and os.path.getsize(temp_json_output_file) >0:
                    with open(temp_json_output_file, 'r') as file:
                        data = json.load(file)
                    log.debug(f"Success parsing whatw00f json file output")
                    return data
                else:
                    log.debug(f"whatw00f json file output is empty")
                    return {"error":"whatw00f json file output is empty"}
            else:
                log.error(f"Error running whatw00f: {process.stderr}")
                return {"error":f"Error running whatw00f: {process.stderr}"}
        except subprocess.TimeoutExpired:
            log.error(f"whatw00f Timeout")
            return {"error":"whatw00f Timeout"}
        except Exception as e:
            log.error(f"Error running whatw00f: {str(e)}")
            return {"error":f"whatw00f error {str(e)}"}
        finally:
            if temp_json_output_file and os.path.exists(temp_json_output_file):
                os.remove(temp_json_output_file)


    def method_whatwaf(self, tmp_input_file):
        log.debug(f"Running Module WAF Detection dengan method whatwaf")

        tmp_dir = ''

        try:
            tmp_dir = tempfile.mkdtemp()

            cmd = ['whatwaf','-F','-J','-ra', '-t','5','--skip','-l',tmp_input_file,'-o',tmp_dir,'--force-file']
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if process.returncode ==0:
                json_output_files = [f for f in os.listdir(tmp_dir) if f.endswith('.json')] #nyari file json di dir output hopefully ga salah
                if json_output_files:
                    hit_files = os.path.join(tmp_dir,json_output_files[0])
                    with open(hit_files,'r') as file:
                        data= json.load(file)
                        log.debug(f"Success parsing whatwaf json file output")
                        return data
                else:
                    log.debug(f"whatwaf json file output is empty")
                    return {"error":"whatwaf json file output is empty"}
        except subprocess.TimeoutExpired:
            log.error(f"whatwaf Timeout")
            return {"error":"whatwaf Timeout"}
        except Exception as e:
            log.error(f"Error running whatwaf: {str(e)}")
            return {"error":f"whatwaf error {str(e)}"}
        finally:
            if tmp_dir and os.path.exists(tmp_dir):
                os.rmdir(tmp_dir)



