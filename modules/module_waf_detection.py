import json
import os.path
import shutil
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
                    if not hostname.startswith(('http://','https://')):
                        hostname = f'http://{hostname}'
                    host_list.append(hostname)
                    log.debug(f"Adding {hostname} to host list")
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
            ("method_wafw00f",self.method_wafw00f),
            ("method_whatwaf", self.method_whatwaf)
        ]
        result = {}
        try:
            for tool,func in method:
                data = func(tmp_input_file)
                if data:
                    result[tool] = data
                    isError= isinstance(data, dict) and 'error' in data
                    if self.mode == 'default' and not isError:
                        return result
        finally:
            if tmp_input_file and os.path.exists(tmp_input_file):
                os.remove(tmp_input_file)

        if not result:
            log.debug(f"No WAF Found")
            return {"message":"No WAF Found"}

        return result



    def method_wafw00f(self, tmp_input_file):
        log.debug(f"Running Module WAF Detection dengan method wafw00f")

        result = {}

        temp_json_output_file = ''
        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as json_output_file:
                temp_json_output_file = json_output_file.name

            cmd = ['wafw00f', '-i', tmp_input_file, '-o', temp_json_output_file, '-f','json','-a','--no-colors']
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if process.returncode == 0:
                if os.path.exists(temp_json_output_file) and os.path.getsize(temp_json_output_file) >0:
                    with open(temp_json_output_file, 'r') as file:
                        data = json.load(file)
                    log.debug(f"Success parsing wafw00f json file output")
                    return data
                else:
                    log.debug(f"wafw00f json file output is empty")
                    return {"error":"wafw00f json file output is empty"}
            else:
                log.error(f"Error running wafw00f: {process.stderr}")
                return {"error":f"Error running wafw00f: {process.stderr}"}
        except subprocess.TimeoutExpired:
            log.error(f"wafw00f Timeout")
            return {"error":"wafw00f Timeout"}
        except Exception as e:
            log.error(f"Error running wafw00f: {str(e)}")
            return {"error":f"wafw00f error {str(e)}"}
        finally:
            if temp_json_output_file and os.path.exists(temp_json_output_file):
                os.remove(temp_json_output_file)


    def method_whatwaf(self, tmp_input_file):
        log.debug(f"Running Module WAF Detection dengan method whatwaf")

        tmp_dir = ''

        try:

            whatwaf_global_cache = os.path.expanduser('~/.whatwaf/json_output')
            try: #bersihkan cache hasil scan lama tool ini
                if os.path.exists(whatwaf_global_cache):
                    for filename in os.listdir(whatwaf_global_cache):
                        filepath = os.path.join(whatwaf_global_cache, filename)
                        try:
                            if os.path.isfile(filepath) or os.path.islink(filepath):
                                os.unlink(filepath)
                            elif os.path.isdir(filepath):
                                shutil.rmtree(filepath)
                        except Exception as e:
                            log.error(f"Failed to delete file {filepath}: {str(e)}")
            except Exception as e:
                log.error(f"Error deleting whatwaf global cache: {str(e)}")
                return {"error":f"Error deleting whatwaf global cache: {str(e)}"}

            tmp_dir = tempfile.mkdtemp()

            cmd = ['whatwaf','-F','-J','--ra', '-t','5','--skip','-l',tmp_input_file,'-o',tmp_dir,'--force-file']
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if process.returncode ==0:
                json_output_files = [f for f in os.listdir(whatwaf_global_cache) if f.endswith('.json')] #nyari file json di dir output hopefully ga salah
                if json_output_files:
                    combined_data = []
                    decoder = json.JSONDecoder()
                    for f in json_output_files:
                        hit_files = os.path.join(whatwaf_global_cache,f)
                        log.debug(f"parsing {hit_files}")
                        try:
                            if os.path.exists(hit_files) and os.path.getsize(hit_files) <=0 :
                                continue
                            with open(hit_files,'r') as file:
                                data= file.read()
                            position=0
                            while position <len(data):

                                if data[position].isspace():
                                    position+=1 #handling 1 line kosong diakhir file output tool whatwaf biar ga error posisinya
                                    continue

                                obj, index = decoder.raw_decode(data,position)
                                position = index
                                combined_data.append(obj)

                        except Exception as e:
                            log.error(f"Error parsing {hit_files}: {str(e)}")
                            return {"error":f"Error parsing {hit_files}: {str(e)}"} #ganti pakai continue kalauy mau handle partial failure dengan cara bisa lanjut ke file berikutnya dan gak berhenti di file yg gagal
                    if not combined_data:
                        return {"error":"failed to combine json data from whatwaf output"}
                    log.debug(f"found {len(combined_data)} json file output from whatwaf")
                    return combined_data
                else:
                    log.debug(f"whatwaf json file output is empty")
                    return {"error":"whatwaf json file output is empty"}
            else:
                log.error(f"Error running whatwaf: {process.stderr}")
                return {"error":f"Error running whatwaf: {process.stderr}"}
        except subprocess.TimeoutExpired:
            log.error(f"whatwaf Timeout")
            return {"error":"whatwaf Timeout"}
        except Exception as e:
            log.error(f"Error running whatwaf: {str(e)}")
            return {"error":f"whatwaf error {str(e)}"}
        finally:
            if tmp_dir and os.path.exists(tmp_dir):
                shutil.rmtree(tmp_dir)



