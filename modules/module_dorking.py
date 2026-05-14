import os
import random
import subprocess
import time

from ddgs import DDGS

from utils.logger import log


class DorkingModule:
    def __init__(self, domain, config):
        self.domain = domain
        self.config = config
        self.mode = self.config.get('settings', {}).get('execution_mode', 'default')
        self.dorks = self.load_dorks_from_file("dorks_list.txt")
    def load_dorks_from_file(self, filename):
        dorks = {}
        try:
            with open(filename, 'r') as file:
                for line in file:
                    if not line.strip() or line.startswith('#'):
                        continue
                    if "|" in line:
                        category, query = line.strip().split("|", 1)
                        dorks[category.strip()] = f"site:{self.domain} {query.strip()}"
        except Exception as e:
            log.error(f"Failed to process dorks file: {str(e)}")
        return dorks

    def run(self):
        log.info(f"Running Module Google Dorking dengan mode {self.mode} untuk {self.domain}")

        method = [
            ("xnldorker",self.method_xnldorker),
            ("manual_search",self.method_manual_search)
        ]

        results = {}

        for tool,func in method:
            data = func()
            if data:
                results[tool] = data
                isError= isinstance(data,dict) and "error" in data
                if self.mode == "default" and not isError:
                    return results

        if not results:
            log.warning(f"No entry found in dorking by all method")
            return {"error":"No interesting search found"}
        return results

    def method_xnldorker(self):
        result ={}
        for category, query in self.dorks.items():
            queryString = query.replace("OR", "| ")
            tmpFile = f"tmp_xnldorker_{category}.txt"
            cmd = ["xnldorker" , "-i",queryString, "-es","google,yandex","-o",tmpFile ,"-ow"]
            try:
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
                if process.returncode != 0:
                    log.error(f"Error running xnldorker: {process.stderr}")
                    return { "error":f"Error running xnldorker: {process.stderr}"}
                if os.path.exists(tmpFile):
                    with open(tmpFile, 'r') as file:
                        lines = [line.strip() for line in file.readlines() if line.strip()]
                        if lines:
                            result[category] = lines

            except subprocess.TimeoutExpired:
                log.error(f"Xnldorker Timeout")
                return {"error":"Xnldorker Timeout"}

            except Exception as e:
                log.error(f"Error running xnldorker: {str(e)}")
                return {"error":f"xnldorker error {str(e)}"}
            finally:
                if os.path.exists(tmpFile):
                    os.remove(tmpFile) #hati hati klo gak ada permission bisa crash disini

        return result if result else {"message":"No interesting search found"}

    def method_manual_search(self):
        result = {}


        for category, query in self.dorks.items():
            try:
                url = []
                with DDGS() as ddgs:
                    try:
                        searchResults = ddgs.text(query, max_results=10)
                        for r in searchResults:
                            if 'href' in r:
                                url.append(r['href'])
                        if url:
                            result[category] = url
                        time.sleep(random.randint(1,2)) #mencoba membuat delay yang asymetris untuk mencoba menghindari bot detection
                    except Exception as esearch:
                        log.error(f"Error running search engine: {str(esearch)}")
                        continue
            except Exception as e:
                log.error(f"Error running manual search: {str(e)}")
                return {"error":f"manual search google dork error {str(e)}"}

        # if not result and isError:
        #     return None
        # if not result and not isError:
        #     return {"message":"No interesting search found"}

        return result if result else {"message":"No interesting search found"}



