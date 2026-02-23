import json
import os.path
from utils.logger import log
from datetime import datetime
import yaml

def create_output_dir(domain):
    path = os.path.join("outputs",domain)
    if not os.path.exists(path):
        os.makedirs(path)
        log.debug(f"folder output {domain} berhasil dibuat {path}")
    return path

def save_json_report(data, folderPath,):
    timestamp = datetime.now().strftime("%y%m%d_%H%M%S")

    domain = data.get('target','unknown')
    filename = f"report_{domain}.json"
    fullPath = os.path.join(folderPath, filename)

    try:
        with open(fullPath,'w') as file:
            json.dump(data,file, indent=4, default=str)
        log.info(f"Laporan tersimpan di {fullPath}")
        return fullPath
    except Exception as e:
        log.error(f"gagal menyimpan laporan json di {fullPath} dengan error : {str(e)}")
        return None

def read_config(path="config/config.yaml"):
    if not os.path.exists(path):
        log.critical(f"File config tidak ditemukan di {path}")
        exit(1)

    with open(path, 'r') as file :
        return yaml.safe_load(file)