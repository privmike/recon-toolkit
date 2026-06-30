from urllib.parse import urlparse
from utils.logger import log

from modules.module_find_email import FindEmailModule


class module_extended_find_email:
    def __init__(self, domain, config, dorks_result):
        self.domain = domain
        self.config = config
        self.dorks_result = dorks_result
        self.ignored_extensions = ('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.zip', '.rar',',xml','.json')

    def run(self):
        log.info("Running Modul: Dork Email Scanner (Menjalankan FindEmailModule per URL)")

        raw_urls = self._extract_and_filter_urls()
        if not raw_urls:
            log.info("Tidak ada URL halaman web valid dari Google Dorking untuk diproses.")
            return {"message": "No valid web URLs found from dorking"}

        log.info(f"Ditemukan {len(raw_urls)} URL web. Memulai eksekusi FindEmailModule...")

        final_results = {}
        for url in raw_urls:
            try:
                parsed_url = urlparse(url)
                cleaned_url = parsed_url.netloc + parsed_url.path

                if cleaned_url.endswith('/'):
                    cleaned_url = cleaned_url[:-1]

                log.info(f"[-] Menjalankan tools (theHarvester, dll) untuk sub-URL: {cleaned_url}")

                scanner = FindEmailModule(cleaned_url, self.config)
                url_scan_result = scanner.run()

                if url_scan_result and "error" not in url_scan_result:
                    final_results[url] = url_scan_result

            except Exception as e:
                log.error(f"Gagal menjalankan FindEmailModule untuk URL {url}: {str(e)}")
                continue

        return final_results if final_results else {"message": "No email found via tools for these specific URLs"}

    def _extract_and_filter_urls(self):
        extracted_urls = []
        for tool, categories in self.dorks_result.items():
            if isinstance(categories, dict):
                for category, url_list in categories.items():
                    if isinstance(url_list, list):
                        for url in url_list:
                            if not url.lower().endswith(self.ignored_extensions):
                                extracted_urls.append(url)
        return list(set(extracted_urls))