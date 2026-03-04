


class FindEmailModule:
    def __init__(self, domain, config):
        self.domain= domain
        self.config = config
        self.mode = self.config.get('settings',{}).get('execution_mode','default')

