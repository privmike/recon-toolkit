import logging
import os.path
import sys


def setup_logger(name="ReconToolkit"):


    if not os.path.exists('logs'):
        os.makedirs('logs')

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    #memastikan handeler gk duplocate saat restart module
    if logger.hasHandlers():
        logger.handlers.clear()

    file_format = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [%(module)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    console_format = logging.Formatter(
        '[%(levelname)s] %(message)s'
    )

    file_handler = logging.FileHandler('logs/recon_execution.log')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_format)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_format)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger

log = setup_logger()