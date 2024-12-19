# logging_setup.py

import logging

def setup_logging(log_file: str = 'ztna_system.log'):
    """Setup centralized logging for the entire system."""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # Create a file handler to log to a file
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)
    
    # Create a logging format
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    
    # Add the handlers to the logger
    logger.addHandler(file_handler)

    logging.info("Logging has been set up.")
