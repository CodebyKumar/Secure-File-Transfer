# app/core/logging.py
import logging
import sys
import json


class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "level": record.levelname,
            "time": self.formatTime(record, self.datefmt),
            "message": record.getMessage(),
            "name": record.name,
        }
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_record)


# Create logger
logger = logging.getLogger("secure_file_transfer")
logger.setLevel(logging.INFO)

# Console handler
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
ch.setFormatter(JsonFormatter())

logger.addHandler(ch)

# Usage:
# from app.core.logging import logger
# logger.info("Application started")
