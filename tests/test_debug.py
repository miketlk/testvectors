import os
import json
import time

TEST_DEBUG = bool(int(os.environ.get("TEST_DEBUG", default="0")))

def debug_print(*args, **kwargs):
    if TEST_DEBUG:
        print(*args, **kwargs)

def _debug_timestamp_file(file_path: str) -> str:
    dir, file = os.path.split(file_path)
    return os.path.join(dir, str(time.time()).replace('.', '') + "_" + file)

def debug_dump(file_path: str, data, timestamp=False):
    if TEST_DEBUG:
        adjusted_path = \
            _debug_timestamp_file(file_path) if timestamp else file_path
        with open(adjusted_path, "w") as f:
            f.write(str(data))

def debug_dump_json(file_path: str, data: dict, timestamp=False):
    if TEST_DEBUG:
        adjusted_path = \
            _debug_timestamp_file(file_path) if timestamp else file_path
        with open(adjusted_path, "w") as f:
            json.dump(data, f, indent=4)
