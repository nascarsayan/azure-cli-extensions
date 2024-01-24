# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

# This module is wrapper around az cli command execution
# az_cli and az_cli_with_retries are two functions which
# can be used to execute az commands.

from operator import le
import subprocess, logging
from functools import total_ordering
from typing import Union, Tuple
from azure.cli.core import get_default_cli
from azure.cli.core import telemetry

# https://github.com/Azure/iotedgedev/blob/4e51ecdcddd4bdd565312dc72401701a202b4e3f/iotedgedev/azurecli.py#L48
class AzCli:
    def __init__(self, logger: logging.Logger, logfile: Union[str, None]=None) -> None:
        self.logfile = logfile
        self.logger = logger
        self.default_cli = get_default_cli()

    def run(self, *args, capture_output = True) -> Tuple[str, int]:
        stdout_data = b''
        f = None
        return_code = 1
        try:
            cmd = ['az'] + list(args)
            self.logger.debug("Running az command: %s", list(args))
            if not capture_output:
                return_code = self.default_cli.invoke(args)
            else:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                if process.stderr is not None:
                    for line in process.stderr:
                        if self.logfile is not None:
                            with open(self.logfile, 'ab') as f:
                                f.write(line)
                if process.stdout is not None:
                    for line in process.stdout:
                        if self.logfile is not None:
                            with open(self.logfile, 'ab') as f:
                                f.write(line)
                        stdout_data += line
                return_code = process.wait()
        except Exception as e:
            if self.logfile is not None:
                with open(self.logfile, 'ab') as f:
                    f.write(str(e).encode('utf-8'))
            self.logger.error("Error running az command: %s", str(e))
            return "", return_code
        res = bytes_to_string(stdout_data)
        return res, return_code

def bytes_to_string(b: bytes) -> str:
    return b.decode('UTF-8', errors='strict')


@total_ordering
class SemanticVersion:
    def __init__(self, version_string):
        self.version_string = version_string
        self.version = [int(v) for v in version_string.split('.')]

    def __repr__(self):
        return f"SemanticVersion('{self.version_string}')"

    def __eq__(self, other):
        if not isinstance(other, SemanticVersion):
            return NotImplemented
        return self.version == other.version

    def __lt__(self, other):
        if not isinstance(other, SemanticVersion):
            return NotImplemented
        return self.version < other.version


class TelemetryLogger(logging.Logger):
    def __init__(self, name, logfile):
        super().__init__(name)
        fh = logging.FileHandler(logfile)
        fh.setFormatter(
            logging.Formatter(
                fmt='%(asctime)s %(levelname)-8s %(name)-12s.%(lineno)-5d %(message)s',
                datefmt='%Y-%m-%dT%H:%M:%S',
            ))
        fh.setLevel(logging.DEBUG)
        self.addHandler(fh)
        sh = logging.StreamHandler()
        sh.setFormatter(
            ColoredFormatter('%(asctime)s %(levelname)-8s %(message)s')
        )
        sh.setLevel(logging.INFO)
        self.addHandler(sh)

    def _push_telemetry(self, level: int, msg: str):
        telemetry.set_exception(
            'AzureArcVMwareOnboarding'+ logging.getLevelName(level),
            fault_type='user', summary=_norm(msg))
                

    def debug(self, msg, *args, **kwargs):
        super().debug(msg, *args, **kwargs)
        self._push_telemetry(logging.DEBUG, msg)
    
    def info(self, msg, *args, **kwargs):
        super().info(msg, *args, **kwargs)
        self._push_telemetry(logging.INFO, msg)

    def warning(self, msg, *args, **kwargs):
        super().warning(msg, *args, **kwargs)
        self._push_telemetry(logging.WARNING, msg)

    def error(self, msg, *args, **kwargs):
        super().error(msg, *args, **kwargs)
        self._push_telemetry(logging.ERROR, msg)

    def critical(self, msg, *args, **kwargs):
        super().critical(msg, *args, **kwargs)
        self._push_telemetry(logging.CRITICAL, msg)


class ColoredFormatter(logging.Formatter):
    default_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
    def __init__(self, format: str=default_format):
        grey = "\x1b[38;20m"
        yellow = "\x1b[33;20m"
        red = "\x1b[31;20m"
        bold_red = "\x1b[31;1m"
        reset = "\x1b[0m"
        self.FORMATS = {
            logging.DEBUG: grey + format + reset,
            logging.INFO: grey + format + reset,
            logging.WARNING: yellow + format + reset,
            logging.ERROR: red + format + reset,
            logging.CRITICAL: bold_red + format + reset
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(fmt=log_fmt, datefmt='%Y-%m-%dT%H:%M:%S')
        return formatter.format(record)

def _remove_cmd_chars(s):
    if isinstance(s, str):
        return s.replace("'", '_').replace('"', '_').replace('\r\n', ' ').replace('\n', ' ')
    return s


def _remove_symbols(s):
    if isinstance(s, str):
        for c in '$%^&|':
            s = s.replace(c, '_')
    return s

def _norm(s):
    return _remove_symbols(_remove_cmd_chars(s))
