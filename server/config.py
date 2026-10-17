import logging
from pathlib import Path

PORT_INFO = Path(__file__).resolve().parent / "port.info"
DEFAULT_PORT = 1369
MIN_PORT = 1
MAX_PORT = 65535
PORT_INFO_LIMIT = 16

logger = logging.getLogger(__name__)


def _parse_port(path):
    with open(path, "rb") as f:
        data = f.read(PORT_INFO_LIMIT + 1)
    if len(data) > PORT_INFO_LIMIT:
        raise ValueError("file is too big")

    value = data.decode("ascii").strip()
    if not value.isdigit():
        raise ValueError(f"'{value}' is not a number")

    port = int(value)
    if port < MIN_PORT or port > MAX_PORT:
        raise ValueError(f"{port} is not a valid port")
    return port


def read_port(path=PORT_INFO):
    try:
        return _parse_port(path)
    except UnicodeDecodeError:
        reason = "non ascii content"
    except ValueError as e:
        reason = str(e)
    except OSError as e:
        reason = e.strerror

    logger.warning("port.info: %s, falling back to %d", reason, DEFAULT_PORT)
    return DEFAULT_PORT
