from __future__ import annotations

from aiohttp import web

from .app import create_app
from .config import AppConfig


def main() -> None:
    config = AppConfig.from_env()
    app = create_app(config=config)
    web.run_app(app, host=config.host, port=config.port)


if __name__ == "__main__":
    main()
