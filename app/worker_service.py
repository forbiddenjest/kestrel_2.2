"""Standalone process entry point for background jobs and metrics."""
import asyncio
import logging
import sys
from app.config import production_problems, settings
from app.worker import worker_loop

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s [%(name)s] %(message)s")
    problems = production_problems(settings)
    if problems:
        sys.exit("Refusing to start: " + "; ".join(problems))
    asyncio.run(worker_loop())
