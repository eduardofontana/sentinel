import time
import logging
from fnmatch import fnmatch
from collections import defaultdict
from pathlib import Path
from typing import Callable, Optional, Dict, Any, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent

logger = logging.getLogger("SentinelFW.Watcher")


class RuleFileHandler(FileSystemEventHandler):
    def __init__(self, callback, debounce_seconds: float = 1.0):
        super().__init__()
        self.callback = callback
        self.debounce_seconds = debounce_seconds
        self.last_modified: Dict[str, float] = {}
        self.watched_files: Set[str] = set()
        self.directory_patterns: Dict[str, Set[str]] = defaultdict(set)

    def add_file_watch(self, file_path: str) -> None:
        file = Path(file_path).resolve()
        self.watched_files.add(str(file))
        self.directory_patterns[str(file.parent)].add(file.name)

    def add_directory_watch(self, directory: str, pattern: str) -> None:
        dir_path = Path(directory).resolve()
        self.directory_patterns[str(dir_path)].add(pattern)

    def on_modified(self, event):
        if event.is_directory:
            return

        if not isinstance(event, FileModifiedEvent):
            return

        file_path = event.src_path

        if not self._should_watch(file_path):
            return

        now = time.time()
        last_time = self.last_modified.get(file_path, 0)

        if now - last_time < self.debounce_seconds:
            return

        self.last_modified[file_path] = now
        logger.info(f"Rule file modified: {file_path}")
        self.callback(file_path)

    def _should_watch(self, file_path: str) -> bool:
        file = Path(file_path).resolve()
        ext = file.suffix.lower()
        if ext not in ['.yaml', '.yml', '.rules']:
            return False

        directory = str(file.parent)

        patterns = self.directory_patterns.get(directory)
        if patterns:
            return any(fnmatch(file.name, pattern) for pattern in patterns)

        return str(file) in self.watched_files


class RuleWatcher:
    def __init__(self, debounce_seconds: float = 1.0):
        self.observer = Observer()
        self.handler = RuleFileHandler(self._on_rule_changed, debounce_seconds)
        self.callbacks = []
        self._running = False

    def _on_rule_changed(self, file_path: str) -> None:
        for callback in self.callbacks:
            try:
                callback(file_path)
            except Exception as e:
                logger.error(f"Error in rule change callback: {e}")

    def watch_file(self, file_path: str) -> None:
        path = Path(file_path)
        if not path.exists():
            logger.warning(f"File does not exist: {file_path}")
            return

        directory = str(path.parent)
        self.handler.add_file_watch(str(path))
        self.observer.schedule(self.handler, directory, recursive=False)
        logger.info(f"Watching: {file_path}")

    def watch_directory(self, directory: str, pattern: str = "*.yaml") -> None:
        dir_path = Path(directory)
        if not dir_path.exists():
            logger.warning(f"Directory does not exist: {directory}")
            return

        self.handler.add_directory_watch(directory, pattern)
        self.observer.schedule(self.handler, directory, recursive=False)
        logger.info(f"Watching directory: {directory} for {pattern}")

    def register_callback(self, callback: Callable[[str], None]) -> None:
        self.callbacks.append(callback)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self.observer.start()
        logger.info("Rule watcher started")

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        self.observer.stop()
        self.observer.join()
        logger.info("Rule watcher stopped")

    def is_running(self) -> bool:
        return self._running
