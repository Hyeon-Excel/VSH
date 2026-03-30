import os
import sys
import time
import asyncio
import threading

from dotenv import load_dotenv

load_dotenv()

from mcp_server_unified import validate_code, l3_pipeline

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH_DIR = os.path.abspath(os.path.dirname(__file__))
WATCH_TARGET = os.path.abspath(os.path.join(WATCH_DIR, "vuln_sample.py"))


def _run_l3(file_path: str) -> None:
    asyncio.run(l3_pipeline.run(WATCH_DIR))


class VSHFileHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return
        src = os.path.abspath(event.src_path)
        if src != WATCH_TARGET:
            return

        print(f"\n[VSH Watcher] 변경 감지: {src}")

        # 1. L1/L2 동기 실행
        validate_code(src)

        # 2. L3 별도 스레드에서 asyncio.run()으로 실행
        t = threading.Thread(target=_run_l3, args=(src,), daemon=True)
        t.start()


def main():
    print(f"[VSH Watcher] 감시 시작: {WATCH_TARGET}")
    print("[VSH Watcher] Ctrl+C로 종료\n")

    handler = VSHFileHandler()
    observer = Observer()
    observer.schedule(handler, path=WATCH_DIR, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[VSH Watcher] 종료 중...")
        observer.stop()

    observer.join()
    print("[VSH Watcher] 종료 완료")


if __name__ == "__main__":
    main()
