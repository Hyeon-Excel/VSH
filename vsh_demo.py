# -*- coding: utf-8 -*-
import os
import sys
import time
import asyncio
import threading

from dotenv import load_dotenv

load_dotenv()

from mcp_server_unified import (
    validate_code,
    l3_pipeline,
    report_generator,
)

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH_DIR = os.path.abspath(os.path.dirname(__file__))
WATCH_TARGET = os.path.abspath(os.path.join(WATCH_DIR, "vuln_sample.py"))
_SCAN_DONE = False
_SCAN_DONE = False

BANNER = """
╔══════════════════════════════════════╗
║   VSH - Vibe Coding Secure Helper   ║
║   실시간 취약점 탐지 시스템 시연    ║
╚══════════════════════════════════════╝
"""


def _run_l3(file_path: str) -> None:
    global _SCAN_DONE

    async def _inner():
        await l3_pipeline.run(WATCH_DIR)
        print("[L3] 리포트 생성 중...")
        try:
            report_path = await report_generator.generate()
            print(f"[L3] 리포트 생성 완료: {report_path}")
            print()
            print("=" * 54)
            print("✅  VSH 스캔 완료")
            print("=" * 54)
            print()
        except Exception as e:
            print(f"[L3] 리포트 생성 실패: {e}")

    asyncio.run(_inner())
    _SCAN_DONE = True


class VSHFileHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return
        src = os.path.abspath(event.src_path)
        if src != WATCH_TARGET:
            return

        print(f"\n[VSH Demo] 변경 감지: {src}")

        # 1. L1/L2 동기 실행
        validate_code(src)

        # 2. L3 별도 스레드에서 asyncio.run()으로 실행
        t = threading.Thread(target=_run_l3, args=(src,), daemon=True)
        t.start()


def _auto_trigger() -> None:
    time.sleep(3)
    print(f"[VSH Demo] 자동 트리거: {WATCH_TARGET} touch")
    os.utime(WATCH_TARGET, None)


def main():
    print(BANNER)
    print(f"[VSH Demo] 감시 대상: {WATCH_TARGET}")
    print("[VSH Demo] 3초 후 자동 분석이 시작됩니다...\n")

    handler = VSHFileHandler()
    observer = Observer()
    observer.schedule(handler, path=WATCH_DIR, recursive=False)
    observer.start()

    trigger = threading.Thread(target=_auto_trigger, daemon=True)
    trigger.start()

    try:
        while not _SCAN_DONE:
            time.sleep(1)
        print("\n[VSH Demo] 종료 중...")
        observer.stop()
    except KeyboardInterrupt:
        print("\n[VSH Demo] 종료 중...")
        observer.stop()

    observer.join()
    print("[VSH Demo] 종료 완료")


if __name__ == "__main__":
    main()
