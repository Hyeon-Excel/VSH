from __future__ import annotations

import argparse

from vsh_runtime.watcher import ProjectWatcher


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", required=True)
    parser.add_argument("--debounce", type=float, default=1.0)
    args = parser.parse_args()
    watcher = ProjectWatcher(args.path, debounce_sec=args.debounce)
    watcher.watch_forever()


if __name__ == "__main__":
    main()
