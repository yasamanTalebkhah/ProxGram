#!/usr/bin/env python3
"""Verify the bot can resolve the destination chat before posting.

Runs getChat against TELEGRAM_BOT_TOKEN / TELEGRAM_CHANNEL_ID and prints a
one-line verdict. Exit codes: 0 = chat resolved, 1 = verification failed.
Used as a fail-fast step in the workflow (and handy as a manual diagnostic).
"""

import sys

from main import TELEGRAM_BOT_TOKEN, TELEGRAM_CHANNEL_ID, get_chat_info


def main() -> int:
    print(f"Checking destination chat for target: {TELEGRAM_CHANNEL_ID}...")
    info = get_chat_info(TELEGRAM_BOT_TOKEN, TELEGRAM_CHANNEL_ID)
    if info:
        print(f'SUCCESS: Connected to {info.get("title")} '
              f'(@{info.get("username")}) [ID: {info.get("id")}]')
        return 0
    print("WARNING: Destination chat verification failed or blocked by network.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
