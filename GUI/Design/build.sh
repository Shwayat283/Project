#!/bin/bash

set -e

echo "Installing dependencies..."
pip install --upgrade pip
pip install playwright pillow pyinstaller

echo "Installing Playwright browsers..."
playwright install chromium

echo "Building executable with PyInstaller..."

/bin/pyinstaller --name RocScanner \
    --icon=image.png \
    --add-data "image.png:." \
    --add-data "scanners:scanners" \
    --hidden-import playwright.sync_api \
    --hidden-import playwright._impl._api_types \
    --hidden-import playwright._impl._browser \
    --hidden-import playwright._impl._browser_context \
    --hidden-import playwright._impl._browser_type \
    --hidden-import playwright._impl._connection \
    --hidden-import playwright._impl._event_context_manager \
    --hidden-import playwright._impl._frame \
    --hidden-import playwright._impl._input \
    --hidden-import playwright._impl._js_handle \
    --hidden-import playwright._impl._page \
    --hidden-import playwright._impl._playwright \
    --hidden-import playwright._impl._transport \
    --hidden-import PIL._tkinter_finder \
    --collect-all playwright \
    --noconsole \
    --onefile \
    GUI.py

echo "Build complete. Press Enter to continue..."
read
