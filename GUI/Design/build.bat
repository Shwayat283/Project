@echo off
pip install playwright
playwright install chromium
pyinstaller --name RocScanner ^
            --icon=image.png ^
            --add-data "image.png;." ^
            --add-data "scanners;scanners" ^
            --hidden-import playwright.sync_api ^
            --hidden-import playwright._impl._api_types ^
            --hidden-import playwright._impl._browser ^
            --hidden-import playwright._impl._browser_context ^
            --hidden-import playwright._impl._browser_type ^
            --hidden-import playwright._impl._connection ^
            --hidden-import playwright._impl._event_context_manager ^
            --hidden-import playwright._impl._frame ^
            --hidden-import playwright._impl._input ^
            --hidden-import playwright._impl._js_handle ^
            --hidden-import playwright._impl._page ^
            --hidden-import playwright._impl._playwright ^
            --hidden-import playwright._impl._transport ^
            --collect-all playwright ^
            --noconsole ^
            --onefile ^
            GUI.py
pause 