@echo off
echo Cleaning previous builds...
rmdir /S /Q build dist
del /F /Q *.spec

echo Installing required packages...
pip install playwright
pip install pyinstaller

echo Installing Playwright browsers...
playwright install chromium

echo Creating browser directory...
mkdir browsers
xcopy /E /I /Y %USERPROFILE%\AppData\Local\ms-playwright browsers\ms-playwright

echo Building executable...
pyinstaller --clean ^
            --name RocScanner ^
            --icon=image.png ^
            --add-data "image.png;." ^
            --add-data "scanners;scanners" ^
            --add-data "browsers\ms-playwright;playwright\driver\package\.local-browsers" ^
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
            --log-level DEBUG ^
            GUI.py

echo Cleaning up temporary files...
rmdir /S /Q browsers
rmdir /S /Q build
del /F /Q *.spec

echo Build complete! Executable can be found in the 'dist' folder.
echo.
echo If you encounter any issues, please check the 'build.log' file.
pause 