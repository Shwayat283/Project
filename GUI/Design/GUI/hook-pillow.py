# hook-pillow.py
from PyInstaller.utils.hooks import collect_data_files

# Include Pillow's Tkinter compatibility files
datas = collect_data_files('PIL')
