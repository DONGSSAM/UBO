@echo off
if not exist "venv\Scripts\python.exe" (
    echo Creating virtual environment...
    python -m venv venv
) else (
    echo Virtual environment already exists.
)