@echo off
TITLE JDGS Homeshield Roofing - ROOFSYS-TRI Launcher
echo ===============================================
echo     Starting JDGS Homeshield Roofing System
echo ===============================================
echo.

REM Check if virtual environment exists
IF NOT EXIST ".venv\Scripts\activate" (
    echo ERROR: Virtual environment not found.
    echo Please run:  python -m venv .venv
    echo.
    pause
    exit /b
)

echo Activating virtual environment...
call .venv\Scripts\activate

echo.
echo Checking for required Python packages...
python -c "import uvicorn" >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Missing dependencies! Installing...
    pip install -r requirements.txt
)

echo.
echo Launching server at http://127.0.0.1:8000 ...
echo Press CTRL+C to stop the server.
echo.

uvicorn main:app --reload --port 8000

echo.
echo Server stopped.
pause