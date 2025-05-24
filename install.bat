@echo off
REM Installation script for Python Logging Agent
REM This script installs dependencies and sets up the agent

echo Python Logging Agent Installation
echo ===================================

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from https://python.org
    pause
    exit /b 1
)

echo Python found. Checking version...
python -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"
if errorlevel 1 (
    echo Error: Python 3.8 or higher is required
    pause
    exit /b 1
)

echo Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo Error: Failed to install dependencies
    pause
    exit /b 1
)

echo Creating logs directory...
if not exist "logs" mkdir logs

echo Testing configuration...
python main.py validate-config
if errorlevel 1 (
    echo Warning: Configuration validation failed
    echo Please check config/default_config.yaml
)

echo.
echo Installation completed successfully!
echo.
echo Next steps:
echo 1. Review and customize config/default_config.yaml
echo 2. Test the agent: python main.py test
echo 3. Run in console mode: python main.py console
echo 4. Install as service: python main.py service install
echo.
pause
