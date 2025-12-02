#!/bin/bash
#-------------------------------------------------------------------------------------------------------
# Setup Virtual Environment for at_acs_card_reader
# This script creates a Python virtual environment and installs required dependencies
#-------------------------------------------------------------------------------------------------------

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="$(basename "${SCRIPT_DIR}")"
VENV_DIR="${SCRIPT_DIR}/${PROJECT_NAME}_venv"

echo "=================================================="
echo "Setting up Python virtual environment for ${PROJECT_NAME}"
echo "=================================================="
echo "Script directory: ${SCRIPT_DIR}"
echo "Virtual environment: ${VENV_DIR}"
echo ""

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is not installed or not in PATH"
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo "Using: ${PYTHON_VERSION}"
echo ""

# Remove old virtual environment if it exists
if [ -d "${VENV_DIR}" ]; then
    echo "Removing existing virtual environment..."
    rm -rf "${VENV_DIR}"
    echo "Done."
    echo ""
fi

# Create new virtual environment
echo "Creating virtual environment..."
python3 -m venv "${VENV_DIR}"

if [ $? -ne 0 ]; then
    echo "Error: Failed to create virtual environment"
    exit 1
fi
echo "Virtual environment created successfully."
echo ""

# Activate virtual environment
echo "Activating virtual environment..."
source "${VENV_DIR}/bin/activate"

if [ $? -ne 0 ]; then
    echo "Error: Failed to activate virtual environment"
    exit 1
fi
echo "Virtual environment activated."
echo ""

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

if [ $? -ne 0 ]; then
    echo "Warning: Failed to upgrade pip, continuing anyway..."
fi
echo ""

# Install required packages
echo "Installing required packages..."
echo "-----------------------------------"

# Check if requirements.txt exists
REQUIREMENTS_FILE="${SCRIPT_DIR}/requirements.txt"
if [ -f "${REQUIREMENTS_FILE}" ]; then
    echo "Installing from requirements.txt..."
    pip install -r "${REQUIREMENTS_FILE}"
    
    if [ $? -ne 0 ]; then
        echo "Error: Failed to install required packages from requirements.txt"
        exit 1
    fi
else
    echo "Warning: requirements.txt not found at ${REQUIREMENTS_FILE}"
    echo "Skipping package installation."
fi

echo ""
echo "-----------------------------------"
echo "Installed packages:"
echo "-----------------------------------"
pip list
echo ""

# Create log directory if it doesn't exist
LOG_DIR="${SCRIPT_DIR}/log"
if [ ! -d "${LOG_DIR}" ]; then
    echo "Creating log directory..."
    mkdir -p "${LOG_DIR}"
    echo "Log directory created: ${LOG_DIR}"
    echo ""
fi

# Deactivate virtual environment
deactivate

echo "=================================================="
echo "Setup completed successfully!"
echo "=================================================="
echo ""
echo "To activate the virtual environment, run:"
echo "  source ${VENV_DIR}/bin/activate"
echo ""
echo "To run the card reader:"
echo "  source ${VENV_DIR}/bin/activate"
echo "  python serial_card_reader.py"
echo ""
