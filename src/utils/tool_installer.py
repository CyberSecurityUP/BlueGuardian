"""Automatic tool installation system.

This module provides automatic installation of security analysis tools
required by various agents and analyzers.
"""

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger


class ToolInstaller:
    """Automatic tool installer for security analysis tools.

    This class handles installation of various tools required by the framework
    including Volatility, YARA, pefile, and others.
    """

    # Tool definitions with installation methods
    TOOLS = {
        'volatility3': {
            'check_command': ['vol', '-h'],
            'install_method': 'pip',
            'package': 'volatility3',
            'description': 'Memory forensics framework',
        },
        'yara': {
            'check_command': ['yara', '--version'],
            'install_method': 'system',
            'package': {
                'ubuntu': 'yara',
                'debian': 'yara',
                'centos': 'yara',
                'macos': 'yara',
            },
            'pip_fallback': 'yara-python',
            'description': 'Pattern matching engine',
        },
        'radare2': {
            'check_command': ['r2', '-v'],
            'install_method': 'system',
            'package': {
                'ubuntu': 'radare2',
                'debian': 'radare2',
                'macos': 'radare2',
            },
            'description': 'Reverse engineering framework',
        },
        'pefile': {
            'check_command': None,  # Python module
            'install_method': 'pip',
            'package': 'pefile',
            'description': 'PE file parser',
        },
        'oletools': {
            'check_command': None,
            'install_method': 'pip',
            'package': 'oletools',
            'description': 'Office document analyzer',
        },
        'jsbeautifier': {
            'check_command': None,
            'install_method': 'pip',
            'package': 'jsbeautifier',
            'description': 'JavaScript beautifier',
        },
    }

    def __init__(self, auto_install: bool = False):
        """Initialize tool installer.

        Args:
            auto_install: Automatically install missing tools without prompting
        """
        self.auto_install = auto_install
        self.os_type = platform.system().lower()
        self.installed_tools: Dict[str, bool] = {}

        logger.info(f"Initialized ToolInstaller (OS: {self.os_type})")

    def check_tool(self, tool_name: str) -> bool:
        """Check if a tool is installed.

        Args:
            tool_name: Name of the tool

        Returns:
            True if tool is installed
        """
        if tool_name not in self.TOOLS:
            logger.warning(f"Unknown tool: {tool_name}")
            return False

        tool_def = self.TOOLS[tool_name]

        # Check if it's a Python module
        if tool_def['check_command'] is None:
            try:
                __import__(tool_name.replace('-', '_'))
                logger.debug(f"Tool {tool_name} (Python module) is installed")
                return True
            except ImportError:
                logger.debug(f"Tool {tool_name} (Python module) is NOT installed")
                return False

        # Check if it's a system command
        try:
            result = subprocess.run(
                tool_def['check_command'],
                capture_output=True,
                timeout=5,
            )
            installed = result.returncode == 0
            if installed:
                logger.debug(f"Tool {tool_name} is installed")
            else:
                logger.debug(f"Tool {tool_name} is NOT installed")
            return installed
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.debug(f"Tool {tool_name} is NOT installed")
            return False

    def install_tool(self, tool_name: str) -> bool:
        """Install a tool.

        Args:
            tool_name: Name of the tool to install

        Returns:
            True if installation succeeded
        """
        if tool_name not in self.TOOLS:
            logger.error(f"Unknown tool: {tool_name}")
            return False

        tool_def = self.TOOLS[tool_name]
        logger.info(f"Installing {tool_name}: {tool_def['description']}")

        try:
            if tool_def['install_method'] == 'pip':
                return self._install_pip_package(tool_def['package'])
            elif tool_def['install_method'] == 'system':
                return self._install_system_package(tool_def)
            else:
                logger.error(f"Unknown install method: {tool_def['install_method']}")
                return False

        except Exception as e:
            logger.error(f"Failed to install {tool_name}: {e}", exc_info=True)
            return False

    def _install_pip_package(self, package_name: str) -> bool:
        """Install a Python package via pip.

        Args:
            package_name: Name of the package

        Returns:
            True if successful
        """
        logger.info(f"Installing pip package: {package_name}")

        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", package_name],
                check=True,
                capture_output=True,
            )
            logger.info(f"Successfully installed {package_name}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install {package_name}: {e.stderr.decode()}")
            return False

    def _install_system_package(self, tool_def: Dict) -> bool:
        """Install a system package.

        Args:
            tool_def: Tool definition dictionary

        Returns:
            True if successful
        """
        # Get package name for current OS
        package_info = tool_def['package']
        if isinstance(package_info, dict):
            package_name = package_info.get(self._get_distro())
            if not package_name:
                logger.warning(f"No package defined for {self.os_type}")
                # Try pip fallback if available
                if 'pip_fallback' in tool_def:
                    logger.info("Trying pip fallback")
                    return self._install_pip_package(tool_def['pip_fallback'])
                return False
        else:
            package_name = package_info

        logger.info(f"Installing system package: {package_name}")

        # Determine package manager
        if self.os_type == 'linux':
            return self._install_linux_package(package_name)
        elif self.os_type == 'darwin':
            return self._install_macos_package(package_name)
        else:
            logger.error(f"Unsupported OS for system packages: {self.os_type}")
            return False

    def _get_distro(self) -> str:
        """Get Linux distribution name.

        Returns:
            Distribution name (ubuntu, debian, centos, etc.)
        """
        if self.os_type != 'linux':
            return self.os_type

        try:
            # Try reading /etc/os-release
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('ID='):
                        return line.split('=')[1].strip().strip('"').lower()
        except:
            pass

        return 'linux'

    def _install_linux_package(self, package_name: str) -> bool:
        """Install a package on Linux.

        Args:
            package_name: Name of the package

        Returns:
            True if successful
        """
        # Try different package managers
        package_managers = [
            ('apt-get', ['sudo', 'apt-get', 'install', '-y', package_name]),
            ('yum', ['sudo', 'yum', 'install', '-y', package_name]),
            ('dnf', ['sudo', 'dnf', 'install', '-y', package_name]),
        ]

        for pm_name, command in package_managers:
            if shutil.which(pm_name):
                logger.info(f"Using {pm_name} to install {package_name}")
                try:
                    subprocess.run(command, check=True, capture_output=True)
                    logger.info(f"Successfully installed {package_name}")
                    return True
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to install with {pm_name}: {e.stderr.decode()}")
                    continue

        logger.error(f"No suitable package manager found")
        return False

    def _install_macos_package(self, package_name: str) -> bool:
        """Install a package on macOS.

        Args:
            package_name: Name of the package

        Returns:
            True if successful
        """
        # Check for Homebrew
        if not shutil.which('brew'):
            logger.error("Homebrew not installed. Please install from https://brew.sh")
            return False

        logger.info(f"Using Homebrew to install {package_name}")

        try:
            subprocess.run(
                ['brew', 'install', package_name],
                check=True,
                capture_output=True,
            )
            logger.info(f"Successfully installed {package_name}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install {package_name}: {e.stderr.decode()}")
            return False

    def check_and_install_tools(self, required_tools: List[str]) -> Dict[str, bool]:
        """Check and optionally install required tools.

        Args:
            required_tools: List of tool names

        Returns:
            Dictionary mapping tool names to installation status
        """
        results = {}

        for tool_name in required_tools:
            logger.info(f"Checking tool: {tool_name}")

            if self.check_tool(tool_name):
                logger.info(f"✓ {tool_name} is already installed")
                results[tool_name] = True
                continue

            # Tool is not installed
            logger.warning(f"✗ {tool_name} is not installed")

            if self.auto_install:
                logger.info(f"Auto-installing {tool_name}...")
                success = self.install_tool(tool_name)
                results[tool_name] = success
            else:
                logger.info(
                    f"To install {tool_name}, run: blueguardian install-tool {tool_name}"
                )
                results[tool_name] = False

        return results

    def install_all_tools(self) -> Dict[str, bool]:
        """Install all defined tools.

        Returns:
            Dictionary mapping tool names to installation status
        """
        logger.info("Installing all tools...")
        return self.check_and_install_tools(list(self.TOOLS.keys()))

    def get_tool_info(self, tool_name: str) -> Optional[Dict]:
        """Get information about a tool.

        Args:
            tool_name: Name of the tool

        Returns:
            Tool information dictionary or None
        """
        return self.TOOLS.get(tool_name)

    def list_tools(self) -> List[Dict]:
        """List all available tools with their status.

        Returns:
            List of tool information dictionaries
        """
        tools_list = []

        for tool_name, tool_def in self.TOOLS.items():
            installed = self.check_tool(tool_name)
            tools_list.append({
                'name': tool_name,
                'description': tool_def['description'],
                'installed': installed,
                'install_method': tool_def['install_method'],
            })

        return tools_list

    def generate_install_script(self, output_path: str = 'install_tools.sh') -> None:
        """Generate a shell script to install all tools.

        Args:
            output_path: Path to output script
        """
        logger.info(f"Generating install script: {output_path}")

        script_lines = [
            '#!/bin/bash',
            '# BlueGuardian AI - Tool Installation Script',
            '# Auto-generated by ToolInstaller',
            '',
            'echo "Installing BlueGuardian AI tools..."',
            '',
        ]

        # Add pip packages
        script_lines.append('# Python packages')
        script_lines.append('echo "Installing Python packages..."')
        pip_packages = [
            tool_def['package']
            for tool_def in self.TOOLS.values()
            if tool_def['install_method'] == 'pip'
        ]
        if pip_packages:
            script_lines.append(f"pip install {' '.join(pip_packages)}")
        script_lines.append('')

        # Add system packages (Linux - apt)
        script_lines.append('# System packages (apt-get)')
        script_lines.append('if command -v apt-get &> /dev/null; then')
        script_lines.append('  echo "Installing system packages with apt-get..."')
        for tool_name, tool_def in self.TOOLS.items():
            if tool_def['install_method'] == 'system':
                package = tool_def['package']
                if isinstance(package, dict):
                    ubuntu_package = package.get('ubuntu')
                    if ubuntu_package:
                        script_lines.append(f'  sudo apt-get install -y {ubuntu_package}')
        script_lines.append('fi')
        script_lines.append('')

        # Add system packages (macOS - brew)
        script_lines.append('# System packages (Homebrew)')
        script_lines.append('if command -v brew &> /dev/null; then')
        script_lines.append('  echo "Installing system packages with Homebrew..."')
        for tool_name, tool_def in self.TOOLS.items():
            if tool_def['install_method'] == 'system':
                package = tool_def['package']
                if isinstance(package, dict):
                    macos_package = package.get('macos')
                    if macos_package:
                        script_lines.append(f'  brew install {macos_package}')
        script_lines.append('fi')
        script_lines.append('')

        script_lines.append('echo "Installation complete!"')

        # Write script
        with open(output_path, 'w') as f:
            f.write('\n'.join(script_lines))

        # Make executable
        os.chmod(output_path, 0o755)

        logger.info(f"Install script generated: {output_path}")
