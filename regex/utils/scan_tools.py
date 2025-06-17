import subprocess
import os


def scan_with_grep(directory, pattern):
    """Grep kullanarak tarama yapar - Ubuntu subsystem için optimize edildi."""
    try:
        # Linux için daha geniş dosya türleri dahil et
        result = subprocess.run(
            ['grep', '-r', '-n', '--include=*.txt', '--include=*.log', '--include=*.conf', 
             '--include=*.py', '--include=*.js', '--include=*.html', '--include=*.css', 
             '--include=*.json', '--include=*.xml', '--include=*.yaml', '--include=*.yml',
             pattern, directory],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout.splitlines()
    except subprocess.TimeoutExpired:
        return ["Timeout: Grep search took too long"]
    except subprocess.CalledProcessError as e:
        return []
    except FileNotFoundError:
        return ["Error: grep command not found. Please install grep."]


def scan_with_ripgrep(directory, pattern):
    """Ripgrep kullanarak tarama yapar - Ubuntu subsystem için optimize edildi."""
    try:
        result = subprocess.run(
            ['rg', '--line-number', '--type', 'text', pattern, directory],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout.splitlines()
    except subprocess.TimeoutExpired:
        return ["Timeout: Ripgrep search took too long"]
    except subprocess.CalledProcessError as e:
        return []
    except FileNotFoundError:
        return ["Error: ripgrep (rg) command not found. Please install ripgrep."]


def scan_with_ag(directory, pattern):
    """The Silver Searcher (ag) kullanarak tarama yapar - Ubuntu subsystem için optimize edildi."""
    try:
        result = subprocess.run(
            ['ag', '--line-numbers', '--nobreak', pattern, directory],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout.splitlines()
    except subprocess.TimeoutExpired:
        return ["Timeout: Silver Searcher search took too long"]
    except subprocess.CalledProcessError as e:
        return []
    except FileNotFoundError:
        return ["Error: ag command not found. Please install silversearcher-ag."]


def scan_with_ack(directory, pattern):
    """Ack kullanarak tarama yapar - Ubuntu subsystem için optimize edildi."""
    try:
        result = subprocess.run(
            ['ack', '--noheading', '--nocolor', '--line', pattern, directory],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout.splitlines()
    except subprocess.TimeoutExpired:
        return ["Timeout: Ack search took too long"]
    except subprocess.CalledProcessError as e:
        return []
    except FileNotFoundError:
        return ["Error: ack command not found. Please install ack."]


def check_tool_availability():
    """Tarama araçlarının kurulu olup olmadığını kontrol eder."""
    tools = {
        'grep': ['grep', '--version'],
        'ripgrep': ['rg', '--version'],
        'ag': ['ag', '--version'],
        'ack': ['ack', '--version']
    }
    
    available_tools = {}
    for tool_name, command in tools.items():
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            available_tools[tool_name] = result.returncode == 0
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            available_tools[tool_name] = False
    
    return available_tools 