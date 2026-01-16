import json
import os
import sys
import socket
import ssl
import urllib.request
import urllib.error

_config = None
_version = None
_remote_config = None

# Remote API configuration
API_BASE_URL = "https://api.oczsvalitcvat.zb.if.atcsg.net"
DEVICE_NAME = socket.gethostname()  # Auto-detect hostname, or set manually

#-------------------------------------------------------------------------------------------------------------------
# Path Functions
#-------------------------------------------------------------------------------------------------------------------
def get_script_path():
    """Return the path of the main script (not this module)"""
    return os.path.dirname(os.path.realpath(sys.argv[0]))


def get_conf_path():
    """Return the path to the conf directory"""
    if __name__ == "__main__":
        return os.path.join(get_script_path())
    else:
        return os.path.join(get_script_path(), "conf")

#-------------------------------------------------------------------------------------------------------------------
# Local Config Functions
#-------------------------------------------------------------------------------------------------------------------
def get_config():
    """Load card reader configuration from serial_card_reader.json"""
    global _config
    if _config is None:  # load only once
        config_path = os.path.join(get_conf_path(), "serial_card_reader.json")
        with open(config_path, "r") as f:
            _config = json.load(f)
    return _config

#-------------------------------------------------------------------------------------------------------------------
# Version Functions
#-------------------------------------------------------------------------------------------------------------------
def get_version():
    """Load version information from verze.json"""
    global _version
    if _version is None:  # load only once
        version_path = os.path.join(get_conf_path(), "verze.json")
        try:
            with open(version_path, "r") as f:
                _version = json.load(f)
        except FileNotFoundError:
            _version = {"verze": "unknown"}
    return _version.get('verze', _version.get('version', 'unknown'))

#-------------------------------------------------------------------------------------------------------------------
# Reader Configuration Functions
#-------------------------------------------------------------------------------------------------------------------
def get_reader_configurations():
    """Get list of reader configurations with defaults"""
    config = get_config()
    reader_configs = config.get('reader_configurations', [])
    
    # Backward compatibility
    if not reader_configs:
        if isinstance(config, list):
            reader_configs = config
        else:
            reader_configs = [config]
    
    readers = []
    for idx, reader_config in enumerate(reader_configs):
        reader = {
            'reader_type': reader_config.get('reader_type', 'default'),
            'port': reader_config.get('port', '/dev/ttyACM_back_left'),
            'baudrate': reader_config.get('baudrate', 115200),
            'interval': reader_config.get('interval', 1.0),
            'code': reader_config.get('code', f'ns=1;i={100011 + idx * 4}'),
            'code_potvrzeni': reader_config.get('code_potvrzeni', f'ns=1;i={100012 + idx * 4}'),
            'code_health_check': reader_config.get('code_health_check', f'ns=1;i={100013 + idx * 4}'),
            'code_health_check_message': reader_config.get('code_health_check_message', f'ns=1;i={100014 + idx * 4}'),
        }
        readers.append(reader)
    
    return readers

#-------------------------------------------------------------------------------------------------------------------
# Log Configuration Functions
#-------------------------------------------------------------------------------------------------------------------
def get_log_level():
    """Get log level from config, default INFO"""
    config = get_config()
    return config.get('log_level', 'INFO').upper()

def get_log_retention_days():
    """Get log retention days from config, default 30"""
    config = get_config()
    return config.get('log_retention_days', 30)

#-------------------------------------------------------------------------------------------------------------------
# Remote Config Functions
#-------------------------------------------------------------------------------------------------------------------
def fetch_remote_config(device_name=None, timeout=10, verify_ssl=False):
    """
    Fetch card reader configuration from remote API.
    
    Args:
        device_name: Device/machine name (default: hostname)
        timeout: Request timeout in seconds (default: 10)
        verify_ssl: Verify SSL certificate (default: True, set False for self-signed certs)
        
    Returns:
        dict: Configuration from remote API
        
    Raises:
        Exception: If request fails
    """
    global _remote_config
    
    if device_name is None:
        device_name = DEVICE_NAME
    
    url = f"{API_BASE_URL}/getConfigReader?name={device_name}"
    
    try:
        # Create SSL context
        if verify_ssl:
            ssl_context = ssl.create_default_context()
        else:
            # For self-signed or internal certificates
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        # Create request with headers
        request = urllib.request.Request(
            url,
            headers={
                'Accept': 'application/json',
                'User-Agent': 'at_card_reader/1.0'
            }
        )
        
        # Make the request
        with urllib.request.urlopen(request, timeout=timeout, context=ssl_context) as response:
            if response.status == 200:
                data = response.read().decode('utf-8')
                _remote_config = json.loads(data)
                return _remote_config
            else:
                raise Exception(f"HTTP {response.status}: {response.reason}")
                
    except urllib.error.HTTPError as e:
        raise Exception(f"HTTP Error {e.code}: {e.reason}")
    except urllib.error.URLError as e:
        raise Exception(f"URL Error: {e.reason}")
    except json.JSONDecodeError as e:
        raise Exception(f"JSON decode error: {e}")
    except Exception as e:
        raise Exception(f"Request failed: {e}")

#-------------------------------------------------------------------------------------------------------------------
# Remote Root Config Functions
#-------------------------------------------------------------------------------------------------------------------
def fetch_remote_root_config(device_name=None, timeout=10, verify_ssl=False):
    """
    Fetch root configuration from remote API.
    
    Args:
        device_name: Device/machine name (default: hostname)
        timeout: Request timeout in seconds (default: 10)
        verify_ssl: Verify SSL certificate (default: True, set False for self-signed certs)
        
    Returns:
        dict: Configuration from remote API
        
    Raises:
        Exception: If request fails
    """
    global _remote_config
    
    if device_name is None:
        device_name = DEVICE_NAME
    
    url = f"{API_BASE_URL}/getConfigRoot?name={device_name}"
    
    try:
        # Create SSL context
        if verify_ssl:
            ssl_context = ssl.create_default_context()
        else:
            # For self-signed or internal certificates
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        # Create request with headers
        request = urllib.request.Request(
            url,
            headers={
                'Accept': 'application/json',
                'User-Agent': 'at_card_reader/1.0'
            }
        )
        
        # Make the request
        with urllib.request.urlopen(request, timeout=timeout, context=ssl_context) as response:
            if response.status == 200:
                data = response.read().decode('utf-8')
                _remote_config = json.loads(data)
                return _remote_config
            else:
                raise Exception(f"HTTP {response.status}: {response.reason}")
                
    except urllib.error.HTTPError as e:
        raise Exception(f"HTTP Error {e.code}: {e.reason}")
    except urllib.error.URLError as e:
        raise Exception(f"URL Error: {e.reason}")
    except json.JSONDecodeError as e:
        raise Exception(f"JSON decode error: {e}")
    except Exception as e:
        raise Exception(f"Request failed: {e}")

#-------------------------------------------------------------------------------------------------------------------
# Get Remote Config with Fallback
#-------------------------------------------------------------------------------------------------------------------
def get_remote_config(device_name=None, timeout=10, fallback_to_local=True, verify_ssl=False):
    """
    Get configuration from remote API with optional fallback to local config.
    
    Args:
        device_name: Device/machine name (default: hostname)
        timeout: Request timeout in seconds (default: 10)
        fallback_to_local: If True, use local config on failure (default: True)
        verify_ssl: Verify SSL certificate (default: True)
        
    Returns:
        dict: Configuration dictionary
    """
    try:
        config = fetch_remote_config(device_name, timeout, verify_ssl)
        print(f"Remote config loaded for device: {device_name or DEVICE_NAME}")
        return config
    except Exception as e:
        print(f"Failed to fetch remote config: {e}")
        if fallback_to_local:
            print("Falling back to local configuration...")
            return get_config()
        raise

#-------------------------------------------------------------------------------------------------------------------
# Update Local Config from Remote
#-------------------------------------------------------------------------------------------------------------------
def update_local_config_from_remote(device_name=None, timeout=10, verify_ssl=False):
    """
    Fetch remote config and save it to local serial_card_reader.json file.
    
    Args:
        device_name: Device/machine name (default: hostname)
        timeout: Request timeout in seconds (default: 10)
        verify_ssl: Verify SSL certificate (default: True)
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        remote_config = fetch_remote_config(device_name, timeout, verify_ssl)
        remote_root_config = fetch_remote_root_config(device_name, timeout, verify_ssl)

        config_path = os.path.join(get_conf_path(), "serial_card_reader.json")
        
        # Backup existing config
        backup_path = config_path + ".backup"
        if os.path.exists(config_path):
            import shutil
            shutil.copy2(config_path, backup_path)
        
        final_data = {
            "log_level": remote_root_config["log_level"],
            "log_retention_days": int(remote_root_config["log_retention_days"]),
            "reader_configurations": remote_config["reader_configurations"]
        }

        with open(config_path, "w") as f:
            json.dump(final_data, f, indent=4)
        
        # Clear cached config so it reloads
        global _config
        _config = None
        
        print(f"Local config updated from remote API")
        return True
        
    except Exception as e:
        print(f"Failed to update local config: {e}")
        return False

#-------------------------------------------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    update_local_config_from_remote()
