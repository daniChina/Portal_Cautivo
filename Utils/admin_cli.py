import subprocess
from Utils.logger import get_logger

logger = get_logger()

def execute_command(command, args):
    """
    Execute a system command using subprocess, handle errors and log
    
    Args:
        command (str): The command to execute ('iptables')
        args (list): Arguments for the command
    
    Returns:
        tuple: (success, stdout, stderr) where success is a boolean
    """
    
    full_command = [command] + args
    logger.log(f"Executing command: {' '.join(full_command)}", level='INFO')
    
    try:
        result = subprocess.run(
            full_command,
            capture_output=True,
            text=True,
            check=False
        )
        success = result.returncode == 0
        stdout = result.stdout
        stderr = result.stderr
        
        if success:
            logger.log(f"Command executed successfully. Output: {stdout.strip()}", level='INFO')
        else:
            logger.log(f"Command failed with return code {result.returncode}", level='WARNING')
        return success, stdout, stderr
    except Exception as e:
        logger.log(f"Error executing command: {str(e)}", level='ERROR')
        return False, "", str(e)