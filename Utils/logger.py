# utils/logger.py
"""
Enhanced logging system
"""
import os
import re
import time
from datetime import datetime

class Logger:
    """Enhanced logging system"""
    
    def __init__(self, log_file='data/logs/portal.log'):
        self.log_file = log_file
        self.levels = {
            'INFO': 'ℹ️',
            'WARNING': '⚠️',
            'ERROR': '❌',
            'SUCCESS': '✅',
            'DEBUG': '🐛'
        }
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    def info(self, message):
        """Log info message"""
        self.log(message, 'INFO')
    
    def warning(self, message):
        """Log warning message"""
        self.log(message, 'WARNING')
    
    def error(self, message):
        """Log error message"""
        self.log(message, 'ERROR')
    
    def success(self, message):
        """Log success message"""
        self.log(message, 'SUCCESS')
    
    def debug(self, message):
        """Log debug message"""
        self.log(message, 'DEBUG')
    
    def log(self, message, level='INFO'):
        """Log a message"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        icon = self.levels.get(level, 'ℹ️')
        
        line = f"[{timestamp}] {icon} {level}: {message}\n"
        
        # Print to console
        print(f"[{timestamp}] {message}")
        
        # Write to file
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(line)
        except Exception:
            pass
        
        return line
    
    def clean_old_logs(self, days=7):
        """Clean old logs"""
        try:
            if not os.path.exists(self.log_file):
                return
            
            with open(self.log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Keep only recent logs
            limit = time.time() - (days * 24 * 3600)
            new_lines = []
            
            for line in lines:
                # Extract timestamp
                match = re.search(r'\[(\d{4}-\d{2}-\d{2})', line)
                if match:
                    date_str = match.group(1)
                    date = datetime.strptime(date_str, '%Y-%m-%d')
                    if date.timestamp() > limit:
                        new_lines.append(line)
            
            with open(self.log_file, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
                
        except Exception:
            pass

# Global instance
_logger = None

def get_logger():
    """Get logger instance"""
    global _logger
    if _logger is None:
        _logger = Logger()
    return _logger