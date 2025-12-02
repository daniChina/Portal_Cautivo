#!/usr/bin/env python3
"""
Sistema de logging para el portal cautivo
"""

import os
import sys
import time
from datetime import datetime
from typing import Optional
from threading import Lock

class Logger:
    """Logger unificado para todo el sistema"""
    
    def __init__(self, name: str = "Portal", log_file: str = "data/logs/portal.log", 
                 level: str = "INFO", max_size_mb: int = 10):
        self.name = name
        self.log_file = log_file
        self.level = level.upper()
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.lock = Lock()
        
        # Niveles de log
        self.levels = {
            "DEBUG": 10,
            "INFO": 20,
            "WARNING": 30,
            "ERROR": 40,
            "CRITICAL": 50
        }
        
        # Crear directorio de logs si no existe
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
    
    def _should_log(self, level: str) -> bool:
        """Determina si se debe registrar un mensaje basado en el nivel"""
        current_level = self.levels.get(self.level, 20)  # INFO por defecto
        message_level = self.levels.get(level.upper(), 20)
        return message_level >= current_level
    
    def _rotate_log_if_needed(self):
        """Rota el archivo de log si es demasiado grande"""
        try:
            if os.path.exists(self.log_file):
                size = os.path.getsize(self.log_file)
                if size > self.max_size_bytes:
                    # Rotar archivo
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    backup_file = f"{self.log_file}.{timestamp}.bak"
                    os.rename(self.log_file, backup_file)
                    
                    # Mantener solo los últimos 5 backups
                    log_dir = os.path.dirname(self.log_file)
                    backups = sorted([f for f in os.listdir(log_dir) 
                                    if f.startswith(os.path.basename(self.log_file) + ".")])
                    
                    if len(backups) > 5:
                        for old_backup in backups[:-5]:
                            os.remove(os.path.join(log_dir, old_backup))
        except Exception as e:
            print(f"Error rotando log: {e}")
    
    def log(self, message: str, level: str = "INFO", source: Optional[str] = None):
        """Registra un mensaje"""
        with self.lock:
            if not self._should_log(level):
                return
            
            # Rotar si es necesario
            self._rotate_log_if_needed()
            
            # Crear entrada de log
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            source_str = f"[{source}]" if source else f"[{self.name}]"
            
            log_entry = f"{timestamp} [{level.upper():8}] {source_str} {message}"
            
            # Escribir en consola
            colors = {
                "DEBUG": "\033[36m",    # Cyan
                "INFO": "\033[32m",     # Verde
                "WARNING": "\033[33m",  # Amarillo
                "ERROR": "\033[31m",    # Rojo
                "CRITICAL": "\033[41m"  # Rojo fondo
            }
            reset = "\033[0m"
            
            color = colors.get(level.upper(), "")
            console_entry = f"{color}{log_entry}{reset}"
            print(console_entry)
            
            # Escribir en archivo
            try:
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    f.write(log_entry + "\n")
            except Exception as e:
                print(f"Error escribiendo en archivo de log: {e}")
    
    # Métodos de conveniencia
    def debug(self, message: str, source: Optional[str] = None):
        self.log(message, "DEBUG", source)
    
    def info(self, message: str, source: Optional[str] = None):
        self.log(message, "INFO", source)
    
    def warning(self, message: str, source: Optional[str] = None):
        self.log(message, "WARNING", source)
    
    def error(self, message: str, source: Optional[str] = None):
        self.log(message, "ERROR", source)
    
    def critical(self, message: str, source: Optional[str] = None):
        self.log(message, "CRITICAL", source)
    
    def get_log_tail(self, lines: int = 50) -> list:
        """Obtiene las últimas líneas del log"""
        try:
            if not os.path.exists(self.log_file):
                return ["Archivo de log no encontrado"]
            
            with open(self.log_file, 'r', encoding='utf-8') as f:
                all_lines = f.readlines()
                return all_lines[-lines:]
        except Exception as e:
            return [f"Error leyendo log: {e}"]
    
    def clear_log(self):
        """Limpia el archivo de log"""
        try:
            with open(self.log_file, 'w') as f:
                f.write("")
            self.info("Log limpiado")
        except Exception as e:
            print(f"Error limpiando log: {e}")

# Logger global para uso rápido
_logger_instance = None

def get_logger(name: str = "Portal") -> Logger:
    """Obtiene una instancia del logger"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = Logger(name)
    return _logger_instance