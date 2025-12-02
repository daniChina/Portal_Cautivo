#!/usr/bin/env python3
import click
import json
from datetime import datetime
from Auth.user_manager import UserManager
from Auth.session_manager import SessionManager

@click.group()
def cli():
    """CLI de administración del Portal Cautivo"""
    pass

@cli.command()
@click.argument('email')
@click.password_option()
def add_user(email, password):
    """Añade un nuevo usuario"""
    manager = UserManager()
    if manager.add_user(email, password):
        click.echo(f" Usuario {email} creado")
    else:
        click.echo(f" Error creando usuario")

@cli.command()
def list_users():
    """Lista todos los usuarios"""
    manager = UserManager()
    users = manager.get_all_users()
    
    click.echo("\n📋 Usuarios registrados:")
    click.echo("-" * 40)
    for user in users:
        click.echo(f"  • {user['email']} - Creado: {user['created_at']}")
    click.echo("-" * 40)

@cli.command()
def active_sessions():
    """Muestra sesiones activas"""
    manager = SessionManager()
    sessions = manager.get_active_sessions()
    
    click.echo("\n🌐 Sesiones activas:")
    click.echo("-" * 60)
    for session in sessions:
        click.echo(f"  IP: {session['ip']}")
        click.echo(f"  Usuario: {session['user']}")
        click.echo(f"  Inicio: {session['start_time']}")
        click.echo(f"  Expira: {session['expiry_time']}")
        click.echo("-" * 60)

@cli.command()
@click.option('--ip', help='Bloquear IP específica')
@click.option('--all', is_flag=True, help='Bloquear todas las IPs')
def block(ip, all):
    """Bloquea acceso a IPs"""
    from Network.firewall import FirewallManager
    from Core.config import PortalConfig
    
    config = PortalConfig()
    firewall = FirewallManager(config)
    
    if all:
        # Implementar bloqueo de todas las IPs
        click.echo("Bloqueando todas las IPs...")
    elif ip:
        firewall.block_client(ip)
        click.echo(f"IP {ip} bloqueada")

if __name__ == "__main__":
    cli()