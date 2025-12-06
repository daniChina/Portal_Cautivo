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
    users = manager.list_users()
    
    click.echo(" Usuarios registrados:")
    click.echo("-" * 40)
    for user in users:
        click.echo(f"  • {user['email']} - Creado: {user['created_at']}")
    click.echo("-" * 40)

@cli.command()
def active_sessions():
    """Muestra sesiones activas"""
    manager = SessionManager()
    sessions = manager.get_active_sessions()
    
    click.echo(" Sesiones activas:")
    click.echo("-" * 60)
    for session in sessions:
        click.echo(f"  IP: {session.get('client_ip', 'N/A')}")
        click.echo(f"  Usuario: {session.get('username', 'N/A')}")
        click.echo(f"  Inicio: {session.get('created_at', 'N/A')}")
        click.echo(f"  Expira: {session.get('expires_at', 'N/A')}")
        click.echo("-" * 60)


@cli.command()
@click.option('--ip', help='Bloquear IP específica')
def block(ip):
    """Bloquea acceso a una IP"""
    # Crear configuración manual
    config = {
        'internal_interface': 'wlan0',
        'external_interface': 'eth0',
        'gateway_ip': '192.168.100.1'
    }
    
    from Network.firewall import FirewallManager
    firewall = FirewallManager(config)
    
    if ip:
        firewall.block_client(ip)
        click.echo(f"IP {ip} bloqueada")


if __name__ == "__main__":
    cli()