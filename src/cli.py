"""
Command-line interface for secureVault password manager.

Provides commands for managing the encrypted password vault.
"""

import click
import getpass
import json
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

from . import crypto, password_gen, clipboard
from .vault import Vault, VaultEntry
from .config import Config


console = Console()


def get_master_password(prompt: str = "Master password: ", confirm: bool = False) -> str:
    """
    Securely get master password from user.
    
    Args:
        prompt: Prompt to display
        confirm: Whether to ask for confirmation
        
    Returns:
        Master password
    """
    password = getpass.getpass(prompt)
    
    if confirm:
        password2 = getpass.getpass("Confirm master password: ")
        if password != password2:
            console.print("[red]Passwords do not match![/red]")
            sys.exit(1)
    
    return password


@click.group()
@click.version_option(version="1.0.0", prog_name="secureVault")
def cli():
    """
    secureVault - Secure Offline Password Manager
    
    A cryptographically secure, offline password manager using:
    - Argon2id for master password hashing
    - HKDF for key derivation
    - AES-256-GCM for authenticated encryption
    """
    pass


@cli.command()
@click.option('--vault-path', type=click.Path(), help='Custom vault file path')
def init(vault_path: Optional[str]):
    """Initialize a new password vault."""
    vault = Vault(Config.get_vault_path(vault_path))
    
    try:
        console.print(Panel.fit(
            "[bold cyan]Initialize New Vault[/bold cyan]\n\n"
            "Choose a strong master password. This password:\n"
            "• Will encrypt all your passwords\n"
            "• Cannot be recovered if forgotten\n"
            "• Should be unique and memorable",
            border_style="cyan"
        ))
        
        master_password = get_master_password(confirm=True)
        
        if len(master_password) < 8:
            console.print("[yellow]Warning: Password is short. Consider using a longer password.[/yellow]")
        
        with console.status("[bold green]Initializing vault..."):
            vault.initialize(master_password)
        
        console.print(f"\n[green]✓[/green] Vault created at: {vault.vault_path}")
        console.print(f"[green]✓[/green] File permissions set to 600 (owner only)")
        
    except FileExistsError:
        console.print(f"[red]Error: Vault already exists at {vault.vault_path}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option('--vault-path', type=click.Path(), help='Custom vault file path')
@click.option('--service', '-s', prompt=True, help='Service name (e.g., github.com)')
@click.option('--username', '-u', prompt=True, help='Username or email')
@click.option('--password', '-p', help='Password (will prompt if not provided)')
@click.option('--generate', '-g', is_flag=True, help='Generate a random password')
@click.option('--length', '-l', default=20, help='Password length for generation')
@click.option('--url', help='Service URL')
@click.option('--notes', help='Additional notes')
def add(vault_path: Optional[str], service: str, username: str, password: Optional[str],
        generate: bool, length: int, url: Optional[str], notes: Optional[str]):
    """Add a new password entry to the vault."""
    vault = Vault(Config.get_vault_path(vault_path))
    
    try:
        # Unlock vault
        master_password = get_master_password()
        if not vault.unlock(master_password):
            console.print("[red]Error: Incorrect master password[/red]")
            sys.exit(1)
        
        # Generate or get password
        if generate:
            password = password_gen.generate_password(length=length)
            console.print(f"\n[green]Generated password:[/green] {password}")
            
            if Config.SHOW_ENTROPY:
                entropy = password_gen.calculate_entropy(password)
                console.print(f"[dim]Entropy: {entropy:.1f} bits[/dim]")
        elif not password:
            password = getpass.getpass("Password: ")
        
        # Create entry
        entry = VaultEntry(
            service=service,
            username=username,
            password=password,
            url=url,
            notes=notes
        )
        
        # Add to vault
        vault.add_entry(entry)
        
        console.print(f"\n[green]✓[/green] Added entry for {service}")
        
        # Copy to clipboard if available
        if clipboard.is_available():
            if click.confirm("Copy password to clipboard?", default=True):
                clipboard.copy_to_clipboard(password, Config.CLIPBOARD_TIMEOUT)
                console.print(f"[green]✓[/green] Copied to clipboard (will clear in {Config.CLIPBOARD_TIMEOUT}s)")
        
    except FileNotFoundError:
        console.print(f"[red]Error: Vault not found. Run 'securevault init' first.[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option('--vault-path', type=click.Path(), help='Custom vault file path')
@click.argument('service')
@click.option('--username', '-u', help='Username (if multiple entries for service)')
@click.option('--show', '-s', is_flag=True, help='Show password on screen')
@click.option('--no-copy', is_flag=True, help='Do not copy to clipboard')
def get(vault_path: Optional[str], service: str, username: Optional[str], show: bool, no_copy: bool):
    """Retrieve a password from the vault."""
    vault = Vault(Config.get_vault_path(vault_path))
    
    try:
        # Unlock vault
        master_password = get_master_password()
        if not vault.unlock(master_password):
            console.print("[red]Error: Incorrect master password[/red]")
            sys.exit(1)
        
        # Get entry
        entry = vault.get_entry(service, username)
        
        if not entry:
            console.print(f"[red]Error: No entry found for '{service}'[/red]")
            sys.exit(1)
        
        # Display entry info
        console.print(f"\n[bold cyan]{entry.service}[/bold cyan]")
        console.print(f"Username: {entry.username}")
        if entry.url:
            console.print(f"URL: {entry.url}")
        if entry.notes:
            console.print(f"Notes: {entry.notes}")
        
        # Show password if requested
        if show:
            console.print(f"\n[yellow]Password:[/yellow] {entry.password}")
        
        # Copy to clipboard
        if not no_copy and clipboard.is_available():
            clipboard.copy_to_clipboard(entry.password, Config.CLIPBOARD_TIMEOUT)
            console.print(f"\n[green]✓[/green] Password copied to clipboard (will clear in {Config.CLIPBOARD_TIMEOUT}s)")
        elif not clipboard.is_available() and not show:
            console.print(f"\n[yellow]Clipboard not available. Use --show to display password.[/yellow]")
        
    except FileNotFoundError:
        console.print(f"[red]Error: Vault not found.[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option('--vault-path', type=click.Path(), help='Custom vault file path')
@click.option('--search', '-s', help='Filter by service name')
def list(vault_path: Optional[str], search: Optional[str]):
    """List all stored services."""
    vault = Vault(Config.get_vault_path(vault_path))
    
    try:
        # Unlock vault
        master_password = get_master_password()
        if not vault.unlock(master_password):
            console.print("[red]Error: Incorrect master password[/red]")
            sys.exit(1)
        
        # Get entries
        entries = vault.list_entries(search)
        
        if not entries:
            if search:
                console.print(f"[yellow]No entries found matching '{search}'[/yellow]")
            else:
                console.print("[yellow]Vault is empty[/yellow]")
            return
        
        # Create table
        table = Table(title=f"Vault Entries ({len(entries)} total)")
        table.add_column("Service", style="cyan", no_wrap=True)
        table.add_column("Username", style="green")
        table.add_column("URL", style="blue")
        
        for entry in sorted(entries, key=lambda x: x['service'].lower()):
            table.add_row(entry['service'], entry['username'], entry['url'])
        
        console.print(table)
        
    except FileNotFoundError:
        console.print(f"[red]Error: Vault not found.[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option('--vault-path', type=click.Path(), help='Custom vault file path')
@click.argument('service')
@click.option('--username', '-u', help='Username (if multiple entries for service)')
@click.option('--new-password', '-p', help='New password')
@click.option('--generate', '-g', is_flag=True, help='Generate new password')
@click.option('--length', '-l', default=20, help='Password length for generation')
@click.option('--new-username', help='New username')
@click.option('--new-url', help='New URL')
@click.option('--new-notes', help='New notes')
def update(vault_path: Optional[str], service: str, username: Optional[str],
           new_password: Optional[str], generate: bool, length: int,
           new_username: Optional[str], new_url: Optional[str], new_notes: Optional[str]):
    """Update an existing entry."""
    vault = Vault(Config.get_vault_path(vault_path))
    
    try:
        # Unlock vault
        master_password = get_master_password()
        if not vault.unlock(master_password):
            console.print("[red]Error: Incorrect master password[/red]")
            sys.exit(1)
        
        # Get existing entry
        entry = vault.get_entry(service, username)
        if not entry:
            console.print(f"[red]Error: No entry found for '{service}'[/red]")
            sys.exit(1)
        
        # Update fields
        if generate:
            new_password = password_gen.generate_password(length=length)
            console.print(f"\n[green]Generated password:[/green] {new_password}")
        elif new_password is None:
            # Keep existing password if not specified
            new_password = entry.password
        
        updated_entry = VaultEntry(
            service=service,
            username=new_username or entry.username,
            password=new_password,
            url=new_url if new_url is not None else entry.url,
            notes=new_notes if new_notes is not None else entry.notes
        )
        
        # Update in vault
        vault.update_entry(service, username, updated_entry)
        
        console.print(f"\n[green]✓[/green] Updated entry for {service}")
        
    except FileNotFoundError:
        console.print(f"[red]Error: Vault not found.[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option('--vault-path', type=click.Path(), help='Custom vault file path')
@click.argument('service')
@click.option('--username', '-u', help='Username (if multiple entries for service)')
@click.confirmation_option(prompt='Are you sure you want to delete this entry?')
def delete(vault_path: Optional[str], service: str, username: Optional[str]):
    """Delete an entry from the vault."""
    vault = Vault(Config.get_vault_path(vault_path))
    
    try:
        # Unlock vault
        master_password = get_master_password()
        if not vault.unlock(master_password):
            console.print("[red]Error: Incorrect master password[/red]")
            sys.exit(1)
        
        # Delete entry
        if vault.delete_entry(service, username):
            console.print(f"\n[green]✓[/green] Deleted entry for {service}")
        else:
            console.print(f"[red]Error: No entry found for '{service}'[/red]")
            sys.exit(1)
        
    except FileNotFoundError:
        console.print(f"[red]Error: Vault not found.[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option('--length', '-l', default=Config.DEFAULT_PASSWORD_LENGTH, help='Password length')
@click.option('--no-lowercase', is_flag=True, help='Exclude lowercase letters')
@click.option('--no-uppercase', is_flag=True, help='Exclude uppercase letters')
@click.option('--no-digits', is_flag=True, help='Exclude digits')
@click.option('--no-special', is_flag=True, help='Exclude special characters')
@click.option('--passphrase', '-pp', is_flag=True, help='Generate passphrase instead')
@click.option('--words', '-w', default=Config.DEFAULT_PASSPHRASE_WORDS, help='Number of words in passphrase')
def generate(length: int, no_lowercase: bool, no_uppercase: bool, no_digits: bool,
             no_special: bool, passphrase: bool, words: int):
    """Generate a random password without storing it."""
    try:
        if passphrase:
            # Generate passphrase
            result = password_gen.generate_passphrase(
                num_words=words,
                separator=Config.DEFAULT_PASSPHRASE_SEPARATOR
            )
            console.print(f"\n[bold green]Generated Passphrase:[/bold green]")
            console.print(f"{result}")
        else:
            # Generate password
            result = password_gen.generate_password(
                length=length,
                use_lowercase=not no_lowercase,
                use_uppercase=not no_uppercase,
                use_digits=not no_digits,
                use_special=not no_special
            )
            console.print(f"\n[bold green]Generated Password:[/bold green]")
            console.print(f"{result}")
        
        # Show entropy
        if Config.SHOW_ENTROPY:
            entropy = password_gen.calculate_entropy(result)
            console.print(f"\n[dim]Entropy: {entropy:.1f} bits[/dim]")
        
        # Copy to clipboard
        if clipboard.is_available():
            if click.confirm("\nCopy to clipboard?", default=True):
                clipboard.copy_to_clipboard(result, Config.CLIPBOARD_TIMEOUT)
                console.print(f"[green]✓[/green] Copied to clipboard (will clear in {Config.CLIPBOARD_TIMEOUT}s)")
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option('--vault-path', type=click.Path(), help='Custom vault file path')
def change_master(vault_path: Optional[str]):
    """Change the master password."""
    vault = Vault(Config.get_vault_path(vault_path))
    
    try:
        # Load vault
        vault._load()
        
        console.print(Panel.fit(
            "[bold yellow]Change Master Password[/bold yellow]\n\n"
            "This will re-encrypt all entries with a new master password.",
            border_style="yellow"
        ))
        
        old_password = get_master_password("Current master password: ")
        new_password = get_master_password("New master password: ", confirm=True)
        
        with console.status("[bold green]Re-encrypting vault..."):
            if vault.change_master_password(old_password, new_password):
                console.print("\n[green]✓[/green] Master password changed successfully")
            else:
                console.print("\n[red]Error: Incorrect current password[/red]")
                sys.exit(1)
        
    except FileNotFoundError:
        console.print(f"[red]Error: Vault not found.[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option('--vault-path', type=click.Path(), help='Custom vault file path')
@click.argument('output_file', type=click.Path())
@click.confirmation_option(prompt='WARNING: This will export passwords in PLAINTEXT. Continue?')
def export(vault_path: Optional[str], output_file: str):
    """Export vault to unencrypted JSON (DANGEROUS!)."""
    vault = Vault(Config.get_vault_path(vault_path))
    
    try:
        # Unlock vault
        master_password = get_master_password()
        if not vault.unlock(master_password):
            console.print("[red]Error: Incorrect master password[/red]")
            sys.exit(1)
        
        # Export entries
        entries = vault.export_unencrypted()
        
        # Write to file
        with open(output_file, 'w') as f:
            json.dump(entries, f, indent=2)
        
        console.print(f"\n[green]✓[/green] Exported {len(entries)} entries to {output_file}")
        console.print("[yellow]⚠[/yellow]  Remember to delete this file after use!")
        
    except FileNotFoundError:
        console.print(f"[red]Error: Vault not found.[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command(name='import')
@click.option('--vault-path', type=click.Path(), help='Custom vault file path')
@click.argument('input_file', type=click.Path(exists=True))
def import_cmd(vault_path: Optional[str], input_file: str):
    """Import entries from unencrypted JSON."""
    vault = Vault(Config.get_vault_path(vault_path))
    
    try:
        # Unlock vault
        master_password = get_master_password()
        if not vault.unlock(master_password):
            console.print("[red]Error: Incorrect master password[/red]")
            sys.exit(1)
        
        # Read entries
        with open(input_file, 'r') as f:
            entries_data = json.load(f)
        
        # Import entries
        with console.status("[bold green]Importing entries..."):
            count = vault.import_entries(entries_data)
        
        console.print(f"\n[green]✓[/green] Imported {count} entries")
        
    except FileNotFoundError:
        console.print(f"[red]Error: Vault not found.[/red]")
        sys.exit(1)
    except json.JSONDecodeError:
        console.print(f"[red]Error: Invalid JSON file[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == '__main__':
    cli()
