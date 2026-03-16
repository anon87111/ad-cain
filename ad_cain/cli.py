"""CLI entry point for AD-Cain."""

from __future__ import annotations

import sys

import click

from ad_cain import __version__
from ad_cain.config import LDAPConfig, ExportConfig, ImportConfig
from ad_cain.logger import setup_logger, get_logger

log = get_logger("cli")


@click.group()
@click.version_option(version=__version__, prog_name="ad-cain")
def cli():
    """AD-Cain: Active Directory Lab State Snapshot & Restore Tool."""
    pass


# ── export ───────────────────────────────────────────────────────────

@cli.command()
@click.option("--server", "-s", required=True, help="Domain Controller hostname or IP.")
@click.option("--port", "-p", default=389, type=int, help="LDAP port (default: 389).")
@click.option("--ssl", is_flag=True, help="Use LDAPS (port 636).")
@click.option("--username", "-u", prompt=True, help="Bind username (UPN or DOMAIN\\user).")
@click.option("--password", "-pw", prompt=True, hide_input=True, help="Bind password.")
@click.option("--output", "-o", required=True, type=click.Path(), help="Output JSON file path.")
@click.option("--sysvol", type=click.Path(exists=True), default=None,
              help="Path to mounted SYSVOL share (for GPO file export).")
@click.option("--include-gpos/--no-gpos", default=True, help="Include GPOs.")
@click.option("--include-trusts/--no-trusts", default=True, help="Include domain trusts.")
@click.option("--verbose", "-v", is_flag=True, help="Verbose logging.")
def export(server, port, ssl, username, password, output, sysvol,
           include_gpos, include_trusts, verbose):
    """Export Active Directory state to a JSON file."""
    import logging
    setup_logger(level=logging.DEBUG if verbose else logging.INFO)

    from ad_cain.config import LDAPConfig, ExportConfig
    from ad_cain.core.connection import LDAPConnectionManager
    from ad_cain.core.exporter import run_export

    ldap_cfg = LDAPConfig(
        server=server,
        port=636 if ssl else port,
        use_ssl=ssl,
        username=username,
        password=password,
    )
    export_cfg = ExportConfig(
        include_gpos=include_gpos,
        include_trusts=include_trusts,
        sysvol_path=sysvol,
        output_path=output,
    )

    try:
        with LDAPConnectionManager(ldap_cfg) as mgr:
            state = run_export(mgr.connection, mgr.base_dn, server, export_cfg)
            state.save(output)
            click.echo(f"\nExport saved to {output}")
            click.echo(f"  OUs:       {len(state.ous)}")
            click.echo(f"  Users:     {len(state.users)}")
            click.echo(f"  Groups:    {len(state.groups)}")
            click.echo(f"  Computers: {len(state.computers)}")
            click.echo(f"  GPOs:      {len(state.gpos)}")
            click.echo(f"  Trusts:    {len(state.trusts)}")
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


# ── restore ──────────────────────────────────────────────────────────

@cli.command()
@click.option("--server", "-s", required=True, help="Target Domain Controller.")
@click.option("--port", "-p", default=389, type=int, help="LDAP port.")
@click.option("--ssl", is_flag=True, help="Use LDAPS.")
@click.option("--username", "-u", prompt=True, help="Bind username.")
@click.option("--password", "-pw", prompt=True, hide_input=True, help="Bind password.")
@click.option("--state-file", "-f", required=True, type=click.Path(exists=True),
              help="State JSON file to restore from.")
@click.option("--sysvol", type=click.Path(exists=True), default=None,
              help="Path to SYSVOL for GPO file restoration.")
@click.option("--default-password", default="ChangeMe123!",
              help="Default password for created users.")
@click.option("--skip-users", is_flag=True, help="Skip user creation.")
@click.option("--skip-groups", is_flag=True, help="Skip group creation.")
@click.option("--skip-computers", is_flag=True, help="Skip computer creation.")
@click.option("--skip-gpos", is_flag=True, help="Skip GPO restoration.")
@click.option("--skip-trusts", is_flag=True, help="Skip trust output.")
@click.option("--dry-run", is_flag=True, help="Validate only, make no changes.")
@click.option("--verbose", "-v", is_flag=True, help="Verbose logging.")
def restore(server, port, ssl, username, password, state_file, sysvol,
            default_password, skip_users, skip_groups, skip_computers,
            skip_gpos, skip_trusts, dry_run, verbose):
    """Restore Active Directory state from a JSON file."""
    import logging
    setup_logger(level=logging.DEBUG if verbose else logging.INFO)

    from ad_cain.core.connection import LDAPConnectionManager
    from ad_cain.core.importer import run_import

    ldap_cfg = LDAPConfig(
        server=server,
        port=636 if ssl else port,
        use_ssl=ssl,
        username=username,
        password=password,
    )
    import_cfg = ImportConfig(
        state_file=state_file,
        sysvol_path=sysvol,
        dry_run=dry_run,
        default_password=default_password,
        skip_users=skip_users,
        skip_groups=skip_groups,
        skip_computers=skip_computers,
        skip_gpos=skip_gpos,
        skip_trusts=skip_trusts,
    )

    try:
        with LDAPConnectionManager(ldap_cfg) as mgr:
            result = run_import(mgr.connection, mgr.base_dn, import_cfg)
            prefix = "[DRY RUN] " if dry_run else ""
            click.echo(f"\n{prefix}Restoration summary:")
            click.echo(f"  OUs:       {result.ous_created}")
            click.echo(f"  Users:     {result.users_created}")
            click.echo(f"  Computers: {result.computers_created}")
            click.echo(f"  Groups:    {result.groups_created}")
            click.echo(f"  GPOs:      {result.gpos_created}")
            click.echo(f"  Trusts:    {result.trusts_logged} (manual)")
            click.echo(f"  Duration:  {result.duration_seconds}s")
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


# ── validate ─────────────────────────────────────────────────────────

@cli.command()
@click.option("--state-file", "-f", required=True, type=click.Path(exists=True),
              help="State file to validate.")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output.")
def validate(state_file, verbose):
    """Validate a state file's schema and references."""
    import logging
    setup_logger(level=logging.DEBUG if verbose else logging.INFO)

    from ad_cain.core.validator import validate_state_file

    try:
        state = validate_state_file(state_file)
        click.echo(f"State file is valid: {state_file}")
        click.echo(f"  Version:   {state.version}")
        click.echo(f"  Domain:    {state.source_domain}")
        click.echo(f"  OUs:       {len(state.ous)}")
        click.echo(f"  Users:     {len(state.users)}")
        click.echo(f"  Groups:    {len(state.groups)}")
        click.echo(f"  Computers: {len(state.computers)}")
        click.echo(f"  GPOs:      {len(state.gpos)}")
        click.echo(f"  Trusts:    {len(state.trusts)}")
    except Exception as exc:
        click.echo(f"Validation failed: {exc}", err=True)
        sys.exit(1)


# ── info ─────────────────────────────────────────────────────────────

@cli.command()
@click.option("--state-file", "-f", required=True, type=click.Path(exists=True),
              help="State file to inspect.")
def info(state_file):
    """Display summary information about a state file."""
    from ad_cain.models.state import StateContainer

    try:
        state = StateContainer.load(state_file)
        click.echo(f"AD-Cain State File: {state_file}")
        click.echo(f"  Version:        {state.version}")
        click.echo(f"  Timestamp:      {state.timestamp}")
        click.echo(f"  Source domain:   {state.source_domain}")
        click.echo(f"  Source DC:       {state.source_dc}")
        click.echo(f"  Tool version:    {state.metadata.export_tool_version}")
        click.echo(f"  Export duration: {state.metadata.export_duration_seconds}s")
        click.echo()
        click.echo("Object counts:")
        click.echo(f"  OUs:       {len(state.ous)}")
        click.echo(f"  Users:     {len(state.users)}")
        click.echo(f"  Groups:    {len(state.groups)}")
        click.echo(f"  Computers: {len(state.computers)}")
        click.echo(f"  GPOs:      {len(state.gpos)}")
        click.echo(f"  Trusts:    {len(state.trusts)}")
        if state.metadata.warnings:
            click.echo()
            click.echo("Warnings:")
            for w in state.metadata.warnings:
                click.echo(f"  - {w}")
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    cli()
