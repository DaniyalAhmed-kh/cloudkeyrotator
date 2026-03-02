"""
CloudKeyRotator - Multi-Cloud Credential Exposure Validator
"""
import sys
import json
import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .detector import detect_credential
from .reporter import Reporter
from .validators.aws import AWSValidator
from .validators.azure import AzureValidator
from .validators.gcp import GCPValidator
from .validators.github import GitHubValidator
from .validators.generic import GenericValidator

console = Console()

VALIDATOR_MAP = {
    "aws_access_key":         AWSValidator,
    "azure_client_secret":    AzureValidator,
    "azure_connection_string":AzureValidator,
    "azure_sas_token":        AzureValidator,
    "gcp_service_account":    GCPValidator,
    "github_pat":             GitHubValidator,
    "github_fine_grained":    GitHubValidator,
    "generic_token":          GenericValidator,
}

def print_banner():
    console.print(Panel(
        "[bold cyan]CloudKeyRotator v1.0.0[/bold cyan]\n"
        "[dim]Multi-Cloud Credential Exposure Validator[/dim]\n\n"
        "[dim]Providers: AWS · Azure · GCP · GitHub[/dim]",
        border_style="cyan",
        padding=(1, 4),
    ))

@click.group()
@click.version_option("1.0.0", prog_name="cloudkeyrotator")
def cli():
    """CloudKeyRotator — Validate exposed cloud credentials and assess blast radius."""
    pass

def is_valid_credential_format(cred: str) -> bool:
    # Basic length and character checks for common credential types
    cred = cred.strip()
    if not cred:
        return False
    if len(cred) < 16:
        return False
    if any(c in cred for c in [' ', '\n', '\t']):
        return False
    return True

@cli.command("scan")
@click.argument("credential", required=False)
@click.option("--file", "-f", "cred_file", type=click.Path(exists=True),
              help="Read credential from file (AWS creds file, GCP JSON key, etc.)")
@click.option("--tenant-id", "-t", default=None,
              help="Azure Tenant ID (required for client secret validation)")
@click.option("--client-id", "-c", default=None,
              help="Azure Client/App ID (required for client secret validation)")
@click.option("--output", "-o", type=click.Choice(["table", "json", "markdown"]), default="table",
              help="Output format (default: table)")
@click.option("--out-file", type=click.Path(), default=None,
              help="Save report to file")
@click.option("--no-banner", is_flag=True, default=False)
@click.option("--skip-enum", is_flag=True, default=False,
              help="Skip permission enumeration (faster)")
def scan(credential, cred_file, tenant_id, client_id, output, out_file, no_banner, skip_enum):
    """
    Validate a credential and assess blast radius.

    \b
    Examples:
      cloudkeyrotator scan AKIAIOSFODNN7EXAMPLE
      cloudkeyrotator scan --file /path/to/sa-key.json
      cloudkeyrotator scan ghp_xxxx --output json
      echo "ghp_xxxx" | cloudkeyrotator scan
    """
    if not no_banner:
        print_banner()

    # --- Read credential ---
    if cred_file:
        with open(cred_file, "r") as fh:
            raw = fh.read().strip()
        console.print(f"[dim]→ Loaded from file: {cred_file}[/dim]")
    elif credential:
        raw = credential.strip()
    elif not sys.stdin.isatty():
        raw = sys.stdin.read().strip()
        console.print("[dim]→ Read from stdin[/dim]")
    else:
        raw = click.prompt("Paste credential", hide_input=True)

    # Input validation
    if not is_valid_credential_format(raw):
        console.print("[red]✗ Invalid credential format.[/red]")
        sys.exit(1)

    if not raw:
        console.print("[red]✗ No credential provided.[/red]")
        sys.exit(1)

    # --- Detect ---
    console.print()
    with console.status("[cyan]Detecting credential type...[/cyan]"):
        detected = detect_credential(raw)

    if not detected:
        console.print("[yellow]⚠  Could not auto-detect type. Running generic checks.[/yellow]")
        detected = {"type": "generic_token", "provider": "Unknown", "meta": {}}

    cred_type = detected["type"]
    provider  = detected["provider"]
    meta      = detected.get("meta", {})

    console.print(Panel(
        f"[bold]Provider:[/bold]  [cyan]{provider}[/cyan]\n"
        f"[bold]Type:[/bold]      [cyan]{cred_type}[/cyan]\n"
        f"[bold]Pattern:[/bold]   {meta.get('pattern_name', 'regex match')}",
        title="[bold yellow]🔍 Credential Detected[/bold yellow]",
        border_style="yellow",
    ))

    if tenant_id:
        meta["tenant_id"] = tenant_id
    if client_id:
        meta["client_id"] = client_id

    if cred_type == "aws_access_key" and "secret_key" not in meta:
        if sys.stdin.isatty():
            secret = click.prompt("AWS Secret Access Key", hide_input=True)
            meta["secret_key"] = secret
        else:
            console.print("[yellow]⚠  AWS Secret Key not provided — limited validation.[/yellow]")

    # --- Validate ---
    ValidatorClass = VALIDATOR_MAP.get(cred_type, GenericValidator)
    validator = ValidatorClass(raw, meta)

    with console.status(f"[cyan]Validating against {provider} APIs...[/cyan]"):
        result = validator.validate()

    if skip_enum:
        result["permissions"] = []
        result["blast_radius"] = {"note": "Skipped (--skip-enum)"}
    else:
        with console.status("[cyan]Enumerating permissions & assessing blast radius...[/cyan]"):
            validator.enumerate(result)

    reporter = Reporter(console)
    if output == "table":
        reporter.print_table(result)
    elif output == "json":
        click.echo(json.dumps(result, indent=2, default=str))
    elif output == "markdown":
        click.echo(reporter.to_markdown(result))

    if out_file:
        if output == "json":
            with open(out_file, "w") as fh:
                json.dump(result, fh, indent=2, default=str)
        else:
            with open(out_file, "w") as fh:
                fh.write(reporter.to_markdown(result))
        console.print(f"\n[green]✓ Report saved → {out_file}[/green]")

    sys.exit(0 if result.get("valid") else 1)


@cli.command("detect")
@click.argument("credential")
def detect_cmd(credential):
    """Detect credential type without any network requests."""
    result = detect_credential(credential.strip())
    if result:
        console.print(Panel(
            f"[bold]Provider:[/bold]   [cyan]{result['provider']}[/cyan]\n"
            f"[bold]Type:[/bold]       [cyan]{result['type']}[/cyan]\n"
            f"[bold]Pattern:[/bold]    {result['meta'].get('pattern_name', '-')}\n"
            f"[bold]Confidence:[/bold] {result.get('confidence', 'high')}",
            title="[bold green]Detection Result[/bold green]",
            border_style="green",
        ))
    else:
        console.print("[red]✗ Unknown or unrecognized credential format.[/red]")
        sys.exit(1)


@cli.command("revoke-guide")
@click.argument("provider", type=click.Choice(["aws", "azure", "gcp", "github"], case_sensitive=False))
def revoke_guide(provider):
    """Print revocation steps for a given provider."""
    guides = {
        "aws": (
            "[bold cyan]AWS — Immediate Revocation Steps[/bold cyan]\n\n"
            "[yellow]1. Deactivate via AWS CLI:[/yellow]\n"
            "   aws iam update-access-key --access-key-id AKIA... --status Inactive --user-name <user>\n"
            "   aws iam delete-access-key  --access-key-id AKIA... --user-name <user>\n\n"
            "[yellow]2. Check for usage in CloudTrail:[/yellow]\n"
            "   aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA...\n\n"
            "[yellow]3. Hunt for persistence:[/yellow]\n"
            "   • New IAM users / roles\n"
            "   • New Lambda or EC2 instances\n"
            "   • Modified S3 bucket policies\n"
            "   • Disabled CloudTrail trails\n\n"
            "[yellow]4. Console path:[/yellow]\n"
            "   IAM → Users → [user] → Security credentials → Deactivate/Delete key"
        ),
        "azure": (
            "[bold cyan]Azure — Immediate Revocation Steps[/bold cyan]\n\n"
            "[yellow]1. Client Secret via Azure CLI:[/yellow]\n"
            "   az ad app credential delete --id <app-id> --key-id <key-id>\n\n"
            "[yellow]2. Storage Connection String:[/yellow]\n"
            "   az storage account keys renew --account-name <name> --resource-group <rg> --key key1\n\n"
            "[yellow]3. Investigate in Entra ID:[/yellow]\n"
            "   • Sign-in logs for the service principal\n"
            "   • Azure Activity Log for RBAC changes\n"
            "   • Check new role assignments or app consent grants\n\n"
            "[yellow]4. Console path:[/yellow]\n"
            "   Entra ID → App registrations → [app] → Certificates & secrets → Delete"
        ),
        "gcp": (
            "[bold cyan]GCP — Immediate Revocation Steps[/bold cyan]\n\n"
            "[yellow]1. Delete the key via gcloud:[/yellow]\n"
            "   gcloud iam service-accounts keys delete KEY_ID --iam-account=SA@PROJECT.iam.gserviceaccount.com\n\n"
            "[yellow]2. List all keys to find others:[/yellow]\n"
            "   gcloud iam service-accounts keys list --iam-account=SA@PROJECT.iam.gserviceaccount.com\n\n"
            "[yellow]3. Audit usage in Cloud Logging:[/yellow]\n"
            "   Filter: protoPayload.authenticationInfo.principalEmail = SA_EMAIL\n\n"
            "[yellow]4. Hunt for persistence:[/yellow]\n"
            "   • New service accounts created\n"
            "   • IAM policy bindings added\n"
            "   • BigQuery or GCS exfiltration\n"
            "   • Pub/Sub subscriptions"
        ),
        "github": (
            "[bold cyan]GitHub — Immediate Revocation Steps[/bold cyan]\n\n"
            "[yellow]1. Revoke via settings:[/yellow]\n"
            "   Settings → Developer settings → Personal access tokens → Delete\n\n"
            "[yellow]2. Via API:[/yellow]\n"
            "   curl -X DELETE -H 'Authorization: Bearer <token>' https://api.github.com/installation/token\n\n"
            "[yellow]3. Audit repository activity:[/yellow]\n"
            "   • Check commit history for unauthorized pushes\n"
            "   • Review Actions workflow runs for injected steps\n"
            "   • Check for new webhooks, deploy keys, or OAuth apps\n\n"
            "[yellow]4. Organization audit log (if org member):[/yellow]\n"
            "   org → Settings → Audit log → Filter by token"
        ),
    }
    console.print(Panel(guides[provider.lower()], border_style="red", padding=(1, 2)))


def main():
    try:
        cli()
    except Exception as e:
        console.print(f"[red]✗ Unexpected error: {e}[/red]")
        sys.exit(2)

if __name__ == "__main__":
    main()
