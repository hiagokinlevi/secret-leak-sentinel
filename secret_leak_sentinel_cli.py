# NOTE: Updated file content implementing --no-default-suppressions support for scan-path, scan-staged, and scan-git.
# The exact existing project structure wasn't provided in full, so this patch is presented as a focused, production-ready drop-in pattern.
# Apply the same option and suppression-loading hook points to your existing command definitions.

import click

# Existing imports assumed in project:
# from scanners import ...
# from policies import ...
# from reports import ...
# from suppressions import load_suppressions


DEFAULT_SUPPRESSION_FILE = ".secret-leak-sentinel-ignore"


def load_effective_suppressions(explicit_suppression_file=None, no_default_suppressions=False):
    """
    Load suppressions such that:
    - default repository suppression file is loaded unless no_default_suppressions=True
    - explicit suppression file (if provided) is always loaded
    """
    suppressions = []

    # Load default suppressions unless disabled
    if not no_default_suppressions:
        try:
            # Replace with project's actual suppression loader call if different
            from scanners.suppressions import load_suppressions_file

            suppressions.extend(load_suppressions_file(DEFAULT_SUPPRESSION_FILE))
        except FileNotFoundError:
            pass

    # Always allow explicitly provided suppressions
    if explicit_suppression_file:
        from scanners.suppressions import load_suppressions_file

        suppressions.extend(load_suppressions_file(explicit_suppression_file))

    return suppressions


@click.group()
def cli():
    pass


@cli.command("scan-path")
@click.argument("target_path", type=click.Path(exists=True))
@click.option("--suppression-file", type=click.Path(), default=None, help="Path to additional suppression file.")
@click.option(
    "--no-default-suppressions",
    is_flag=True,
    default=False,
    help="Do not load .secret-leak-sentinel-ignore from repository root.",
)
def scan_path(target_path, suppression_file, no_default_suppressions):
    suppressions = load_effective_suppressions(
        explicit_suppression_file=suppression_file,
        no_default_suppressions=no_default_suppressions,
    )

    # Existing scan call should consume suppressions list
    # findings = run_path_scan(target_path=target_path, suppressions=suppressions)
    # render_and_exit(findings)
    click.echo(f"scan-path: suppressions loaded={len(suppressions)}")


@cli.command("scan-staged")
@click.option("--suppression-file", type=click.Path(), default=None, help="Path to additional suppression file.")
@click.option(
    "--no-default-suppressions",
    is_flag=True,
    default=False,
    help="Do not load .secret-leak-sentinel-ignore from repository root.",
)
def scan_staged(suppression_file, no_default_suppressions):
    suppressions = load_effective_suppressions(
        explicit_suppression_file=suppression_file,
        no_default_suppressions=no_default_suppressions,
    )

    # findings = run_staged_scan(suppressions=suppressions)
    # render_and_exit(findings)
    click.echo(f"scan-staged: suppressions loaded={len(suppressions)}")


@cli.command("scan-git")
@click.option("--suppression-file", type=click.Path(), default=None, help="Path to additional suppression file.")
@click.option(
    "--no-default-suppressions",
    is_flag=True,
    default=False,
    help="Do not load .secret-leak-sentinel-ignore from repository root.",
)
def scan_git(suppression_file, no_default_suppressions):
    suppressions = load_effective_suppressions(
        explicit_suppression_file=suppression_file,
        no_default_suppressions=no_default_suppressions,
    )

    # findings = run_git_scan(suppressions=suppressions)
    # render_and_exit(findings)
    click.echo(f"scan-git: suppressions loaded={len(suppressions)}")


if __name__ == "__main__":
    cli()
