from rich.console import Console
console = Console()

class Logger(object):
    def __init__(self, verbosity=0, quiet=False):
        self.verbosity = verbosity
        self.quiet = quiet
        if verbosity == 3:
            exit(0)
        elif verbosity == 4:
            exit(0)
        elif verbosity == 5:
            exit(0)

        elif verbosity == 6:
            exit(0)
        elif verbosity > 6:
            exit(0)

    def alert(self, message):
        if not self.quiet:
            console.print("{}[!]{} {}".format("[yellow]", "[/yellow]", message), highlight=False)

    def debug(self, message):
        if self.verbosity == 2:
            console.print("{}[DEBUG]{} {}".format("[yellow3]", "[/yellow3]", message), highlight=False)

    def verbose(self, message):
        if self.verbosity >= 1:
            console.print("{}[VERBOSE]{} {}".format("[blue]", "[/blue]", message), highlight=False)

    def info(self, message):
        if not self.quiet:
            console.print("{}[*]{} {}".format("[bold blue]", "[/bold blue]", message), highlight=False)

    def success(self, message):
        if not self.quiet:
            console.print("{}[+]{} {}".format("[bold green]", "[/bold green]", message), highlight=False)

    def warning(self, message):
        if not self.quiet:
            console.print("{}[-]{} {}".format("[bold orange3]", "[/bold orange3]", message), highlight=False)

    def error(self, message):
        if not self.quiet:
            console.print("{}[-]{} {}".format("[bold red]", "[/bold red]", message), highlight=False)
