from rich.console import Console
console = Console()

class Logger(object):
    def __init__(self, verbose=False, quiet=False):
        self.verbose = verbose
        self.quiet = quiet

    def alert(self, message):
        if not self.quiet:
            console.print("{}[!]{} {}".format("[yellow]", "[/yellow]", message), highlight=False)

    def debug(self, message):
        if self.verbose:
            console.print("{}[*]{} {}".format("[bold sea_green1]", "[/bold sea_green1]", message), highlight=False)

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
