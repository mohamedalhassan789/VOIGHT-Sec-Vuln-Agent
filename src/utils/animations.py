"""
Animations and Visual Effects for SecVuln Agent
Chicago PD Intelligence Unit Theme - VOIGHT Style
"We protect. Whatever it takes."
"""

import time
import sys
import itertools
import random
from typing import Optional

# Enable UTF-8 encoding for Windows console
if sys.platform == 'win32':
    try:
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')
    except Exception:
        pass  # If it fails, continue without UTF-8


# Color codes (cross-platform compatible)
class Colors:
    """ANSI color codes for terminal output - CPD Theme."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    # CPD Color Scheme
    CPD_BLUE = '\033[38;5;18m'  # Dark blue (CPD uniform)
    RED = '\033[91m'  # Danger/Critical
    GREEN = '\033[92m'  # All clear
    YELLOW = '\033[93m'  # Warning/Amber lights
    BLUE = '\033[94m'  # Info
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'  # Report text
    GRAY = '\033[90m'  # Secondary text

    # Background colors
    BG_RED = '\033[101m'
    BG_BLUE = '\033[104m'
    BG_YELLOW = '\033[103m'


def print_colored(text: str, color: str = Colors.WHITE, bold: bool = False, end: str = '\n'):
    """Print colored text to terminal."""
    style = Colors.BOLD if bold else ''
    print(f"{style}{color}{text}{Colors.RESET}", end=end)


# Voight Quotes
VOIGHT_QUOTES = [
    "I'm the guy who does what needs to be done",
    "This is my unit, we handle things our way",
    "Nobody gets hurt on my watch",
    "We protect this city, no matter what",
    "Whatever it takes to keep you safe",
    "I don't play by the rules, I make my own"
]

# Banner Taglines
BANNER_TAGLINES = [
    "VOIGHT - Protecting your infrastructure since 2025",
    "No vulnerability escapes the Intelligence Unit",
    "We do whatever it takes to keep you secure",
    "Your security. Our watch. 24/7."
]

# PD Radio Codes
RADIO_CODES = {
    'success': '10-4',      # Acknowledged
    'scanning': '10-20',    # Location
    'critical': '10-33',    # Emergency
    'complete': 'Code 4',   # No further assistance needed
    'alert': 'Signal 25',   # Report in person
    'info': '10-4',         # General acknowledgment
    'error': '10-999',      # Officer down / Critical failure
    'warning': '10-34'      # Trouble at this station
}


def police_siren_effect(duration: float = 2.0):
    """Police siren effect - Red/Blue color flashing."""
    end_time = time.time() + duration
    siren_pattern = "  🚨  "

    while time.time() < end_time:
        # Red flash
        print_colored(siren_pattern * 10, Colors.RED, bold=True, end='\r')
        sys.stdout.flush()
        time.sleep(0.15)

        # Blue flash
        print_colored(siren_pattern * 10, Colors.BLUE, bold=True, end='\r')
        sys.stdout.flush()
        time.sleep(0.15)

    # Clear line
    print("\r" + " " * 80, end='\r')


def print_gradient_line(text: str, colors: list):
    """Print text with gradient colors."""
    chars_per_color = len(text) // len(colors)
    result = ""

    for i, char in enumerate(text):
        color_index = min(i // max(1, chars_per_color), len(colors) - 1)
        result += f"{colors[color_index]}{char}"

    print(result + Colors.RESET)


def animated_header_setup():
    """Display animated CPD Intelligence Unit header for setup wizard."""

    # Clear screen (cross-platform)
    print("\033[2J\033[H", end='')

    # Police siren effect
    police_siren_effect(2.0)

    # Case File Opening
    print_colored("\n    Case File Opening...\n", Colors.YELLOW, bold=True)
    time.sleep(0.5)

    case_file = r"""
    ┌─────────────────────────────────────────┐
    │  INTELLIGENCE UNIT          │
    │ Case File: SEC-VULN-2025          │
    │ Lead Detective: VOIGHT                  │
    │ Status: [ACTIVE]                        │
    └─────────────────────────────────────────┘
    """

    # Print case file header
    for line in case_file.split('\n'):
        print_colored(line, Colors.CPD_BLUE, bold=True)
        time.sleep(0.1)

    print()

    # VOIGHT ASCII logo
    logo = r"""
   ██╗   ██╗ ██████╗ ██╗ ██████╗ ██╗  ██╗████████╗
   ██║   ██║██╔═══██╗██║██╔════╝ ██║  ██║╚══██╔══╝
   ██║   ██║██║   ██║██║██║  ███╗███████║   ██║
   ╚██╗ ██╔╝██║   ██║██║██║   ██║██╔══██║   ██║
    ╚████╔╝ ╚██████╔╝██║╚██████╔╝██║  ██║   ██║
     ╚═══╝   ╚═════╝ ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝
    """

    # Animate logo with blue gradient
    for line in logo.split('\n'):
        print_colored(line, Colors.BLUE, bold=True)
        time.sleep(0.08)

    # Tagline
    tagline = "        Security Vulnerability Intelligence Agent"
    print_colored(tagline, Colors.CYAN, bold=True)

    # Voight quote
    quote = f'          "{random.choice(VOIGHT_QUOTES)}"'
    print_colored(quote, Colors.GRAY)
    print()

    # Badge scan animation
    print_colored("    🔍 Scanning credentials", Colors.YELLOW, end='')
    for _ in range(3):
        for dot in ['   ', '.  ', '.. ', '...']:
            print(f"\r    🔍 Scanning credentials{dot}", end='')
            sys.stdout.flush()
            time.sleep(0.2)

    # Badge scan progress bar
    print()
    for i in range(1, 21):
        progress_bar(i, 20, "📋 Badge scan", length=30)
        time.sleep(0.05)

    # Unit ready
    print_colored("\n    ✓ [Code 4] Intelligence Unit ready for deployment\n", Colors.GREEN, bold=True)
    time.sleep(0.5)


def animated_header_agent():
    """Display animated CPD Intelligence Unit header for main agent."""

    # Clear screen
    print("\033[2J\033[H", end='')

    # Police siren effect
    police_siren_effect(2.0)

    # Case File Opening
    print_colored("\n    Intelligence Unit - Active Monitoring\n", Colors.YELLOW, bold=True)
    time.sleep(0.3)

    # Case file header
    case_file = r"""
    ┌─────────────────────────────────────────┐
    │  INTELLIGENCE UNIT          │
    │ Case File: SEC-VULN-2025          │
    │ Lead Detective: VOIGHT                  │
    │ Status: [ACTIVE]                        │
    └─────────────────────────────────────────┘
    """

    for line in case_file.split('\n'):
        print_colored(line, Colors.CPD_BLUE, bold=True)
        time.sleep(0.08)

    print()

    # VOIGHT ASCII logo
    logo = r"""
   ██╗   ██╗ ██████╗ ██╗ ██████╗ ██╗  ██╗████████╗
   ██║   ██║██╔═══██╗██║██╔════╝ ██║  ██║╚══██╔══╝
   ██║   ██║██║   ██║██║██║  ███╗███████║   ██║
   ╚██╗ ██╔╝██║   ██║██║██║   ██║██╔══██║   ██║
    ╚████╔╝ ╚██████╔╝██║╚██████╔╝██║  ██║   ██║
     ╚═══╝   ╚═════╝ ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝
    """

    # Animate logo
    for line in logo.split('\n'):
        print_colored(line, Colors.BLUE, bold=True)
        time.sleep(0.06)

    # Tagline and quote
    tagline = "        Security Vulnerability Intelligence Agent"
    print_colored(tagline, Colors.CYAN, bold=True)

    quote = f'          "{random.choice(VOIGHT_QUOTES)}"'
    print_colored(quote, Colors.GRAY)

    # Random banner tagline
    banner = f"        {random.choice(BANNER_TAGLINES)}"
    print_colored(banner, Colors.YELLOW)
    print()

    # Animated loading with police-themed spinners
    police_spinners = itertools.cycle(['🚨', '🔍', '📋', '🎯'])

    messages = [
        ("[10-20]", "Loading configuration"),
        ("[10-20]", "Initializing collectors"),
        ("[10-20]", "Setting up processors"),
        ("[10-20]", "Preparing notifiers")
    ]

    for code, message in messages:
        for _ in range(8):
            print_colored(f"    {next(police_spinners)} {code} {message}...", Colors.YELLOW, end='\r')
            sys.stdout.flush()
            time.sleep(0.1)
        print_colored(f"    ✓ [10-4] {message}", Colors.GREEN)

    print_colored("\n    [Code 4] All units operational. Intelligence Unit standing by.\n", Colors.GREEN, bold=True)


def spinner_context(message: str, success_message: Optional[str] = None):
    """Context manager for showing a police-themed spinner during long operations."""

    class SpinnerContext:
        def __init__(self, msg, success_msg):
            self.message = msg
            self.success_message = success_msg or f"{msg} complete"
            self.spinner = itertools.cycle(['🚨', '🔍', '📋', '🎯'])  # Police-themed spinners
            self.running = False

        def __enter__(self):
            self.running = True
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.running = False
            if exc_type is None:
                print(f"\r{' ' * 60}\r", end='')
                print_colored(f"    ✓ [10-4] {self.success_message}", Colors.GREEN)
            else:
                print(f"\r{' ' * 60}\r", end='')
                print_colored(f"    ✗ [10-999] {self.message} failed", Colors.RED)
            return False

        def update(self):
            """Call this periodically in your loop."""
            print_colored(f"    {next(self.spinner)} [10-20] {self.message}...", Colors.YELLOW, end='\r')
            sys.stdout.flush()

    return SpinnerContext(message, success_message)


def progress_bar(current: int, total: int, prefix: str = '', length: int = 40):
    """Display a progress bar."""
    percent = current / total
    filled = int(length * percent)
    bar = '█' * filled + '░' * (length - filled)

    # Color based on progress
    if percent < 0.33:
        color = Colors.RED
    elif percent < 0.66:
        color = Colors.YELLOW
    else:
        color = Colors.GREEN

    print_colored(f"\r    {prefix} |{bar}| {int(percent * 100)}% ({current}/{total})", color, end='')
    sys.stdout.flush()

    if current == total:
        print()  # New line when complete


def print_box(title: str, content: list, color: str = Colors.CYAN):
    """Print content in a nice box."""
    width = max(len(title), max(len(line) for line in content)) + 4

    print_colored("    ╔" + "═" * width + "╗", color)
    print_colored(f"    ║ {title.center(width - 2)} ║", color, bold=True)
    print_colored("    ╠" + "═" * width + "╣", color)

    for line in content:
        padding = width - len(line) - 2
        print_colored(f"    ║ {line}{' ' * padding} ║", color)

    print_colored("    ╚" + "═" * width + "╝", color)


def print_status(message: str, status: str = 'info'):
    """Print a status message with PD radio code."""
    # Map status to PD radio codes and colors
    status_map = {
        'success': (f"[{RADIO_CODES['success']}]", '✓', Colors.GREEN),
        'error': (f"[{RADIO_CODES['error']}]", '✗', Colors.RED),
        'warning': (f"[{RADIO_CODES['warning']}]", '⚠', Colors.YELLOW),
        'info': (f"[{RADIO_CODES['info']}]", 'ℹ', Colors.BLUE),
        'scanning': (f"[{RADIO_CODES['scanning']}]", '🔍', Colors.CYAN),
        'critical': (f"[{RADIO_CODES['critical']}]", '🚨', Colors.RED),
        'complete': (f"[{RADIO_CODES['complete']}]", '✓', Colors.GREEN),
        'alert': (f"[{RADIO_CODES['alert']}]", '📢', Colors.YELLOW)
    }

    code, icon, color = status_map.get(status, status_map['info'])
    print_colored(f"    {icon} {code} {message}", color)


def celebrate():
    """Show a CPD-themed celebration animation."""
    celebration = [
        "    🚨 ⭐ 🎖️ ⭐ 🚨 ⭐ 🎖️ ⭐ 🚨",
        "    ⭐ 🎖️ ⭐ 🚨 ⭐ 🎖️ ⭐ 🚨 ⭐",
        "    🎖️ ⭐ 🚨 ⭐ 🎖️ ⭐ 🚨 ⭐ 🎖️"
    ]

    for _ in range(3):
        for line in celebration:
            print_colored(line, Colors.BLUE, bold=True)
            time.sleep(0.1)
        print("\033[3A", end='')  # Move cursor up 3 lines
        time.sleep(0.2)

    print("\n" * 3)
    print_colored("    [Code 4] Mission accomplished. Unit standing down.\n", Colors.GREEN, bold=True)


def typewriter_effect(text: str, color: str = Colors.WHITE, delay: float = 0.03):
    """Print text with typewriter effect."""
    for char in text:
        print_colored(char, color, end='')
        sys.stdout.flush()
        time.sleep(delay)
    print()


# Example usage and testing
if __name__ == "__main__":
    # Test setup header
    print_colored("Testing Setup Wizard Header...\n", Colors.CYAN, bold=True)
    animated_header_setup()
    time.sleep(2)

    # Test agent header
    print_colored("\n\nTesting Agent Header...\n", Colors.CYAN, bold=True)
    animated_header_agent()
    time.sleep(2)

    # Test progress bar
    print("\n[10-20] Testing progress bar:")
    for i in range(1, 51):
        progress_bar(i, 50, "🔍 Scanning", length=40)
        time.sleep(0.05)

    # Test status messages
    print("\n[10-20] Testing PD radio code status messages:")
    print_status("Agent initialized successfully", 'success')
    print_status("Scanning vulnerability sources", 'scanning')
    print_status("Critical vulnerability detected", 'critical')
    print_status("Low battery warning", 'warning')
    print_status("Connection failed", 'error')
    print_status("System information", 'info')
    print_status("All systems operational", 'complete')
    print_status("Immediate action required", 'alert')

    # Test celebration
    print("\n[10-20] Testing celebration:")
    celebrate()

    # Test box
    print_box("CASE SUMMARY - SEC-VULN-2025", [
        "Total vulnerabilities detected: 42",
        "Critical (P0): 5",
        "High (P1): 12",
        "Medium (P2): 25",
        "",
        "Status: All alerts dispatched",
        "Detective: VOIGHT"
    ], Colors.CPD_BLUE)
