"""
Ephemera CLI - SUDO History Command
Displays scrolling list of sudo access events.
"""
import sys
import requests
from .common import BASE_URL, load_session

# ANSI Color Codes
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

def colorize(text, color):
    """Apply ANSI color to text, with fallback for non-TTY."""
    if sys.stdout.isatty():
        return f"{color}{text}{Colors.RESET}"
    return text

def result_badge(result):
    """Return colored badge for result type."""
    badges = {
        'approved': colorize('→ Approved', Colors.GREEN),
        'denied': colorize('→ Denied', Colors.RED),
        'timeout': colorize('→ Timeout', Colors.YELLOW),
    }
    return badges.get(result.lower(), result)

def print_sudo_history(args):
    """Display sudo history in a formatted table."""
    print(f"\n{Colors.BOLD}SUDO Access History{Colors.RESET}" if sys.stdout.isatty() else "\nSUDO Access History")
    print("═" * 60)
    
    session_data = load_session()
    if not session_data:
        print(colorize("Not logged in. Run: ephemera login", Colors.RED))
        return
    
    try:
        s = requests.Session()
        s.cookies.update(session_data['cookies'])
        
        limit = getattr(args, 'limit', 20)
        res = s.get(f"{BASE_URL}/api/sudo/history", params={"limit": limit})
        
        if res.status_code == 401:
            print(colorize("Session expired. Run: ephemera login", Colors.RED))
            return
        
        if res.status_code != 200:
            print(f"Error: {res.text}")
            return
        
        history = res.json().get('history', [])
        
        if not history:
            print(colorize("No sudo history found.", Colors.DIM))
            print("═" * 60)
            return
        
        # Print header
        print(f"{'TIME':<20} {'COMMAND':<20} {'RESULT'}")
        print("─" * 60)
        
        for event in history:
            # Format time (2025-12-05T19:20:00Z -> 2025-12-05 19:20)
            time_str = event.get('completed_at', event.get('created_at', ''))[:16].replace('T', ' ')
            
            # Format command (truncate if too long)
            command = event.get('command', 'sudo')[:18]
            hostname = event.get('hostname', 'unknown')
            cmd_display = f"{command}@{hostname}"[:20]
            
            # Result badge
            result = result_badge(event.get('result', 'unknown'))
            
            print(f"{time_str:<20} {cmd_display:<20} {result}")
        
        print("═" * 60)
        print(f"Showing {len(history)} most recent events")
        
    except requests.RequestException as e:
        print(colorize(f"Error connecting to server: {e}", Colors.RED))
    except Exception as e:
        print(colorize(f"Error: {e}", Colors.RED))
