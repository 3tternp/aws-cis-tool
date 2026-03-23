import argparse
import sys
from pathlib import Path
from colorama import init, Fore, Style
from tabulate import tabulate
from aws_cis_tool import __version__
from aws_cis_tool.auth import AWSAuth
from aws_cis_tool.checks import get_all_checks
from aws_cis_tool.report import ReportGenerator

def print_banner():
    banner = f"""{Fore.MAGENTA}
    ___ _       __ _____   _____________   ____                  __                         __  
   /   | |     / // ___/  / ____/  _/   | / __ )___  ____  _____/ /_  ____ ___  ____ ______/ /__
  / /| | | /| / / \\__ \\  / /    / // /| |/ __  / _ \\/ __ \\/ ___/ __ \\/ __ `__ \\/ __ `/ ___/ //_/
 / ___ | |/ |/ / ___/ / / /____/ // ___ / /_/ /  __/ / / / /__/ / / / / / / / / /_/ / /  / ,<   
/_/  |_|__/|__//____/  \\____/___/_/  |_/_____/\\___/_/ /_/\\___/_/ /_/_/ /_/ /_/\\__,_/_/  /_/|_|  
                                                                                                
    v{__version__}
    {Style.RESET_ALL}"""
    print(banner)

def print_changelog():
    changelog_path = Path(__file__).resolve().parent / "CHANGELOG.md"
    if not changelog_path.exists():
        print("CHANGELOG.md not found.")
        return
    print(changelog_path.read_text(encoding="utf-8", errors="replace"))

def main():
    init(autoreset=True)
    parser = argparse.ArgumentParser(description=f"AWS CIS Benchmark Tool v{__version__}")
    parser.add_argument("-p", "--profile", help="AWS profile name to use (for standard or SSO)", default=None)
    parser.add_argument("-r", "--region", help="AWS region to use", default=None)
    parser.add_argument("-o", "--output", help="Output format: json, html, pdf, or all", choices=['json', 'html', 'pdf', 'all'], default='all')
    parser.add_argument("-d", "--output-dir", help="Directory to save reports", default="reports")
    parser.add_argument("--changelog", help="Print changelog and exit", action="store_true")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    
    args = parser.parse_args()

    if args.changelog:
        print_changelog()
        return
    
    print_banner()
    
    auth = AWSAuth(profile_name=args.profile, region_name=args.region)
    if not auth.authenticate():
        sys.exit(1)
        
    print(f"\n{Fore.CYAN}[*] Initializing CIS Benchmark Checks...{Style.RESET_ALL}")
    checks = get_all_checks(auth)
    
    print(f"{Fore.CYAN}[*] Starting {len(checks)} checks...{Style.RESET_ALL}\n")
    
    results = []
    summary = {"PASS": 0, "FAIL": 0, "ERROR": 0}
    
    for check in checks:
        print(f"Running Check {check.check_id} - {check.title}...", end=" ")
        check.execute()
        result_dict = check.to_dict()
        results.append(result_dict)
        
        status = result_dict['result']
        if status == 'PASS':
            print(f"{Fore.GREEN}[PASS]{Style.RESET_ALL}")
            summary["PASS"] += 1
        elif status == 'FAIL':
            print(f"{Fore.RED}[FAIL]{Style.RESET_ALL}")
            summary["FAIL"] += 1
        else:
            print(f"{Fore.YELLOW}[ERROR]{Style.RESET_ALL}")
            summary["ERROR"] += 1

    print("\n" + "="*50)
    print(f"{Fore.CYAN}Execution Summary{Style.RESET_ALL}")
    print("="*50)
    
    table_data = [
        [f"{Fore.GREEN}PASS{Style.RESET_ALL}", summary['PASS']],
        [f"{Fore.RED}FAIL{Style.RESET_ALL}", summary['FAIL']],
        [f"{Fore.YELLOW}ERROR{Style.RESET_ALL}", summary['ERROR']]
    ]
    print(tabulate(table_data, headers=["Status", "Count"], tablefmt="grid"))
    print("\n")
    
    # Get account ID for report naming
    sts = auth.get_client('sts')
    account_id = sts.get_caller_identity().get('Account')
    
    print(f"{Fore.CYAN}[*] Generating Reports...{Style.RESET_ALL}")
    report_gen = ReportGenerator(results, account_id, output_dir=args.output_dir)
    
    if args.output in ['json', 'all']:
        json_file = report_gen.generate_json()
        print(f"{Fore.GREEN}[+] JSON report saved to: {json_file}{Style.RESET_ALL}")
        
    if args.output in ['html', 'all']:
        html_file = report_gen.generate_html()
        print(f"{Fore.GREEN}[+] HTML report saved to: {html_file}{Style.RESET_ALL}")

    if args.output in ['pdf', 'all']:
        pdf_file = report_gen.generate_pdf()
        if pdf_file:
            print(f"{Fore.GREEN}[+] PDF report saved to: {pdf_file}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
