import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import sys
import re
import os
from tabulate import tabulate

from aws_cis_tool.auth import AWSAuth
from aws_cis_tool.checks import get_all_checks
from aws_cis_tool.report import ReportGenerator

# Regex to strip ANSI color codes from stdout before inserting into Tkinter Text
ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

class TextRedirector:
    def __init__(self, widget):
        self.widget = widget

    def write(self, text):
        clean_text = ansi_escape.sub('', text)
        self.widget.configure(state="normal")
        self.widget.insert(tk.END, clean_text)
        self.widget.see(tk.END)
        self.widget.configure(state="disabled")

    def flush(self):
        pass

class AWSCISApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AWS CIS Benchmark Scanner")
        self.geometry("850x700")
        
        # Configure grid weight for responsive design
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        self.create_widgets()
        
        # Redirect standard output and error to the console widget
        self.redirector = TextRedirector(self.console)
        sys.stdout = self.redirector
        sys.stderr = self.redirector
        
    def create_widgets(self):
        main_frame = ttk.Frame(self)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=15, pady=15)
        main_frame.grid_columnconfigure(0, weight=1)
        
        # --- Authentication Settings ---
        auth_frame = ttk.LabelFrame(main_frame, text="Authentication Settings")
        auth_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10), ipady=5)
        auth_frame.grid_columnconfigure(1, weight=1)
        
        self.auth_mode_var = tk.StringVar(value="profile")
        
        mode_frame = ttk.Frame(auth_frame)
        mode_frame.grid(row=0, column=0, columnspan=2, sticky="w", padx=10, pady=5)
        
        ttk.Radiobutton(mode_frame, text="AWS Profile / SSO", variable=self.auth_mode_var, value="profile", command=self.toggle_auth_fields).pack(side=tk.LEFT, padx=(0, 20))
        ttk.Radiobutton(mode_frame, text="Access Keys", variable=self.auth_mode_var, value="keys", command=self.toggle_auth_fields).pack(side=tk.LEFT)
        
        # Profile specific fields
        self.profile_label = ttk.Label(auth_frame, text="Profile Name:")
        self.profile_entry = ttk.Entry(auth_frame)
        self.sso_btn = ttk.Button(auth_frame, text="Login via SSO", command=self.open_sso_terminal)
        
        # Keys specific fields
        self.ak_label = ttk.Label(auth_frame, text="Access Key ID:")
        self.ak_entry = ttk.Entry(auth_frame)
        
        self.sk_label = ttk.Label(auth_frame, text="Secret Access Key:")
        self.sk_entry = ttk.Entry(auth_frame, show="*")
        
        self.token_label = ttk.Label(auth_frame, text="Session Token (Optional):")
        self.token_entry = ttk.Entry(auth_frame, show="*")
        
        # Common field
        self.region_label = ttk.Label(auth_frame, text="Region:")
        self.region_entry = ttk.Entry(auth_frame)
        
        # --- Report Settings ---
        report_frame = ttk.LabelFrame(main_frame, text="Report Settings")
        report_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10), ipady=5)
        report_frame.grid_columnconfigure(1, weight=1)
        
        self.json_var = tk.BooleanVar(value=True)
        self.html_var = tk.BooleanVar(value=True)
        self.pdf_var = tk.BooleanVar(value=True)
        
        format_frame = ttk.Frame(report_frame)
        format_frame.grid(row=0, column=0, columnspan=3, sticky="w", padx=10, pady=5)
        ttk.Label(format_frame, text="Formats:").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Checkbutton(format_frame, text="JSON", variable=self.json_var).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(format_frame, text="HTML", variable=self.html_var).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(format_frame, text="PDF", variable=self.pdf_var).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(report_frame, text="Output Directory:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.out_dir_entry = ttk.Entry(report_frame)
        self.out_dir_entry.insert(0, "reports")
        self.out_dir_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=5)
        
        ttk.Button(report_frame, text="Browse", command=self.browse_dir).grid(row=1, column=2, padx=10, pady=5)
        
        # --- Action Button ---
        self.run_btn = ttk.Button(main_frame, text="Run Benchmark Scan", command=self.start_scan)
        self.run_btn.grid(row=2, column=0, sticky="ew", pady=(0, 10), ipady=5)
        
        # --- Console Output ---
        console_frame = ttk.LabelFrame(main_frame, text="Execution Logs")
        console_frame.grid(row=3, column=0, sticky="nsew")
        main_frame.grid_rowconfigure(3, weight=1)
        
        self.console = scrolledtext.ScrolledText(console_frame, state="disabled", bg="black", fg="lightgray", font=("Consolas", 10))
        self.console.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Initialize UI state
        self.toggle_auth_fields()

    def browse_dir(self):
        directory = filedialog.askdirectory()
        if directory:
            self.out_dir_entry.delete(0, tk.END)
            self.out_dir_entry.insert(0, directory)

    def toggle_auth_fields(self):
        mode = self.auth_mode_var.get()
        
        # Hide all first
        self.profile_label.grid_remove()
        self.profile_entry.grid_remove()
        self.sso_btn.grid_remove()
        self.ak_label.grid_remove()
        self.ak_entry.grid_remove()
        self.sk_label.grid_remove()
        self.sk_entry.grid_remove()
        self.token_label.grid_remove()
        self.token_entry.grid_remove()
        self.region_label.grid_remove()
        self.region_entry.grid_remove()
        
        if mode == "profile":
            self.profile_label.grid(row=1, column=0, sticky="w", padx=10, pady=2)
            self.profile_entry.grid(row=1, column=1, sticky="ew", padx=10, pady=2)
            self.sso_btn.grid(row=1, column=2, sticky="ew", padx=10, pady=2)
            self.region_label.grid(row=2, column=0, sticky="w", padx=10, pady=2)
            self.region_entry.grid(row=2, column=1, sticky="ew", padx=10, pady=2)
        else:
            self.ak_label.grid(row=1, column=0, sticky="w", padx=10, pady=2)
            self.ak_entry.grid(row=1, column=1, sticky="ew", padx=10, pady=2)
            self.sk_label.grid(row=2, column=0, sticky="w", padx=10, pady=2)
            self.sk_entry.grid(row=2, column=1, sticky="ew", padx=10, pady=2)
            self.token_label.grid(row=3, column=0, sticky="w", padx=10, pady=2)
            self.token_entry.grid(row=3, column=1, sticky="ew", padx=10, pady=2)
            self.region_label.grid(row=4, column=0, sticky="w", padx=10, pady=2)
            self.region_entry.grid(row=4, column=1, sticky="ew", padx=10, pady=2)

    def open_sso_terminal(self):
        try:
            import platform
            system = platform.system()
            
            msg = "This will open a new terminal window to run 'aws configure sso'.\n\nPlease follow the instructions in the terminal to complete the login process."
            if not messagebox.askokcancel("Launch SSO Login", msg):
                return
                
            if system == "Windows":
                # Use ShellExecute to run as Administrator (fixes Access Denied errors)
                import ctypes
                try:
                    ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", "/k aws configure sso", None, 1)
                except Exception as e:
                    # Fallback if elevation fails
                    print(f"Failed to elevate: {e}")
                    os.system("start cmd /k aws configure sso")
            elif system == "Darwin": # macOS
                # Using AppleScript to open Terminal and run command
                cmd = """osascript -e 'tell application "Terminal" to do script "aws configure sso"'"""
                os.system(cmd)
            elif system == "Linux":
                # Try common terminals
                terminals = [
                    ["gnome-terminal", "--", "bash", "-c", "aws configure sso; exec bash"],
                    ["x-terminal-emulator", "-e", "bash -c 'aws configure sso; exec bash'"],
                    ["xterm", "-e", "bash -c 'aws configure sso; exec bash'"]
                ]
                success = False
                for term_cmd in terminals:
                    try:
                        subprocess.Popen(term_cmd)
                        success = True
                        break
                    except FileNotFoundError:
                        continue
                
                if not success:
                    messagebox.showwarning("Terminal Not Found", "Could not automatically launch a terminal. Please run 'aws configure sso' manually in your terminal.")
            else:
                messagebox.showwarning("Unsupported OS", f"Cannot open terminal automatically on {system}. Please run 'aws configure sso' manually.")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open terminal: {str(e)}")

    def start_scan(self):
        self.run_btn.config(state="disabled")
        self.console.configure(state="normal")
        self.console.delete(1.0, tk.END)
        self.console.configure(state="disabled")
        
        # Gather inputs
        mode = self.auth_mode_var.get()
        region = self.region_entry.get().strip() or None
        out_dir = self.out_dir_entry.get().strip() or "reports"
        
        auth_kwargs = {"region_name": region}
        if mode == "profile":
            prof = self.profile_entry.get().strip() or None
            auth_kwargs["profile_name"] = prof
        else:
            ak = self.ak_entry.get().strip()
            sk = self.sk_entry.get().strip()
            token = self.token_entry.get().strip() or None
            if not ak or not sk:
                messagebox.showerror("Error", "Access Key and Secret Key are required!")
                self.run_btn.config(state="normal")
                return
            auth_kwargs["aws_access_key_id"] = ak
            auth_kwargs["aws_secret_access_key"] = sk
            auth_kwargs["aws_session_token"] = token
            
        formats = []
        if self.json_var.get(): formats.append("json")
        if self.html_var.get(): formats.append("html")
        if self.pdf_var.get(): formats.append("pdf")
        
        # Run in a background thread to prevent UI freezing
        thread = threading.Thread(target=self.run_scan_thread, args=(auth_kwargs, out_dir, formats))
        thread.daemon = True
        thread.start()
        
    def run_scan_thread(self, auth_kwargs, out_dir, formats):
        try:
            print("="*60)
            print(" Starting AWS CIS Benchmark Scan...")
            print("="*60)
            
            auth = AWSAuth(**auth_kwargs)
            if not auth.authenticate():
                print("\n[!] Authentication failed. Please check your credentials.")
                self.run_btn.config(state="normal")
                return
                
            print("\n[*] Initializing CIS Benchmark Checks...")
            checks = get_all_checks(auth)
            
            print(f"[*] Starting {len(checks)} checks...\n")
            
            results = []
            summary = {"PASS": 0, "FAIL": 0, "ERROR": 0}
            
            for check in checks:
                print(f"Running Check {check.check_id} - {check.title}...", end=" ")
                check.execute()
                result_dict = check.to_dict()
                results.append(result_dict)
                
                status = result_dict['result']
                print(f"[{status}]")
                if status in summary:
                    summary[status] += 1
                else:
                    summary["ERROR"] += 1

            print("\n" + "="*60)
            print(" Execution Summary")
            print("="*60)
            
            table_data = [
                ["PASS", summary['PASS']],
                ["FAIL", summary['FAIL']],
                ["ERROR", summary['ERROR']]
            ]
            print(tabulate(table_data, headers=["Status", "Count"], tablefmt="grid"))
            print("\n")
            
            sts = auth.get_client('sts')
            account_id = sts.get_caller_identity().get('Account')
            
            if formats:
                print("[*] Generating Reports...")
                report_gen = ReportGenerator(results, account_id, output_dir=out_dir)
                
                if 'json' in formats:
                    json_file = report_gen.generate_json()
                    print(f"[+] JSON report saved to: {json_file}")
                    
                if 'html' in formats:
                    html_file = report_gen.generate_html()
                    print(f"[+] HTML report saved to: {html_file}")

                if 'pdf' in formats:
                    pdf_file = report_gen.generate_pdf()
                    if pdf_file:
                        print(f"[+] PDF report saved to: {pdf_file}")
            
            print("\n[*] Scan Completed Successfully!")
            messagebox.showinfo("Success", "Benchmark Scan completed successfully!")
            
        except Exception as e:
            print(f"\n[!] An error occurred during scan: {str(e)}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("Error", f"An error occurred:\n{str(e)}")
        finally:
            self.run_btn.config(state="normal")

if __name__ == "__main__":
    app = AWSCISApp()
    app.mainloop()