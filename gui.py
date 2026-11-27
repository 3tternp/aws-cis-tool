"""Launch the AWS CIS Benchmark Scanner web dashboard (opens in your browser)."""
import argparse

from aws_cis_tool.webui import serve

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="AWS CIS Benchmark Scanner - web UI")
    p.add_argument("--port", type=int, default=8765, help="Port to listen on (default 8765, 0 = random)")
    p.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1; keep it local)")
    p.add_argument("--no-browser", action="store_true", help="Do not open a browser automatically")
    a = p.parse_args()
    serve(a.host, a.port, open_browser=not a.no_browser)
