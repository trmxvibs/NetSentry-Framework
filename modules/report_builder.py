#report_builder.py
#Date-13/12/2025
#Author- Lokesh Kumar
#github - @trmxvibs
#Madeinindia
import re
import os
import json
from datetime import datetime

class HTMLReportGenerator:
    def __init__(self, domain, scan_data, score):
        self.domain = domain
        self.scan_data = scan_data
        self.score = score
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.stats = {
            "critical": scan_data.count("[☠️]") + scan_data.count("CRITICAL"),
            "high": scan_data.count("[$$$]") + scan_data.count("RCE"),
            "medium": scan_data.count("[⚠️]") + scan_data.count("WARNING"),
            "safe": scan_data.count("[✓]") + scan_data.count("[+]")
        }

    def generate_html(self):
        # Escape HTML characters to prevent self-XSS in report
        safe_data = self.scan_data.replace("<", "&lt;").replace(">", "&gt;")
        
        # Colorize the raw logs for HTML display
        formatted_log = safe_data
        formatted_log = formatted_log.replace("[☠️]", '<span class="badge crit">[☠️] CRITICAL</span>')
        formatted_log = formatted_log.replace("[$$$]", '<span class="badge loot">[$$$] LOOT</span>')
        formatted_log = formatted_log.replace("[⚠️]", '<span class="badge warn">[⚠️] WARNING</span>')
        formatted_log = formatted_log.replace("[✓]", '<span class="text-success">[✓]</span>')
        formatted_log = formatted_log.replace("[+]", '<span class="text-info">[+]</span>')

        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Net-Sentry Report: {self.domain}</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                :root {{ --bg: #0d1117; --panel: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; --crit: #ff7b72; --warn: #d29922; --safe: #3fb950; }}
                body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', monospace; margin: 0; padding: 20px; }}
                .container {{ max-width: 1200px; margin: auto; }}
                .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 20px; }}
                .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
                .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
                .score-box {{ text-align: center; font-size: 3rem; font-weight: bold; color: {self.get_score_color()}; }}
                .log-window {{ background: #000; color: #0f0; padding: 15px; border-radius: 5px; height: 500px; overflow-y: scroll; white-space: pre-wrap; font-family: 'Consolas', monospace; font-size: 0.9rem; border: 1px solid var(--border); }}
                .badge {{ padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 0.8rem; }}
                .crit {{ background: rgba(255, 123, 114, 0.2); color: var(--crit); border: 1px solid var(--crit); }}
                .warn {{ background: rgba(210, 153, 34, 0.2); color: var(--warn); border: 1px solid var(--warn); }}
                .loot {{ background: rgba(210, 153, 34, 0.2); color: gold; border: 1px solid gold; }}
                .text-success {{ color: var(--safe); }} .text-info {{ color: var(--accent); }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div>
                        <h1>NET-SENTRY <span style="font-size:1rem; color:var(--accent)">v65.0</span></h1>
                        <div style="color: #8b949e">Target: {self.domain} | Date: {self.timestamp}</div>
                    </div>
                    <button onclick="window.print()" style="background:var(--accent); border:none; padding:10px 20px; border-radius:5px; cursor:pointer; font-weight:bold;">PRINT PDF</button>
                </div>

                <div class="grid">
                    <div class="card">
                        <h3>RISK SCORE</h3>
                        <div class="score-box">{self.score}/100</div>
                        <p style="text-align:center; color:#8b949e">Security Posture Assessment</p>
                    </div>
                    <div class="card">
                        <h3>THREAT DISTRIBUTION</h3>
                        <canvas id="vulnChart" style="max-height:150px"></canvas>
                    </div>
                </div>

                <div class="card">
                    <h3>MISSION LOGS (FULL SCAN)</h3>
                    <div class="log-window">{formatted_log}</div>
                </div>

                <div class="card" style="text-align:center; font-size:0.8rem; color:#8b949e">
                    GENERATED BY NET-SENTRY AUTOMATED RED TEAM FRAMEWORK<br>
                    CONFIDENTIAL - AUTHORIZED EYES ONLY
                </div>
            </div>

            <script>
                const ctx = document.getElementById('vulnChart').getContext('2d');
                new Chart(ctx, {{
                    type: 'doughnut',
                    data: {{
                        labels: ['Critical', 'High/Loot', 'Warnings', 'Safe Checks'],
                        datasets: [{{
                            data: [{self.stats['critical']}, {self.stats['high']}, {self.stats['medium']}, {self.stats['safe']}],
                            backgroundColor: ['#ff7b72', '#ffd700', '#d29922', '#3fb950'],
                            borderWidth: 0
                        }}]
                    }},
                    options: {{ maintainAspectRatio: false, plugins: {{ legend: {{ position: 'right', labels: {{ color: '#c9d1d9' }} }} }} }}
                }});
            </script>
        </body>
        </html>
        """
        return html_template

    def get_score_color(self):
        if self.score > 70: return "#ff7b72" # Red
        if self.score > 40: return "#d29922" # Orange
        return "#3fb950" # Green

def generate_html_report(domain, scan_text, score):
    generator = HTMLReportGenerator(domain, scan_text, score)

    return generator.generate_html()
