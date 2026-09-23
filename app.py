"""
XRAC-AI Interactive Web Simulation Console
Zero-dependency, standalone HTTP server running at http://localhost:8000.
Provides an interactive GUI to simulate access requests, adjust contextual sliders,
visualize the formal Explanation Graph, inspect SHAP attributions, and review audit logs.
"""
import http.server
import socketserver
import json
import urllib.parse
from src.context_layer import ContextLayer, AccessRequest
from src.risk_engine import RiskScoringEngine
from src.decision_module import AccessDecisionModule
from src.explanation_layer import ExplanationLayer
from src.audit_logger import AuditLogger
import config

PORT = 8000

# Initialize core pipeline
context_layer = ContextLayer()
risk_engine = RiskScoringEngine()
decision_module = AccessDecisionModule()
explanation_layer = ExplanationLayer(risk_engine)
audit_logger = AuditLogger("access_audit_log.jsonl")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XRAC-AI | Explainable Risk-Based Access Control</title>
    <!-- Tailwind CSS CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- Mermaid CDN -->
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <script>mermaid.initialize({ startOnLoad: false, theme: 'neutral' });</script>
    <style>
        .risk-gauge { transition: width 0.5s ease-in-out; }
    </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen font-sans antialiased">
    <!-- Header -->
    <header class="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50 px-6 py-4 flex flex-wrap justify-between items-center">
        <div class="flex items-center space-x-3">
            <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-indigo-500 to-cyan-400 flex items-center justify-center font-bold text-white shadow-lg shadow-indigo-500/30">
                X
            </div>
            <div>
                <h1 class="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                    XRAC-AI
                    <span class="text-xs px-2.5 py-0.5 rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-mono">SACMAT '25 + XAI</span>
                </h1>
                <p class="text-xs text-slate-400">Explainable, Risk-Based Access Control Using AI &bull; VIT Vellore (Harika, Ashmit, Priyanshu)</p>
            </div>
        </div>
        <div class="flex items-center gap-2 mt-2 sm:mt-0">
            <button onclick="loadPreset('routine')" class="px-3 py-1.5 text-xs font-medium rounded-lg bg-emerald-950/60 text-emerald-300 border border-emerald-800/60 hover:bg-emerald-900/80 transition">
                Preset: Routine (Grant)
            </button>
            <button onclick="loadPreset('remote')" class="px-3 py-1.5 text-xs font-medium rounded-lg bg-amber-950/60 text-amber-300 border border-amber-800/60 hover:bg-amber-900/80 transition">
                Preset: Remote (Step-Up)
            </button>
            <button onclick="loadPreset('attack')" class="px-3 py-1.5 text-xs font-medium rounded-lg bg-rose-950/60 text-rose-300 border border-rose-800/60 hover:bg-rose-900/80 transition">
                Preset: Attack (Deny)
            </button>
        </div>
    </header>

    <!-- Main Content -->
    <main class="max-w-7xl mx-auto p-6 grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        <!-- Left Panel: Contextual Request Generator -->
        <section class="lg:col-span-5 bg-slate-900/90 rounded-2xl border border-slate-800 p-6 shadow-xl space-y-5">
            <div class="flex justify-between items-center border-b border-slate-800 pb-3">
                <h2 class="text-base font-semibold text-slate-200 flex items-center gap-2">
                    <span class="text-indigo-400">1.</span> Context & Identity Telemetry
                </h2>
                <span class="text-xs text-slate-400 font-mono">Stage 1 Ingestion</span>
            </div>

            <div class="grid grid-cols-2 gap-3 text-xs">
                <div>
                    <label class="block text-slate-400 mb-1">User ID</label>
                    <input id="userId" type="text" value="alice@enterprise.org" class="w-full bg-slate-800 rounded-lg px-3 py-1.5 border border-slate-700 text-white font-mono focus:outline-none focus:border-indigo-500">
                </div>
                <div>
                    <label class="block text-slate-400 mb-1">Assigned Role</label>
                    <select id="role" class="w-full bg-slate-800 rounded-lg px-3 py-1.5 border border-slate-700 text-white focus:outline-none focus:border-indigo-500">
                        <option>Software Engineer</option>
                        <option>DevOps Admin</option>
                        <option>Financial Officer</option>
                        <option>Security Auditor</option>
                        <option>Contractor / Intern</option>
                    </select>
                </div>
            </div>

            <!-- Context Sliders -->
            <div class="space-y-3.5 pt-2">
                <div>
                    <div class="flex justify-between text-xs mb-1">
                        <span class="text-slate-300 font-medium">Device Trust Score</span>
                        <span id="lbl_dev_trust" class="font-mono text-indigo-400">0.95</span>
                    </div>
                    <input type="range" id="dev_trust" min="0" max="1" step="0.05" value="0.95" oninput="updateSliders()" class="w-full accent-indigo-500">
                </div>

                <div>
                    <div class="flex justify-between text-xs mb-1">
                        <span class="text-slate-300 font-medium">IP Threat / Reputation Risk</span>
                        <span id="lbl_ip_rep" class="font-mono text-indigo-400">0.05</span>
                    </div>
                    <input type="range" id="ip_rep" min="0" max="1" step="0.05" value="0.05" oninput="updateSliders()" class="w-full accent-indigo-500">
                </div>

                <div>
                    <div class="flex justify-between text-xs mb-1">
                        <span class="text-slate-300 font-medium">Geo-Velocity (Travel Speed)</span>
                        <span id="lbl_geo_vel" class="font-mono text-indigo-400">25 km/h</span>
                    </div>
                    <input type="range" id="geo_vel" min="0" max="2000" step="25" value="25" oninput="updateSliders()" class="w-full accent-indigo-500">
                    <p class="text-[10px] text-slate-500 mt-0.5">> 900 km/h triggers instant Impossible Travel override</p>
                </div>

                <div>
                    <div class="flex justify-between text-xs mb-1">
                        <span class="text-slate-300 font-medium">Access Hour Anomaly Score</span>
                        <span id="lbl_hour_anom" class="font-mono text-indigo-400">0.10</span>
                    </div>
                    <input type="range" id="hour_anom" min="0" max="1" step="0.05" value="0.10" oninput="updateSliders()" class="w-full accent-indigo-500">
                </div>

                <div>
                    <div class="flex justify-between text-xs mb-1">
                        <span class="text-slate-300 font-medium">Resource Sensitivity Tier</span>
                        <span id="lbl_res_sens" class="font-mono text-indigo-400">Level 2 (Internal)</span>
                    </div>
                    <input type="range" id="res_sens" min="1" max="5" step="1" value="2" oninput="updateSliders()" class="w-full accent-indigo-500">
                </div>

                <div>
                    <div class="flex justify-between text-xs mb-1">
                        <span class="text-slate-300 font-medium">Failed Attempts in Last Hour</span>
                        <span id="lbl_failed_att" class="font-mono text-indigo-400">0</span>
                    </div>
                    <input type="range" id="failed_att" min="0" max="12" step="1" value="0" oninput="updateSliders()" class="w-full accent-indigo-500">
                </div>

                <div>
                    <div class="flex justify-between text-xs mb-1">
                        <span class="text-slate-300 font-medium">Keystroke / Biometric Anomaly</span>
                        <span id="lbl_keystroke" class="font-mono text-indigo-400">0.10</span>
                    </div>
                    <input type="range" id="keystroke" min="0" max="1" step="0.05" value="0.10" oninput="updateSliders()" class="w-full accent-indigo-500">
                </div>

                <div class="grid grid-cols-2 gap-3 pt-1">
                    <label class="flex items-center space-x-2 text-xs text-slate-300 bg-slate-800/60 p-2.5 rounded-lg border border-slate-700/60 cursor-pointer">
                        <input type="checkbox" id="vpn" checked onchange="submitEvaluation()" class="rounded accent-indigo-500">
                        <span>Corporate VPN Active</span>
                    </label>
                    <label class="flex items-center space-x-2 text-xs text-slate-300 bg-slate-800/60 p-2.5 rounded-lg border border-slate-700/60 cursor-pointer">
                        <input type="checkbox" id="priv_elev" onchange="submitEvaluation()" class="rounded accent-indigo-500">
                        <span>Elevation Requested</span>
                    </label>
                </div>
            </div>

            <button onclick="submitEvaluation()" class="w-full py-2.5 rounded-xl font-semibold text-sm bg-gradient-to-r from-indigo-500 to-cyan-500 hover:from-indigo-600 hover:to-cyan-600 text-white shadow-lg shadow-indigo-500/25 transition">
                Evaluate Access Request
            </button>
        </section>

        <!-- Right Panel: Results & Explanation Graph -->
        <section class="lg:col-span-7 space-y-6">
            
            <!-- Decision Banner & Score Card -->
            <div class="bg-slate-900/90 rounded-2xl border border-slate-800 p-6 shadow-xl">
                <div class="flex flex-wrap justify-between items-center gap-4 mb-4">
                    <div>
                        <span class="text-xs uppercase tracking-wider text-slate-400 font-semibold">Stage 2 & 3 Output</span>
                        <h3 class="text-lg font-bold text-white">Dynamic Access Decision</h3>
                    </div>
                    <div id="decisionBadge" class="px-5 py-2 rounded-xl text-sm font-extrabold tracking-wide uppercase shadow-md flex items-center gap-2">
                        <!-- Populated by JS -->
                    </div>
                </div>

                <!-- Risk Score Bar -->
                <div class="space-y-2">
                    <div class="flex justify-between items-end">
                        <span class="text-xs text-slate-400">Calculated Continuous Risk Score:</span>
                        <span id="riskScoreVal" class="text-2xl font-black font-mono text-white">--</span>
                    </div>
                    <div class="w-full h-3 bg-slate-800 rounded-full overflow-hidden relative">
                        <div id="riskBar" class="risk-gauge h-full rounded-full bg-emerald-500" style="width: 0%"></div>
                    </div>
                    <div class="flex justify-between text-[10px] text-slate-500 font-mono">
                        <span>0 (Low Risk)</span>
                        <span>&theta;low = 35.0 (Step-Up)</span>
                        <span>&theta;high = 75.0 (Deny)</span>
                        <span>100 (Critical)</span>
                    </div>
                </div>

                <div id="policyAlert" class="mt-4 p-3 rounded-lg bg-slate-800/80 border border-slate-700 text-xs text-slate-300">
                    <!-- Policy Rule matched -->
                </div>
            </div>

            <!-- Stage 4: Formal Explanation Graph (Hasel Mehri et al. SACMAT '25) -->
            <div class="bg-slate-900/90 rounded-2xl border border-slate-800 p-6 shadow-xl space-y-4">
                <div class="flex justify-between items-center border-b border-slate-800 pb-3">
                    <div>
                        <h3 class="text-base font-semibold text-slate-200 flex items-center gap-2">
                            <span class="text-indigo-400">4.</span> Formal Explanation Graph
                        </h3>
                        <p class="text-xs text-slate-400">Operationalizing Hasel Mehri et al. (SACMAT '25) DAG Structure</p>
                    </div>
                    <span class="text-xs px-2.5 py-1 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 font-mono">Soundness: 100%</span>
                </div>

                <!-- Mermaid Diagram Container -->
                <div id="mermaidContainer" class="bg-slate-950 p-4 rounded-xl border border-slate-800 overflow-x-auto min-h-[180px] flex items-center justify-center">
                    <p class="text-xs text-slate-500">Evaluating diagram...</p>
                </div>

                <!-- Feature Attributions (SHAP) -->
                <div>
                    <h4 class="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">SHAP Feature Attributions (&phi; delta from baseline)</h4>
                    <div id="attributionBars" class="space-y-1.5 text-xs">
                        <!-- Populated by JS -->
                    </div>
                </div>

                <!-- Stakeholder Narratives Tabs -->
                <div class="pt-2 border-t border-slate-800">
                    <div class="flex space-x-2 border-b border-slate-800 pb-2 text-xs">
                        <button onclick="setTab('user')" id="tab_user" class="px-3 py-1 font-semibold text-indigo-400 border-b-2 border-indigo-500">End-User View</button>
                        <button onclick="setTab('analyst')" id="tab_analyst" class="px-3 py-1 text-slate-400 hover:text-slate-200">SOC Analyst View</button>
                        <button onclick="setTab('remedy')" id="tab_remedy" class="px-3 py-1 text-slate-400 hover:text-slate-200">Counterfactual Remediation</button>
                    </div>
                    <div id="tabContent" class="mt-3 text-xs text-slate-300 p-3 bg-slate-950 rounded-xl border border-slate-800/80 leading-relaxed">
                        <!-- Populated by JS -->
                    </div>
                </div>
            </div>

            <!-- Stage 5: Tamper-Evident Audit Record -->
            <div class="bg-slate-900/90 rounded-2xl border border-slate-800 p-6 shadow-xl space-y-3">
                <div class="flex justify-between items-center">
                    <h3 class="text-base font-semibold text-slate-200 flex items-center gap-2">
                        <span class="text-indigo-400">5.</span> Audit & Compliance Telemetry
                    </h3>
                    <span class="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
                        <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                        GDPR Art. 22 / ISO 27001 Logged
                    </span>
                </div>
                <div class="p-3 bg-slate-950 rounded-xl font-mono text-[11px] text-slate-400 space-y-1 overflow-x-auto border border-slate-800">
                    <div><span class="text-indigo-400">SHA-256 Digest:</span> <span id="auditHash" class="text-slate-200">--</span></div>
                    <div><span class="text-indigo-400">Timestamp:</span> <span id="auditTime">--</span> | <span class="text-indigo-400">Audit Status:</span> <span class="text-emerald-400">Cryptographically Sealed</span></div>
                </div>
            </div>

        </section>
    </main>

    <script>
        let currentData = null;
        let activeTab = 'user';

        function updateSliders() {
            document.getElementById('lbl_dev_trust').innerText = document.getElementById('dev_trust').value;
            document.getElementById('lbl_ip_rep').innerText = document.getElementById('ip_rep').value;
            document.getElementById('lbl_geo_vel').innerText = document.getElementById('geo_vel').value + ' km/h';
            document.getElementById('lbl_hour_anom').innerText = document.getElementById('hour_anom').value;
            
            const resNames = ["", "1 (Public)", "2 (Internal)", "3 (Confidential)", "4 (Restricted)", "5 (Critical Secrets)"];
            document.getElementById('lbl_res_sens').innerText = resNames[document.getElementById('res_sens').value];
            document.getElementById('lbl_failed_att').innerText = document.getElementById('failed_att').value;
            document.getElementById('lbl_keystroke').innerText = document.getElementById('keystroke').value;
            
            submitEvaluation();
        }

        function loadPreset(type) {
            if (type === 'routine') {
                document.getElementById('dev_trust').value = 0.95;
                document.getElementById('ip_rep').value = 0.05;
                document.getElementById('geo_vel').value = 20;
                document.getElementById('hour_anom').value = 0.05;
                document.getElementById('res_sens').value = 2;
                document.getElementById('failed_att').value = 0;
                document.getElementById('keystroke').value = 0.10;
                document.getElementById('vpn').checked = true;
                document.getElementById('priv_elev').checked = false;
            } else if (type === 'remote') {
                document.getElementById('dev_trust').value = 0.65;
                document.getElementById('ip_rep').value = 0.35;
                document.getElementById('geo_vel').value = 350;
                document.getElementById('hour_anom').value = 0.65;
                document.getElementById('res_sens').value = 4;
                document.getElementById('failed_att').value = 2;
                document.getElementById('keystroke').value = 0.40;
                document.getElementById('vpn').checked = false;
                document.getElementById('priv_elev').checked = false;
            } else if (type === 'attack') {
                document.getElementById('dev_trust').value = 0.15;
                document.getElementById('ip_rep').value = 0.90;
                document.getElementById('geo_vel').value = 1450;
                document.getElementById('hour_anom').value = 0.90;
                document.getElementById('res_sens').value = 5;
                document.getElementById('failed_att').value = 7;
                document.getElementById('keystroke').value = 0.85;
                document.getElementById('vpn').checked = false;
                document.getElementById('priv_elev').checked = true;
            }
            updateSliders();
        }

        async function submitEvaluation() {
            const payload = {
                user_id: document.getElementById('userId').value,
                role: document.getElementById('role').value,
                device_trust_score: parseFloat(document.getElementById('dev_trust').value),
                ip_reputation_risk: parseFloat(document.getElementById('ip_rep').value),
                geo_velocity_kmh: parseFloat(document.getElementById('geo_vel').value),
                hour_anomaly_score: parseFloat(document.getElementById('hour_anom').value),
                resource_sensitivity: parseInt(document.getElementById('res_sens').value),
                failed_attempts_last_hour: parseInt(document.getElementById('failed_att').value),
                vpn_connected: document.getElementById('vpn').checked ? 1 : 0,
                privilege_elevation_requested: document.getElementById('priv_elev').checked ? 1 : 0,
                keystroke_anomaly_score: parseFloat(document.getElementById('keystroke').value)
            };

            try {
                const res = await fetch('/api/evaluate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                currentData = data;
                renderResults(data);
            } catch (err) {
                console.error("Evaluation error:", err);
            }
        }

        function renderResults(data) {
            // Badge
            const badge = document.getElementById('decisionBadge');
            const scoreVal = document.getElementById('riskScoreVal');
            const riskBar = document.getElementById('riskBar');
            
            scoreVal.innerText = data.risk_score + ' / 100';
            riskBar.style.width = data.risk_score + '%';

            if (data.decision === 'GRANT') {
                badge.className = "px-5 py-2 rounded-xl text-sm font-extrabold uppercase bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 shadow-lg shadow-emerald-500/10";
                badge.innerHTML = "<span>&#10003;</span> GRANT";
                riskBar.className = "risk-gauge h-full rounded-full bg-emerald-500";
            } else if (data.decision === 'STEP_UP_MFA') {
                badge.className = "px-5 py-2 rounded-xl text-sm font-extrabold uppercase bg-amber-500/20 text-amber-400 border border-amber-500/40 shadow-lg shadow-amber-500/10";
                badge.innerHTML = "<span>&#9888;</span> STEP-UP MFA";
                riskBar.className = "risk-gauge h-full rounded-full bg-amber-500";
            } else {
                badge.className = "px-5 py-2 rounded-xl text-sm font-extrabold uppercase bg-rose-500/20 text-rose-400 border border-rose-500/40 shadow-lg shadow-rose-500/10";
                badge.innerHTML = "<span>&#10007;</span> DENY";
                riskBar.className = "risk-gauge h-full rounded-full bg-rose-500";
            }

            document.getElementById('policyAlert').innerHTML = `<strong>Enforced Policy:</strong> ${data.policy_rule_matched} ${data.is_override ? '<span class="text-rose-400 font-bold ml-1">(' + data.override_reason + ')</span>' : ''}`;

            // Render Mermaid Graph
            const mermaidElem = document.getElementById('mermaidContainer');
            mermaidElem.innerHTML = `<div class="mermaid">${data.mermaid_diagram}</div>`;
            try {
                mermaid.run({ nodes: [mermaidElem.querySelector('.mermaid')] });
            } catch (e) {
                console.warn(e);
            }

            // Render Feature Attributions
            const attrContainer = document.getElementById('attributionBars');
            attrContainer.innerHTML = '';
            const sortedAttrs = Object.entries(data.attributions).sort((a,b) => Math.abs(b[1]) - Math.abs(a[1]));
            
            sortedAttrs.slice(0, 5).forEach(([factor, delta]) => {
                const isPos = delta >= 0;
                const widthPercent = Math.min(100, Math.abs(delta) * 2.5);
                const barColor = isPos ? 'bg-rose-500' : 'bg-emerald-500';
                const sign = isPos ? '+' : '';

                attrContainer.innerHTML += `
                    <div>
                        <div class="flex justify-between text-[11px] mb-0.5">
                            <span class="text-slate-300">${factor.replace(/_/g, ' ')}</span>
                            <span class="font-mono ${isPos ? 'text-rose-400' : 'text-emerald-400'}">${sign}${delta.toFixed(1)} pts</span>
                        </div>
                        <div class="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div class="h-full rounded-full ${barColor}" style="width: ${widthPercent}%"></div>
                        </div>
                    </div>
                `;
            });

            // Narratives Tab
            renderTabContent();

            // Audit
            document.getElementById('auditHash').innerText = data.audit_record.integrity_hash;
            document.getElementById('auditTime').innerText = data.audit_record.timestamp;
        }

        function setTab(tab) {
            activeTab = tab;
            ['user', 'analyst', 'remedy'].forEach(t => {
                const btn = document.getElementById('tab_' + t);
                if (t === tab) {
                    btn.className = "px-3 py-1 font-semibold text-indigo-400 border-b-2 border-indigo-500";
                } else {
                    btn.className = "px-3 py-1 text-slate-400 hover:text-slate-200";
                }
            });
            renderTabContent();
        }

        function renderTabContent() {
            if (!currentData) return;
            const container = document.getElementById('tabContent');
            if (activeTab === 'user') {
                container.innerHTML = `<p class="font-medium text-slate-200">${currentData.narratives.end_user}</p>`;
            } else if (activeTab === 'analyst') {
                container.innerHTML = `<pre class="whitespace-pre-wrap font-mono text-[11px] text-slate-300">${currentData.narratives.analyst}</pre>`;
            } else {
                container.innerHTML = `<pre class="whitespace-pre-wrap font-mono text-[11px] text-emerald-300">${currentData.narratives.counterfactual}</pre>`;
            }
        }

        // Initialize on load
        window.addEventListener('DOMContentLoaded', () => {
            updateSliders();
        });
    </script>
</body>
</html>
"""

class XRACRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ["/", "/index.html"]:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode("utf-8"))
        elif parsed.path == "/api/logs":
            logs = audit_logger.get_recent_logs(limit=20)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(logs).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/evaluate":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            payload = json.loads(body.decode("utf-8"))

            req = AccessRequest(
                request_id=f"REQ-SIM-{int(1000 + (len(audit_logger.get_recent_logs(100)) + 1))}",
                user_id=payload.get("user_id", "user@enterprise.org"),
                role=payload.get("role", "Software Engineer"),
                department="Corporate",
                target_resource="service://secure-api",
                device_id="SIMULATED-DEV-01",
                ip_address="198.51.100.22",
                location="Simulation Subnet",
                device_trust_score=float(payload.get("device_trust_score", 0.95)),
                ip_reputation_risk=float(payload.get("ip_reputation_risk", 0.05)),
                geo_velocity_kmh=float(payload.get("geo_velocity_kmh", 25.0)),
                hour_anomaly_score=float(payload.get("hour_anomaly_score", 0.10)),
                resource_sensitivity=int(payload.get("resource_sensitivity", 2)),
                failed_attempts_last_hour=int(payload.get("failed_attempts_last_hour", 0)),
                vpn_connected=int(payload.get("vpn_connected", 1)),
                privilege_elevation_requested=int(payload.get("privilege_elevation_requested", 0)),
                keystroke_anomaly_score=float(payload.get("keystroke_anomaly_score", 0.10))
            )

            # Pipeline execution
            feat_vec, feat_dict = context_layer.extract_features(req)
            instant_flags = context_layer.detect_instant_flags(req)
            risk_score = risk_engine.predict_risk(feat_vec)
            decision_res = decision_module.evaluate(risk_score, instant_flags)
            attributions = explanation_layer.compute_feature_attributions(feat_vec, risk_score)
            graph = explanation_layer.build_explanation_graph(req, decision_res, attributions)
            narratives = explanation_layer.generate_narratives(req, decision_res, attributions)

            audit_rec = audit_logger.log_record(
                request_id=req.request_id,
                user_id=req.user_id,
                role=req.role,
                resource=req.target_resource,
                decision_result=decision_res,
                attributions=attributions,
                narratives=narratives,
                context_features=feat_dict
            )

            response_data = {
                "decision": decision_res.decision,
                "risk_score": decision_res.risk_score,
                "policy_rule_matched": decision_res.policy_rule_matched,
                "is_override": decision_res.is_override,
                "override_reason": decision_res.override_reason,
                "required_action": decision_res.required_action,
                "attributions": attributions,
                "mermaid_diagram": graph.mermaid_diagram,
                "narratives": narratives,
                "audit_record": audit_rec
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

def main():
    print(f"[*] Starting XRAC-AI Interactive Web Console at http://localhost:{PORT}")
    print("[*] Press Ctrl+C to terminate the server.")
    with socketserver.TCPServer(("", PORT), XRACRequestHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Server stopped.")

if __name__ == "__main__":
    main()
