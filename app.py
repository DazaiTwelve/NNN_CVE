"""
Professional Penetration Testing Report Generator - v3.0
Enterprise-grade security scanning with CVE intelligence and NLP mapping
"""
import streamlit as st
import os
import sys
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import json
import time

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from pentest_report_generator.scanners.scanner_automation import ScannerAutomation
from pentest_report_generator.parsers.nmap_parser import NmapParser
from pentest_report_generator.parsers.nikto_parser import NiktoParser
from pentest_report_generator.parsers.nessus_parser import NessusParser
from pentest_report_generator.utils.normalizer import DataNormalizer
from pentest_report_generator.utils.cve_enrichment import CVEEnrichment
from pentest_report_generator.utils.report_summary import ReportSummary
from pentest_report_generator.utils.export_formats import ExportFormats
from pentest_report_generator.utils.notification_system import NotificationSystem
from pentest_report_generator.reports.pdf_generator import PDFReportGenerator

# Page configuration
st.set_page_config(
    page_title="NNN-CVE",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Professional CSS styling
st.markdown("""
<style>
    * {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    
    .main-header {
        background: linear-gradient(135deg, #1e3a8a 0%, #0f172a 100%);
        padding: 30px;
        border-radius: 8px;
        color: white;
        margin-bottom: 30px;
        border-left: 4px solid #3b82f6;
    }
    
    .main-header h1 {
        margin: 0;
        font-size: 2.2em;
        font-weight: 700;
        letter-spacing: 0.5px;
    }
    
    .main-header p {
        margin: 5px 0 0 0;
        font-size: 0.95em;
        color: #cbd5e1;
        font-weight: 300;
    }
    
    .section-header {
        background-color: #f8fafc;
        padding: 15px 20px;
        border-left: 4px solid #3b82f6;
        margin: 25px 0 15px 0;
        border-radius: 4px;
    }
    
    .section-header h2 {
        margin: 0;
        font-size: 1.3em;
        color: #1e293b;
        font-weight: 600;
    }
    
    .metric-card {
        background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
        padding: 20px;
        border-radius: 8px;
        border: 1px solid #e2e8f0;
        margin: 10px 0;
    }
    
    .log-container {
        background-color: #0f172a;
        color: #e2e8f0;
        padding: 15px;
        border-radius: 6px;
        font-family: 'Courier New', monospace;
        font-size: 12px;
        max-height: 500px;
        overflow-y: auto;
        white-space: pre-wrap;
        word-wrap: break-word;
        border: 1px solid #1e293b;
    }
    
    .cve-item {
        background-color: #fef3c7;
        border-left: 3px solid #f59e0b;
        padding: 12px;
        margin: 8px 0;
        border-radius: 4px;
        font-size: 0.9em;
    }
    
    .cve-item-critical {
        background-color: #fee2e2;
        border-left: 3px solid #ef4444;
    }
    
    .cve-item-high {
        background-color: #fed7aa;
        border-left: 3px solid #f97316;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'findings' not in st.session_state:
    st.session_state.findings = []
if 'scan_logs' not in st.session_state:
    st.session_state.scan_logs = []
if 'cve_report' not in st.session_state:
    st.session_state.cve_report = None
if 'target_ip' not in st.session_state:
    st.session_state.target_ip = None

# Main Header
st.markdown("""
<div class="main-header">
    <h1>NNN-CVE</h1>
    <p>Nmap-Nikito-Nessus-CVE Mapper and report generator and Classifier</p>
</div>
""", unsafe_allow_html=True)

# Sidebar Configuration
with st.sidebar:
    st.title("Configuration")
    
    mode = st.radio("Operation Mode", ["Scan Target", "Upload Reports"], label_visibility="collapsed")
    
    st.markdown("---")
    
    st.subheader("Notifications")
    enable_notifications = st.checkbox("Enable Alerts", value=False)
    notif_type = "Slack"
    slack_webhook = ""
    email_recipients = ""
    
    if enable_notifications:
        notif_type = st.selectbox("Alert Type", ["Slack", "Email", "Both"])
        
        if notif_type in ["Slack", "Both"]:
            slack_webhook = st.text_input("Slack Webhook URL", type="password")
        if notif_type in ["Email", "Both"]:
            email_recipients = st.text_area("Email Recipients (comma-separated)")
    
    st.markdown("---")
    
    with st.expander("Authorized Targets"):
        st.code("scanme.nmap.org\ntestphp.vulnweb.com\ntesthtml5.vulnweb.com\ntestasp.vulnweb.com")
        st.warning("Only scan authorized targets. Unauthorized scanning is illegal.")

# Initialize variables
use_nlp_mapping = False
nlp_confidence = 0.3
enable_cve = True
cve_api_key = ""

# Main content
if mode == "Scan Target":
    st.markdown('<div class="section-header"><h2>Target Configuration</h2></div>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        target_ip = st.text_input(
            "Target IP or Hostname",
            placeholder="e.g., 192.168.1.1 or scanme.nmap.org",
            label_visibility="collapsed"
        )
        st.session_state.target_ip = target_ip
    
    with col2:
        status_text = "Ready" if target_ip else "Waiting for input"
        st.metric("Status", status_text)
    
    with col3:
        st.metric("Mode", "Scan")
    
    st.markdown("---")
    
    st.markdown('<div class="section-header"><h2>Scanner Selection</h2></div>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.subheader("Nmap")
        use_nmap = st.checkbox("Enable", value=True, key="nmap_enable")
        nmap_speed = "fast"
        if use_nmap:
            nmap_speed = st.select_slider(
                "Scan Speed",
                options=["quick", "fast", "balanced", "thorough", "cve"],
                value="fast"
            )
    
    with col2:
        st.subheader("Nikto")
        use_nikto = st.checkbox("Enable", value=True, key="nikto_enable")
        nikto_port = 80
        nikto_speed = "fast"
        if use_nikto:
            nikto_port = st.number_input("Port", 1, 65535, 80)
            nikto_speed = st.select_slider(
                "Scan Speed",
                options=["fast", "balanced", "thorough"],
                value="fast",
                key="nikto_speed"
            )
    
    with col3:
        st.subheader("Nessus")
        use_nessus = st.checkbox("Enable", value=False, key="nessus_enable")
        nessus_policy = "basic"
        if use_nessus:
            nessus_policy = st.selectbox(
                "Policy Type",
                ["basic", "full", "intrusive", "aggressive"],
                key="nessus_policy"
            )
    
    st.markdown("---")
    
    st.markdown('<div class="section-header"><h2>Advanced Options</h2></div>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        show_realtime = st.checkbox("Real-time Output", value=True)
        show_commands = st.checkbox("Show Commands", value=True)
    
    with col2:
        auto_enrich_cve = st.checkbox("Auto-enrich CVEs", value=True)
        generate_summary = st.checkbox("Generate Summary", value=True)
    
    with col3:
        st.subheader("AI CVE Mapping")
        use_nlp_mapping = st.checkbox("Enable NLP Discovery", value=False)
        if use_nlp_mapping:
            nlp_confidence = st.slider("Confidence", 0.1, 0.9, 0.3, 0.1)
    
    st.markdown("---")
    
    normalizer = DataNormalizer()
    if st.button("Start Security Scan", type="primary", use_container_width=True):
        if not target_ip:
            st.error("Please enter a target")
        elif not (use_nmap or use_nikto or use_nessus):
            st.error("Select at least one scanner")
        else:
            st.session_state.scan_logs = []
            
            st.markdown(f"""
            <div class="main-header">
                <h2>Scan In Progress</h2>
                <p>Target: {target_ip} | Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            """, unsafe_allow_html=True)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                nmap_status = st.empty()
                nmap_status.info("Nmap: Queued" if use_nmap else "Nmap: Skipped")
            with col2:
                nikto_status = st.empty()
                nikto_status.info("Nikto: Queued" if use_nikto else "Nikto: Skipped")
            with col3:
                nessus_status = st.empty()
                nessus_status.info("Nessus: Queued" if use_nessus else "Nessus: Skipped")
            
            progress_bar = st.progress(0)
            
            if show_realtime:
                st.subheader("Scan Output")
                log_display = st.empty()
            
            def ui_callback(message, msg_type="info"):
                st.session_state.scan_logs.append({
                    'msg': message,
                    'type': msg_type,
                    'time': datetime.now().strftime('%H:%M:%S')
                })
                
                if show_realtime:
                    log_lines = []
                    for entry in st.session_state.scan_logs[-50:]:
                        msg = entry['msg']
                        timestamp = entry['time']
                        log_lines.append(f"[{timestamp}] {msg}")
                    log_display.code("\n".join(log_lines), language=None)
            
            try:
                overall_status = st.empty()
                overall_status.info("Initializing...")
                progress_bar.progress(10)
                
                scanner = ScannerAutomation(
                    target_ip,
                    verbose=show_realtime,
                    ui_callback=ui_callback
                )
                
                # Build tools list
                tools_to_run = []
                if use_nmap:
                    tools_to_run.append('nmap')
                if use_nikto:
                    tools_to_run.append('nikto')
                if use_nessus:
                    tools_to_run.append('nessus')
                
                # Run scans with all parameters
                scan_results = scanner.run_selected_scans(
                    tools=tools_to_run,
                    nmap_mode=nmap_speed if use_nmap else 'fast',
                    nikto_port=nikto_port if use_nikto else 80,
                    nikto_tuning=nikto_speed if use_nikto else 'fast',
                )
                
                # Update status for each scanner
                if scan_results.get('nmap'):
                    nmap_status.success("Nmap: Completed")
                    progress_bar.progress(30)
                else:
                    if use_nmap:
                        nmap_status.error("Nmap: Failed")
                
                if scan_results.get('nikto'):
                    nikto_status.success("Nikto: Completed")
                    progress_bar.progress(60)
                else:
                    if use_nikto:
                        nikto_status.error("Nikto: Failed")
                
                if scan_results.get('nessus'):
                    nessus_status.success("Nessus: Completed")
                    progress_bar.progress(80)
                else:
                    if use_nessus:
                        nessus_status.error("Nessus: Failed")
                
                overall_status.info("Processing results...")
                progress_bar.progress(85)
                
                # Parse results from all scanners
                all_findings = []
                
                if scan_results.get('nmap'):
                    parser = NmapParser(scan_results['nmap'])
                    nmap_findings = parser.parse()
                    all_findings.extend(nmap_findings)
                    ui_callback(f"Nmap: Found {len(nmap_findings)} items", "success")
                
                if scan_results.get('nikto'):
                    parser = NiktoParser(scan_results['nikto'])
                    nikto_findings = parser.parse()
                    all_findings.extend(nikto_findings)
                    ui_callback(f"Nikto: Found {len(nikto_findings)} items", "success")
                
                if scan_results.get('nessus'):
                    parser = NessusParser(scan_results['nessus'])
                    nessus_findings = parser.parse()
                    all_findings.extend(nessus_findings)
                    ui_callback(f"Nessus: Found {len(nessus_findings)} items", "success")
                
                progress_bar.progress(90)
                st.session_state.findings = normalizer.normalize_findings(all_findings)
                
                # NLP CVE Mapping (Always Enabled)
                if st.session_state.findings:
                    overall_status.info("Running NLP CVE mapping...")
                    progress_bar.progress(95)
                    
                    try:
                        from pentest_report_generator.utils.cve_nlp_mapper import CVENLPMapper
                        nlp_mapper = CVENLPMapper()
                        
                        if len(nlp_mapper.cve_database) == 0:
                            ui_callback("Loading 500 CVE database...", "info")
                            cve_count = nlp_mapper.download_cve_database()
                            ui_callback(f"Loaded {cve_count} CVEs", "success")
                        else:
                            ui_callback("Using cached 500 CVEs", "success")
                        
                        ui_callback("Building search index...", "info")
                        nlp_mapper.build_search_index()
                        
                        ui_callback("Mapping findings to CVEs...", "info")
                        st.session_state.findings = nlp_mapper.map_findings_to_cves(
                            st.session_state.findings,
                            confidence_threshold=nlp_confidence
                        )
                        ui_callback("NLP CVE mapping complete!", "success")
                        
                    except ImportError as e:
                        ui_callback("Install: pip install scikit-learn nltk", "warning")
                    except Exception as e:
                        ui_callback(f"NLP error: {str(e)}", "error")
                
                progress_bar.progress(100)
                overall_status.success("Scan Complete")
                st.success(f"Scan completed successfully. Found {len(st.session_state.findings)} vulnerabilities.")
                
                if st.session_state.scan_logs:
                    log_text = "\n".join([f"[{l['time']}] {l['msg']}" for l in st.session_state.scan_logs])
                    st.download_button(
                        "Download Scan Logs",
                        data=log_text,
                        file_name=f"scan_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                        mime="text/plain",
                        use_container_width=True
                    )
            
            except Exception as e:
                overall_status.error(f"Error: {str(e)}")
                st.error(f"Scan failed: {str(e)}")


elif mode == "Upload Reports":
    st.markdown('<div class="section-header"><h2>Upload Existing Reports</h2></div>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        nmap_file = st.file_uploader("Nmap XML Report", type=['xml'])
    with col2:
        nikto_file = st.file_uploader("Nikto Report", type=['xml', 'txt'])
    with col3:
        nessus_file = st.file_uploader("Nessus Report", type=['nessus'])
    
    # Initialize normalizer here for Upload Reports
    normalizer = DataNormalizer()
    
    if st.button("Process Reports", type="primary", use_container_width=True):
        all_findings = []
        temp_dir = "temp_uploads"
        os.makedirs(temp_dir, exist_ok=True)
        
        progress = st.progress(0)
        status = st.empty()
        
        with st.spinner("Processing reports..."):
            if nmap_file:
                status.info("Parsing Nmap...")
                progress.progress(20)
                nmap_path = os.path.join(temp_dir, "nmap.xml")
                with open(nmap_path, "wb") as f:
                    f.write(nmap_file.getbuffer())
                parser = NmapParser(nmap_path)
                nmap_findings = parser.parse()
                all_findings.extend(nmap_findings)
                st.success(f"Nmap: {len(nmap_findings)} findings parsed")
            
            if nikto_file:
                status.info("Parsing Nikto...")
                progress.progress(40)
                nikto_ext = "xml" if nikto_file.name.endswith('.xml') else "txt"
                nikto_path = os.path.join(temp_dir, f"nikto.{nikto_ext}")
                with open(nikto_path, "wb") as f:
                    f.write(nikto_file.getbuffer())
                parser = NiktoParser(nikto_path)
                nikto_findings = parser.parse()
                all_findings.extend(nikto_findings)
                st.success(f"Nikto: {len(nikto_findings)} findings parsed")
            
            if nessus_file:
                status.info("Parsing Nessus...")
                progress.progress(60)
                nessus_path = os.path.join(temp_dir, "nessus.nessus")
                with open(nessus_path, "wb") as f:
                    f.write(nessus_file.getbuffer())
                parser = NessusParser(nessus_path)
                nessus_findings = parser.parse()
                all_findings.extend(nessus_findings)
                st.success(f"Nessus: {len(nessus_findings)} findings parsed")
            
            if all_findings:
                status.info("Normalizing findings...")
                progress.progress(70)
                st.session_state.findings = normalizer.normalize_findings(all_findings)
                st.success(f"Normalized {len(st.session_state.findings)} findings")
                
                # NLP CVE Mapping (Auto-enable for uploads)
                status.info("Running NLP CVE mapping...")
                progress.progress(80)
                
                try:
                    from pentest_report_generator.utils.cve_nlp_mapper import CVENLPMapper
                    nlp_mapper = CVENLPMapper()
                    
                    if len(nlp_mapper.cve_database) == 0:
                        status.info("Loading 500 CVE database...")
                        cve_count = nlp_mapper.download_cve_database()
                        status.info(f"Loaded {cve_count} CVEs")
                    else:
                        status.info("Using cached 500 CVEs")
                    
                    status.info("Building search index...")
                    nlp_mapper.build_search_index()
                    
                    status.info("Mapping findings to CVEs using NLP...")
                    st.session_state.findings = nlp_mapper.map_findings_to_cves(
                        st.session_state.findings,
                        confidence_threshold=0.25
                    )
                    st.success("NLP CVE mapping complete!")
                    
                except ImportError:
                    st.warning("Install: pip install scikit-learn nltk")
                except Exception as e:
                    st.warning(f"NLP mapping: {str(e)}")
                
                progress.progress(100)
                st.success(f"Complete! Processed {len(st.session_state.findings)} findings with NLP CVE mapping")
            else:
                progress.progress(100)
                st.warning("No valid reports uploaded")


# Results Display with Visualizations
if st.session_state.findings:
    st.markdown("---")
    
    st.markdown('<div class="section-header"><h2>Security Analysis Results</h2></div>', unsafe_allow_html=True)
    
    # Initialize normalizer for results section
    normalizer = DataNormalizer()
    
    try:
        stats = normalizer.get_statistics(st.session_state.findings)
    except Exception as e:
        st.error(f"Statistics error: {e}")
        stats = {'total': len(st.session_state.findings), 'by_severity': {}, 'by_host': {}}
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric("Total Vulnerabilities", stats['total'])
    with col2:
        critical = stats['by_severity'].get('Critical', 0)
        st.metric("Critical", critical)
    with col3:
        st.metric("High", stats['by_severity'].get('High', 0))
    with col4:
        st.metric("Medium", stats['by_severity'].get('Medium', 0))
    with col5:
        low_info = stats['by_severity'].get('Low', 0) + stats['by_severity'].get('Informational', 0)
        st.metric("Low/Info", low_info)
    
    st.markdown("---")
    
    # Visualizations
    st.markdown('<div class="section-header"><h2>Vulnerability Analysis</h2></div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Severity Distribution Pie Chart
        severity_data = pd.DataFrame({
            'Severity': list(stats['by_severity'].keys()),
            'Count': list(stats['by_severity'].values())
        })
        
        fig_pie = px.pie(
            severity_data,
            values='Count',
            names='Severity',
            title='Vulnerability Distribution by Severity',
            color='Severity',
            color_discrete_map={
                'Critical': '#ef4444',
                'High': '#f97316',
                'Medium': '#f59e0b',
                'Low': '#84cc16',
                'Informational': '#06b6d4'
            }
        )
        fig_pie.update_traces(textposition='inside', textinfo='percent+label')
        fig_pie.update_layout(showlegend=True, height=400)
        st.plotly_chart(fig_pie, use_container_width=True)
    
    with col2:
        # Severity Bar Chart
        fig_bar = px.bar(
            severity_data,
            x='Severity',
            y='Count',
            title='Vulnerability Count by Severity',
            color='Severity',
            color_discrete_map={
                'Critical': '#ef4444',
                'High': '#f97316',
                'Medium': '#f59e0b',
                'Low': '#84cc16',
                'Informational': '#06b6d4'
            }
        )
        fig_bar.update_layout(showlegend=False, height=400)
        st.plotly_chart(fig_bar, use_container_width=True)
    
    # Host Distribution
    if stats.get('by_host') and len(stats['by_host']) > 0:
        st.markdown('<div class="section-header"><h2>Vulnerability Distribution by Host</h2></div>', unsafe_allow_html=True)
        
        host_data = pd.DataFrame({
            'Host': list(stats['by_host'].keys())[:10],
            'Vulnerabilities': list(stats['by_host'].values())[:10]
        })
        
        fig_host = px.bar(
            host_data,
            x='Host',
            y='Vulnerabilities',
            title='Vulnerabilities per Host (Top 10)',
            color='Vulnerabilities',
            color_continuous_scale='Reds'
        )
        fig_host.update_layout(height=400)
        st.plotly_chart(fig_host, use_container_width=True)
    
    st.markdown("---")
    
    # CVE Intelligence
    st.markdown('<div class="section-header"><h2>CVE Intelligence</h2></div>', unsafe_allow_html=True)
    
    col_refresh = st.columns(1)
    with col_refresh[0]:
        if st.button("Refresh Results"):
            st.rerun()
    
    if st.session_state.findings:
        try:
            all_cves = set()
            critical_cves = []
            high_cves = []
            
            for finding in st.session_state.findings:
                cve_ids = finding.get('cve_ids', [])
                all_cves.update(cve_ids)
                
                for match in finding.get('cve_matches', []):
                    if match.get('similarity_score', 0) > 0.3:
                        if finding.get('severity') in ['Critical']:
                            critical_cves.append({
                                'id': match['cve_id'],
                                'score': match.get('similarity_score', 0),
                                'host': finding.get('host', 'Unknown'),
                                'severity': 'CRITICAL'
                            })
                        elif finding.get('severity') in ['High']:
                            high_cves.append({
                                'id': match['cve_id'],
                                'score': match.get('similarity_score', 0),
                                'host': finding.get('host', 'Unknown'),
                                'severity': 'HIGH'
                            })
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Unique CVEs", len(all_cves))
            with col2:
                st.metric("Critical CVEs", len(critical_cves))
            with col3:
                st.metric("High CVEs", len(high_cves))
            with col4:
                mapped = sum(1 for f in st.session_state.findings if f.get('cve_ids'))
                st.metric("Mapped Findings", mapped)
            
            if critical_cves:
                with st.expander("Critical CVEs"):
                    for cve in critical_cves[:5]:
                        st.markdown(f"""
                        <div class="cve-item cve-item-critical">
                            <strong>{cve['id']}</strong> | Confidence: {cve['score']:.1%} | Host: {cve['host']}
                        </div>
                        """, unsafe_allow_html=True)
            
            if high_cves:
                with st.expander("High CVEs"):
                    for cve in high_cves[:5]:
                        st.markdown(f"""
                        <div class="cve-item cve-item-high">
                            <strong>{cve['id']}</strong> | Confidence: {cve['score']:.1%} | Host: {cve['host']}
                        </div>
                        """, unsafe_allow_html=True)
            
            if all_cves:
                st.success(f"Found {len(all_cves)} unique CVEs from NLP mapping")
            elif st.session_state.findings:
                st.info("No CVEs matched with current confidence threshold (0.3)")
        
        except Exception as e:
            st.warning(f"CVE metrics display error: {str(e)}")

    
        st.markdown("---")
    
    # Export Options
    st.markdown('<div class="section-header"><h2>Export Reports</h2></div>', unsafe_allow_html=True)
    
    col1, col2, col3, col4 = st.columns(4)
    
    # Generate data for exports
    findings_df = pd.DataFrame(st.session_state.findings)
    
    with col1:
        if st.button("Download PDF Report", use_container_width=True):
            try:
                from reportlab.lib.pagesizes import letter
                from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
                from reportlab.lib.units import inch
                from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
                from reportlab.lib import colors
                from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
                import io
                import kaleido
                
                # Create PDF buffer
                pdf_buffer = io.BytesIO()
                doc = SimpleDocTemplate(pdf_buffer, pagesize=letter, 
                                       topMargin=0.5*inch, bottomMargin=0.5*inch,
                                       leftMargin=0.75*inch, rightMargin=0.75*inch)
                story = []
                
                # Styles
                styles = getSampleStyleSheet()
                
                title_style = ParagraphStyle(
                    'CustomTitle',
                    parent=styles['Heading1'],
                    fontSize=28,
                    textColor=colors.HexColor('#1e3a8a'),
                    spaceAfter=12,
                    alignment=TA_CENTER,
                    fontName='Helvetica-Bold'
                )
                
                subtitle_style = ParagraphStyle(
                    'SubTitle',
                    parent=styles['Normal'],
                    fontSize=11,
                    textColor=colors.HexColor('#64748b'),
                    spaceAfter=20,
                    alignment=TA_CENTER,
                    fontName='Helvetica'
                )
                
                heading_style = ParagraphStyle(
                    'CustomHeading',
                    parent=styles['Heading2'],
                    fontSize=14,
                    textColor=colors.white,
                    spaceAfter=12,
                    spaceBefore=12,
                    fontName='Helvetica-Bold',
                    backColor=colors.HexColor('#3b82f6'),
                    borderPadding=10
                )
                
                # Title Page
                story.append(Spacer(1, 0.5*inch))
                story.append(Paragraph("SECURITY ASSESSMENT REPORT", title_style))
                story.append(Paragraph("Professional Penetration Testing", subtitle_style))
                story.append(Spacer(1, 0.3*inch))
                
                # Header Info Table
                header_data = [
                    ['Target IP/Hostname:', st.session_state.target_ip or 'Uploaded Report'],
                    ['Assessment Date:', datetime.now().strftime('%B %d, %Y')],
                    ['Assessment Time:', datetime.now().strftime('%H:%M:%S')],
                    ['Total Vulnerabilities:', str(len(st.session_state.findings))],
                    ['Report Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                ]
                
                header_table = Table(header_data, colWidths=[2.5*inch, 3.5*inch])
                header_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e0e7ff')),
                    ('BACKGROUND', (1, 0), (1, -1), colors.white),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#1e293b')),
                    ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
                    ('ALIGN', (1, 0), (1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 11),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('TOPPADDING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
                ]))
                story.append(header_table)
                story.append(Spacer(1, 0.4*inch))
                
                # Executive Summary Section
                story.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
                story.append(Spacer(1, 0.15*inch))
                
                # Risk Overview
                risk_overview = f"""
                <b>Assessment Overview:</b><br/>
                This security assessment identified a total of <b>{len(st.session_state.findings)} vulnerabilities</b> across the target infrastructure. 
                The assessment includes critical, high, medium, low, and informational severity findings. This report provides detailed information 
                about each finding, including its impact, likelihood, and recommended remediation steps.
                """
                
                story.append(Paragraph(risk_overview, styles['Normal']))
                story.append(Spacer(1, 0.2*inch))
                
                # Severity Summary Table
                summary_data = [
                    ['Severity Level', 'Count', 'Percentage', 'Risk Level'],
                ]
                
                total_vulns = len(st.session_state.findings)
                severity_colors = {
                    'Critical': colors.HexColor('#fee2e2'),
                    'High': colors.HexColor('#fed7aa'),
                    'Medium': colors.HexColor('#fef3c7'),
                    'Low': colors.HexColor('#dcfce7'),
                    'Informational': colors.HexColor('#e0e7ff')
                }
                
                for severity in ['Critical', 'High', 'Medium', 'Low', 'Informational']:
                    count = stats['by_severity'].get(severity, 0)
                    percentage = f"{(count/total_vulns*100):.1f}%" if total_vulns > 0 else "0%"
                    risk = 'CRITICAL' if severity == 'Critical' else 'HIGH' if severity == 'High' else 'MEDIUM' if severity == 'Medium' else 'LOW'
                    summary_data.append([severity, str(count), percentage, risk])
                
                summary_table = Table(summary_data, colWidths=[1.5*inch, 1*inch, 1.2*inch, 1.3*inch])
                summary_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3b82f6')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('TOPPADDING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
                    ('ROWBACKGROUNDS', (0, 1), (-1, 1), [colors.HexColor('#fee2e2')]),
                    ('ROWBACKGROUNDS', (0, 2), (-1, 2), [colors.HexColor('#fed7aa')]),
                    ('ROWBACKGROUNDS', (0, 3), (-1, 3), [colors.HexColor('#fef3c7')]),
                    ('ROWBACKGROUNDS', (0, 4), (-1, 4), [colors.HexColor('#dcfce7')]),
                    ('ROWBACKGROUNDS', (0, 5), (-1, 5), [colors.HexColor('#e0e7ff')]),
                ]))
                story.append(summary_table)
                story.append(Spacer(1, 0.4*inch))
                
                # Add Charts Page
                story.append(PageBreak())
                story.append(Paragraph("VULNERABILITY ANALYSIS CHARTS", heading_style))
                story.append(Spacer(1, 0.2*inch))
                
                # Generate and add pie chart
                try:
                    severity_data = pd.DataFrame({
                        'Severity': list(stats['by_severity'].keys()),
                        'Count': list(stats['by_severity'].values())
                    })
                    
                    fig_pie = px.pie(
                        severity_data,
                        values='Count',
                        names='Severity',
                        title='Vulnerability Distribution by Severity',
                        color='Severity',
                        color_discrete_map={
                            'Critical': '#ef4444',
                            'High': '#f97316',
                            'Medium': '#f59e0b',
                            'Low': '#84cc16',
                            'Informational': '#06b6d4'
                        }
                    )
                    fig_pie.update_traces(textposition='inside', textinfo='percent+label')
                    fig_pie.update_layout(showlegend=True, height=400, width=600)
                    
                    pie_img_buffer = io.BytesIO()
                    fig_pie.write_image(pie_img_buffer, format='png')
                    pie_img_buffer.seek(0)
                    
                    pie_img = Image(pie_img_buffer, width=4*inch, height=3*inch)
                    story.append(pie_img)
                    story.append(Spacer(1, 0.2*inch))
                except Exception as e:
                    st.warning(f"Could not add pie chart to PDF: {str(e)}")
                
                # Generate and add bar chart
                try:
                    fig_bar = px.bar(
                        severity_data,
                        x='Severity',
                        y='Count',
                        title='Vulnerability Count by Severity',
                        color='Severity',
                        color_discrete_map={
                            'Critical': '#ef4444',
                            'High': '#f97316',
                            'Medium': '#f59e0b',
                            'Low': '#84cc16',
                            'Informational': '#06b6d4'
                        }
                    )
                    fig_bar.update_layout(showlegend=False, height=400, width=600)
                    
                    bar_img_buffer = io.BytesIO()
                    fig_bar.write_image(bar_img_buffer, format='png')
                    bar_img_buffer.seek(0)
                    
                    bar_img = Image(bar_img_buffer, width=4*inch, height=3*inch)
                    story.append(bar_img)
                    story.append(Spacer(1, 0.2*inch))
                except Exception as e:
                    st.warning(f"Could not add bar chart to PDF: {str(e)}")
                
                # Add host distribution chart if available
                if stats.get('by_host'):
                    try:
                        story.append(PageBreak())
                        story.append(Paragraph("HOST ANALYSIS", heading_style))
                        story.append(Spacer(1, 0.2*inch))
                        
                        host_data = pd.DataFrame({
                            'Host': list(stats['by_host'].keys()),
                            'Vulnerabilities': list(stats['by_host'].values())
                        })
                        
                        fig_host = px.bar(
                            host_data,
                            x='Host',
                            y='Vulnerabilities',
                            title='Vulnerabilities per Host',
                            color='Vulnerabilities',
                            color_continuous_scale='Reds'
                        )
                        fig_host.update_layout(height=400, width=600)
                        
                        host_img_buffer = io.BytesIO()
                        fig_host.write_image(host_img_buffer, format='png')
                        host_img_buffer.seek(0)
                        
                        host_img = Image(host_img_buffer, width=5*inch, height=3.5*inch)
                        story.append(host_img)
                    except Exception as e:
                        st.warning(f"Could not add host chart to PDF: {str(e)}")
                
                # Detailed Findings Section
                story.append(PageBreak())
                story.append(Paragraph("DETAILED FINDINGS", heading_style))
                story.append(Spacer(1, 0.15*inch))
                
                # Group findings by severity
                grouped_findings = {}
                for finding in st.session_state.findings:
                    severity = finding.get('severity', 'Informational')
                    if severity not in grouped_findings:
                        grouped_findings[severity] = []
                    grouped_findings[severity].append(finding)
                
                # Display findings by severity
                severity_order = ['Critical', 'High', 'Medium', 'Low', 'Informational']
                finding_number = 1
                
                for severity in severity_order:
                    if severity in grouped_findings:
                        for finding in grouped_findings[severity]:
                            # Finding header
                            finding_header = f"<b>[{finding_number}] {finding.get('title', 'Unknown')}</b>"
                            story.append(Paragraph(finding_header, styles['Heading3']))
                            story.append(Spacer(1, 0.1*inch))
                            
                            # Finding details table
                            details = [
                                ['Severity:', finding.get('severity', 'N/A')],
                                ['Host:', finding.get('host', 'N/A')],
                                ['Port:', str(finding.get('port', 'N/A'))],
                                ['Type:', finding.get('type', 'N/A')],
                            ]
                            
                            details_table = Table(details, colWidths=[1.5*inch, 4*inch])
                            details_table.setStyle(TableStyle([
                                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
                                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                                ('FONTSIZE', (0, 0), (-1, -1), 10),
                                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                                ('TOPPADDING', (0, 0), (-1, -1), 8),
                                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                            ]))
                            story.append(details_table)
                            story.append(Spacer(1, 0.1*inch))
                            
                            # Description
                            description = f"<b>Description:</b><br/>{finding.get('description', 'N/A')}"
                            story.append(Paragraph(description, styles['Normal']))
                            story.append(Spacer(1, 0.1*inch))
                            
                            # CVE Info if available
                            if finding.get('cve_ids'):
                                cve_text = f"<b>Associated CVEs:</b><br/>"
                                for cve_match in finding.get('cve_matches', [])[:5]:
                                    cve_text += f"• {cve_match.get('cve_id', 'N/A')} ({cve_match.get('similarity_score', 0):.1%} confidence)<br/>"
                                story.append(Paragraph(cve_text, styles['Normal']))
                                story.append(Spacer(1, 0.1*inch))
                            
                            # Remediation
                            remediation = f"<b>Recommended Remediation:</b><br/>Review and implement security best practices to address this vulnerability. Consult vendor documentation for specific remediation steps."
                            story.append(Paragraph(remediation, styles['Normal']))
                            story.append(Spacer(1, 0.25*inch))
                            
                            # Page break after every 3 findings
                            if finding_number % 3 == 0:
                                story.append(PageBreak())
                            
                            finding_number += 1
                
                # Conclusion
                story.append(PageBreak())
                story.append(Paragraph("CONCLUSION", heading_style))
                story.append(Spacer(1, 0.15*inch))
                
                conclusion_text = f"""
                This security assessment has identified {len(st.session_state.findings)} vulnerabilities requiring attention. 
                The findings range from critical issues requiring immediate remediation to informational items for awareness.<br/><br/>
                <b>Key Recommendations:</b><br/>
                • Address all Critical and High severity findings immediately<br/>
                • Develop a remediation plan for Medium severity findings<br/>
                • Monitor Low and Informational findings for potential impact<br/>
                • Implement a continuous security monitoring program<br/>
                • Conduct regular security assessments to track progress<br/><br/>
                For detailed remediation guidance, please refer to the vendor security advisories and industry best practices.
                """
                story.append(Paragraph(conclusion_text, styles['Normal']))
                
                # Footer
                story.append(Spacer(1, 0.5*inch))
                footer_style = ParagraphStyle(
                    'Footer',
                    parent=styles['Normal'],
                    fontSize=9,
                    textColor=colors.HexColor('#94a3b8'),
                    alignment=TA_CENTER
                )
                
                # Build PDF
                doc.build(story)
                
                # Download
                pdf_buffer.seek(0)
                st.download_button(
                    "Download PDF",
                    data=pdf_buffer.getvalue(),
                    file_name=f"security_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                    key="pdf_download"
                )
                st.success("Professional PDF report with graphs generated successfully")
            except ImportError:
                st.error("Install required packages: pip install reportlab kaleido")
            except Exception as e:
                st.error(f"PDF generation failed: {str(e)}")
    
    with col2:
        if st.button("Download CSV", use_container_width=True):
            try:
                csv_data = findings_df.to_csv(index=False)
                st.download_button(
                    "Download CSV",
                    data=csv_data,
                    file_name=f"findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    use_container_width=True,
                    key="csv_download"
                )
                st.success("CSV exported successfully")
            except Exception as e:
                st.error(f"CSV export failed: {str(e)}")
    
    with col3:
        if st.button("Download JSON", use_container_width=True):
            try:
                json_data = json.dumps(st.session_state.findings, indent=2, default=str)
                st.download_button(
                    "Download JSON",
                    data=json_data,
                    file_name=f"findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                    use_container_width=True,
                    key="json_download"
                )
                st.success("JSON exported successfully")
            except Exception as e:
                st.error(f"JSON export failed: {str(e)}")
    
    with col4:
        if st.button("Download HTML", use_container_width=True):
            try:
                html_content = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>Security Assessment Report</title>
                    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
                    <style>
                        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.6; }}
                        .container {{ max-width: 900px; margin: 0 auto; background: white; }}
                        .header {{ background: linear-gradient(135deg, #1e3a8a 0%, #0f172a 100%); color: white; padding: 60px 40px; text-align: center; }}
                        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
                        .header p {{ font-size: 1.1em; color: #cbd5e1; }}
                        .info-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; padding: 40px; border-bottom: 2px solid #e2e8f0; }}
                        .info-item {{ padding: 15px; background: #f8fafc; border-radius: 6px; }}
                        .info-item strong {{ color: #3b82f6; }}
                        .summary {{ padding: 40px; }}
                        .summary h2 {{ color: #1e293b; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #3b82f6; }}
                        .severity-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 30px; }}
                        .severity-card {{ padding: 20px; border-radius: 8px; text-align: center; }}
                        .critical {{ background: #fee2e2; border-left: 4px solid #ef4444; }}
                        .high {{ background: #fed7aa; border-left: 4px solid #f97316; }}
                        .medium {{ background: #fef3c7; border-left: 4px solid #f59e0b; }}
                        .low {{ background: #dcfce7; border-left: 4px solid #10b981; }}
                        .info {{ background: #e0e7ff; border-left: 4px solid #3b82f6; }}
                        .severity-card .number {{ font-size: 2em; font-weight: bold; margin-bottom: 5px; }}
                        .severity-card .label {{ font-size: 0.9em; font-weight: 600; }}
                        .charts-section {{ padding: 40px; background: #f8fafc; }}
                        .chart-container {{ margin-bottom: 40px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
                        .findings {{ padding: 40px; }}
                        .finding {{ margin-bottom: 40px; padding: 20px; background: #f8fafc; border-radius: 8px; border-left: 4px solid #3b82f6; }}
                        .finding-title {{ font-size: 1.3em; font-weight: bold; color: #1e293b; margin-bottom: 15px; }}
                        .finding-meta {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 15px; }}
                        .meta-item {{ padding: 10px; background: white; border-radius: 4px; border: 1px solid #e2e8f0; }}
                        .meta-label {{ font-size: 0.85em; color: #64748b; font-weight: 600; }}
                        .meta-value {{ font-size: 0.95em; color: #1e293b; margin-top: 3px; }}
                        .finding-section {{ margin-bottom: 15px; }}
                        .finding-section h4 {{ color: #3b82f6; margin-bottom: 8px; font-size: 0.95em; }}
                        .finding-section p {{ color: #475569; line-height: 1.6; }}
                        .cve-list {{ background: white; padding: 10px; border-radius: 4px; border-left: 3px solid #f59e0b; }}
                        .cve-item {{ padding: 5px 0; font-size: 0.9em; }}
                        .footer {{ background: #f8fafc; padding: 30px; text-align: center; border-top: 2px solid #e2e8f0; color: #64748b; font-size: 0.9em; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>Security Assessment Report</h1>
                            <p>Professional Penetration Testing & Vulnerability Assessment</p>
                        </div>
                        
                        <div class="info-grid">
                            <div class="info-item">
                                <strong>Target:</strong><br/>{st.session_state.target_ip or 'Uploaded Report'}
                            </div>
                            <div class="info-item">
                                <strong>Assessment Date:</strong><br/>{datetime.now().strftime('%B %d, %Y')}
                            </div>
                            <div class="info-item">
                                <strong>Total Findings:</strong><br/>{len(st.session_state.findings)}
                            </div>
                        </div>
                        
                        <div class="summary">
                            <h2>Severity Summary</h2>
                            <div class="severity-grid">
                                <div class="severity-card critical">
                                    <div class="number">{stats['by_severity'].get('Critical', 0)}</div>
                                    <div class="label">Critical</div>
                                </div>
                                <div class="severity-card high">
                                    <div class="number">{stats['by_severity'].get('High', 0)}</div>
                                    <div class="label">High</div>
                                </div>
                                <div class="severity-card medium">
                                    <div class="number">{stats['by_severity'].get('Medium', 0)}</div>
                                    <div class="label">Medium</div>
                                </div>
                                <div class="severity-card low">
                                    <div class="number">{stats['by_severity'].get('Low', 0)}</div>
                                    <div class="label">Low</div>
                                </div>
                                <div class="severity-card info">
                                    <div class="number">{stats['by_severity'].get('Informational', 0)}</div>
                                    <div class="label">Info</div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="charts-section">
                            <h2>Vulnerability Analysis Charts</h2>
                            <div class="chart-container">
                                <div id="pieChart"></div>
                            </div>
                            <div class="chart-container">
                                <div id="barChart"></div>
                            </div>
                        </div>
                        
                        <div class="findings">
                            <h2>Detailed Findings</h2>
                """
                
                for i, finding in enumerate(st.session_state.findings[:50], 1):
                    severity_class = finding.get('severity', 'info').lower()
                    html_content += f"""
                            <div class="finding">
                                <div class="finding-title">[{i}] {finding.get('title', 'Unknown')}</div>
                                <div class="finding-meta">
                                    <div class="meta-item">
                                        <div class="meta-label">Severity</div>
                                        <div class="meta-value"><strong>{finding.get('severity', 'N/A')}</strong></div>
                                    </div>
                                    <div class="meta-item">
                                        <div class="meta-label">Host</div>
                                        <div class="meta-value">{finding.get('host', 'N/A')}</div>
                                    </div>
                                    <div class="meta-item">
                                        <div class="meta-label">Port</div>
                                        <div class="meta-value">{finding.get('port', 'N/A')}</div>
                                    </div>
                                    <div class="meta-item">
                                        <div class="meta-label">Type</div>
                                        <div class="meta-value">{finding.get('type', 'N/A')}</div>
                                    </div>
                                </div>
                                
                                <div class="finding-section">
                                    <h4>Description</h4>
                                    <p>{finding.get('description', 'N/A')}</p>
                                </div>
                    """
                    
                    if finding.get('cve_ids'):
                        html_content += """
                                <div class="finding-section">
                                    <h4>Associated CVEs</h4>
                                    <div class="cve-list">
                        """
                        for cve_match in finding.get('cve_matches', [])[:5]:
                            html_content += f"""
                                        <div class="cve-item">
                                            • {cve_match.get('cve_id', 'N/A')} ({cve_match.get('similarity_score', 0):.1%} confidence)
                                        </div>
                            """
                        html_content += """
                                    </div>
                                </div>
                        """
                    
                    html_content += """
                                <div class="finding-section">
                                    <h4>Remediation</h4>
                                    <p>Review and implement security best practices to address this vulnerability. Consult vendor documentation for specific remediation steps.</p>
                                </div>
                            </div>
                    """
                
                # Add chart data
                severity_data_dict = {
                    'Critical': stats['by_severity'].get('Critical', 0),
                    'High': stats['by_severity'].get('High', 0),
                    'Medium': stats['by_severity'].get('Medium', 0),
                    'Low': stats['by_severity'].get('Low', 0),
                    'Informational': stats['by_severity'].get('Informational', 0),
                }
                
                html_content += f"""
                        </div>
                        
                        <div class="footer">
                            <p> Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        </div>
                    </div>
                    
                    <script>
                        // Pie Chart
                        var pieData = [{{
                            labels: {list(severity_data_dict.keys())},
                            values: {list(severity_data_dict.values())},
                            type: 'pie',
                            marker: {{
                                colors: ['#ef4444', '#f97316', '#f59e0b', '#84cc16', '#06b6d4']
                            }}
                        }}];
                        
                        var pieLayout = {{
                            title: 'Vulnerability Distribution by Severity',
                            height: 400
                        }};
                        
                        Plotly.newPlot('pieChart', pieData, pieLayout);
                        
                        // Bar Chart
                        var barData = [{{
                            x: {list(severity_data_dict.keys())},
                            y: {list(severity_data_dict.values())},
                            type: 'bar',
                            marker: {{
                                color: ['#ef4444', '#f97316', '#f59e0b', '#84cc16', '#06b6d4']
                            }}
                        }}];
                        
                        var barLayout = {{
                            title: 'Vulnerability Count by Severity',
                            xaxis: {{ title: 'Severity' }},
                            yaxis: {{ title: 'Count' }},
                            height: 400
                        }};
                        
                        Plotly.newPlot('barChart', barData, barLayout);
                    </script>
                </body>
                </html>
                """
                
                st.download_button(
                    "Download HTML",
                    data=html_content,
                    file_name=f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                    mime="text/html",
                    use_container_width=True,
                    key="html_download"
                )
                st.success("HTML report with interactive charts generated successfully")
            except Exception as e:
                st.error(f"HTML export failed: {str(e)}")


st.markdown("---")
st.markdown("""
<div style='text-align: center; padding: 20px; color: #64748b; font-size: 0.9em;'>
    <p><strong>NNN-CVE</strong></p>
</div>
""", unsafe_allow_html=True)

