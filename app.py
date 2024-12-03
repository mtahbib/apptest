import streamlit as st
import shodan
import pandas as pd
import plotly.express as px
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

SHODAN_API_KEY = 'I3MYDxnH8JA8mRhnnbcgBwgXDxdRnEm5'
api = shodan.Shodan(SHODAN_API_KEY)

# Function to fetch CVE data from Shodan
def fetch_shodan_data(ip):
    try:
        host = api.host(ip)
        vulnerabilities = host.get('vulns', [])
        return [{"CVE ID": cve_id} for cve_id in vulnerabilities]
    except shodan.APIError as e:
        return {"error": str(e)}

# Function to fetch CVE details from CIRCL API
def fetch_cve_data_circl(cve_id):
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                "CVSS Score": data.get("cvss", "N/A"),
                "Severity": "High" if data.get("cvss", 0) >= 7 else "Low",
                "Summary": data.get("summary", "No description available"),
                "References": data.get("references", [])
            }
        else:
            return {"CVSS Score": "N/A", "Severity": "Unknown", "Summary": "No data available", "References": []}
    except Exception as e:
        return {"CVSS Score": "N/A", "Severity": "Unknown", "Summary": str(e), "References": []}

# Process CVEs with threading
def process_cves_with_threading(cves):
    enriched_data = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_cve = {executor.submit(fetch_cve_data_circl, cve["CVE ID"]): cve for cve in cves}
        for future in as_completed(future_to_cve):
            cve = future_to_cve[future]
            try:
                enriched_cve = future.result()
                enriched_cve["CVE ID"] = cve["CVE ID"]
                enriched_data.append(enriched_cve)
            except Exception as e:
                enriched_data.append({"CVE ID": cve["CVE ID"], "CVSS Score": "N/A", "Severity": "Unknown", "Summary": str(e), "References": []})
    return enriched_data

# Categorize CVEs by severity
def categorize_cves(cves):
    grouped = {"Critical": [], "High": [], "Medium": [], "Low": [], "Unknown": []}
    for cve in cves:
        score = cve.get("CVSS Score", "N/A")
        try:
            score = float(score)
            if score >= 9:
                grouped["Critical"].append(cve)
            elif score >= 7:
                grouped["High"].append(cve)
            elif score >= 4:
                grouped["Medium"].append(cve)
            else:
                grouped["Low"].append(cve)
        except ValueError:
            grouped["Unknown"].append(cve)
    return grouped

# Header with title
st.markdown('<div class="header">IP Vulnerability Monitoring & Analytics Tool</div>', unsafe_allow_html=True)

# Input IP addresses
user_input = st.text_area("Enter IP address (For multiple IP use comma  ""):", "")
ip_list = [ip.strip() for ip in user_input.split(',') if ip.strip()]

# Analyze button
if st.button("Analyze IPs"):
    if not ip_list:
        st.error("Please provide at least one IP address.")
    else:
        all_cve_data = []
        start_time = time.time()

        def process_ip(ip):
            cve_data = fetch_shodan_data(ip)
            if isinstance(cve_data, dict) and "error" in cve_data:
                return {"ip": ip, "error": cve_data["error"]}
            enriched_data = process_cves_with_threading(cve_data[:10])  # Limit to first 10 CVEs per IP
            return {"ip": ip, "data": enriched_data}

        with ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(process_ip, ip_list))

        for result in results:
            ip = result["ip"]
            st.subheader(f"IP Address: {ip}")

            if "error" in result:
                st.error(f"Error fetching data for {ip}: {result['error']}")
                continue

            data = result.get("data", [])
            if not data:
                st.warning(f"No vulnerabilities found for IP: {ip}")
                continue

            all_cve_data.extend(data)

            grouped_cves = categorize_cves(data)

            col1, col2 = st.columns([1, 2])
            with col1:
                st.subheader(f"Summary for IP: {ip}")
                for severity, cves in grouped_cves.items():
                    st.write(f"- **{severity} Severity:** {len(cves)} CVEs")

            with col2:
                severity_counts = {severity: len(cves) for severity, cves in grouped_cves.items()}
                fig = px.pie(
                    names=list(severity_counts.keys()),
                    values=list(severity_counts.values()),
                    title=f"Severity Distribution for {ip}",
                    color_discrete_sequence=px.colors.sequential.RdBu
                )
                fig.update_layout(legend=dict(yanchor="top", y=1, xanchor="right", x=1))
                st.plotly_chart(fig, use_container_width=True)

            for severity, cves in grouped_cves.items():
                if cves:
                    with st.expander(f"{severity} Severity CVEs ({len(cves)} total)"):
                        for cve in cves:
                            st.markdown(f"""
                                - **CVE ID**: {cve['CVE ID']}
                                - **CVSS Score**: {cve['CVSS Score']}
                                - **Severity**: {cve['Severity']}
                                - **Summary**: {cve['Summary']}
                                - **References**: {', '.join(cve['References']) if cve['References'] else 'None'}
                            """)

        st.success(f"Analysis completed!")

        if all_cve_data:
            df = pd.DataFrame(all_cve_data)
            csv = df.to_csv(index=False)
            st.download_button(
                label="Download CVE Report as CSV",
                data=csv,
                file_name="cve_report.csv",
                mime="text/csv"
            )

# Add footer
st.markdown(
    """
    <hr>
    <div style="text-align: center; font-size: 12px; color: gray;">
        Made by <b>Tahbib Manzoor</b>
    </div>
    """,
    unsafe_allow_html=True
)
