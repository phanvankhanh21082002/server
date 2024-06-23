import subprocess
import json
import pdfkit
import sys

def run_python_script(script_path, *args):
    try:
        result = subprocess.run(['python3', script_path, *args], capture_output=True, text=True)
        return json.loads(result.stdout)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        print(f"Error running {script_path}: {e}")
        return None

def generate_report(apk_file_path, extract_folder,file_hash):
    # Run the scripts and capture their outputs
    clamav_scan_results = run_python_script('/home/ubuntu/Downloads/code_static/clamav_scan.py', apk_file_path)
    file_information_output = run_python_script('/home/ubuntu/Downloads/code_static/file_information.py', apk_file_path)
    app_information_output = run_python_script('/home/ubuntu/Downloads/code_static/app_information.py', apk_file_path)
    app_components_output = run_python_script('/home/ubuntu/Downloads/code_static/acti_service_recei_provide.py', apk_file_path)
    certificate_info_output = run_python_script('/home/ubuntu/Downloads/code_static/read_certificate_sdk.py', apk_file_path)
    permissions_info_output = run_python_script('/home/ubuntu/Downloads/code_static/read_manifest.py', extract_folder)
    api_info_output = run_python_script('/home/ubuntu/Downloads/code_static/read_android_api.py', extract_folder)
    browsable_activities_output = run_python_script('/home/ubuntu/Downloads/code_static/read_browser_activities.py', extract_folder)
    manifest_analysis_output = run_python_script('/home/ubuntu/Downloads/code_static/read_manifest_analysis.py', apk_file_path, extract_folder)
    owasp_analysis_output = run_python_script('/home/ubuntu/Downloads/code_static/owasp_analysis.py', extract_folder)
    shared_library_analysis_output = run_python_script('/home/ubuntu/Downloads/code_static/shared_library_analysis.py', extract_folder)
    niap_analysis_output = run_python_script('/home/ubuntu/Downloads/code_static/niap_analysis.py', extract_folder)
    apkid_analysis_output = run_python_script('/home/ubuntu/Downloads/code_static/apkid_analysis.py', apk_file_path)
    server_locations_output = run_python_script('/home/ubuntu/Downloads/code_static/server_locations.py', extract_folder)
    url_domain_email_output = run_python_script('/home/ubuntu/Downloads/code_static/url_domain_email.py', extract_folder)
    
    # Sort permissions by level
    sorted_permissions = sorted(permissions_info_output, key=lambda x: ('1' if x['level'] == 'dangerous' else ('2' if x['level'] == 'normal' else '3')))

    # Create HTML content
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>APK Analysis Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { text-align: center; }
            .section { margin-bottom: 5px; }
            .section-title { font-size: 18px; margin-bottom: 5px; }
            .box { border: 1px solid #000; padding: 10px; margin-bottom: 5px; }
            .normal { background-color: #d4edda; color: #155724; }
            .dangerous { background-color: #f8d7da; color: #721c24; }
            .unknown { background-color: #e2e3e5; color: #383d41; }
            .info { background-color: #cce5ff; color: #004085; }
            .permission-table, .issue-table, .clamav-table { width: 100%; border-collapse: collapse; margin-top: 5px; table-layout: fixed; font-size: 12px; }
            .permission-table th, .permission-table td, .issue-table th, .issue-table td, .clamav-table th, .clamav-table td { border: 1px solid #000; padding: 8px; text-align: left; word-wrap: break-word; }
            .permission-table th, .issue-table th, .clamav-table th { background-color: #f2f2f2; }
            .narrow-column { width: 10%; }
            .medium-column { width: 20%; }
            .wide-column { width: 35%; }
            .extra-wide-column { width: 40%; }
            tr { page-break-inside: avoid; }
            .break-row { border-top: 1px solid #000; }
            .warning { background-color: #fff3cd; color: #856404; }
        </style>
    </head>
    <body>
        <h1>APK Analysis Report</h1>
        <div class="section">
            <div class="section-title">ClamAV Scan Results</div>
            <table class="clamav-table">
                <tr>
                    <th class="wide-column">Filename</th>
                    <th class="extra-wide-column">Details</th>
                </tr>
    """

    # Add ClamAV scan results
    if clamav_scan_results:
        html_content += f"""
                <tr class="info">
                    <td>{clamav_scan_results['filename']}</td>
                    <td><pre>{clamav_scan_results['details']}</pre></td>
                </tr>
        """
    
    html_content += """
            </table>
        </div>
        <div class="section">
            <div class="section-title">File Information</div>
            <div class="box">
    """

    for key, value in (file_information_output or {}).items():
        html_content += f"<p><strong>{key}:</strong> {value}</p>"

    html_content += """
            </div>
        </div>
        <div class="section">
            <div class="section-title">App Information</div>
            <div class="box">
    """

    for key, value in (app_information_output or {}).items():
        html_content += f"<p><strong>{key}:</strong> {value}</p>"

    html_content += """
            </div>
        </div>
        <div class="section">
            <div class="section-title">App Components</div>
            <table class="issue-table">
                <tr>
                    <th class="medium-column">Type</th>
                    <th class="extra-wide-column">Details</th>
                </tr>
    """

    for component_type, components in (app_components_output or {}).items():
        details = '<br>'.join(components)
        html_content += f"""
                <tr>
                    <td>{component_type}</td>
                    <td>{details}</td>
                </tr>
        """
    
    html_content += """
            </table>
        </div>
        <div class="section">
            <div class="section-title">Signer Certificate</div>
            <div class="box">
    """

    if certificate_info_output:
        if "certificate_info" in certificate_info_output:
            for line in certificate_info_output["certificate_info"].split('\n'):
                html_content += f"<p>{line}</p>"
        else:
            html_content += "<p>Verification Failed</p>"

    html_content += """
            </div>
        </div>
        <div class="section">
            <div class="section-title">Permissions Information</div>
            <table class="permission-table">
                <tr>
                    <th>Permission</th>
                    <th class="narrow-column">Level</th>
                    <th>Description</th>
                    <th>Details</th>
                </tr>
    """

    for perm in sorted_permissions:
        level_class = perm["level"]
        html_content += f"""
                <tr class="{level_class}">
                    <td>{perm['name']}</td>
                    <td>{perm['level']}</td>
                    <td>{perm['description']}</td>
                    <td>{perm['details']}</td>
                </tr>
        """

    html_content += """
            </table>
        </div>
        <div class="section">
            <div class="section-title">Browsable Activities</div>
            <table class="permission-table">
                <tr>
                    <th class="wide-column">Activity</th>
                    <th class="medium-column">Scheme</th>
                    <th class="medium-column">Host</th>
                    <th class="narrow-column">Path</th>
                </tr>
    """

    for activity in (browsable_activities_output or []):
        html_content += f"""
                <tr class="info">
                    <td>{activity['Activity']}</td>
                    <td>{activity['Scheme']}</td>
                    <td>{activity['Host']}</td>
                    <td>{activity['Path']}</td>
                </tr>
        """

    html_content += """
            </table>
        </div>
        <div class="section">
            <div class="section-title">Android API Information</div>
            <table class="permission-table">
                <tr>
                    <th class="medium-column">API ID</th>
                    <th class="narrow-column">Severity</th>
                    <th class="wide-column">Message</th>
                </tr>
    """

    for api_id, info in (api_info_output or {}).items():
        html_content += f"""
                <tr class="info break-row">
                    <td>{api_id}</td>
                    <td>{info['severity']}</td>
                    <td>{info['message']}</td>
                </tr>
        """

    html_content += """
            </table>
        </div>
                <div class="section">
            <div class="section-title">Manifest Analysis</div>
            <table class="issue-table">
                <tr>
                    <th class="wide-column">Issue</th>
                    <th class="narrow-column">Severity</th>
                </tr>
    """

    for issue in (manifest_analysis_output or []):
        html_content += f"""
                <tr class="warning">
                    <td>{issue['name']}</td>
                    <td>warning</td>
                </tr>
        """

    html_content += """
            </table>
        </div>
        <div class="section">
            <div class="section-title">OWASP Analysis</div>
            <table class="issue-table">
                <tr>
                    <th class="medium-column">CWE</th>
                    <th class="wide-column">Code</th>
                    <th class="narrow-column">Severity</th>
                    <th class="medium-column">Description</th>
                </tr>
    """

    for finding in (owasp_analysis_output or []):
        severity_class = finding["Severity"].lower()
        html_content += f"""
                <tr class="{severity_class}">
                    <td>{finding['CWE']}</td>
                    <td>{finding['Code']}</td>
                    <td>{finding['Severity']}</td>
                    <td>{finding['Description']}</td>
                </tr>
        """

    html_content += """
            </table>
        </div>
        <div class="section">
            <div class="section-title">Shared Library Analysis</div>
            <table class="issue-table">
                <tr>
                    <th class="medium-column">Shared Object</th>
                    <th class="narrow-column">NX</th>
                    <th class="narrow-column">Stack Canary</th>
                    <th class="narrow-column">RELRO</th>
                    <th class="medium-column">RPATH</th>
                    <th class="medium-column">RUNPATH</th>
                    <th class="medium-column">FORTIFY</th>
                    <th class="medium-column">SYMBOLS STRIPPED</th>
                </tr>
    """

    for lib in (shared_library_analysis_output or []):
        html_content += f"""
                <tr class="info">
                    <td>{lib['name']}</td>
                    <td>{lib['nx']['is_nx']}</td>
                    <td>{lib['stack_canary']['has_canary']}</td>
                    <td>{lib['relocation_readonly']['relro']}</td>
                    <td>{lib['rpath']['rpath'] if lib['rpath']['rpath'] is not None else 'None'}</td>
                    <td>{lib['runpath']['runpath'] if lib['runpath']['runpath'] is not None else 'None'}</td>
                    <td>{lib['fortify']['is_fortified']}</td>
                    <td>{lib['symbol']['is_stripped']}</td>
                </tr>
        """

    html_content += """
            </table>
        </div>
        <div class="section">
            <div class="section-title">NIAP Analysis</div>
            <table class="issue-table">
                <tr>
                    <th class="medium-column">Identifier</th>
                    <th class="medium-column">Requirement</th>
                    <th class="wide-column">Feature</th>
                    <th class="extra-wide-column">Description</th>
                </tr>
    """

    for niap in (niap_analysis_output or []):
        html_content += f"""
                <tr class="info">
                    <td>{niap[0]}</td>
                    <td>{niap[1]}</td>
                    <td>{niap[2]}</td>
                    <td>{niap[3]}</td>
                </tr>
        """

    html_content += """
            </table>
        </div>
        <div class="section">
            <div class="section-title">APKiD Analysis</div>
            <table class="issue-table">
                <tr>
                    <th class="medium-column">DEX File</th>
                    <th class="medium-column">Finding</th>
                    <th class="wide-column">Description</th>
                </tr>
    """

    for dex_file, findings in (apkid_analysis_output or {}).items():
        for finding in findings:
            html_content += f"""
                <tr class="info">
                    <td>{dex_file}</td>
                    <td>{finding['finding']}</td>
                    <td>{finding['description']}</td>
                </tr>
        """

    html_content += """
            </table>
        </div>
        <div class="section">
            <div class="section-title">Server Locations</div>
            <table class="issue-table">
                <tr>
                    <th class="wide-column">Domain Name</th>
                    <th class="extra-wide-column">Details</th>
                </tr>
    """

    for domain, details in (server_locations_output or {}).items():
        if details['ip'] != 'N/A':
            google_maps_link = details.get('google_maps_link', 'N/A')
            html_content += f"""
                <tr class="info">
                    <td>{domain}</td>
                    <td>IP: {details['ip']}<br>Country: {details['country']}<br>Region: {details['region']}<br>City: {details['city']}<br>ASN: {details['asn']}<br><a href="{google_maps_link}" target="_blank">View on Google Maps</a></td>
                </tr>
        """

    html_content += """
            </table>
        </div>
        <div class="section">
            <div class="section-title">URLs, Domains, and Emails</div>
            <table class="issue-table">
                <tr>
                    <th class="medium-column">Type</th>
                    <th class="wide-column">Details</th>
                </tr>
    """

    if url_domain_email_output:
        for type_, details in zip(url_domain_email_output["Type"], url_domain_email_output["Details"]):
            if details:  # Only include types with details
                html_content += f"""
                    <tr class="info">
                        <td>{type_}</td>
                        <td>{'<br>'.join(details)}</td>
                    </tr>
        """

    html_content += """
            </table>
        </div>
    </body>
    </html>
    """

    # Save the HTML content to a file
    if clamav_scan_results:
        relevant_details = extract_relevant_clamav_details(clamav_scan_results['details'])

    html_file_path = f"/var/www/html/reports_html/{file_hash}.html"
    txt_file_path = f"/var/www/html/reports_txt/{file_hash}.txt"

    with open(html_file_path, "w") as html_file:
        html_file.write(html_content)

    # Save ClamAV scan results to a TXT file
    with open(txt_file_path, "w") as txt_file:
        txt_file.write(relevant_details)

    print(f"Report generated and saved to {txt_file_path}")

# Function to extract relevant details
def extract_relevant_clamav_details(details):
    summary_start = details.find("----------- SCAN SUMMARY -----------")
    if summary_start != -1:
        return details[summary_start + len("----------- SCAN SUMMARY -----------"):].strip()
    return details

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 report.py <apk_file_path> <extract_folder> <file_hash>")
        sys.exit(1)

    apk_file_path = sys.argv[1]
    extract_folder = sys.argv[2]
    file_hash = sys.argv[3]
    generate_report(apk_file_path, extract_folder, file_hash)

