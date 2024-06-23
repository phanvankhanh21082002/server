import os
import json
import subprocess
import sys

def run_grep_search(directory, pattern):
    try:
        result = subprocess.run(['grep', '-r', '-n', '-E', pattern, directory], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"An error occurred while running grep: {e}")
        return ""

def analyze_code_with_rules(source_directory, rule_directory):
    findings = []
    seen_code_snippets = set()  # Set to track unique code snippets
    # Iterate over all JSON files in the rule directory
    for rule_filename in os.listdir(rule_directory):
        if rule_filename.endswith('.json'):
            rule_file_path = os.path.join(rule_directory, rule_filename)
            with open(rule_file_path, 'r') as rule_file:
                rules = json.load(rule_file)
                for pattern_info in rules['patterns']:
                    pattern = pattern_info['pattern']
                    class_name = pattern_info.get('class', None)
                    matches = run_grep_search(source_directory, pattern)
                    if matches:
                        for match in matches.strip().split('\n'):
                            if not match:
                                continue
                            file_path, line_number, code_line = match.split(':', 2)
                            if code_line.strip() in seen_code_snippets:
                                continue  # Skip if code snippet is already seen
                            seen_code_snippets.add(code_line.strip())  # Add to seen set
                            if class_name:
                                with open(file_path, 'r') as java_file:
                                    file_content = java_file.read()
                                    if class_name in file_content:
                                        findings.append((file_path, line_number, code_line.strip(), rule_filename, pattern_info['name']))
                            else:
                                findings.append((file_path, line_number, code_line.strip(), rule_filename, pattern_info['name']))
    return findings

def get_cwe_details(rule_filename):
    cwe_details = {
        'findHardcodedCredentials.json': ('CWE-798', 'Use of Hard-coded Credentials', 'Hard-coded credentials like passwords or keys in software enable unauthorized access.', 'Dangerous'),
        'improper_control_of_generation_of_code.json': ('CWE-94', 'Improper Control of Generation of Code', 'Generates code using unvalidated inputs that could alter its structure or behavior.', 'Dangerous'),
        'storage_of_sensitive_data_without_access_control.json': ('CWE-921', 'Storage of Sensitive Data in a Mechanism without Access Control', 'Stores sensitive data without access control, exposing it to unauthorized access.', 'Warning'),
        'cleartext_storage_of_sensitive_information.json': ('CWE-312', 'Cleartext Storage of Sensitive Information', 'Stores sensitive information unencrypted, risking exposure to unauthorized entities.', 'Warning'),
        'sql_command.json': ('CWE-89', 'Improper Neutralization of Special Elements used in an SQL Command', 'Forms SQL commands using unvalidated inputs, potentially altering command behavior or causing SQL injection.', 'Dangerous'),
        'improper_export_of_android_application_components.json': ('CWE-926', 'Improper Export of Android Application Components', 'Exports Android components without restricting access to authorized apps only.', 'Warning'),
        'exposed_dangerous_method_or_function.json': ('CWE-749', 'Exposed Dangerous Method or Function', 'Provides a dangerous method or function through an API without adequate restrictions.', 'Warning'),
        'insertion_of_sensitive_information_into_log.json': ('CWE-532', 'Insertion of sensitive information into Log file', 'Logs sensitive information, potentially exposing it to unauthorized access.', 'Warning'),
        'RSA_algorithm_without_oaep.json': ('CWE-780', 'Use of RSA Algorithm without OAEP', 'Uses RSA without optimal padding, weakening encryption.', 'Dangerous'),
        'cleartext_transmission_of_sensitive_information.json': ('CWE-319', 'Cleartext Transmission of Sensitive Information', 'Transmits sensitive data unencrypted, exposing it to eavesdropping.', 'Warning'),
        'broken_or_risky_cryptographic_algorithm.json': ('CWE-327', 'Use of a Broken or Risky Cryptographic Algorithm', 'Uses insecure or outdated cryptographic algorithms.', 'Dangerous'),
        'improper_input_validation.json': ('CWE-20', 'Improper Input Validation', 'Accepts data without proper validation, leading to potential security risks.', 'Warning'),
        'xss_cwe_79.json': ('CWE-79', 'Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)', 'Fails to properly sanitize user input for web page generation, leading to cross-site scripting (XSS).', 'Dangerous'),
        'weak_hash.json': ('CWE-328', 'Use of Weak Hash', 'Employs weak hashing algorithms, making it easier to breach.', 'Warning'),
        'active_debug.json': ('CWE-489', 'Active Debug Code', 'Contains active debug code which could be exploited if accessed by attackers.', 'Warning'),
        'path_traversal.json': ('CWE-22', 'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)', 'Allows directory traversal attacks due to improper handling of file paths.', 'Dangerous'),
        'relative_path_traversal.json': ('CWE-23', 'Relative Path Traversal', 'Does not adequately handle relative paths, allowing traversal outside restricted directories.', 'Dangerous'),
        'crypto_weak_pseudo_random_number.json': ('CWE-338', 'Use of Cryptographically Weak Pseudo-Random Number Generator', 'Uses weak PRNGs in security contexts, compromising cryptographic functions.', 'Warning'),
        'improper_neutralization_of_argument_delimiters.json': ('CWE-88', 'Improper Neutralization of Argument Delimiters in a Command (Argument Injection)', 'Does not properly separate commands from data, leading to argument injection.', 'Dangerous'),
        'improper_verification_of_intent_by_broadcast_receiver.json': ('CWE-925', 'Improper Verification of Intent by Broadcast Receiver', 'Fails to verify the source of intents in broadcast receivers, risking spoofing and data leaks.', 'Warning'),
        'external_control_of_file_name.json': ('CWE-73', 'External Control of File Name or Path', 'Allows external control over file names or paths, potentially leading to unauthorized file access.', 'Warning'),
        'os_command_injection.json': ('CWE-78', 'Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)', 'Susceptible to OS command injections by not neutralizing special elements in command strings.', 'Dangerous'),
        'improper_output_for_logs.json': ('CWE-117', 'Improper Output Neutralization for Logs', 'Does not properly neutralize data written to logs, potentially exposing sensitive information.', 'Warning'),
        'improper_verification_of_source_a_communication.json': ('CWE-940', 'Improper Verification of Source of a Communication Channel', 'Does not verify the source of incoming communication, risking data interception.', 'Dangerous'),
        'deserialization_of_untrusted_data.json': ('CWE-502', 'Deserialization of Untrusted Data', 'Unsafe deserialization of data can lead to execution of malicious code.', 'Dangerous'),
        'url_redirection_to_untrusted_site.json': ('CWE-601', 'URL Redirection to Untrusted Site (Open Redirect)', 'Enables URL redirection to untrusted sites, facilitating phishing attacks.', 'Warning')
    }

    return cwe_details.get(rule_filename, ('Unknown', 'Unknown CWE', 'No description available', 'Unknown'))

def main():
    source_directory = sys.argv[1]
    rule_directory = '/home/ubuntu/Downloads/code_static/owasp_rule'

    findings = analyze_code_with_rules(source_directory, rule_directory)

    # Collect findings in a structured format for JSON output
    structured_findings = []
    for finding in findings:
        rule_filename = finding[3]
        cwe, name, description, severity = get_cwe_details(rule_filename)
        structured_findings.append({
            "CWE": f"{cwe}: {name}",
            "Code": f"Code: {finding[2]}",
            "Description": description,
            "Severity": severity
        })

    # Output the structured findings as JSON
    print(json.dumps(structured_findings, indent=4))

if __name__ == "__main__":
    main()
