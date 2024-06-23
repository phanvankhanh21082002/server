import os
import logging
import json
import sys

logger = logging.getLogger(__name__)

def settings_enabled(setting):
    # Mock function to represent the settings check. Replace with actual implementation.
    return True

def apkid_analysis(apk_file):
    """APKID Analysis of DEX files."""
    if not settings_enabled('APKID_ENABLED'):
        return {}
    
    try:
        import apkid
    except ImportError:
        logger.error('APKiD - Could not import APKiD')
        return {}
    
    if not os.path.exists(apk_file):
        logger.error('APKiD - APK not found')
        return {}
    
    apkid_ver = getattr(apkid, '__version__', 'unknown')
    from apkid.apkid import Scanner, Options
    from apkid.output import OutputFormatter
    from apkid.rules import RulesManager
    
    logger.info('Running APKiD %s', apkid_ver)
    
    options = Options(
        timeout=30,
        verbose=False,
        entry_max_scan_size=100 * 1024 * 1024,  # Example max memory size
        recursive=True,
    )
    
    rules_manager = RulesManager()
    rules = rules_manager.load()
    
    output = OutputFormatter(
        json_output=True,
        output_dir=None,
        rules_manager=rules_manager,
        include_types=False,
    )
    
    scanner = Scanner(rules, options)
    res = scanner.scan_file(apk_file)
    
    try:
        findings = output._build_json_output(res)['files']
    except AttributeError:
        try:
            findings = output.build_json_output(res)['files']
        except AttributeError:
            logger.error('yara-python dependency required by '
                         'APKiD is not installed properly. '
                         'Skipping APKiD analysis!')
            return {}
    
    sanitized = {}
    for item in findings:
        filename = item['filename']
        if '!' in filename:
            filename = filename.split('!', 1)[1]
        sanitized[filename] = item['matches']
    
    return sanitized

def get_description(finding):
    descriptions = {
        "anti_vm": "Code that detects if the app is running in a virtual machine.",
        "compiler": "Identifiers related to specific compilers or obfuscation tools.",
        "obfuscation": "Techniques used to obfuscate code, making it difficult to reverse-engineer.",
        "malicious_code": "Patterns commonly found in malware.",
        "sensitive_data_exposure": "Code that might expose sensitive data.",
        "network_exfiltration": "Code related to networking and data exfiltration.",
        "encryption": "Implementation of encryption, potentially to protect or hide data.",
        "rooting_detection": "Code that detects if the device has been rooted."
    }
    return descriptions.get(finding, "No description provided")

def main():
    apk_file = sys.argv[1]

    results = apkid_analysis(apk_file)
    file_info = {}
    for dex_file, matches in results.items():
        file_info[dex_file] = []
        for match in matches:
            if isinstance(match, dict):
                rule = match.get('rule', 'Unknown rule')
            else:
                rule = match
            
            description = get_description(rule)
            
            file_info[dex_file].append({
                'finding': rule,
                'description': description
            })

    print(json.dumps(file_info))

if __name__ == "__main__":
    main()
