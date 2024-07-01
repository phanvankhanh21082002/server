import sys
import subprocess
import concurrent.futures
import os
import threading

def run_script(script, *args):
    try:
        result = subprocess.run(['python3', script, *args], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error running {script}: {result.stderr}")
        return result
    except Exception as e:
        print(f"Exception running {script}: {e}")
        return None

def run_jadx(apk_file, output_dir):
    try:
        result = subprocess.run(['jadx', apk_file, '-d', output_dir], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error running jadx: {result.stderr}")
        return result.returncode
    except Exception as e:
        print(f"Exception running jadx: {e}")
        return 1

def move_files_when_ready(new_dir, file_hash, result_text):
    html_file_path = os.path.join(new_dir, f"{file_hash}.html")
    txt_file_path = os.path.join(new_dir, f"{file_hash}.txt")

    # Write the final result to txt file
    with open(txt_file_path, 'w') as f:
        f.write(result_text)

    reports_txt_dir = "/var/www/html/reports_txt"
    reports_html_dir = "/var/www/html/reports_html"

    # Move the files to their respective directories
    os.makedirs(reports_txt_dir, exist_ok=True)
    os.makedirs(reports_html_dir, exist_ok=True)
    
    os.rename(txt_file_path, os.path.join(reports_txt_dir, f"{file_hash}.txt"))
    os.rename(html_file_path, os.path.join(reports_html_dir, f"{file_hash}.html"))
    
    print(f"Reports moved to {reports_txt_dir} and {reports_html_dir}")

def main(apk_file_path, extract_folder, file_hash):
    report_script = "/home/ubuntu/Downloads/code_static/report.py"
    clamav_script = "/home/ubuntu/Downloads/code_static/clamav_scan.py"
    ml_script = "/home/ubuntu/Downloads/code_static/machine_learning_ccn.py"
    
    # Initialize variables to capture script outputs
    clamav_infected = False
    ml_is_malware = False
    
    # Run jadx to decompile the APK
    jadx_result = run_jadx(apk_file_path, extract_folder)
    if jadx_result != 0:
        print(f"jadx failed for {apk_file_path}")
        return

    # Use threading events to synchronize the completion of the scripts
    event_report_done = threading.Event()
    event_clamav_done = threading.Event()
    event_ml_done = threading.Event()

    def run_report_script():
        report_result = run_script(report_script, apk_file_path, extract_folder, file_hash)
        if report_result and report_result.returncode == 0:
            event_report_done.set()
        else:
            print(f"report.py failed for {apk_file_path}")

    def run_clamav_script():
        nonlocal clamav_infected
        clamav_result = run_script(clamav_script, apk_file_path)
        if clamav_result and clamav_result.returncode == 0:
            if "Infected files: 0" not in clamav_result.stdout:
                clamav_infected = True
            event_clamav_done.set()
        else:
            print(f"clamav_scan.py failed for {apk_file_path}")

    def run_ml_script():
        nonlocal ml_is_malware
        ml_result = run_script(ml_script, apk_file_path)
        if ml_result and ml_result.returncode == 0:
            ml_is_malware = "malware" in ml_result.stdout.strip().lower()
            event_ml_done.set()
        else:
            print(f"machine_learning_ccn.py failed for {apk_file_path}")

    # Run the scripts in separate threads
    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.submit(run_report_script)
        executor.submit(run_clamav_script)
        executor.submit(run_ml_script)

    # Wait for all scripts to complete
    event_report_done.wait()
    event_clamav_done.wait()
    event_ml_done.wait()

    # Determine final result based on clamav and ml results
    if clamav_infected and ml_is_malware:
        final_result = "Malware"
    elif clamav_infected or ml_is_malware:
        final_result = "Warning"
    else:
        final_result = "Clean"

    # Move the reports to their respective directories
    move_files_when_ready(extract_folder, file_hash, f"Result: {final_result}")

    print(f"All scripts have finished for {apk_file_path}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 parallel.py <apk_file_path> <extract_folder> <file_hash>")
        sys.exit(1)

    apk_file_path = sys.argv[1]
    extract_folder = sys.argv[2]
    file_hash = sys.argv[3]

    main(apk_file_path, extract_folder, file_hash)
