#!/bin/bash

WATCH_DIR="/home/ubuntu/uploads"
ANALYSIS_DIR="/home/ubuntu/apk_analysis"
PARALLEL_SCRIPT="/home/ubuntu/Downloads/code_static/parallel.py"

monitor_and_process() {
    inotifywait -m -e create --format "%f" "$WATCH_DIR" | while read NEW_FILE
    do
        if [[ "$NEW_FILE" == *.apk ]]
        then
            echo "New APK file detected: $NEW_FILE"
            
            # Full path of the new APK file
            FILE_PATH="$WATCH_DIR/$NEW_FILE"
            echo "File path: $FILE_PATH"

            # Wait until the file is fully written
            while [ ! -s "$FILE_PATH" ]; do
                echo "Waiting for the file to be fully written: $FILE_PATH"
                sleep 1
            done
            
            # Verify that the file is fully written by checking if its size stabilizes
            while true; do
                FILE_SIZE=$(stat -c%s "$FILE_PATH")
                sleep 1
                NEW_FILE_SIZE=$(stat -c%s "$FILE_PATH")
                if [ "$FILE_SIZE" -eq "$NEW_FILE_SIZE" ]; then
                    break
                fi
                echo "File size is changing. Waiting for it to stabilize: $FILE_PATH"
            done
            
            # Calculate the hash of the APK file
            FILE_HASH=$(sha256sum "$FILE_PATH" | awk '{print $1}')
            echo "File hash: $FILE_HASH"
            
            # Define the directory path named with the file hash
            NEW_DIR="$ANALYSIS_DIR/$FILE_HASH"

            # Check if the directory already exists
            if [ -d "$NEW_DIR" ]; then
                echo "Directory $NEW_DIR already exists. Skipping processing."
            else
                mkdir -p "$NEW_DIR"
                
                # Move the new APK file into the new directory
                mv "$FILE_PATH" "$NEW_DIR/$NEW_FILE"
                echo "Moved $NEW_FILE to $NEW_DIR"
                
                # Run the processing script
                python3 "$PARALLEL_SCRIPT" "$NEW_DIR/$NEW_FILE" "$NEW_DIR" "$FILE_HASH"
            fi
        fi
    done
}

while true
do
    monitor_and_process
    sleep 1
done
