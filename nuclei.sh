#!/bin/bash

# Function to check if a command exists
command_exists () {
    type "$1" &> /dev/null ;
}

# Ensure all necessary commands are available
echo "Checking required tools..."
for cmd in subfinder amass nuclei assetfinder notify; do
    command_exists "$cmd" || { echo "$cmd not found. Please install $cmd and ensure it's in your PATH."; exit 1; }
done

# Check if the input is a file or a single domain
if [ $# -ne 1 ]; then
  echo "Usage: $0 <target-domain or input-file>"
  exit 1
fi

INPUT="$1"

# Create a main directory to store all results if it doesn't exist
MAIN_OUTPUT_DIR="output"
mkdir -p "$MAIN_OUTPUT_DIR" || { echo "Failed to create main directory: $MAIN_OUTPUT_DIR"; exit 1; }

# Determine if the input is a file or a single domain
if [ -f "$INPUT" ]; then
    DOMAIN_LIST=$(cat "$INPUT")
else
    DOMAIN_LIST="$INPUT"
fi

# Process each domain
for TARGET in $DOMAIN_LIST; do
    # Skip empty lines and comments
    [[ -z "$TARGET" || "$TARGET" =~ ^# ]] && continue

    # Create a directory for each main domain under the main output directory
    DOMAIN_OUTPUT_DIR="$MAIN_OUTPUT_DIR/$TARGET"

    # Check if the directory already exists and remove it if it does
    if [ -d "$DOMAIN_OUTPUT_DIR" ]; then
        echo "Directory for $TARGET already exists. Removing existing directory: $DOMAIN_OUTPUT_DIR"
        rm -rf "$DOMAIN_OUTPUT_DIR"
    fi

    # Create a new directory for the domain
    mkdir -p "$DOMAIN_OUTPUT_DIR" || { echo "Failed to create directory: $DOMAIN_OUTPUT_DIR"; exit 1; }

    # Run subfinder
    echo -e "\nRunning subfinder for $TARGET..."
    subfinder -d "$TARGET" -all -silent -o "$DOMAIN_OUTPUT_DIR/subdomains_subfinder.txt"
    if [ $? -ne 0 ]; then
      echo "subfinder failed for $TARGET"
      continue
    else
      subfinder_count=$(wc -l < "$DOMAIN_OUTPUT_DIR/subdomains_subfinder.txt")
      echo "Subdomains found by subfinder for $TARGET: $subfinder_count"
    fi

    # Run amass
    echo -e "\nRunning amass for $TARGET..."
    amass enum -passive -d "$TARGET" -silent -o "$DOMAIN_OUTPUT_DIR/subdomains_amass.txt"
    if [ $? -ne 0 ]; then
      echo "amass failed for $TARGET. Skipping amass step."
      amass_count=0
    else
      amass_count=$(wc -l < "$DOMAIN_OUTPUT_DIR/subdomains_amass.txt")
      echo "Subdomains found by Amass for $TARGET: $amass_count"
    fi

    # Run assetfinder
    echo -e "\nRunning assetfinder for $TARGET..."
    assetfinder --subs-only "$TARGET" > "$DOMAIN_OUTPUT_DIR/subdomains_assetfinder.txt"
    if [ $? -ne 0 ]; then
      echo "assetfinder failed for $TARGET"
      continue
    else
      assetfinder_count=$(wc -l < "$DOMAIN_OUTPUT_DIR/subdomains_assetfinder.txt")
      echo "Subdomains found by assetfinder for $TARGET: $assetfinder_count"
    fi

    # Combine results and remove duplicates
    echo -e "\nCombining subdomain results for $TARGET..."
    cat "$DOMAIN_OUTPUT_DIR"/subdomains_*.txt | sort -u > "$DOMAIN_OUTPUT_DIR/all_subdomains.txt"
    if [ $? -ne 0 ]; then
      echo "Combining subdomains failed for $TARGET"
      continue
    else
      combined_count=$(wc -l < "$DOMAIN_OUTPUT_DIR/all_subdomains.txt")
      echo "Total unique subdomains for $TARGET: $combined_count"
    fi

    # Proceed to scan for web application vulnerabilities using nuclei
    echo -e "\nScanning for web application vulnerabilities for $TARGET..."
    nuclei_output="$DOMAIN_OUTPUT_DIR/webapp_vulnerabilities.txt"

    # Splitting subdomains into chunks and running nuclei on each chunk
    CHUNK_SIZE=100  # Adjusted chunk size to reduce memory usage
    split -l $CHUNK_SIZE "$DOMAIN_OUTPUT_DIR/all_subdomains.txt" "$DOMAIN_OUTPUT_DIR/subdomain_chunks_" --numeric-suffixes=1 -a 3

    for file in "$DOMAIN_OUTPUT_DIR"/subdomain_chunks_*; do
        nuclei_chunk_output="$file.nuclei_output.txt"
        nuclei -l "$file" -t /root/nuclei-templates/ -etags ssl -severity low,medium,high,critical -o "$nuclei_chunk_output" -silent
        nuclei_exit_code=$?
        if [ $nuclei_exit_code -ne 0 ]; then
            echo "Nuclei scan failed for $file with exit code $nuclei_exit_code"
        else
            echo "Nuclei scan completed for $file"
        fi
    done

    # Combining nuclei results
    cat "$DOMAIN_OUTPUT_DIR"/subdomain_chunks_*.nuclei_output.txt > "$nuclei_output"

    # Check if vulnerabilities were found
    if [ -s "$nuclei_output" ]; then
        echo -e "\e[31mWeb application vulnerabilities found for $TARGET:\e[0m"
        cat "$nuclei_output"
        cat "$nuclei_output" | notify -d 10
    else
        echo "No web application vulnerabilities found for $TARGET."
    fi

    echo -e "\nFinished processing $TARGET."
done

echo -e "\nScript completed successfully."
