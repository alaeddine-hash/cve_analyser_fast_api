# cve_analysis.py

import json
import re
import logging

from cve_check_gpt import process_cve_exploitability_metrics
from get_cve import get_cve_by_id
from augmented_cve_gpt import process_cve_augmentation
from exploitation_context import process_cve_exploitation_context
from patch_and_mitigation import process_cve_patch_and_mitigation

# Configure logging
logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def analyze_cve(cve_id):
    # Validate CVE ID format
    cve_pattern = r'^CVE-\d{4}-\d{4,7}$'
    if not re.match(cve_pattern, cve_id):
        logging.error(f"Invalid CVE ID format: {cve_id}")
        return None, "Invalid CVE ID format. Please enter a valid CVE ID in the format 'CVE-YYYY-NNNN'."

    # Fetch CVE data
    cve_entry = get_cve_by_id(cve_id)
    if not cve_entry:
        logging.error(f"No data found for CVE ID {cve_id}")
        return None, f"No data found for CVE ID {cve_id}."

    # Process CVE data
    cve_entry = process_cve_augmentation(cve_entry)
    cve_entry = process_cve_exploitation_context(cve_entry)
    cve_entry = process_cve_exploitability_metrics(cve_entry)
    cve_entry = process_cve_patch_and_mitigation(cve_entry)

    return cve_entry, None
