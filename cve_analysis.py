# cve_analysis.py

from decimal import Decimal
import json
import re
import logging
import os
from datetime import datetime
import asyncio

from cve_check_gpt import process_cve_exploitability_metrics
from get_cve import get_cve_by_id
from augmented_cve_gpt import process_cve_augmentation
from exploitation_context import process_cve_exploitation_context
from patch_and_mitigation import process_cve_patch_and_mitigation

# Configure logging
logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def default_serializer(obj):
    """ Custom serializer to handle non-serializable objects like datetime and Decimal """
    if isinstance(obj, datetime):
        return obj.isoformat()  # Convert datetime to ISO format
    elif isinstance(obj, Decimal):
        return float(obj)  # Convert Decimal to float for JSON serialization
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")


def save_output_to_file(cve_entry, filename='output.json'):
    # Check if the file exists
    if os.path.exists(filename):
        # Read existing data
        with open(filename, 'r') as f:
            try:
                data = json.load(f)
                if not isinstance(data, list):
                    data = [data]
            except json.JSONDecodeError:
                data = []
    else:
        data = []

    # Append new entry
    data.append(cve_entry)

    # Write back to the file with custom serializer
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4, default=default_serializer)

async def analyze_cve(cve_id):
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
    cve_entry = await process_cve_augmentation(cve_entry)
    cve_entry = await process_cve_exploitation_context(cve_entry)
    cve_entry = await process_cve_exploitability_metrics(cve_entry)
    cve_entry = await process_cve_patch_and_mitigation(cve_entry)

    # Save output to file
    save_output_to_file(cve_entry)

    return cve_entry, None
