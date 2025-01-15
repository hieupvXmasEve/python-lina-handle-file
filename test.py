import re

from PyPDF2 import PdfReader


def extract_issues(text, key):

    # issue_blocks = re.findall(r"Issue ID:.*?(?=(Issue ID:|\Z))", text, re.DOTALL)
    issue_blocks = re.findall(r"Issue ID:.*?(?=(?:Issue ID:|\Z))", text, re.DOTALL)

    issues = []
    for block in issue_blocks:
        lines = block.split("\n")
        issue = {}
        current_key = None
        current_value = ""

        for line in lines:
            line = line.strip()
            if line == "":
                continue

            # Check if the line starts with any of the keys
            match = None
            for key in keys:
                if line.startswith(key):
                    match = key
                    break

            if match:
                # If there is a current key, save the previous key-value pair
                if current_key:
                    issue[current_key] = current_value.strip()
                # Set the new key and start a new value
                current_key = match
                current_value = line[len(match) :].strip()
            else:
                # Append the line to the current value
                current_value += " " + line

        # Add the last key-value pair
        if current_key:
            issue[current_key] = current_value.strip()
        issues.append(issue)

    return issues


# read file pdf

pdf_file = "Sample_SAST_Report.pdf"
reader = PdfReader(pdf_file)
# Extract text from PDF
pdf_text = ""
for page in reader.pages:
    pdf_text += page.extract_text()
# List of keys to extract
keys = [
    "Fix Group ID",
    "Status",
    "Date",
    "API",
    "Notes",
    "How to Fix",
    "Issue ID",
    "Severity",
    "Classification",
    "Location",
    "Line",
    "Source File",
    "Availability Impact",
    "Confidentiality Impact",
    "Integrity Impact",
    "Date Created",
    "Last Updated",
    "CWE",
    "Caller",
    # Add any other keys found in the text
]
extracted_issues = extract_issues(pdf_text, keys)
# Print the extracted issues
print(len(extracted_issues))
for issue in extracted_issues:
    print("---")
