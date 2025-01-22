import io
import re
import pandas as pd
import pdfplumber
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from PyPDF2 import PdfReader
import subprocess
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="PDF Vulnerability Scanner API",
    description="API for scanning and extracting vulnerability information from PDF reports",
    version="1.0.0",
)

# Add CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)


def extract_tables_from_nessus(text_content):
    # Precompile regex patterns
    summary_pattern = re.compile(
        r"Critical\s+High\s+Medium\s+Low\s+Info\s+Total\n(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)"
    )
    details_pattern = re.compile(
        r"(Critical|High|Medium|Low)\s+\((\d+\.?\d*)\)\s+(\d+)\s+([^\n]+)"
    )

    # Extract Summary table data
    summary_match = summary_pattern.search(text_content)
    if summary_match:
        summary_df = pd.DataFrame(
            {
                "Category": ["Critical", "High", "Medium", "Low", "Info", "Total"],
                "Count": list(map(int, summary_match.groups())),
            }
        )
    else:
        summary_df = pd.DataFrame()

    # Extract Details table data
    details_data = []
    for match in details_pattern.finditer(text_content):
        details_data.append(
            {
                "Severity": match.group(1),
                "Risk Score": float(match.group(2)),
                "Plugin Id": int(match.group(3)),
                "Name": match.group(4).strip(),
            }
        )

    details_df = pd.DataFrame(details_data)

    return summary_df, details_df


@app.post("/api/process-pdf-nessus")
async def process_pdf(file: UploadFile):
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="File must be a PDF")

    try:
        with pdfplumber.open(file.file) as pdf:
            # Process each page individually
            summary_data, details_data = [], []
            for page in pdf.pages:
                text_content = page.extract_text()
                if text_content:
                    page_summary_df, page_details_df = extract_tables_from_nessus(
                        text_content
                    )
                    if not page_summary_df.empty:
                        summary_data.append(page_summary_df)
                    if not page_details_df.empty:
                        details_data.append(page_details_df)

        # Combine all page data
        summary_df = (
            pd.concat(summary_data, ignore_index=True)
            .groupby("Category", as_index=False)
            .sum()
            if summary_data
            else pd.DataFrame()
        )
        details_df = (
            pd.concat(details_data, ignore_index=True)
            if details_data
            else pd.DataFrame()
        )

        # Convert DataFrames to JSON serializable format
        summary_json = summary_df.to_dict(orient="records")
        details_json = details_df.to_dict(orient="records")

        return JSONResponse(content={"summary": summary_json, "details": details_json})

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"An error occurred while processing the file: {str(e)}",
        )


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
    "URL",
    "Sink",
    # Add any other keys found in the text
]


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


@app.post("/api/process-pdf-scan")
async def scan_pdf(file: UploadFile = File(...)):
    """
    Scan a PDF file for vulnerability issues

    Args:
        file: PDF file to scan

    Returns:
        Dict containing total issues count and list of vulnerability issues
    """
    try:
        # Validate file type
        if not file.filename.endswith(".pdf"):
            raise HTTPException(status_code=400, detail="File must be a PDF")

        # Read file contents
        contents = await file.read()
        pdf_file = io.BytesIO(contents)
        reader = PdfReader(pdf_file)

        # Extract text from PDF
        pdf_text = ""
        for page in reader.pages:
            pdf_text += page.extract_text()

        extracted_issues = extract_issues(pdf_text, keys)

        # response_data = ScanResponse(
        #     total_issues=len(extracted_issues), issues=extracted_issues
        # )
        return JSONResponse(
            content={"total_issues": len(extracted_issues), "issues": extracted_issues}
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e

# Handle text file upload
@app.post("/api/process-text-file")
async def process_text_file(file: UploadFile = File(...)):
    try:
        # Validate file type
        if not file.filename.endswith(".txt"):
            raise HTTPException(status_code=400, detail="File must be a text file")

        # Read file contents and decode to string
        contents = await file.read()
        text_content = contents.decode('utf-8')  # Decode bytes to string
        extracted_issues = extract_issues(text_content, keys)

        return JSONResponse(
            content={
                "total_issues": len(extracted_issues),
                "issues": extracted_issues,
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e