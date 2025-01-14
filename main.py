import io
import re
from typing import List

import pandas as pd
import pdfplumber
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from PyPDF2 import PdfReader

app = FastAPI(
    title="PDF Vulnerability Scanner API",
    description="API for scanning and extracting vulnerability information from PDF reports",
    version="1.0.0",
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


# @app.post("/api/process-pdf")
#
class VulnerabilityIssue(BaseModel):
    ID: str
    Severity: str
    Type: str
    Location: str
    Details: str
    Status: str


class ScanResponse(BaseModel):
    total_issues: int
    issues: List[VulnerabilityIssue]


@app.post("/api/process-pdf-scan", response_model=ScanResponse)
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

        # Regular expression pattern for matching issues
        issue_pattern = re.compile(
            r"Issue ID:\s+([a-zA-Z0-9\-]+).*?"
            r"Severity:\s+(High|Medium|Low).*?"
            r"Status:\s*(Open|Closed).*?"
            r"Location\s+(.+?):(\d+).*?"
            r"CWE:\s+(\d+).*?"
            r"Notes:\s+(.*?)How to Fix",
            re.DOTALL,
        )

        # Extract issues
        issues = []
        for match in issue_pattern.finditer(pdf_text):
            issues.append(
                VulnerabilityIssue(
                    ID=match.group(1),
                    Severity=match.group(2),
                    Type="Extracted Type Placeholder",
                    Status=match.group(3),
                    Location=f"{match.group(4)}:{match.group(5)}",
                    Details=f"CWE: {match.group(6)} - {match.group(7).strip()}",
                )
            )

        return ScanResponse(total_issues=len(issues), issues=issues)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
