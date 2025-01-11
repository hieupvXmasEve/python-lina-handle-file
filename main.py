from fastapi import FastAPI, UploadFile, HTTPException
from fastapi.responses import JSONResponse
import pdfplumber
import pandas as pd
import re

app = FastAPI()


def extract_tables_from_nessus(text_content):
    # Extract Summary table data
    summary_pattern = r"Critical\s+High\s+Medium\s+Low\s+Info\s+Total\n(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)"
    summary_match = re.search(summary_pattern, text_content)

    if summary_match:
        summary_data = {
            'Category': ['Critical', 'High', 'Medium', 'Low', 'Info', 'Total'],
            'Count': list(map(int, summary_match.groups()))
        }
        summary_df = pd.DataFrame(summary_data)
    else:
        summary_df = pd.DataFrame()

    # Extract Details table data
    details_pattern = r"(Critical|High|Medium|Low)\s+\((\d+\.?\d*)\)\s+(\d+)\s+([^\n]+)"
    details_matches = re.finditer(details_pattern, text_content)

    details_data = []
    for match in details_matches:
        details_data.append({
            'Severity': match.group(1),
            'Risk Score': float(match.group(2)),
            'Plugin Id': int(match.group(3)),
            'Name': match.group(4).strip()
        })

    details_df = pd.DataFrame(details_data)

    return summary_df, details_df


@app.post("/api/process-pdf")
async def process_pdf(file: UploadFile):
    # Check if file is a PDF
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="File must be a PDF")

    try:
        # Read the PDF file content
        with pdfplumber.open(file.file) as pdf:
            text_content = "\n".join([page.extract_text() for page in pdf.pages])

        # Process the text content
        summary_df, details_df = extract_tables_from_nessus(text_content)

        # Convert DataFrames to JSON serializable format
        summary_json = summary_df.to_dict(orient="records")
        details_json = details_df.to_dict(orient="records")

        # Return the response
        return JSONResponse(content={
            "summary": summary_json,
            "details": details_json
        })

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred while processing the file: {str(e)}")
