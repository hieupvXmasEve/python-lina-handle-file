from fastapi import FastAPI, UploadFile, HTTPException
from fastapi.responses import JSONResponse
import pdfplumber
import pandas as pd
import re

app = FastAPI()


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
        summary_df = pd.DataFrame({
            'Category': ['Critical', 'High', 'Medium', 'Low', 'Info', 'Total'],
            'Count': list(map(int, summary_match.groups()))
        })
    else:
        summary_df = pd.DataFrame()

    # Extract Details table data
    details_data = []
    for match in details_pattern.finditer(text_content):
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
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="File must be a PDF")

    try:
        with pdfplumber.open(file.file) as pdf:
            # Process each page individually
            summary_data, details_data = [], []
            for page in pdf.pages:
                text_content = page.extract_text()
                if text_content:
                    page_summary_df, page_details_df = extract_tables_from_nessus(text_content)
                    if not page_summary_df.empty:
                        summary_data.append(page_summary_df)
                    if not page_details_df.empty:
                        details_data.append(page_details_df)

        # Combine all page data
        summary_df = pd.concat(summary_data, ignore_index=True).groupby('Category',
                                                                        as_index=False).sum() if summary_data else pd.DataFrame()
        details_df = pd.concat(details_data, ignore_index=True) if details_data else pd.DataFrame()

        # Convert DataFrames to JSON serializable format
        summary_json = summary_df.to_dict(orient="records")
        details_json = details_df.to_dict(orient="records")

        return JSONResponse(content={
            "summary": summary_json,
            "details": details_json
        })

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred while processing the file: {str(e)}")
