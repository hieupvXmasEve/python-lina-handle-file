import pymupdf
from pypdf import PdfReader, PdfWriter
import tabula

import pandas as pd


def main():
    # Step 1: Read all tables from the PDF
    pdf_path = "output.pdf"
    pdf_text = ""

    with pymupdf.open(pdf_path) as doc:
        text = chr(12).join([page.get_text() for page in doc])
        # Extract text from PDF
        pdf_text += page.extract_text()

        print(text)


if __name__ == "__main__":
    main()
