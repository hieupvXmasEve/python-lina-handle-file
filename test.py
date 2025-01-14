import pymupdf  # PyMuPDF
import re


def extract_tables_from_pdf(pdf_path):
    # Mở file PDF
    doc = pymupdf.open(pdf_path)
    tables = []

    # Lặp qua từng trang trong file PDF
    for page_num in range(len(doc)):
        page = doc.load_page(page_num)
        text = page.get_text("text")  # Lấy văn bản từ trang

        # Tách văn bản thành các dòng
        lines = text.split('\n')

        # Bắt đầu trích xuất dữ liệu từ các dòng
        table_data = []
        for line1 in lines:
            # Sử dụng regex để trích xuất các trường dữ liệu
            issue_matches = re.finditer(
                r"Issue ID: (?P<IssueID>.+?)\n"
                r"Severity: (?P<Severity>.+?)\n"
                r"Classification (?P<Classification>.+?)\n"
                r"Status (?P<Status>.+?)\n"
                r"Fix Group ID: (?P<FixGroupID>.+?)\n"
                r"Location (?P<Location>.+?)\n"
                r"Line (?P<Line>\d+)\n"
                r"Source File (?P<SourceFile>.+?)\n"
                r"Availability Impact (?P<AvailabilityImpact>.+?)\n"
                r"Confidentiality Impact (?P<ConfidentialityImpact>.+?)\n"
                r"Integrity Impact (?P<IntegrityImpact>.+?)\n"
                r"Date Created (?P<DateCreated>.+?)\n"
                r"Last Updated (?P<LastUpdated>.+?)\n"
                r"CWE: (?P<CWE>\d+)",
                line1,
                re.DOTALL,
            )
            if issue_matches:
                table_data.append(line1)

        # Xử lý dữ liệu để tạo thành các bảng
        if table_data:
            tables.append(table_data)

    return tables


# Đường dẫn đến file PDF
pdf_path = "Sample_SAST_Report.pdf"

# Trích xuất dữ liệu từ file PDF
tables = extract_tables_from_pdf(pdf_path)

# In kết quả
for i, table in enumerate(tables):
    print(f"Table {i + 1}:")
    for line in table:
        print(line)
    print("\n")
