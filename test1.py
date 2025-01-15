from pypdf import PdfReader, PdfWriter


def main():
    # Đường dẫn đến file PDF gốc và file PDF mới
    input_file = "Sample_SAST_Report.pdf"  # Thay bằng tên file gốc của bạn
    output_file = "output.pdf"  # Tên file kết quả

    # Đọc file PDF
    reader = PdfReader(input_file)
    writer = PdfWriter()

    # Trích xuất các trang từ trang 4 đến trang 20
    start_page = 4 - 1  # Trang bắt đầu (Python bắt đầu từ 0)
    end_page = 20  # Trang kết thúc

    for page_num in range(start_page, end_page):
        writer.add_page(reader.pages[page_num])

    # Ghi ra file PDF mới
    with open(output_file, "wb") as output_pdf:
        writer.write(output_pdf)

    print(f"Đã tạo file PDF mới: {output_file}")


if __name__ == "__main__":
    main()
