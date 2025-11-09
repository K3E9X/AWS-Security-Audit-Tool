#!/usr/bin/env python3
"""
Convert security guides from Markdown to PDF
"""
import os
import markdown
from weasyprint import HTML, CSS
from pathlib import Path

# Directory containing the markdown files
GUIDES_DIR = Path("/home/user/Machine71/security-guides")
OUTPUT_DIR = Path("/home/user/Machine71/security-guides/pdf")

# Create output directory if it doesn't exist
OUTPUT_DIR.mkdir(exist_ok=True)

# CSS styling for the PDF
CSS_STYLE = """
@page {
    size: A4;
    margin: 2.5cm;
    @top-center {
        content: "AWS Security Guide for SaaS Applications";
        font-size: 10pt;
        color: #666;
    }
    @bottom-center {
        content: "Page " counter(page) " of " counter(pages);
        font-size: 10pt;
        color: #666;
    }
}

body {
    font-family: 'DejaVu Sans', Arial, sans-serif;
    font-size: 11pt;
    line-height: 1.6;
    color: #333;
}

h1 {
    color: #232F3E;
    font-size: 24pt;
    margin-top: 20pt;
    margin-bottom: 15pt;
    border-bottom: 3px solid #FF9900;
    padding-bottom: 10pt;
}

h2 {
    color: #232F3E;
    font-size: 18pt;
    margin-top: 15pt;
    margin-bottom: 10pt;
    border-bottom: 2px solid #FF9900;
    padding-bottom: 5pt;
}

h3 {
    color: #232F3E;
    font-size: 14pt;
    margin-top: 12pt;
    margin-bottom: 8pt;
}

h4 {
    color: #555;
    font-size: 12pt;
    margin-top: 10pt;
    margin-bottom: 6pt;
}

code {
    background-color: #f4f4f4;
    padding: 2pt 4pt;
    font-family: 'DejaVu Sans Mono', monospace;
    font-size: 9pt;
    border: 1px solid #ddd;
    border-radius: 3px;
}

pre {
    background-color: #f4f4f4;
    padding: 10pt;
    border-left: 3px solid #FF9900;
    overflow-x: auto;
    font-family: 'DejaVu Sans Mono', monospace;
    font-size: 9pt;
    line-height: 1.4;
}

pre code {
    background-color: transparent;
    padding: 0;
    border: none;
}

table {
    border-collapse: collapse;
    width: 100%;
    margin: 10pt 0;
    font-size: 10pt;
}

table th {
    background-color: #232F3E;
    color: white;
    padding: 8pt;
    text-align: left;
    border: 1px solid #ddd;
}

table td {
    padding: 6pt 8pt;
    border: 1px solid #ddd;
}

table tr:nth-child(even) {
    background-color: #f9f9f9;
}

blockquote {
    border-left: 4px solid #FF9900;
    padding-left: 15pt;
    margin-left: 0;
    font-style: italic;
    color: #555;
    background-color: #fef9f2;
    padding: 10pt 15pt;
}

a {
    color: #0073bb;
    text-decoration: none;
}

ul, ol {
    margin: 10pt 0;
    padding-left: 20pt;
}

li {
    margin: 5pt 0;
}

.warning {
    background-color: #fff3cd;
    border-left: 4px solid #ff9900;
    padding: 10pt;
    margin: 10pt 0;
}

.success {
    background-color: #d4edda;
    border-left: 4px solid #28a745;
    padding: 10pt;
    margin: 10pt 0;
}

.info {
    background-color: #d1ecf1;
    border-left: 4px solid #0c5460;
    padding: 10pt;
    margin: 10pt 0;
}
"""

def convert_markdown_to_pdf(md_file: Path, output_file: Path):
    """
    Convert a markdown file to PDF with styling
    """
    print(f"Converting {md_file.name} to PDF...")

    # Read markdown content
    with open(md_file, 'r', encoding='utf-8') as f:
        md_content = f.read()

    # Convert markdown to HTML
    html_content = markdown.markdown(
        md_content,
        extensions=[
            'extra',
            'codehilite',
            'tables',
            'fenced_code',
            'toc',
            'nl2br'
        ]
    )

    # Wrap in HTML structure
    full_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>{md_file.stem}</title>
    </head>
    <body>
        {html_content}
    </body>
    </html>
    """

    # Convert HTML to PDF
    HTML(string=full_html).write_pdf(
        output_file,
        stylesheets=[CSS(string=CSS_STYLE)]
    )

    print(f"✓ Created: {output_file.name}")

def main():
    """
    Convert all security guide markdown files to PDF
    """
    print("=" * 60)
    print("AWS Security Guides - Markdown to PDF Converter")
    print("=" * 60)
    print()

    # List of guide files to convert
    guide_files = [
        "README.md",
        "00-Executive-Summary.md",
        "01-IAM-Security-Guide.md",
        "02-Network-Security-Guide.md",
        "03-Hosting-Security-Guide.md",
        "04-CloudWatch-Supervision-Guide.md",
        "05-Applications-Storage-Security-Guide.md"
    ]

    converted_count = 0

    for guide_file in guide_files:
        md_path = GUIDES_DIR / guide_file
        pdf_path = OUTPUT_DIR / f"{md_path.stem}.pdf"

        if md_path.exists():
            try:
                convert_markdown_to_pdf(md_path, pdf_path)
                converted_count += 1
            except Exception as e:
                print(f"✗ Error converting {guide_file}: {e}")
        else:
            print(f"✗ File not found: {guide_file}")

    print()
    print("=" * 60)
    print(f"Conversion Complete: {converted_count}/{len(guide_files)} files")
    print(f"Output directory: {OUTPUT_DIR}")
    print("=" * 60)

    # List generated PDFs
    pdf_files = list(OUTPUT_DIR.glob("*.pdf"))
    if pdf_files:
        print("\nGenerated PDF files:")
        for pdf_file in sorted(pdf_files):
            size_mb = pdf_file.stat().st_size / (1024 * 1024)
            print(f"  - {pdf_file.name} ({size_mb:.2f} MB)")

if __name__ == "__main__":
    main()
