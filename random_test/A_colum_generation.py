import pandas as pd

# Path to the Excel file
file_path = r"D:\Agent\sample-excel-filtering\UploadedJournal 2 (2).xlsx"

try:
    # Load the first sheet
    df = pd.read_excel(file_path, sheet_name=0)

    # Print column headings
    print("📌 Column Headings in the Excel file:")
    for col in df.columns:
        print(f"• {col}")
except FileNotFoundError:
    print(f"Error: File not found at {file_path}")
except Exception as e:
    print(f"An error occurred: {e}")
