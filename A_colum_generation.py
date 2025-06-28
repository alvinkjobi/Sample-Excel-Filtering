import pandas as pd

# Path to the Excel file
file_path = r"F:\AI ML\Agent\sample-excel-filtering\UploadedJournal 2 (2).xlsx"

# Load the first sheet
xls = pd.ExcelFile(file_path)
df = xls.parse(xls.sheet_names[0])

# Print column headings
print("📌 Column Headings in the Excel file:")
for col in df.columns:
    print(f"• {col}")
