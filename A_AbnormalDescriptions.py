import pandas as pd
import os
import re
import tkinter as tk
from tkinter import messagebox

def find_abnormal_description_entries(df, columns_to_check=None, abnormal_terms=None):
    """
    Filters rows where the description/title contains abnormal or red-flag keywords.

    Args:
        df (pd.DataFrame): Input DataFrame.
        columns_to_check (list): List of columns to scan (e.g., Description, Title).
        abnormal_terms (list): List of red-flag terms to detect.

    Returns:
        pd.DataFrame: Filtered DataFrame with suspicious descriptions.
    """
    if columns_to_check is None:
        columns_to_check = ['Description', 'Title']
    if abnormal_terms is None:
        abnormal_terms = ['fraud', 'error', 'suspense', 'reversal', 'manual']

    # Create regex pattern for any of the red-flag keywords
    pattern = r'|'.join([re.escape(term) for term in abnormal_terms])

    # Check across all specified columns
    mask = df[columns_to_check].fillna('').astype(str).apply(lambda col: col.str.lower().str.contains(pattern))
    combined_mask = mask.any(axis=1)

    return df[combined_mask]

# --- Main Execution ---

# Load Excel
file_path = r"D:\Agent\UploadedJournal 2 (2).xlsx"
xls = pd.ExcelFile(file_path)
df = xls.parse(xls.sheet_names[0])
print("Columns:", df.columns.tolist())

# Run abnormal entry detection
abnormal_df = find_abnormal_description_entries(df, columns_to_check=['Description', 'Title'])
print(abnormal_df)
# Save results
if not abnormal_df.empty:
    output_path = os.path.join(os.path.dirname(file_path), "AbnormalDescriptions.xlsx")
    abnormal_df.to_excel(output_path, index=False)
    print(f"\n🚨 Abnormal description entries saved to: {output_path}")
else:
    print("\n✅ No abnormal or suspicious descriptions found.")

def run_ui():
    file_path = r"D:\Agent\UploadedJournal 2 (2).xlsx"
    xls = pd.ExcelFile(file_path)
    df = xls.parse(xls.sheet_names[0])

    def on_submit():
        abnormal_df = find_abnormal_description_entries(df)
        if abnormal_df.empty:
            messagebox.showinfo("Result", "✅ No abnormal or suspicious descriptions found.")
        else:
            output_path = os.path.join(os.path.dirname(file_path), "AbnormalDescriptions.xlsx")
            abnormal_df.to_excel(output_path, index=False)
            messagebox.showinfo("Success", f"🚨 Abnormal description entries saved to: {output_path}")

    root = tk.Tk()
    root.title("Find Abnormal Descriptions")
    root.attributes('-fullscreen', True)  # Fullscreen

    # Center frame for widgets
    frame = tk.Frame(root, bg="#f0f0f0")
    frame.place(relx=0.5, rely=0.5, anchor="center")

    label_font = ("Arial", 28)
    button_font = ("Arial", 24)

    tk.Label(frame, text="Detect abnormal/red-flag descriptions.", font=label_font, bg="#f0f0f0").pack(pady=40)
    tk.Button(frame, text="Run Detection", command=on_submit, font=button_font, bg="#4CAF50", fg="white", width=16, height=2).pack(pady=40)

    # Exit button at bottom right
    def exit_fullscreen():
        root.destroy()
    tk.Button(root, text="Exit", command=exit_fullscreen, font=button_font, bg="#f44336", fg="white", width=8, height=1).place(relx=0.98, rely=0.98, anchor="se")

    root.mainloop()

if __name__ == "__main__":
    run_ui()
