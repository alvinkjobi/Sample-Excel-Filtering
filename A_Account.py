import pandas as pd
import os
import re
import tkinter as tk
from tkinter import messagebox

def find_sensitive_account_entries(df, account_column='Account Name', sensitive_terms=None):
    """
    Filters rows where the account name suggests it's a sensitive account.

    Args:
        df (pd.DataFrame): Input DataFrame.
        account_column (str): Column name containing account names.
        sensitive_terms (list): List of sensitive account-related keywords.

    Returns:
        pd.DataFrame: Filtered DataFrame with sensitive account entries.
    """
    if sensitive_terms is None:
        sensitive_terms = ['revenue', 'reserve', 'reserves', 'accrual', 'accruals']

    # Create regex pattern to match any sensitive term
    pattern = r'|'.join([re.escape(term) for term in sensitive_terms])

    # Apply pattern to column
    mask = df[account_column].fillna('').astype(str).str.lower().str.contains(pattern)
    return df[mask]

def run_ui():
    file_path = r"D:\Agent\UploadedJournal 2 (2).xlsx"
    xls = pd.ExcelFile(file_path)
    df = xls.parse(xls.sheet_names[0])

    def on_submit():
        sensitive_df = find_sensitive_account_entries(df)
        if sensitive_df.empty:
            messagebox.showinfo("Result", "✅ No entries found related to sensitive accounts.")
        else:
            output_path = os.path.join(os.path.dirname(file_path), "SensitiveAccountEntries.xlsx")
            sensitive_df.to_excel(output_path, index=False)
            messagebox.showinfo("Success", f"💼 Sensitive account entries saved to: {output_path}")

    root = tk.Tk()
    root.title("Find Sensitive Account Entries")
    root.attributes('-fullscreen', True)  # Fullscreen

    # Center frame for widgets
    frame = tk.Frame(root, bg="#f0f0f0")
    frame.place(relx=0.5, rely=0.5, anchor="center")

    label_font = ("Arial", 28)
    button_font = ("Arial", 24)

    tk.Label(frame, text="Detect sensitive account entries.", font=label_font, bg="#f0f0f0").pack(pady=40)
    tk.Button(frame, text="Run Detection", command=on_submit, font=button_font, bg="#4CAF50", fg="white", width=16, height=2).pack(pady=40)

    # Exit button at bottom right
    def exit_fullscreen():
        root.destroy()
    tk.Button(root, text="Exit", command=exit_fullscreen, font=button_font, bg="#f44336", fg="white", width=8, height=1).place(relx=0.98, rely=0.98, anchor="se")

    root.mainloop()

# --- Main Execution ---

if __name__ == "__main__":
    run_ui()
