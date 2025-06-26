import pandas as pd
import os
import tkinter as tk
from tkinter import messagebox

def find_unauthorized_entries(df, status_column='Authorization Status'):
    """
    Filters rows where the authorization status is 'Unauthorized'.

    Args:
        df (pd.DataFrame): Input DataFrame.
        status_column (str): Column to check for 'Unauthorized' status.

    Returns:
        pd.DataFrame: Rows with unauthorized status.
    """
    # Normalize and check for exact 'unauthorized'
    mask = df[status_column].fillna('').astype(str).str.strip().str.lower() == 'unauthorized'
    return df[mask]

def run_ui():
    file_path = r"D:\Agent\UploadedJournal 2 (2).xlsx"
    xls = pd.ExcelFile(file_path)
    df = xls.parse(xls.sheet_names[0])

    def on_submit():
        unauth_df = find_unauthorized_entries(df)
        if unauth_df.empty:
            messagebox.showinfo("Result", "✅ No unauthorized entries found.")
        else:
            output_path = os.path.join(os.path.dirname(file_path), "UnauthorizedEntries.xlsx")
            unauth_df.to_excel(output_path, index=False)
            messagebox.showinfo("Success", f"⛔ Unauthorized entries saved to: {output_path}")

    root = tk.Tk()
    root.title("Find Unauthorized Entries")
    root.attributes('-fullscreen', True)  # Fullscreen

    # Center frame for widgets
    frame = tk.Frame(root, bg="#f0f0f0")
    frame.place(relx=0.5, rely=0.5, anchor="center")

    label_font = ("Arial", 28)
    button_font = ("Arial", 24)

    tk.Label(frame, text="Detect unauthorized entries.", font=label_font, bg="#f0f0f0").pack(pady=40)
    tk.Button(frame, text="Run Detection", command=on_submit, font=button_font, bg="#4CAF50", fg="white", width=16, height=2).pack(pady=40)

    # Exit button at bottom right
    def exit_fullscreen():
        root.destroy()
    tk.Button(root, text="Exit", command=exit_fullscreen, font=button_font, bg="#f44336", fg="white", width=8, height=1).place(relx=0.98, rely=0.98, anchor="se")

    root.mainloop()

# --- Main Execution ---

if __name__ == "__main__":
    run_ui()
