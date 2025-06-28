import pandas as pd
import os
import re
import tkinter as tk
from tkinter import messagebox

def find_senior_personnel_entries(df, title_column='Title', senior_keywords=None):
   

    if senior_keywords is None:
        senior_keywords = [ 'manager', 'senior','director', 'vp', 'cfo', 'ceo']

    # Build regex pattern to match any keyword as whole word or part
    pattern = r'|'.join([re.escape(word) for word in senior_keywords])

    # Normalize and apply pattern match
    mask = df[title_column].fillna('').astype(str).str.lower().str.contains(pattern)
    return df[mask]

def run_ui():
    file_path = r"D:\Agent\UploadedJournal 2 (2).xlsx"
    xls = pd.ExcelFile(file_path)
    df = xls.parse(xls.sheet_names[0])

    def on_submit():
        senior_df = find_senior_personnel_entries(df)
        if senior_df.empty:
            messagebox.showinfo("Result", "✅ No senior personnel entries found.")
        else:
            output_path = os.path.join(os.path.dirname(file_path), "SeniorPersonnelEntries.xlsx")
            senior_df.to_excel(output_path, index=False)
            messagebox.showinfo("Success", f"👔 Senior personnel entries saved to: {output_path}")

    root = tk.Tk()
    root.title("Find Senior Personnel Entries")
    root.attributes('-fullscreen', True)  # Fullscreen

    # Center frame for widgets
    frame = tk.Frame(root, bg="#f0f0f0")
    frame.place(relx=0.5, rely=0.5, anchor="center")

    label_font = ("Arial", 28)
    button_font = ("Arial", 24)

    tk.Label(frame, text="Detect entries by senior personnel.", font=label_font, bg="#f0f0f0").pack(pady=40)
    tk.Button(frame, text="Run Detection", command=on_submit, font=button_font, bg="#4CAF50", fg="white", width=16, height=2).pack(pady=40)

    # Exit button at bottom right
    def exit_fullscreen():
        root.destroy()
    tk.Button(root, text="Exit", command=exit_fullscreen, font=button_font, bg="#f44336", fg="white", width=8, height=1).place(relx=0.98, rely=0.98, anchor="se")

    root.mainloop()

# --- Main Execution ---

if __name__ == "__main__":
    run_ui()
