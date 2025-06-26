import pandas as pd
import os
import tkinter as tk
from tkinter import messagebox

def find_vague_entries(df, columns_to_check=None, vague_terms=None):
    """
    Filters rows where any specified column contains exactly one of the vague terms.

    Args:
        df (pd.DataFrame): Input DataFrame.
        columns_to_check (list): List of column names to check.
        vague_terms (list): List of vague terms (exact match, case-insensitive).

    Returns:
        pd.DataFrame: Filtered rows where any column contains vague term exactly.
    """
    if columns_to_check is None:
        columns_to_check = ['Description', 'Title']
    if vague_terms is None:
        vague_terms = ['' ,'n/a', 'none', 'null', 'empty', 'unspecified', 'unknown', 'not applicable']

    # Lowercase set of vague terms
    vague_terms_set = set(term.strip().lower() for term in vague_terms)

    def is_vague(text):
        if not isinstance(text, str):
            return True
        return text.strip().lower() in vague_terms_set

    # Apply check: any column has exact vague word
    mask = df[columns_to_check].applymap(is_vague).any(axis=1)
    return df[mask]

def run_ui():
    file_path = r"D:\Agent\UploadedJournal 2 (2).xlsx"
    xls = pd.ExcelFile(file_path)
    df = xls.parse(xls.sheet_names[0])

    def on_submit():
        vague_df = find_vague_entries(df)
        if vague_df.empty:
            messagebox.showinfo("Result", "✅ No exact-match vague entries found.")
        else:
            output_path = os.path.join(os.path.dirname(file_path), "VagueExactMatches.xlsx")
            vague_df.to_excel(output_path, index=False)
            messagebox.showinfo("Success", f"🔍 Exact-match vague entries saved to: {output_path}")

    root = tk.Tk()
    root.title("Find Vague Entries")
    root.attributes('-fullscreen', True)  # Fullscreen

    # Center frame for widgets
    frame = tk.Frame(root, bg="#f0f0f0")
    frame.place(relx=0.5, rely=0.5, anchor="center")

    label_font = ("Arial", 28)
    button_font = ("Arial", 24)

    tk.Label(frame, text="Detect vague entries in Description/Title.", font=label_font, bg="#f0f0f0").pack(pady=40)
    tk.Button(frame, text="Run Detection", command=on_submit, font=button_font, bg="#4CAF50", fg="white", width=16, height=2).pack(pady=40)

    # Exit button at bottom right
    def exit_fullscreen():
        root.destroy()
    tk.Button(root, text="Exit", command=exit_fullscreen, font=button_font, bg="#f44336", fg="white", width=8, height=1).place(relx=0.98, rely=0.98, anchor="se")

    root.mainloop()

# --- Main Execution ---

if __name__ == "__main__":
    run_ui()
