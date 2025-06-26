import pandas as pd
import os
import tkinter as tk
from tkinter import messagebox

def find_bypass_entries(df, columns_to_search=None, keywords=None):
    """
    Filters rows where text fields contain suspicious keywords like 'bypass' or 'system change'.

    Args:
        df (pd.DataFrame): Input DataFrame.
        columns_to_search (list): List of column names to scan.
        keywords (list): List of suspicious keywords (case-insensitive).

    Returns:
        pd.DataFrame: Rows matching any of the keywords.
    """
    if columns_to_search is None:
        columns_to_search = ['Description', 'Title']
    if keywords is None:
        keywords = ['bypass', 'system change']

    # Combine selected columns into a single lowercase string for search
    df['__combined_text__'] = df[columns_to_search].fillna('').astype(str).agg(' '.join, axis=1).str.lower()

    # Check if any keyword exists in the combined text
    mask = df['__combined_text__'].apply(lambda x: any(kw in x for kw in keywords))

    # Return matching rows, drop helper column
    return df[mask].drop(columns='__combined_text__')


# --- Main Code ---

# Load Excel
file_path = r"D:\Agent\UploadedJournal 2 (2).xlsx"
xls = pd.ExcelFile(file_path)
df = xls.parse(xls.sheet_names[0])
print("Columns:", df.columns.tolist())

# Run bypass detection
bypass_df = find_bypass_entries(df, columns_to_search=['Description', 'Title'])
print(bypass_df)
# Save results
if not bypass_df.empty:
    output_path = os.path.join(os.path.dirname(file_path), "BypassEntries.xlsx")
    bypass_df.to_excel(output_path, index=False)
    print(f"\n🔍 Bypass-related entries saved to: {output_path}")
else:
    print("\n✅ No entries found with keywords like 'bypass' or 'system change'.")

def run_ui():
    file_path = r"D:\Agent\UploadedJournal 2 (2).xlsx"
    xls = pd.ExcelFile(file_path)
    df = xls.parse(xls.sheet_names[0])

    def on_submit():
        bypass_df = find_bypass_entries(df)
        if bypass_df.empty:
            messagebox.showinfo("Result", "✅ No entries found with keywords like 'bypass' or 'system change'.")
        else:
            output_path = os.path.join(os.path.dirname(file_path), "BypassEntries.xlsx")
            bypass_df.to_excel(output_path, index=False)
            messagebox.showinfo("Success", f"🔍 Bypass-related entries saved to: {output_path}")

    root = tk.Tk()
    root.title("Find Bypass Entries")
    root.attributes('-fullscreen', True)  # Fullscreen

    # Center frame for widgets
    frame = tk.Frame(root, bg="#f0f0f0")
    frame.place(relx=0.5, rely=0.5, anchor="center")

    label_font = ("Arial", 28)
    button_font = ("Arial", 24)

    tk.Label(frame, text="Detect bypass/system change entries.", font=label_font, bg="#f0f0f0").pack(pady=40)
    tk.Button(frame, text="Run Detection", command=on_submit, font=button_font, bg="#4CAF50", fg="white", width=16, height=2).pack(pady=40)

    # Exit button at bottom right
    def exit_fullscreen():
        root.destroy()
    tk.Button(root, text="Exit", command=exit_fullscreen, font=button_font, bg="#f44336", fg="white", width=8, height=1).place(relx=0.98, rely=0.98, anchor="se")

    root.mainloop()

if __name__ == "__main__":
    run_ui()
