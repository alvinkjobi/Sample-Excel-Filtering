import pandas as pd
import os
import tkinter as tk
from tkinter import messagebox

def filter_by_time_range(df, start_time_str, end_time_str, filter_type, time_column='Time', time_format="%H:%M:%S"):
    df['TimeOnly'] = pd.to_datetime(df[time_column], format=time_format, errors='coerce').dt.time
    try:
        start_time = pd.to_datetime(start_time_str, format=time_format).time()
        end_time = pd.to_datetime(end_time_str, format=time_format).time()
    except ValueError:
        return None, "❌ Invalid time format. Please use HH:MM:SS."
    if filter_type == 'inside':
        return df[df['TimeOnly'].between(start_time, end_time, inclusive='both')], None
    elif filter_type == 'outside':
        return df[~df['TimeOnly'].between(start_time, end_time, inclusive='both')], None
    else:
        return None, "❌ Invalid filter type. Use 'inside' or 'outside'."

def run_ui():
    file_path = r"D:\Agent\UploadedJournal 2 (2).xlsx"
    xls = pd.ExcelFile(file_path)
    df = xls.parse(xls.sheet_names[0])

    def on_submit():
        start = entry_start.get()
        end = entry_end.get()
        ftype = filter_var.get()
        filtered, err = filter_by_time_range(df, start, end, ftype)
        if err:
            messagebox.showerror("Error", err)
            return
        if filtered.empty:
            messagebox.showinfo("Result", "⚠️ No data matched the filter criteria.")
        else:
            output_file_path = os.path.join(os.path.dirname(file_path), "FilteredOutput.xlsx")
            filtered.to_excel(output_file_path, index=False)
            messagebox.showinfo("Success", f"✅ Filtered data saved to: {output_file_path}")

    root = tk.Tk()
    root.title("Filter by Time Range")
    root.attributes('-fullscreen', True)  # Make window fullscreen

    # Create a frame to center widgets
    frame = tk.Frame(root, bg="#f0f0f0")
    frame.place(relx=0.5, rely=0.5, anchor="center")

    label_font = ("Arial", 24)
    entry_font = ("Arial", 22)
    button_font = ("Arial", 22)
    radio_font = ("Arial", 20)

    tk.Label(frame, text="Start Time (HH:MM:SS):", font=label_font, bg="#f0f0f0").grid(row=0, column=0, sticky="e", pady=20, padx=10)
    entry_start = tk.Entry(frame, font=entry_font, width=12)
    entry_start.grid(row=0, column=1, pady=20, padx=10)

    tk.Label(frame, text="End Time (HH:MM:SS):", font=label_font, bg="#f0f0f0").grid(row=1, column=0, sticky="e", pady=20, padx=10)
    entry_end = tk.Entry(frame, font=entry_font, width=12)
    entry_end.grid(row=1, column=1, pady=20, padx=10)

    filter_var = tk.StringVar(value="inside")
    radio_frame = tk.Frame(frame, bg="#f0f0f0")
    radio_frame.grid(row=2, column=0, columnspan=2, pady=20)
    tk.Radiobutton(radio_frame, text="Inside", variable=filter_var, value="inside", font=radio_font, bg="#f0f0f0").pack(side="left", padx=30)
    tk.Radiobutton(radio_frame, text="Outside", variable=filter_var, value="outside", font=radio_font, bg="#f0f0f0").pack(side="left", padx=30)

    tk.Button(frame, text="Filter", command=on_submit, font=button_font, bg="#4CAF50", fg="white", width=12, height=2).grid(row=3, column=0, columnspan=2, pady=40)

    # Add an exit button at the bottom right
    def exit_fullscreen():
        root.destroy()
    tk.Button(root, text="Exit", command=exit_fullscreen, font=button_font, bg="#f44336", fg="white", width=8, height=1).place(relx=0.98, rely=0.98, anchor="se")

    root.mainloop()

if __name__ == "__main__":
    run_ui()
    print(f"\n✅ Filtered data saved to: {output_file_path}")
else:
    print("\n⚠️ No data matched the filter criteria.")
