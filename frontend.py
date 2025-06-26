import tkinter as tk
from tkinter import messagebox
import subprocess

def run_script(script_name):
    try:
        subprocess.run(["python", script_name])
    except Exception as e:
        messagebox.showerror("Error", f"Failed to run {script_name}:\n{e}")

def main():
    root = tk.Tk()
    root.title("Agent Analysis Frontend")
    root.state('zoomed')  # For Windows

    root.configure(bg="#f0f4f8")

    # --- Scrollable Frame Setup ---
    canvas = tk.Canvas(root, bg="#f0f4f8", highlightthickness=0)
    scrollbar = tk.Scrollbar(root, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    scroll_frame = tk.Frame(canvas, bg="#ffffff", bd=2, relief="groove")
    scroll_frame_id = canvas.create_window((0, 0), window=scroll_frame, anchor="n")

    def on_frame_configure(event):
        canvas.configure(scrollregion=canvas.bbox("all"))
        canvas.itemconfig(scroll_frame_id, width=event.width)

    scroll_frame.bind("<Configure>", on_frame_configure)
    canvas.bind("<Configure>", on_frame_configure)

    tk.Label(
        scroll_frame,
        text="Agent Analysis Suite",
        font=("Segoe UI", 32, "bold"),
        bg="#ffffff",
        fg="#2d3e50"
    ).pack(pady=(40, 10))

    tk.Label(
        scroll_frame,
        text="Select an analysis to run:",
        font=("Segoe UI", 18),
        bg="#ffffff",
        fg="#2d3e50"
    ).pack(pady=(0, 30))

    buttons = [
        ("Filter by Time Range", "A_time.py"),
        ("Find Abnormal Descriptions", "A_AbnormalDescriptions.py"),
        ("Find Vague Entries", "A_vague.py"),
        ("Find Senior Personnel Entries", "A_senior_level.py"),
        ("Find Bypass Entries", "A_bypass.py"),
        ("Find Unauthorized Entries", "A_authorize.py"),
        ("Find Sensitive Account Entries", "A_Account.py"),
    ]

    for text, script in buttons:
        tk.Button(
            scroll_frame,
            text=text,
            width=35,
            height=2,
            font=("Segoe UI", 14),
            bg="#4f8cff",
            fg="#ffffff",
            activebackground="#2d3e50",
            activeforeground="#ffffff",
            bd=0,
            relief="ridge",
            cursor="hand2",
            command=lambda s=script: run_script(s)
        ).pack(pady=10)

    tk.Button(
        scroll_frame,
        text="Exit",
        width=35,
        height=2,
        font=("Segoe UI", 14),
        bg="#e74c3c",
        fg="#ffffff",
        activebackground="#c0392b",
        activeforeground="#ffffff",
        bd=0,
        relief="ridge",
        cursor="hand2",
        command=root.destroy
    ).pack(pady=(30, 80))  # Increased bottom padding

    root.mainloop()


if __name__ == "__main__":
    main()
