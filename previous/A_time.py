import pandas as pd
import os
import tkinter as tk
from tkinter import scrolledtext, ttk
from tkinter import messagebox
import re
from dateutil import parser as dtparser
from datetime import datetime

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

def parse_time_string(s):
    try:
        t = dtparser.parse(s).time()
        return t.strftime("%H:%M:%S")
    except Exception:
        return None

def extract_time_range_and_type(user_input):
    # Multiple patterns to catch different ways of expressing time ranges
    patterns = [
        # Pattern 1: "X to Y", "X - Y"
        r'(\d{1,2}(:\d{2})?\s*(am|pm)?)\s*(to|-)\s*(\d{1,2}(:\d{2})?\s*(am|pm)?)',
        # Pattern 2: "between X and Y"
        r'between\s+(\d{1,2}(:\d{2})?\s*(am|pm)?)\s+and\s+(\d{1,2}(:\d{2})?\s*(am|pm)?)',
        # Pattern 3: "from X to Y"
        r'from\s+(\d{1,2}(:\d{2})?\s*(am|pm)?)\s+to\s+(\d{1,2}(:\d{2})?\s*(am|pm)?)',
        # Pattern 4: "X and Y" (simple)
        r'(\d{1,2}(:\d{2})?\s*(am|pm)?)\s+and\s+(\d{1,2}(:\d{2})?\s*(am|pm)?)'
    ]
    
    start_time, end_time = None, None
    
    for pattern in patterns:
        match = re.search(pattern, user_input, re.IGNORECASE)
        if match:
            if 'between' in pattern or 'from' in pattern:
                # For "between X and Y" or "from X to Y" patterns
                start_raw = match.group(1)
                end_raw = match.group(4)
            else:
                # For "X to Y" or "X and Y" patterns
                start_raw = match.group(1)
                end_raw = match.group(5)
            
            start_time = parse_time_string(start_raw)
            end_time = parse_time_string(end_raw)
            break
    
    # Determine filter type
    if re.search(r'outside|not between|except|not working|exclude', user_input, re.IGNORECASE):
        filter_type = 'outside'
    else:
        filter_type = 'inside'
    
    return start_time, end_time, filter_type

class ModernChatUI:
    def __init__(self):
        self.root = tk.Tk()
        self.setup_window()
        self.setup_styles()
        self.create_widgets()
        self.load_data()
        self.state = {'mode': 'idle', 'start_time': None, 'end_time': None, 'filter_type': 'inside'}
        
    def setup_window(self):
        self.root.title("Time Filter Assistant")
        self.root.geometry("480x700")
        self.root.configure(bg="#f8f9fa")
        self.root.minsize(400, 600)
        
        # Center the window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (480 // 2)
        y = (self.root.winfo_screenheight() // 2) - (700 // 2)
        self.root.geometry(f"480x700+{x}+{y}")
        
    def setup_styles(self):
        self.colors = {
            'bg': '#f8f9fa',
            'chat_bg': '#ffffff',
            'user_bubble': '#007bff',
            'bot_bubble': '#e9ecef',
            'user_text': '#ffffff',
            'bot_text': '#495057',
            'input_bg': '#ffffff',
            'input_border': '#dee2e6',
            'send_btn': '#007bff',
            'send_btn_hover': '#0056b3'
        }
        
    def create_widgets(self):
        # Header
        header_frame = tk.Frame(self.root, bg=self.colors['bg'], height=80)
        header_frame.pack(fill=tk.X, padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        # Title and status
        title_label = tk.Label(header_frame, text="Time Filter Assistant", 
                              font=("Segoe UI", 18, "bold"), 
                              bg=self.colors['bg'], fg="#212529")
        title_label.pack(pady=(20, 5))
        
        self.status_label = tk.Label(header_frame, text="🟢 Ready to help", 
                                    font=("Segoe UI", 10), 
                                    bg=self.colors['bg'], fg="#6c757d")
        self.status_label.pack()
        
        # Chat container
        chat_container = tk.Frame(self.root, bg=self.colors['chat_bg'])
        chat_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=(10, 0))
        
        # Chat area with custom scrollbar
        self.chat_frame = tk.Frame(chat_container, bg=self.colors['chat_bg'])
        
        # Canvas and scrollbar for custom styling
        self.canvas = tk.Canvas(self.chat_frame, bg=self.colors['chat_bg'], 
                               highlightthickness=0, bd=0)
        self.scrollbar = ttk.Scrollbar(self.chat_frame, orient="vertical", 
                                      command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg=self.colors['chat_bg'])
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        self.chat_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Input area
        input_frame = tk.Frame(self.root, bg=self.colors['bg'], height=70)
        input_frame.pack(fill=tk.X, padx=15, pady=15)
        input_frame.pack_propagate(False)
        
        # Input container with border
        input_container = tk.Frame(input_frame, bg=self.colors['input_bg'], 
                                  relief=tk.SOLID, bd=1)
        input_container.pack(fill=tk.BOTH, expand=True)
        
        self.entry_var = tk.StringVar()
        self.entry = tk.Entry(input_container, textvariable=self.entry_var, 
                             font=("Segoe UI", 12), bg=self.colors['input_bg'], 
                             fg="#495057", bd=0, relief=tk.FLAT)
        self.entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=15, pady=12)
        
        # Send button
        self.send_btn = tk.Button(input_container, text="Send", 
                                 font=("Segoe UI", 10, "bold"),
                                 bg=self.colors['send_btn'], fg="white", 
                                 bd=0, relief=tk.FLAT, cursor="hand2",
                                 padx=20, pady=8, command=self.send_message)
        self.send_btn.pack(side=tk.RIGHT, padx=(0, 10), pady=8)
        
        # Bind events
        self.entry.bind("<Return>", lambda e: self.send_message())
        self.entry.bind("<FocusIn>", self.on_entry_focus)
        self.entry.bind("<FocusOut>", self.on_entry_unfocus)
        
        # Bind mousewheel to canvas
        self.canvas.bind("<MouseWheel>", self.on_mousewheel)
        self.root.bind_all("<MouseWheel>", self.on_mousewheel)
        
    def on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        
    def on_entry_focus(self, event):
        self.entry.configure(bg="#ffffff")
        
    def on_entry_unfocus(self, event):
        self.entry.configure(bg=self.colors['input_bg'])
        
    def load_data(self):
        try:
            file_path = r"F:\AI ML\Agent\sample-excel-filtering\UploadedJournal 2 (2).xlsx"
            xls = pd.ExcelFile(file_path)
            self.df = xls.parse(xls.sheet_names[0])
            self.file_path = file_path
        except Exception as e:
            messagebox.showerror("Error", f"Could not load data file: {str(e)}")
            self.df = pd.DataFrame()  # Empty dataframe as fallback
            
    def add_message(self, text, is_user=False, typing_effect=False):
        # Message container
        msg_frame = tk.Frame(self.scrollable_frame, bg=self.colors['chat_bg'])
        msg_frame.pack(fill=tk.X, padx=10, pady=5)
        
        if is_user:
            # User message (right aligned)
            bubble_frame = tk.Frame(msg_frame, bg=self.colors['chat_bg'])
            bubble_frame.pack(anchor=tk.E)
            
            bubble = tk.Label(bubble_frame, text=text, font=("Segoe UI", 11), 
                             bg=self.colors['user_bubble'], fg=self.colors['user_text'],
                             wraplength=300, justify=tk.LEFT, padx=12, pady=8,
                             relief=tk.FLAT)
            bubble.pack(anchor=tk.E)
            
            # Add timestamp
            time_label = tk.Label(msg_frame, text=datetime.now().strftime("%H:%M"), 
                                 font=("Segoe UI", 8), bg=self.colors['chat_bg'], 
                                 fg="#6c757d")
            time_label.pack(anchor=tk.E, pady=(2, 0))
            
        else:
            # Bot message (left aligned)
            bubble_frame = tk.Frame(msg_frame, bg=self.colors['chat_bg'])
            bubble_frame.pack(anchor=tk.W)
            
            # Bot avatar
            avatar = tk.Label(bubble_frame, text="🤖", font=("Segoe UI", 16), 
                             bg=self.colors['chat_bg'])
            avatar.pack(side=tk.LEFT, anchor=tk.N, padx=(0, 8), pady=8)
            
            bubble = tk.Label(bubble_frame, text=text, font=("Segoe UI", 11), 
                             bg=self.colors['bot_bubble'], fg=self.colors['bot_text'],
                             wraplength=300, justify=tk.LEFT, padx=12, pady=8,
                             relief=tk.FLAT)
            bubble.pack(side=tk.LEFT, anchor=tk.W)
            
            # Add timestamp
            time_label = tk.Label(msg_frame, text=datetime.now().strftime("%H:%M"), 
                                 font=("Segoe UI", 8), bg=self.colors['chat_bg'], 
                                 fg="#6c757d")
            time_label.pack(anchor=tk.W, padx=(32, 0), pady=(2, 0))
        
        # Update canvas and scroll to bottom
        self.root.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self.canvas.yview_moveto(1.0)
        
    def send_message(self):
        user_input = self.entry_var.get().strip()
        if not user_input:
            return
            
        # Add user message
        self.add_message(user_input, is_user=True)
        self.entry_var.set('')
        
        # Show typing indicator
        self.status_label.config(text="🟡 Processing...")
        self.root.update()
        
        # Process the message
        self.root.after(500, lambda: self.process_user_input(user_input))
        
    def process_user_input(self, user_input):
        if self.state['mode'] == 'idle':
            start_time, end_time, filter_type = extract_time_range_and_type(user_input)
            self.state['start_time'] = start_time
            self.state['end_time'] = end_time
            self.state['filter_type'] = filter_type
            
            if not start_time:
                self.state['mode'] = 'awaiting_start'
                self.add_message("Please specify the start time (e.g., 9am or 09:00).")
                self.status_label.config(text="🟠 Waiting for start time")
                return
                
            if not end_time:
                self.state['mode'] = 'awaiting_end'
                self.add_message("Please specify the end time (e.g., 5pm or 17:00).")
                self.status_label.config(text="🟠 Waiting for end time")
                return
                
            # Process complete request
            self.filter_and_respond(start_time, end_time, filter_type)
            
        elif self.state['mode'] == 'awaiting_start':
            start_time = parse_time_string(user_input)
            if not start_time:
                self.add_message("Couldn't understand the time. Please enter start time in HH:MM or 9am format.")
                return
                
            self.state['start_time'] = start_time
            if not self.state['end_time']:
                self.state['mode'] = 'awaiting_end'
                self.add_message("Please specify the end time (e.g., 5pm or 17:00).")
                self.status_label.config(text="🟠 Waiting for end time")
                return
                
            self.filter_and_respond(self.state['start_time'], self.state['end_time'], self.state['filter_type'])
            
        elif self.state['mode'] == 'awaiting_end':
            end_time = parse_time_string(user_input)
            if not end_time:
                self.add_message("Couldn't understand the time. Please enter end time in HH:MM or 5pm format.")
                return
                
            self.state['end_time'] = end_time
            if not self.state['start_time']:
                self.state['mode'] = 'awaiting_start'
                self.add_message("Please specify the start time (e.g., 9am or 09:00).")
                self.status_label.config(text="🟠 Waiting for start time")
                return
                
            self.filter_and_respond(self.state['start_time'], self.state['end_time'], self.state['filter_type'])
            
    def filter_and_respond(self, start_time, end_time, filter_type):
        try:
            filtered, err = filter_by_time_range(self.df, start_time, end_time, filter_type)
            
            if err:
                self.add_message(err)
                self.status_label.config(text="❌ Error occurred")
            elif filtered.empty:
                self.add_message("⚠️ No data matched the filter criteria.")
                self.status_label.config(text="🟢 Ready to help")
            else:
                output_file_path = os.path.join(os.path.dirname(self.file_path), "FilteredOutput.xlsx")
                filtered.to_excel(output_file_path, index=False)
                self.add_message(f"✅ Filtered data saved successfully!\n📁 Location: {output_file_path}\n📊 Records found: {len(filtered)}")
                self.status_label.config(text="🟢 Ready to help")
                
        except Exception as e:
            self.add_message(f"❌ An error occurred: {str(e)}")
            self.status_label.config(text="❌ Error occurred")
            
        self.state['mode'] = 'idle'
        self.entry.focus_set()
        
    def run(self):
        # Initial greeting
        self.root.after(1000, lambda: self.add_message(
            "👋 Hi! I'm your Time Filter Assistant.\n\n"
            "I can help you filter employee data by time ranges. Try asking me something like:\n"
            "• 'Show employees working from 9am to 5pm'\n"
            "• 'Filter data between 9am and 5pm'\n"
            "• 'Get data from 08:00 to 18:00'\n"
            "• 'Show employees outside 9am and 6pm'\n"
            "• 'Filtered data between 10am and 4pm'"
        ))
        
        self.entry.focus_set()
        self.root.mainloop()

def run_chatbot_ui():
    app = ModernChatUI()
    app.run()

if __name__ == "__main__":
    run_chatbot_ui()