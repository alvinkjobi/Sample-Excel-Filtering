import pandas as pd
import os
import tkinter as tk
from tkinter import scrolledtext, ttk
from tkinter import messagebox
from tkinter import filedialog
import re
from datetime import datetime

def find_authorization_entries(df, title_column='Authorization Status', authorization_keywords=None):
    """
    Filter entries to show only those where the Title column contains
    ANY of the user-given titles (case-insensitive, substring match).
    Handles input like 'authorized and unauthorized' or 'authorized' or 'unauthorized'.
    """
    if not authorization_keywords:
        return pd.DataFrame(columns=df.columns)
    if isinstance(authorization_keywords, str):
        parts = re.split(r',|\band\b|\bor\b', authorization_keywords)
        authorization_keywords = [p.strip().lower() for p in parts if p.strip()]
    else:
        authorization_keywords = [kw.strip().lower() for kw in authorization_keywords if kw.strip()]
    titles = df[title_column].fillna('').astype(str).str.lower()
    # Use whole word match to avoid 'authorized' matching 'unauthorized'
    patterns = [rf'\b{re.escape(kw)}\b' for kw in authorization_keywords]
    combined_pattern = '|'.join(patterns)
    mask = titles.str.contains(combined_pattern, regex=True)
    return df[mask]

AUTHORIZATION_PATTERNS = [
    r'"([^"]+)"',
    r'authorization\s+statuses?\s+containing\s+([^)]+)',
    r'(?:entries\s+)?(?:entered\s+by|by)\s+([a-zA-Z0-9\s]+?)\s+users?',
    r'([a-zA-Z0-9\s]+(?:,|\band\b|\bor\b)[a-zA-Z0-9\s,]*)',
    r'([a-zA-Z0-9\s]+)'
]


def extract_authorization_statuses_from_input(user_input):
    """
    Extracts possible authorization statuses from user input using AUTHORIZATION_PATTERNS.
    Returns a list of statuses or None.
    Supports patterns like:
    - "entered by unauthorized users"
    - "Entries by unauthorized users"
    - "Entries entered by unauthorized users"
    - "authorization statuses containing ..."
    - quoted, comma/and/or separated, etc.
    """
    for pattern in AUTHORIZATION_PATTERNS:
        match = re.findall(pattern, user_input, re.IGNORECASE)
        if match:
            if pattern == r'"([^"]+)"':
                return [m.strip().lower() for m in match if m.strip()]
            if pattern == r'authorization\s+statuses?\s+containing\s+([^)]+)':
                titles_str = match[0]
                parts = re.split(r',|\band\b|\bor\b', titles_str)
                return [p.strip().lower() for p in parts if p.strip()]
            if pattern == r'(?:entries\s+)?(?:entered\s+by|by)\s+([a-zA-Z0-9\s]+?)\s+users?':
                m = re.search(pattern, user_input, re.IGNORECASE)
                if m:
                    return [m.group(1).strip().lower()]
            if pattern == r'([a-zA-Z0-9\s]+(?:,|\band\b|\bor\b)[a-zA-Z0-9\s,]*)':
                parts = re.split(r',|\band\b|\bor\b', match[0])
                return [p.strip().lower() for p in parts if p.strip()]
            if pattern == r'([a-zA-Z0-9\s]+)':
                return [match[0].strip().lower()]
    # Fallback: check for common authorization words in the input
    common_words = [
        'unauthorized', 'authorized', 'authorization', 'auth',
        'permit', 'permission', 'access', 'clearance'
    ]
    lowered = user_input.lower()
    found = []
    for word in common_words:
        if re.search(rf'\b{re.escape(word)}\b', lowered):
            found.append(word)
    if not found:
        for word in common_words:
            if word in lowered:
                found.append(word)
    found = sorted(found, key=lambda w: -len(w))
    final = []
    for w in found:
        if not any(w != other and w in other for other in found):
            final.append(w)
    return final if final else None

class SmartFilterBot:
    def __init__(self):
        self.root = tk.Tk()
        self.setup_window()
        self.setup_styles()
        self.create_widgets()
        self.load_data()
        self.reset_state()
        
    def reset_state(self):
        self.state = {
            'mode': 'greeting',  # greeting -> filter_selection -> authorization_filtering
            'filter_type_selected': None,
            'authorization_keywords': None
        }
        
    def setup_window(self):
        self.root.title("Smart Data Filter Assistant")
        self.root.geometry("500x750")
        self.root.configure(bg="#f8f9fa")
        self.root.minsize(450, 650)
        
        # Center the window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (500 // 2)
        y = (self.root.winfo_screenheight() // 2) - (750 // 2)
        self.root.geometry(f"500x750+{x}+{y}")
        
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
            'send_btn_hover': '#0056b3',
            'option_btn': '#28a745',
            'option_btn_hover': '#218838'
        }
        
    def create_widgets(self):
        # Header
        header_frame = tk.Frame(self.root, bg=self.colors['bg'], height=90)
        header_frame.pack(fill=tk.X, padx=0, pady=0)
        
        # Title and status
        title_label = tk.Label(header_frame, text="🤖 Smart Filter Assistant", 
                              font=("Segoe UI", 20, "bold"), 
                              bg=self.colors['bg'], fg="#212529")
        title_label.pack(pady=(15, 5))
        
        self.status_label = tk.Label(header_frame, text="🟢 Ready to help you filter data", 
                                    font=("Segoe UI", 11), 
                                    bg=self.colors['bg'], fg="#6c757d")
        self.status_label.pack()
        
        # Data info
        self.data_info_label = tk.Label(header_frame, text="", 
                                       font=("Segoe UI", 9), 
                                       bg=self.colors['bg'], fg="#6c757d")
        self.data_info_label.pack()
        
        # Upload button
        self.upload_btn = tk.Button(
            header_frame, text="📁 Upload Excel",
            font=("Segoe UI", 10, "bold"),
            bg="#17a2b8", fg="white", bd=0, relief=tk.FLAT, cursor="hand2",
            padx=10, pady=4,
            command=self.upload_excel_file
        )
        self.upload_btn.pack(pady=(5, 0))
        
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
        
        # Quick actions frame (will be shown/hidden as needed)
        self.quick_actions_frame = tk.Frame(self.root, bg=self.colors['bg'])
        
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

    def upload_excel_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Excel File",
            filetypes=[("Excel files", "*.xlsx *.xls")]
        )
        if file_path:
            try:
                xls = pd.ExcelFile(file_path)
                if not xls.sheet_names:
                    messagebox.showerror("Error", "No sheets found in the Excel file.")
                    self.df = pd.DataFrame()
                    self.data_info_label.config(text="❌ No data loaded")
                    return
                # Always load the first sheet for now
                df = xls.parse(xls.sheet_names[0])
                if df.empty:
                    messagebox.showwarning("Warning", "The selected sheet is empty.")
                    self.df = pd.DataFrame()
                    self.data_info_label.config(text="❌ No data loaded")
                    return
                self.df = df
                self.file_path = file_path
                self.data_info_label.config(
                    text=f"📊 Loaded {len(self.df)} records | Columns: {', '.join(self.df.columns.tolist())}"
                )
                self.add_message("✅ Excel file loaded successfully!")
                self.handle_initial_greeting("mesaage")
            except Exception as e:
                messagebox.showerror("Error", f"Could not load data file: {str(e)}")
                self.df = pd.DataFrame()
                self.data_info_label.config(text="❌ No data loaded")

    def on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        
    def on_entry_focus(self, event):
        self.entry.configure(bg="#ffffff")
        
    def on_entry_unfocus(self, event):
        self.entry.configure(bg=self.colors['input_bg'])
        
    def load_data(self):
        # Do not load any file by default; prompt user to upload
        self.df = pd.DataFrame()
        self.file_path = None
        self.data_info_label.config(text="❌ No data loaded. Please upload an Excel file to begin.")
                
    def add_message(self, text, is_user=False, show_options=False, options=None):
        # Message container
        msg_frame = tk.Frame(self.scrollable_frame, bg=self.colors['chat_bg'])
        msg_frame.pack(fill=tk.X, padx=10, pady=8)
        
        if is_user:
            # User message (right aligned)
            bubble_frame = tk.Frame(msg_frame, bg=self.colors['chat_bg'])
            bubble_frame.pack(anchor=tk.E)
            
            bubble = tk.Label(bubble_frame, text=text, font=("Segoe UI", 11), 
                             bg=self.colors['user_bubble'], fg=self.colors['user_text'],
                             wraplength=350, justify=tk.LEFT, padx=15, pady=10,
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
            avatar = tk.Label(bubble_frame, text="🤖", font=("Segoe UI", 18), 
                             bg=self.colors['chat_bg'])
            avatar.pack(side=tk.LEFT, anchor=tk.N, padx=(0, 10), pady=10)
            
            bubble = tk.Label(bubble_frame, text=text, font=("Segoe UI", 11), 
                             bg=self.colors['bot_bubble'], fg=self.colors['bot_text'],
                             wraplength=350, justify=tk.LEFT, padx=15, pady=10,
                             relief=tk.FLAT)
            bubble.pack(side=tk.LEFT, anchor=tk.W)
            
            # Add options if provided
            if show_options and options:
                options_frame = tk.Frame(msg_frame, bg=self.colors['chat_bg'])
                options_frame.pack(anchor=tk.W, padx=(40, 0), pady=(5, 0))
                
                for option_text, option_value in options:
                    btn = tk.Button(options_frame, text=option_text, 
                                   font=("Segoe UI", 10, "bold"),
                                   bg=self.colors['option_btn'], fg="white",
                                   bd=0, relief=tk.FLAT, cursor="hand2",
                                   padx=15, pady=8,
                                   command=lambda val=option_value: self.handle_option_click(val))
                    btn.pack(side=tk.TOP, anchor=tk.W, pady=2, fill=tk.X)
            
            # Add timestamp
            time_label = tk.Label(msg_frame, text=datetime.now().strftime("%H:%M"), 
                                 font=("Segoe UI", 8), bg=self.colors['chat_bg'], 
                                 fg="#6c757d")
            time_label.pack(anchor=tk.W, padx=(40, 0), pady=(2, 0))
        
        # Update canvas and scroll to bottom
        self.root.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self.canvas.yview_moveto(1.0)
        
    def handle_option_click(self, option_value):
        """Handle when user clicks on an option button"""
        self.add_message(option_value, is_user=True)
        self.process_user_input(option_value)
        
    def send_message(self):
        user_input = self.entry_var.get().strip()
        if not user_input:
            return
            
        # Add user message
        self.add_message(user_input, is_user=True)
        self.entry_var.set('')
        
        # Show typing indicator
        self.status_label.config(text="🟡 Processing your request...")
        self.root.update()
        
        # Process the message
        self.root.after(800, lambda: self.process_user_input(user_input))
        
    def process_user_input(self, user_input):
        if self.state['mode'] == 'greeting':
            self.handle_initial_greeting(user_input)
        elif self.state['mode'] == 'filter_selection':
            self.handle_filter_selection(user_input)
        elif self.state['mode'] == 'authorization_filtering':
            self.handle_authorization_filtering(user_input)

    def handle_initial_greeting(self, user_input):
        self.state['mode'] = 'authorization_filtering'
        self.state['filter_type_selected'] = 'authorization'
        self.status_label.config(text="� Processing authorization filter")
        self.add_message("I'll help you filter for authorization statuses. Please specify the statuses (e.g., authorized, unauthorized, pending, etc.).")

    def handle_filter_selection(self, user_input):
        self.state['mode'] = 'authorization_filtering'
        self.state['filter_type_selected'] = 'authorization'
        self.status_label.config(text="🔒 Processing authorization filter")
        self.add_message("I'll help you filter for authorization statuses. Please specify the statuses (e.g., authorized, unauthorized, pending, etc.).")

    def handle_authorization_filtering(self, user_input):
        extracted_statuses = extract_authorization_statuses_from_input(user_input)
        if extracted_statuses:
            self.filter_and_respond_authorization(extracted_statuses)
        else:
            self.add_message("Please specify the authorization statuses you want to search for, separated by commas or using 'and/or'.\nExample: 'authorized, unauthorized, pending'")
            self.status_label.config(text="⌨️ Waiting for statuses")

    def filter_and_respond_authorization(self, custom_keywords=None):
        try:
            self.status_label.config(text="� Filtering for authorization statuses...")
            self.root.update()
            if custom_keywords:
                authorization_titles = custom_keywords
            else:
                authorization_titles = ['authorized', 'unauthorized', 'pending']
            filtered_df = find_authorization_entries(self.df, title_column='Authorization Status', authorization_keywords=authorization_titles)
            if filtered_df.empty:
                self.add_message("⚠️ No authorization records found with the given criteria.\nWould you like to try different statuses?")
                self.status_label.config(text="⚠️ No matches found")
            else:
                output_file_path = os.path.join(os.path.dirname(self.file_path), "Filtered_Authorization.xlsx")
                filtered_df.to_excel(output_file_path, index=False)
                self.add_message(
                    f"✅ Filter complete!\n\n"
                    f"• Authorization statuses used: {', '.join(authorization_titles)}\n"
                    f"• Records found: {len(filtered_df)}\n"
                    f"• Saved to: Filtered_Authorization.xlsx\n\n"
                    f"Want to apply another filter?"
                )
                self.status_label.config(text="✅ Filter completed successfully")
        except Exception as e:
            self.add_message(f"❌ Error during authorization filtering: {str(e)}")
            self.status_label.config(text="❌ Error occurred")
        self.reset_state()
        self.state['mode'] = 'filter_selection'
        self.entry.focus_set()

    def run(self):
        self.root.after(1500, lambda: self.add_message(
            "👋 Hello! I'm your Smart Filter Assistant!\n\n"
            "I can help you filter and analyze your data for senior personnel. "
            "Just tell me what titles or keywords you want to filter for (e.g., manager, director, cfo, accountant, etc.)."
        ))
        self.entry.focus_set()
        self.root.mainloop()

def run_chatbot_ui():
    app = SmartFilterBot()
    app.run()

if __name__ == "__main__":
    run_chatbot_ui()

def find_bypass_entries(df, columns_to_search=None, keywords=None):
    """
    Filters rows where any column contains the word 'bypass' (case-insensitive, substring match).

    Args:
        df (pd.DataFrame): Input DataFrame.
        columns_to_search (list): List of column names to scan. If None, checks all columns.
        keywords (list): Ignored. Always checks for 'bypass'.

    Returns:
        pd.DataFrame: Rows where any column contains 'bypass'.
    """
    if columns_to_search is None:
        columns_to_search = df.columns.tolist()
    valid_columns = [col for col in columns_to_search if col in df.columns]
    if not valid_columns:
        return pd.DataFrame(columns=df.columns)
    mask = df[valid_columns].apply(
        lambda col: col.astype(str).str.lower().str.contains('bypass', na=False)
    ).any(axis=1)
    return df[mask]