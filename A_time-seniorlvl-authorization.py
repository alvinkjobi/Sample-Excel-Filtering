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
        # Handle various time formats
        s = s.strip().lower()
        
        # Remove common words that might interfere
        s = re.sub(r'\b(at|around|about|approximately)\b', '', s).strip()
        
        # Try parsing with dateutil
        parsed = dtparser.parse(s)
        return parsed.strftime("%H:%M:%S")
    except Exception as e:
        print(f"Debug: Failed to parse '{s}': {e}")
        return None

def extract_time_range_and_type(user_input):
    """Extract time range and filter type from user input with improved regex patterns"""
    
    # Clean the input
    user_input = user_input.strip()
    print(f"Debug: Processing input: '{user_input}'")
    
    # Improved patterns with better group handling
    patterns = [
        # Pattern 1: "X to Y", "X - Y" (most common)
        r'(\d{1,2}(?::\d{2})?(?:\s*(?:am|pm))?)\s*(?:to|-)\s*(\d{1,2}(?::\d{2})?(?:\s*(?:am|pm))?)',
        # Pattern 2: "between X and Y"
        r'between\s+(\d{1,2}(?::\d{2})?(?:\s*(?:am|pm))?)\s+and\s+(\d{1,2}(?::\d{2})?(?:\s*(?:am|pm))?)',
        # Pattern 3: "from X to Y"
        r'from\s+(\d{1,2}(?::\d{2})?(?:\s*(?:am|pm))?)\s+to\s+(\d{1,2}(?::\d{2})?(?:\s*(?:am|pm))?)',
        # Pattern 4: "X and Y" (simple)
        r'(\d{1,2}(?::\d{2})?(?:\s*(?:am|pm))?)\s+and\s+(\d{1,2}(?::\d{2})?(?:\s*(?:am|pm))?)'
    ]
    
    start_time, end_time = None, None
    
    for i, pattern in enumerate(patterns):
        match = re.search(pattern, user_input, re.IGNORECASE)
        if match:
            print(f"Debug: Pattern {i+1} matched: {match.groups()}")
            
            # All patterns now use consistent group numbering (1 and 2)
            start_raw = match.group(1).strip()
            end_raw = match.group(2).strip()
            
            print(f"Debug: Extracted times - start: '{start_raw}', end: '{end_raw}'")
            
            start_time = parse_time_string(start_raw)
            end_time = parse_time_string(end_raw)
            
            print(f"Debug: Parsed times - start: '{start_time}', end: '{end_time}'")
            break
    
    # Determine filter type
    if re.search(r'outside|not between|except|not working|exclude', user_input, re.IGNORECASE):
        filter_type = 'outside'
    else:
        filter_type = 'inside'
    
    print(f"Debug: Final result - start: {start_time}, end: {end_time}, type: {filter_type}")
    return start_time, end_time, filter_type

def find_senior_personnel_entries(df, title_column='Title', senior_keywords=None):
    """Filter entries to show only senior personnel based on job titles"""
    if senior_keywords is None:
        senior_keywords = ['manager', 'senior', 'director', 'vp', 'cfo', 'ceo']

    # Match base word and its plural form (e.g., manager|managers)
    pattern = r'|'.join([rf'{re.escape(word)}s?' for word in senior_keywords])

    mask = df[title_column].fillna('').astype(str).str.lower().str.contains(pattern)
    return df[mask]

def find_authorization_entries(df, title_column='Authorization Status', authorization_keywords=None):
    """Filter entries accurately based on authorization status using whole-word matching"""
    if authorization_keywords is None:
        authorization_keywords = ["authorized"]

    # Clean and lower the column
    col_data = df[title_column].fillna('').astype(str).str.lower().str.strip()

    # Build regex to match exact words only (not substrings)
    pattern = r'\b(?:' + '|'.join(re.escape(word.lower()) for word in authorization_keywords) + r')\b'

    # Apply regex with word boundaries
    mask = col_data.str.contains(pattern, regex=True)
    return df[mask]

def detect_filter_intent(user_input):
    """Detect what type of filtering the user wants"""
    user_input = user_input.lower()
    
    # Time-related keywords
    time_keywords = ['time', 'hour', 'am', 'pm', 'morning', 'evening', 'afternoon', 
                     'working hours', 'shift', 'schedule', 'clock']
    
    # Senior personnel keywords
    senior_keywords = ['senior', 'manager', 'director', 'vp', 'ceo', 'cfo', 
                      'leadership', 'management', 'executive', 'supervisor', 
                      'lead', 'head', 'chief', 'senior staff']
    # Authorization keywords
    authorization_keywords = ['authorized', 'unauthorized', 'authorization', 'auth', 
                             'permit', 'permission', 'access', 'clearance']
    # Check for time patterns
    time_patterns = [
        r'\d{1,2}(?::\d{2})?\s*(?:am|pm)',
        r'\d{1,2}:\d{2}',
        r'between.*and.*\d',
        r'from.*to.*\d'
    ]
    
    has_time_keywords = any(keyword in user_input for keyword in time_keywords)
    has_time_pattern = any(re.search(pattern, user_input, re.IGNORECASE) for pattern in time_patterns)
    has_senior_keywords = any(keyword in user_input for keyword in senior_keywords)
    has_authorization_keywords = any(keyword in user_input for keyword in authorization_keywords)   
    
    if has_time_keywords or has_time_pattern:
        return 'time'
    elif has_senior_keywords:
        return 'senior'
    elif has_authorization_keywords:
        return 'Authorization'
    
    return 'unknown'

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
            'mode': 'greeting',  # greeting -> filter_selection -> time_filtering -> senior_filtering -> awaiting_start -> awaiting_end
            'filter_type_selected': None,
            'start_time': None,
            'end_time': None,
            'time_filter_type': 'inside',
            'senior_keywords': None
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
        header_frame.pack_propagate(False)
        
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
            
            # Update data info
            self.data_info_label.config(text=f"📊 Loaded {len(self.df)} records | Columns: {', '.join(self.df.columns.tolist())}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Could not load data file: {str(e)}")
            self.df = pd.DataFrame()  # Empty dataframe as fallback
            self.data_info_label.config(text="❌ No data loaded")
            
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
        elif self.state['mode'] == 'time_filtering':
            self.handle_time_filtering(user_input)
        elif self.state['mode'] == 'senior_filtering':
            self.handle_senior_filtering(user_input)
        elif self.state['mode'] == 'Authorization_filtering':
            self.handle_authorization_filtering(user_input)
        elif self.state['mode'] == 'awaiting_start':
            self.handle_awaiting_start(user_input)
        elif self.state['mode'] == 'awaiting_end':
            self.handle_awaiting_end(user_input)
            
    def handle_initial_greeting(self, user_input):
        """Handle the initial conversation and determine filter type"""
        filter_intent = detect_filter_intent(user_input)
        
        if filter_intent == 'time':
            self.state['mode'] = 'time_filtering'
            self.state['filter_type_selected'] = 'time'
            self.status_label.config(text="🕐 Processing time filter")
            self.add_message("Great! I detected you want to filter by time. Let me help you with that.")
            self.root.after(1000, lambda: self.handle_time_filtering(user_input))
        elif filter_intent == 'senior':
            self.state['mode'] = 'senior_filtering'
            self.state['filter_type_selected'] = 'senior'
            self.status_label.config(text="👔 Processing senior personnel filter")
            self.add_message("Perfect! I'll help you filter for senior personnel. Let me process that for you.")
            self.root.after(1000, lambda: self.handle_senior_filtering(user_input))
        elif filter_intent == 'Authorization':
            self.state['mode'] = 'Authorization_filtering'
            self.state['filter_type_selected'] = 'Authorization'
            self.status_label.config(text="👔 Processing Authorized or Unauthorized filter")
            self.add_message("Perfect! I'll help you filter for Authorized or Unauthorized personnel. Let me process that for you.")
            self.root.after(1000, lambda: self.handle_authorization_filtering(user_input))
        else:
            self.state['mode'] = 'filter_selection'
            self.add_message(
                "I'd be happy to help you filter your data! 📊\n\n"
                "What type of filtering would you like to do?",
                show_options=True,
                options=[
                    ("🕐 Filter by Time", "I want to filter by time"),
                    ("👔 Filter Senior Personnel", "I want to filter senior personnel"),
                    ("👤 Filter by Authorized or Unauthorized", "I want to filter by Authorization Status"),
                    ("🏢 Filter by Department", "I want to filter by department"),
                    ("📈 Custom Filter", "I want custom filtering")
                ]
            )
            self.status_label.config(text="🤔 Waiting for filter type selection")
    def handle_authorization_filtering(self, user_input):
        """Handle authorization filtering logic"""
        user_input_lower = user_input.lower()

        if 'default' in user_input_lower or 'standard' in user_input_lower:
            # Use default keywords
            self.filter_and_respond_auth(None)
        else:
            # Try to extract keywords from the input
            potential_keywords = self.extract_auth_keywords(user_input)
            if potential_keywords:
                self.filter_and_respond_auth(potential_keywords)
            else:
                # Use default if no specific keywords found
                self.filter_and_respond_auth(None)

    def filter_and_respond_auth(self, custom_keywords=None):
        try:
            self.status_label.config(text="👔 Filtering for authorization...")
            self.root.update()

            # Use custom keywords if provided, otherwise default
            if custom_keywords:
                auth_titles = custom_keywords
            else:
                auth_titles = [ 'authorized', 'unauthorized', 'authorization', 'auth',        
                                'permit', 'permission', 'access', 'clearance']

            filtered_df = find_authorization_entries(self.df, title_column='Authorization Status', authorization_keywords=auth_titles)
            if filtered_df.empty:
                self.add_message("⚠️ No authorization records found with the given criteria.\nWould you like to try different titles?",
                                show_options=True,
                                options=[
                                    ("🔄 Try default titles", "Use default Authorization titles"),
                                    ("🔧 Specify custom titles", "I want to specify custom titles")
                                ])
                self.status_label.config(text="⚠️ No matches found")
            else:
                output_file_path = os.path.join(os.path.dirname(self.file_path), "Authorization.xlsx")
                filtered_df.to_excel(output_file_path, index=False)

                self.add_message(
                    f"✅ Filter complete!\n\n"
                    f"• Authorization titles used: {', '.join(auth_titles)}\n"
                    f"• Records found: {len(filtered_df)}\n"
                    f"• Saved to: Authorization.xlsx\n\n"
                    f"Want to apply another filter?",
                    show_options=True,
                    options=[
                        ("🔄 Filter again", "I want to filter data again"),
                        ("✨ New filter type", "I want different filtering")
                    ]
                )
                self.status_label.config(text="✅ Filter completed successfully")

        except Exception as e:
            self.add_message(f"❌ Error during authorization filtering: {str(e)}")
            self.status_label.config(text="❌ Error occurred")

        # Reset for next task
        self.reset_state()
        self.state['mode'] = 'filter_selection'
        self.entry.focus_set()
    def extract_auth_keywords(self, user_input):
        """Extract potential authorization keywords from user input"""
        common_titles = [ 'authorized', 'unauthorized', 'authorization', 'auth',
                          'permit', 'permission', 'access', 'clearance']
        
        # Normalize input and split using commas and 'and'
        parts = re.split(r',|\band\b', user_input.lower())

        found_keywords = []
        for part in parts:
            word = part.strip().rstrip('s')  # remove plural 's'
            if word in common_titles:
                found_keywords.append(word)
        return found_keywords if found_keywords else None
    
    def handle_filter_selection(self, user_input):
        """Handle filter type selection"""
        if any(word in user_input.lower() for word in ['time', 'hour', 'shift', 'schedule']):
            self.state['mode'] = 'time_filtering'
            self.state['filter_type_selected'] = 'time'
            self.status_label.config(text="🕐 Setting up time filter")
            self.add_message("Perfect! Let's set up time-based filtering. 🕐\n\nYou can tell me things like:\n• 'Show data between 9am and 5pm'\n• 'Filter from 08:00 to 18:00'\n• 'Get employees working 10am to 6pm'")
        elif any(word in user_input.lower() for word in ['senior', 'management', 'manager', 'director', 'executive', 'leadership']):
            self.state['mode'] = 'senior_filtering'
            self.state['filter_type_selected'] = 'senior'
            self.status_label.config(text="👔 Setting up senior personnel filter")
            self.add_message("Excellent! I'll help you filter for senior personnel. 👔\n\nI can find employees with titles like:\n• Managers\n• Directors\n• VPs, CEOs, CFOs\n• Senior-level positions\n• Executive roles\n\nWould you like me to use the default search or specify custom titles?",
                           show_options=True,
                           options=[
                               ("✅ Use default search", "Use default senior titles"),
                               ("🔧 Custom titles", "I want to specify custom titles")
                           ])
        elif any(word in user_input.lower() for word in ['authorization', 'authorized', 'unauthorized', 'auth']):
            self.state['mode'] = 'Authorization_filtering'
            self.state['filter_type_selected'] = 'Authorization'
            self.status_label.config(text="👔 Setting up Authorization filter")
            self.add_message("Great! I'll help you filter by Authorization Status. 👔\n\nYou can tell me things like:\n• 'Show only authorized personnel'\n• 'Filter out unauthorized entries'\n\nWould you like to use the default search or specify custom titles?",
                           show_options=True,
                           options=[
                               ("✅ Use default search", "Use default Authorization titles"),
                               ("🔧 Custom titles", "I want to specify custom titles")
                           ])
        elif any(word in user_input.lower() for word in ['name', 'employee']):
            self.add_message("Employee name filtering is coming soon! 👤\n\nFor now, I can help you with time-based filtering or senior personnel filtering. Which would you prefer?",
                           show_options=True,
                           options=[
                               ("🕐 Filter by time", "I want to filter by time"),
                               ("👔 Filter senior personnel", "I want to filter senior personnel")
                           ])
            self.status_label.config(text="🚧 Feature coming soon")
        elif any(word in user_input.lower() for word in ['department', 'dept']):
            self.add_message("Department filtering is coming soon! 🏢\n\nFor now, I can help you with time-based filtering or senior personnel filtering. Which would you prefer?",
                           show_options=True,
                           options=[
                               ("🕐 Filter by time", "I want to filter by time"),
                               ("👔 Filter senior personnel", "I want to filter senior personnel")
                           ])
            self.status_label.config(text="🚧 Feature coming soon")
        else:
            self.add_message("I'm not sure what type of filtering you'd like. Let me show you the available options:",
                           show_options=True,
                           options=[
                               ("🕐 Filter by Time", "I want to filter by time"),
                               ("👔 Filter Senior Personnel", "I want to filter senior personnel"),
                               ("👤 Filter by Authorization", "I want to filter by Authorization"),
                               ("🏢 Filter by Department", "I want to filter by department")
                           ])
           
    def handle_time_filtering(self, user_input):
        """Handle time filtering logic"""
        start_time, end_time, filter_type = extract_time_range_and_type(user_input)
        self.state['start_time'] = start_time
        self.state['end_time'] = end_time
        self.state['time_filter_type'] = filter_type
        
        if not start_time:
            self.state['mode'] = 'awaiting_start'
            self.add_message("I need the start time. Please tell me when you want the time range to begin.\n\nExamples: '9am', '09:00', '8:30am'")
            self.status_label.config(text="⏰ Waiting for start time")
            return
            
        if not end_time:
            self.state['mode'] = 'awaiting_end'
            self.add_message("I need the end time. Please tell me when you want the time range to end.\n\nExamples: '5pm', '17:00', '6:30pm'")
            self.status_label.config(text="⏰ Waiting for end time")
            return
            
        # Process complete request
        self.filter_and_respond_time(start_time, end_time, filter_type)
      
    def handle_senior_filtering(self, user_input):
        """Handle senior personnel filtering logic"""
        user_input_lower = user_input.lower()
        
        if 'default' in user_input_lower or 'standard' in user_input_lower:
            # Use default keywords
            self.filter_and_respond_senior(None)
        elif 'custom' in user_input_lower or 'specify' in user_input_lower:
            self.add_message("Please specify the senior titles you want to search for, separated by commas.\n\nExample: 'manager, director, team lead, supervisor'")
            self.status_label.config(text="⌨️ Waiting for custom titles")
            self.state['mode'] = 'awaiting_custom_titles'
        else:
            # Try to extract keywords from the input
            potential_keywords = self.extract_senior_keywords(user_input)
            if potential_keywords:
                self.filter_and_respond_senior(potential_keywords)
            else:
                # Use default if no specific keywords found
                self.filter_and_respond_senior(None)
                
    def extract_senior_keywords(self, user_input):
        """Extract potential senior keywords from user input"""
        common_titles = ['manager', 'director', 'senior', 'vp', 'ceo', 'cfo', 'cto', 
                        'supervisor', 'lead', 'head', 'chief', 'executive', 'president']
        
        # Normalize input and split using commas and 'and'
        parts = re.split(r',|\band\b', user_input.lower())

        found_keywords = []
        for part in parts:
            word = part.strip().rstrip('s')  # remove plural 's'
            if word in common_titles:
                found_keywords.append(word)
        
        return found_keywords if found_keywords else None
    

        
    def handle_awaiting_start(self, user_input):
        """Handle start time input"""
        start_time = parse_time_string(user_input)
        if not start_time:
            self.add_message("I couldn't understand that time format. 😅\n\nPlease try formats like:\n• 9am\n• 09:00\n• 8:30am")
            return
            
        self.state['start_time'] = start_time
        if not self.state['end_time']:
            self.state['mode'] = 'awaiting_end'
            self.add_message(f"Got it! Start time: {start_time} ✅\n\nNow, what's the end time?")
            self.status_label.config(text="⏰ Waiting for end time")
            return
            
        self.filter_and_respond_time(self.state['start_time'], self.state['end_time'], self.state['time_filter_type'])
        
    def handle_awaiting_end(self, user_input):
        """Handle end time input"""
        end_time = parse_time_string(user_input)
        if not end_time:
            self.add_message("I couldn't understand that time format. 😅\n\nPlease try formats like:\n• 5pm\n• 17:00\n• 6:30pm")
            return
            
        self.state['end_time'] = end_time
        if not self.state['start_time']:
            self.state['mode'] = 'awaiting_start'
            self.add_message(f"Got it! End time: {end_time} ✅\n\nNow, what's the start time?")
            self.status_label.config(text="⏰ Waiting for start time")
            return
            
        self.filter_and_respond_time(self.state['start_time'], self.state['end_time'], self.state['time_filter_type'])
    
    def filter_and_respond_senior(self, custom_keywords=None):
        try:
            self.status_label.config(text="👔 Filtering for senior personnel...")
            self.root.update()

            # Use custom keywords if provided, otherwise default
            if custom_keywords:
                senior_titles = custom_keywords
            else:
                senior_titles = ['manager', 'senior', 'director', 'vp', 'cfo', 'ceo']

            filtered_df = find_senior_personnel_entries(self.df, title_column='Title', senior_keywords=senior_titles)

            if filtered_df.empty:
                self.add_message("⚠️ No senior personnel records found with the given criteria.\nWould you like to try different titles?",
                                show_options=True,
                                options=[
                                    ("🔄 Try default titles", "Use default senior titles"),
                                    ("🔧 Specify custom titles", "I want to specify custom titles")
                                ])
                self.status_label.config(text="⚠️ No matches found")
            else:
                output_file_path = os.path.join(os.path.dirname(self.file_path), "Filtered_SeniorPersonnel.xlsx")
                filtered_df.to_excel(output_file_path, index=False)

                self.add_message(
                    f"✅ Filter complete!\n\n"
                    f"• Senior titles used: {', '.join(senior_titles)}\n"
                    f"• Records found: {len(filtered_df)}\n"
                    f"• Saved to: Filtered_SeniorPersonnel.xlsx\n\n"
                    f"Want to apply another filter?",
                    show_options=True,
                    options=[
                        ("🔄 Filter again", "I want to filter data again"),
                        ("✨ New filter type", "I want different filtering")
                    ]
                )
                self.status_label.config(text="✅ Filter completed successfully")

        except Exception as e:
            self.add_message(f"❌ Error during senior personnel filtering: {str(e)}")
            self.status_label.config(text="❌ Error occurred")

        # Reset for next task
        self.reset_state()
        self.state['mode'] = 'filter_selection'
        self.entry.focus_set()


    def filter_and_respond_time(self, start_time, end_time, filter_type):
        """Process the filtering and respond with results"""
        try:
            self.status_label.config(text="⚙️ Filtering data...")
            self.root.update()
            
            filtered, err = filter_by_time_range(self.df, start_time, end_time, filter_type)
            
            if err:
                self.add_message(f"❌ {err}")
                self.status_label.config(text="❌ Error occurred")
            elif filtered.empty:
                self.add_message("⚠️ No records match your filter criteria.\n\nWould you like to try a different time range?",
                               show_options=True,
                               options=[("🔄 Try again", "I want to filter by time")])
                self.status_label.config(text="⚠️ No results found")
            else:
                output_file_path = os.path.join(os.path.dirname(self.file_path), "FilteredOutput.xlsx")
                filtered.to_excel(output_file_path, index=False)
                
                filter_desc = "inside" if filter_type == "inside" else "outside"
                self.add_message(
                    f"✅ Success! Filtered data saved!\n\n"
                    f"📊 **Results Summary:**\n"
                    f"• Time range: {start_time} to {end_time}\n"
                    f"• Filter type: {filter_desc} time range\n"
                    f"• Records found: {len(filtered)}\n"
                    f"• File saved: FilteredOutput.xlsx\n\n"
                    f"Would you like to perform another filter?",
                    show_options=True,
                    options=[
                        ("🔄 Filter again", "I want to filter data again"),
                        ("✨ New filter type", "I want different filtering")
                    ]
                )
                self.status_label.config(text="✅ Filter completed successfully")
                
        except Exception as e:
            self.add_message(f"❌ An error occurred: {str(e)}")
            self.status_label.config(text="❌ Error occurred")
            
        # Reset state for next operation
        self.reset_state()
        self.state['mode'] = 'filter_selection'
        self.entry.focus_set()
        
    def run(self):
        # Initial greeting with delay for better UX
        self.root.after(1500, lambda: self.add_message(
            "👋 Hello! I'm your Smart Data Filter Assistant!\n\n"
            "I can help you filter and analyze your data in multiple ways. "
            "Just tell me what you're looking for, and I'll guide you through the process.\n\n"
            "💡 **Try saying something like:**\n"
            "• 'I want to filter by time'\n"
            "• 'Show me data between 9am and 5pm'\n"
            "• 'Filter employees by working hours'\n"
            "• 'Help me filter data'"
        ))
        
        self.entry.focus_set()
        self.root.mainloop()

def run_chatbot_ui():
    app = SmartFilterBot()
    app.run()

if __name__ == "__main__":
    run_chatbot_ui()