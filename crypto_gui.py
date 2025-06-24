import os
import sys
import ctypes
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.font import Font

# Add DLL directory
os.add_dll_directory(os.path.abspath(os.path.dirname(__file__)))

# Load the DLLs
key_gen_dll = ctypes.CDLL("./key_generation.dll")
signing_dll = ctypes.CDLL("./signing.dll")
verify_dll = ctypes.CDLL("./verification.dll")
x509_dll = ctypes.CDLL("./x509_ops.dll")

# Define function prototypes for key generation
key_gen_dll.generate_ecdsa_keypair.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
key_gen_dll.generate_ecdsa_keypair.restype = ctypes.c_int

key_gen_dll.generate_rsa_keypair.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p]
key_gen_dll.generate_rsa_keypair.restype = ctypes.c_int

key_gen_dll.generate_csr_c.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
key_gen_dll.generate_csr_c.restype = ctypes.c_int

key_gen_dll.generate_self_signed_certificate_c.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
key_gen_dll.generate_self_signed_certificate_c.restype = ctypes.c_int

# Define function prototypes for signing
signing_dll.sign_ecdsa_c.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
signing_dll.sign_ecdsa_c.restype = ctypes.c_int

signing_dll.sign_rsapss_c.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
signing_dll.sign_rsapss_c.restype = ctypes.c_int

# Define function prototypes for verification
verify_dll.verify_ecdsa_c.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
verify_dll.verify_ecdsa_c.restype = ctypes.c_int

verify_dll.verify_rsapss_c.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
verify_dll.verify_rsapss_c.restype = ctypes.c_int

# Define function prototypes for X509 operations
x509_dll.extract_pubkey_from_cert_c.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
x509_dll.extract_pubkey_from_cert_c.restype = ctypes.c_int

x509_dll.verify_signature_with_cert_c.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
x509_dll.verify_signature_with_cert_c.restype = ctypes.c_int

# Modern light theme colors
COLORS = {
    'bg': '#ffffff',           # Pure white background
    'surface': '#f8fafc',      # Very light gray surface
    'primary': '#0ea5e9',      # Sky blue
    'primary_dark': '#0284c7', # Darker sky blue
    'secondary': '#f472b6',    # Pink
    'success': '#22c55e',      # Green
    'error': '#ef4444',        # Red
    'text': '#0f172a',         # Very dark blue gray
    'text_secondary': '#64748b',# Medium blue gray
    'border': '#e2e8f0',       # Light gray border
    'hover': '#f1f5f9',        # Very light blue gray hover
    'disabled': '#cbd5e1'      # Disabled state
}

STYLES = {
    'font': {
        'family': 'Segoe UI',  # Modern system font
        'sizes': {
            'title': 32,
            'subtitle': 24,
            'header': 16,
            'body': 12
        }
    },
    'spacing': {
        'xs': 4,
        'sm': 8,
        'md': 16,
        'lg': 24,
        'xl': 32
    },
    'radius': 8,
    'shadow': '0 2px 4px rgba(0, 0, 0, 0.1)'  # Subtle shadow
}

class ModernButton(ttk.Button):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.bind('<Enter>', lambda e: self.state(['active']))
        self.bind('<Leave>', lambda e: self.state(['!active']))

class CryptoGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CryptoSuite")
        self.geometry("1280x800")
        self.configure(bg=COLORS['bg'])
        self.minsize(1000, 700)
        
        # Configure fonts
        self.fonts = {
            'title': Font(family=STYLES['font']['family'], 
                         size=STYLES['font']['sizes']['title'], 
                         weight='bold'),
            'subtitle': Font(family=STYLES['font']['family'],
                           size=STYLES['font']['sizes']['subtitle'],
                           weight='bold'),
            'header': Font(family=STYLES['font']['family'],
                         size=STYLES['font']['sizes']['header'],
                         weight='bold'),
            'body': Font(family=STYLES['font']['family'],
                       size=STYLES['font']['sizes']['body'])
        }
        
        # Configure styles
        self._configure_styles()
        
        # Create main layout
        self._create_header()
        self._create_sidebar()
        self._create_main_content()
        
    def _configure_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Frame styles
        style.configure('Main.TFrame',
                       background=COLORS['bg'])
        
        style.configure('Surface.TFrame',
                       background=COLORS['surface'],
                       relief='solid',
                       borderwidth=1,
                       bordercolor=COLORS['border'])
        
        # Label styles
        style.configure('Title.TLabel',
                       background=COLORS['bg'],
                       foreground=COLORS['primary'],
                       font=self.fonts['title'])
        
        style.configure('Subtitle.TLabel',
                       background=COLORS['bg'],
                       foreground=COLORS['text'],
                       font=self.fonts['subtitle'])
        
        style.configure('Header.TLabel',
                       background=COLORS['surface'],
                       foreground=COLORS['text'],
                       font=self.fonts['header'])
        
        style.configure('Body.TLabel',
                       background=COLORS['surface'],
                       foreground=COLORS['text'],
                       font=self.fonts['body'])
        
        # Button styles
        style.configure('Primary.TButton',
                       background=COLORS['primary'],
                       foreground='white',
                       font=self.fonts['body'],
                       padding=STYLES['spacing']['md'],
                       borderwidth=0,
                       relief='flat')
        
        style.map('Primary.TButton',
                 background=[('active', COLORS['primary_dark']),
                           ('disabled', COLORS['disabled'])],
                 foreground=[('disabled', COLORS['text_secondary'])])
        
        style.configure('Secondary.TButton',
                       background=COLORS['surface'],
                       foreground=COLORS['text'],
                       font=self.fonts['body'],
                       padding=STYLES['spacing']['md'],
                       borderwidth=1,
                       bordercolor=COLORS['border'])
        
        style.map('Secondary.TButton',
                 background=[('active', COLORS['hover']),
                           ('disabled', COLORS['disabled'])],
                 foreground=[('disabled', COLORS['text_secondary'])])
        
        # Entry styles
        style.configure('TEntry',
                       background=COLORS['bg'],
                       foreground=COLORS['text'],
                       fieldbackground=COLORS['bg'],
                       insertcolor=COLORS['text'],
                       borderwidth=1,
                       bordercolor=COLORS['border'],
                       padding=STYLES['spacing']['sm'],
                       font=self.fonts['body'])
        
        style.map('TEntry',
                 fieldbackground=[('disabled', COLORS['disabled'])],
                 foreground=[('disabled', COLORS['text_secondary'])])
        
        # Radiobutton styles
        style.configure('TRadiobutton',
                       background=COLORS['surface'],
                       foreground=COLORS['text'],
                       font=self.fonts['body'])
        
        style.map('TRadiobutton',
                 background=[('active', COLORS['hover']),
                           ('disabled', COLORS['disabled'])],
                 foreground=[('disabled', COLORS['text_secondary'])])
        
        # Combobox styles
        style.configure('TCombobox',
                       background=COLORS['bg'],
                       foreground=COLORS['text'],
                       fieldbackground=COLORS['bg'],
                       selectbackground=COLORS['primary'],
                       selectforeground='white',
                       padding=STYLES['spacing']['sm'],
                       font=self.fonts['body'])
        
        style.map('TCombobox',
                 fieldbackground=[('readonly', COLORS['bg']),
                                ('disabled', COLORS['disabled'])],
                 foreground=[('disabled', COLORS['text_secondary'])])
        
    def _create_header(self):
        header = ttk.Frame(self, style='Main.TFrame')
        header.pack(fill='x', padx=STYLES['spacing']['xl'], 
                   pady=STYLES['spacing']['lg'])
        
        ttk.Label(header,
                 text="CryptoSuite",
                 style='Title.TLabel').pack(side='left')
        
    def _create_sidebar(self):
        sidebar = ttk.Frame(self, style='Surface.TFrame')
        sidebar.pack(side='left', fill='y', padx=STYLES['spacing']['lg'],
                    pady=STYLES['spacing']['lg'])
        
        # Navigation buttons
        self.current_view = tk.StringVar(value="keys")
        
        nav_items = [
            ("Key Generation", "keys", "🔑"),
            ("Sign & Verify", "sign", "✍"),
            ("Certificates", "cert", "📜"),
            ("X.509 Operations", "x509", "🔒")
        ]
        
        for text, value, icon in nav_items:
            btn = ttk.Button(sidebar,
                           text=f"{icon} {text}",
                           style='Secondary.TButton',
                           command=lambda v=value: self._switch_view(v))
            btn.pack(fill='x', pady=(0, STYLES['spacing']['sm']))
            
    def _create_main_content(self):
        self.main_content = ttk.Frame(self, style='Surface.TFrame')
        self.main_content.pack(side='left', fill='both', expand=True,
                             padx=(0, STYLES['spacing']['lg']),
                             pady=STYLES['spacing']['lg'])
        
        # Create all views
        self.views = {
            'keys': self._create_keys_view(),
            'sign': self._create_sign_view(),
            'cert': self._create_cert_view(),
            'x509': self._create_x509_view()
        }
        
        # Show default view
        self._switch_view('keys')
        
    def _create_section(self, parent, title=""):
        section = ttk.Frame(parent, style='Surface.TFrame')
        section.pack(fill='x', pady=(0, STYLES['spacing']['lg']))
        
        if title:
            ttk.Label(section,
                     text=title,
                     style='Header.TLabel').pack(anchor='w',
                                               padx=STYLES['spacing']['lg'],
                                               pady=STYLES['spacing']['md'])
        
        content = ttk.Frame(section, style='Surface.TFrame')
        content.pack(fill='x', padx=STYLES['spacing']['lg'],
                    pady=(0, STYLES['spacing']['lg']))
        
        return content
        
    def _create_input_group(self, parent, label, var, browse=False, save=False):
        frame = ttk.Frame(parent, style='Surface.TFrame')
        frame.pack(fill='x', pady=STYLES['spacing']['xs'])
        
        ttk.Label(frame,
                 text=label,
                 style='Body.TLabel').pack(side='left',
                                         padx=(0, STYLES['spacing']['md']))
        
        entry = ttk.Entry(frame, textvariable=var)
        entry.pack(side='left', fill='x', expand=True,
                  padx=(0, STYLES['spacing']['md']))
        
        if browse:
            ModernButton(frame,
                      text="Browse",
                      style='Secondary.TButton',
                      command=lambda: self._select_file(var, save)
                      ).pack(side='left')
            
    def _switch_view(self, view_name):
        # Hide all views
        for view in self.views.values():
            view.pack_forget()
            
        # Show selected view
        self.views[view_name].pack(fill='both', expand=True)
        self.current_view.set(view_name)
        
    def _create_keys_view(self):
        view = ttk.Frame(self.main_content, style='Surface.TFrame')
        
        # Title
        ttk.Label(view,
                 text="Generate Cryptographic Key Pairs",
                 style='Subtitle.TLabel').pack(anchor='w',
                                            pady=(0, STYLES['spacing']['xl']))
        
        # Algorithm selection
        algo_section = self._create_section(view, "Choose Algorithm")
        
        self.keypair_algo_var = tk.StringVar(value="ECDSA")
        ttk.Radiobutton(algo_section,
                       text="ECDSA",
                       variable=self.keypair_algo_var,
                       value="ECDSA",
                       command=self._on_keypair_algo_change
                       ).pack(side='left', padx=STYLES['spacing']['md'])
        
        ttk.Radiobutton(algo_section,
                       text="RSA",
                       variable=self.keypair_algo_var,
                       value="RSA",
                       command=self._on_keypair_algo_change
                       ).pack(side='left', padx=STYLES['spacing']['md'])
        
        # Parameters
        params_section = self._create_section(view, "Algorithm Parameters")
        self.keypair_params_frame = ttk.Frame(params_section, style='Surface.TFrame')
        self.keypair_params_frame.pack(fill='x')
        
        # File paths
        files_section = self._create_section(view, "Output Files")
        self.keypair_priv_var = tk.StringVar()
        self.keypair_pub_var = tk.StringVar()
        self._create_input_group(files_section, "Private Key:", self.keypair_priv_var,
                               browse=True, save=True)
        self._create_input_group(files_section, "Public Key:", self.keypair_pub_var,
                               browse=True, save=True)
        
        # Generate button
        action_section = self._create_section(view)
        ModernButton(action_section,
                  text="Generate Key Pair",
                  style='Primary.TButton',
                  command=self._on_generate_keypair
                  ).pack(fill='x')
        
        # Show default parameters
        self._show_ecdsa_params()
        
        return view
        
    def _create_sign_view(self):
        view = ttk.Frame(self.main_content, style='Surface.TFrame')
        
        ttk.Label(view,
                 text="Sign & Verify Messages",
                 style='Subtitle.TLabel').pack(anchor='w',
                                            pady=(0, STYLES['spacing']['xl']))
        
        # Mode selection
        mode_section = self._create_section(view, "Operation Mode")
        
        self.sign_mode_var = tk.StringVar(value="sign")
        ttk.Radiobutton(mode_section,
                       text="Sign Message",
                       variable=self.sign_mode_var,
                       value="sign",
                       command=self._on_sign_mode_change
                       ).pack(side='left', padx=STYLES['spacing']['md'])
        
        ttk.Radiobutton(mode_section,
                       text="Verify Signature",
                       variable=self.sign_mode_var,
                       value="verify",
                       command=self._on_sign_mode_change
                       ).pack(side='left', padx=STYLES['spacing']['md'])
        
        # Algorithm selection
        algo_section = self._create_section(view, "Algorithm")
        
        self.sign_algo_var = tk.StringVar(value="ECDSA")
        ttk.Radiobutton(algo_section,
                       text="ECDSA",
                       variable=self.sign_algo_var,
                       value="ECDSA"
                       ).pack(side='left', padx=STYLES['spacing']['md'])
        
        ttk.Radiobutton(algo_section,
                       text="RSA-PSS",
                       variable=self.sign_algo_var,
                       value="RSA-PSS"
                       ).pack(side='left', padx=STYLES['spacing']['md'])
        
        # Dynamic content
        self.sign_verify_content = self._create_section(view)
        
        # Show default mode
        self._show_sign_mode()
        
        return view
        
    def _create_cert_view(self):
        view = ttk.Frame(self.main_content, style='Surface.TFrame')
        
        ttk.Label(view,
                 text="Certificate Generation",
                 style='Subtitle.TLabel').pack(anchor='w',
                                            pady=(0, STYLES['spacing']['xl']))
        
        # Input files
        files_section = self._create_section(view, "Input Files")
        self.cert_csr_var = tk.StringVar()
        self.cert_priv_var = tk.StringVar()
        self.cert_out_var = tk.StringVar()
        self._create_input_group(files_section, "CSR Path:", self.cert_csr_var, browse=True)
        self._create_input_group(files_section, "Private Key:", self.cert_priv_var, browse=True)
        self._create_input_group(files_section, "Certificate:", self.cert_out_var,
                               browse=True, save=True)
        
        # Validity period
        validity_section = self._create_section(view, "Validity Period")
        days_frame = ttk.Frame(validity_section, style='Surface.TFrame')
        days_frame.pack(fill='x')
        
        ttk.Label(days_frame,
                 text="Valid for (days):",
                 style='Body.TLabel').pack(side='left',
                                        padx=(0, STYLES['spacing']['md']))
        
        self.cert_days_var = tk.StringVar(value="365")
        ttk.Entry(days_frame,
                 textvariable=self.cert_days_var,
                 width=10).pack(side='left')
        
        # Generate button
        action_section = self._create_section(view)
        ModernButton(action_section,
                  text="Generate Certificate",
                  style='Primary.TButton',
                  command=self._on_generate_cert
                  ).pack(fill='x')
        
        return view
        
    def _create_x509_view(self):
        view = ttk.Frame(self.main_content, style='Surface.TFrame')
        
        ttk.Label(view,
                 text="X.509 Certificate Operations",
                 style='Subtitle.TLabel').pack(anchor='w',
                                            pady=(0, STYLES['spacing']['xl']))
        
        # Extract public key section
        extract_section = self._create_section(view, "Extract Public Key")
        
        self.x509_cert_var = tk.StringVar()
        self.x509_pub_var = tk.StringVar()
        self._create_input_group(extract_section, "Certificate:", self.x509_cert_var, browse=True)
        self._create_input_group(extract_section, "Public Key:", self.x509_pub_var,
                               browse=True, save=True)
        
        ModernButton(extract_section,
                  text="Extract Public Key",
                  style='Primary.TButton',
                  command=self._on_extract_pubkey
                  ).pack(fill='x', pady=(STYLES['spacing']['md'], 0))
        
        # Verify section
        verify_section = self._create_section(view, "Verify with Certificate")
        
        self.x509_msg_var = tk.StringVar()
        self.x509_sig_var = tk.StringVar()
        self._create_input_group(verify_section, "Message:", self.x509_msg_var, browse=True)
        self._create_input_group(verify_section, "Signature:", self.x509_sig_var, browse=True)
        
        ModernButton(verify_section,
                  text="Verify Signature",
                  style='Primary.TButton',
                  command=self._on_verify_with_cert
                  ).pack(fill='x', pady=(STYLES['spacing']['md'], 0))
        
        return view

    # Event handlers
    def _on_keypair_algo_change(self):
        if self.keypair_algo_var.get() == "ECDSA":
            self._show_ecdsa_params()
        else:
            self._show_rsa_params()

    def _on_sign_mode_change(self):
        if self.sign_mode_var.get() == "sign":
            self._show_sign_mode()
        else:
            self._show_verify_mode()

    def _on_generate_keypair(self):
        algo = self.keypair_algo_var.get()
        priv = self.keypair_priv_var.get().strip()
        pub = self.keypair_pub_var.get().strip()

        if not all([priv, pub]):
            messagebox.showerror("Error", "Please fill in all paths.")
            return

        if algo == "ECDSA":
            curve = self.curve_var.get()
            if py_generate_ecdsa_keypair(curve, priv, pub):
                messagebox.showinfo("Success", "ECDSA key pair generated successfully.")
            else:
                messagebox.showerror("Error", "Failed to generate ECDSA key pair.")
        else:
            try:
                bits = int(self.key_size_var.get())
                if py_generate_rsa_keypair(bits, priv, pub):
                    messagebox.showinfo("Success", "RSA key pair generated successfully.")
                else:
                    messagebox.showerror("Error", "Failed to generate RSA key pair.")
            except ValueError:
                messagebox.showerror("Error", "Invalid key size.")

    def _on_sign(self):
        algo = self.sign_algo_var.get()
        priv = self.sign_key_var.get().strip()
        msg = self.sign_msg_var.get().strip()
        sig = self.sign_sig_var.get().strip()

        if not all([priv, msg, sig]):
            messagebox.showerror("Error", "Please fill in all paths.")
            return

        if algo == "ECDSA":
            if py_sign_ecdsa(priv, msg, sig):
                messagebox.showinfo("Success", "Message signed successfully with ECDSA.")
            else:
                messagebox.showerror("Error", "Failed to sign message with ECDSA.")
        else:
            if py_sign_rsapss(priv, msg, sig):
                messagebox.showinfo("Success", "Message signed successfully with RSA-PSS.")
            else:
                messagebox.showerror("Error", "Failed to sign message with RSA-PSS.")

    def _on_verify(self):
        algo = self.sign_algo_var.get()
        pub = self.verify_key_var.get().strip()
        msg = self.verify_msg_var.get().strip()
        sig = self.verify_sig_var.get().strip()

        if not all([pub, msg, sig]):
            messagebox.showerror("Error", "Please fill in all paths.")
            return

        if algo == "ECDSA":
            if py_verify_ecdsa(pub, msg, sig):
                messagebox.showinfo("Success", "ECDSA signature verified successfully.")
            else:
                messagebox.showerror("Error", "ECDSA signature verification failed.")
        else:
            if py_verify_rsapss(pub, msg, sig):
                messagebox.showinfo("Success", "RSA-PSS signature verified successfully.")
            else:
                messagebox.showerror("Error", "RSA-PSS signature verification failed.")

    def _on_generate_cert(self):
        csr = self.cert_csr_var.get().strip()
        priv = self.cert_priv_var.get().strip()
        cert = self.cert_out_var.get().strip()
        
        try:
            days = int(self.cert_days_var.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid number of days.")
            return

        if not all([csr, priv, cert]):
            messagebox.showerror("Error", "Please fill in all paths.")
            return

        if py_generate_self_signed_certificate(csr, priv, cert, days):
            messagebox.showinfo("Success", "Certificate generated successfully.")
        else:
            messagebox.showerror("Error", "Failed to generate certificate.")

    def _on_extract_pubkey(self):
        cert = self.x509_cert_var.get().strip()
        pub = self.x509_pub_var.get().strip()

        if not all([cert, pub]):
            messagebox.showerror("Error", "Please fill in all paths.")
            return

        if py_extract_pubkey_from_cert(cert, pub):
            messagebox.showinfo("Success", "Public key extracted successfully.")
        else:
            messagebox.showerror("Error", "Failed to extract public key.")

    def _on_verify_with_cert(self):
        cert = self.x509_cert_var.get().strip()
        msg = self.x509_msg_var.get().strip()
        sig = self.x509_sig_var.get().strip()

        if not all([cert, msg, sig]):
            messagebox.showerror("Error", "Please fill in all paths.")
            return

        if py_verify_signature_with_cert(cert, msg, sig):
            messagebox.showinfo("Success", "Signature verified successfully.")
        else:
            messagebox.showerror("Error", "Signature verification failed.")

    def _select_file(self, var: tk.StringVar, save: bool = False):
        """Enhanced file dialog with better styling"""
        if save:
            path = filedialog.asksaveasfilename(
                defaultextension="",
                filetypes=[
                    ("PEM files", "*.pem"),
                    ("DER files", "*.der"),
                    ("All files", "*.*")
                ]
            )
        else:
            path = filedialog.askopenfilename(
                filetypes=[
                    ("PEM files", "*.pem"),
                    ("DER files", "*.der"),
                    ("All files", "*.*")
                ]
            )
        if path:
            var.set(path)

    def _show_ecdsa_params(self):
        """Show ECDSA specific parameters"""
        for widget in self.keypair_params_frame.winfo_children():
            widget.destroy()
            
        ttk.Label(self.keypair_params_frame,
                 text="Curve:",
                 style='Body.TLabel').pack(side='left',
                                        padx=(0, STYLES['spacing']['md']))
        
        self.curve_var = tk.StringVar(value="prime256v1")
        curves = ["prime256v1", "secp384r1", "secp521r1"]
        combo = ttk.Combobox(self.keypair_params_frame,
                           textvariable=self.curve_var,
                           values=curves,
                           state="readonly",
                           width=20)
        combo.pack(side='left')

    def _show_rsa_params(self):
        """Show RSA specific parameters"""
        for widget in self.keypair_params_frame.winfo_children():
            widget.destroy()
            
        ttk.Label(self.keypair_params_frame,
                 text="Key Size (bits):",
                 style='Body.TLabel').pack(side='left',
                                        padx=(0, STYLES['spacing']['md']))
        
        self.key_size_var = tk.StringVar(value="2048")
        sizes = ["1024", "2048", "4096"]
        combo = ttk.Combobox(self.keypair_params_frame,
                           textvariable=self.key_size_var,
                           values=sizes,
                           state="readonly",
                           width=10)
        combo.pack(side='left')

    def _show_sign_mode(self):
        """Show signing mode interface"""
        for widget in self.sign_verify_content.winfo_children():
            widget.destroy()
            
        self.sign_key_var = tk.StringVar()
        self.sign_msg_var = tk.StringVar()
        self.sign_sig_var = tk.StringVar()
        
        self._create_input_group(self.sign_verify_content,
                               "Private Key:",
                               self.sign_key_var,
                               browse=True)
        self._create_input_group(self.sign_verify_content,
                               "Message:",
                               self.sign_msg_var,
                               browse=True)
        self._create_input_group(self.sign_verify_content,
                               "Signature:",
                               self.sign_sig_var,
                               browse=True,
                               save=True)
        
        ModernButton(self.sign_verify_content,
                  text="Sign Message",
                  style='Primary.TButton',
                  command=self._on_sign
                  ).pack(fill='x',
                        pady=(STYLES['spacing']['md'], 0))

    def _show_verify_mode(self):
        """Show verification mode interface"""
        for widget in self.sign_verify_content.winfo_children():
            widget.destroy()
            
        self.verify_key_var = tk.StringVar()
        self.verify_msg_var = tk.StringVar()
        self.verify_sig_var = tk.StringVar()
        
        self._create_input_group(self.sign_verify_content,
                               "Public Key:",
                               self.verify_key_var,
                               browse=True)
        self._create_input_group(self.sign_verify_content,
                               "Message:",
                               self.verify_msg_var,
                               browse=True)
        self._create_input_group(self.sign_verify_content,
                               "Signature:",
                               self.verify_sig_var,
                               browse=True)
        
        ModernButton(self.sign_verify_content,
                  text="Verify Signature",
                  style='Primary.TButton',
                  command=self._on_verify
                  ).pack(fill='x',
                        pady=(STYLES['spacing']['md'], 0))

# Python wrapper functions for DLL calls
def py_generate_ecdsa_keypair(curve: str, priv_path: str, pub_path: str) -> bool:
    return bool(key_gen_dll.generate_ecdsa_keypair(
        curve.encode(),
        priv_path.encode(),
        pub_path.encode()
    ))

def py_generate_rsa_keypair(bits: int, priv_path: str, pub_path: str) -> bool:
    return bool(key_gen_dll.generate_rsa_keypair(
        bits,
        priv_path.encode(),
        pub_path.encode()
    ))

def py_sign_ecdsa(priv_path: str, msg_path: str, sig_path: str) -> bool:
    return bool(signing_dll.sign_ecdsa_c(
        priv_path.encode(),
        msg_path.encode(),
        sig_path.encode()
    ))

def py_sign_rsapss(priv_path: str, msg_path: str, sig_path: str) -> bool:
    return bool(signing_dll.sign_rsapss_c(
        priv_path.encode(),
        msg_path.encode(),
        sig_path.encode()
    ))

def py_verify_ecdsa(pub_path: str, msg_path: str, sig_path: str) -> bool:
    return bool(verify_dll.verify_ecdsa_c(
        pub_path.encode(),
        msg_path.encode(),
        sig_path.encode()
    ))

def py_verify_rsapss(pub_path: str, msg_path: str, sig_path: str) -> bool:
    return bool(verify_dll.verify_rsapss_c(
        pub_path.encode(),
        msg_path.encode(),
        sig_path.encode()
    ))

def py_generate_self_signed_certificate(csr_path: str, priv_path: str,
                                      cert_path: str, days: int) -> bool:
    return bool(key_gen_dll.generate_self_signed_certificate_c(
        csr_path.encode(),
        priv_path.encode(),
        cert_path.encode(),
        days
    ))

def py_extract_pubkey_from_cert(cert_path: str, pub_path: str) -> bool:
    return bool(x509_dll.extract_pubkey_from_cert_c(
        cert_path.encode(),
        pub_path.encode()
    ))

def py_verify_signature_with_cert(cert_path: str, msg_path: str,
                                sig_path: str) -> bool:
    return bool(x509_dll.verify_signature_with_cert_c(
        cert_path.encode(),
        msg_path.encode(),
        sig_path.encode()
    ))

if __name__ == "__main__":
    app = CryptoGUI()
    app.mainloop() 