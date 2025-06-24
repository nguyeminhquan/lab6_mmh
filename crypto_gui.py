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

# Custom styles and colors
COLORS = {
    'bg': '#f0f0f0',
    'primary': '#2196F3',
    'primary_dark': '#1976D2',
    'success': '#4CAF50',
    'error': '#f44336',
    'text': '#212121',
    'text_secondary': '#757575'
}

STYLES = {
    'font_family': 'Segoe UI',
    'default_size': 10,
    'header_size': 12,
    'button_padding': 10,
    'entry_padding': 5,
    'container_padding': 20
}

class ModernButton(ttk.Button):
    """Custom button class with hover effect"""
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.bind('<Enter>', self._on_enter)
        self.bind('<Leave>', self._on_leave)
        self.defaultStyle = kwargs.get('style', '')

    def _on_enter(self, e):
        if self.defaultStyle:
            self['style'] = f'{self.defaultStyle}.TButton.Hover'
        else:
            self['style'] = 'Hover.TButton'

    def _on_leave(self, e):
        self['style'] = self.defaultStyle if self.defaultStyle else 'TButton'

# Python wrapper functions
def py_generate_ecdsa_keypair(curve_name: str, priv_path: str, pub_path: str) -> bool:
    return bool(key_gen_dll.generate_ecdsa_keypair(
        curve_name.encode("utf-8"),
        priv_path.encode("utf-8"),
        pub_path.encode("utf-8")
    ))

def py_generate_rsa_keypair(bits: int, priv_path: str, pub_path: str) -> bool:
    return bool(key_gen_dll.generate_rsa_keypair(
        bits,
        priv_path.encode("utf-8"),
        pub_path.encode("utf-8")
    ))

def py_generate_csr(priv_key_path: str, csr_path: str, country: str, state: str, org: str, common_name: str) -> bool:
    return bool(key_gen_dll.generate_csr_c(
        priv_key_path.encode("utf-8"),
        csr_path.encode("utf-8"),
        country.encode("utf-8"),
        state.encode("utf-8"),
        org.encode("utf-8"),
        common_name.encode("utf-8")
    ))

def py_generate_self_signed_certificate(csr_path: str, priv_key_path: str, cert_path: str, days: int) -> bool:
    return bool(key_gen_dll.generate_self_signed_certificate_c(
        csr_path.encode("utf-8"),
        priv_key_path.encode("utf-8"),
        cert_path.encode("utf-8"),
        days
    ))

def py_sign_ecdsa(priv_key_path: str, message_path: str, signature_path: str) -> bool:
    return bool(signing_dll.sign_ecdsa_c(
        priv_key_path.encode("utf-8"),
        message_path.encode("utf-8"),
        signature_path.encode("utf-8")
    ))

def py_sign_rsapss(priv_key_path: str, message_path: str, signature_path: str) -> bool:
    return bool(signing_dll.sign_rsapss_c(
        priv_key_path.encode("utf-8"),
        message_path.encode("utf-8"),
        signature_path.encode("utf-8")
    ))

def py_verify_ecdsa(pub_key_path: str, message_path: str, signature_path: str) -> bool:
    return bool(verify_dll.verify_ecdsa_c(
        pub_key_path.encode("utf-8"),
        message_path.encode("utf-8"),
        signature_path.encode("utf-8")
    ))

def py_verify_rsapss(pub_key_path: str, message_path: str, signature_path: str) -> bool:
    return bool(verify_dll.verify_rsapss_c(
        pub_key_path.encode("utf-8"),
        message_path.encode("utf-8"),
        signature_path.encode("utf-8")
    ))

def py_extract_pubkey_from_cert(cert_path: str, pubkey_path: str) -> bool:
    return bool(x509_dll.extract_pubkey_from_cert_c(
        cert_path.encode("utf-8"),
        pubkey_path.encode("utf-8")
    ))

def py_verify_signature_with_cert(cert_path: str, message_path: str, signature_path: str) -> bool:
    return bool(x509_dll.verify_signature_with_cert_c(
        cert_path.encode("utf-8"),
        message_path.encode("utf-8"),
        signature_path.encode("utf-8")
    ))

class CryptoGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Crypto Tool")
        self.geometry("1000x800")
        self.configure(bg=COLORS['bg'])
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure fonts
        self.default_font = Font(family=STYLES['font_family'], size=STYLES['default_size'])
        self.header_font = Font(family=STYLES['font_family'], size=STYLES['header_size'], weight="bold")
        
        # Configure styles
        self.style.configure('TFrame', background=COLORS['bg'])
        self.style.configure('TLabel', 
                           background=COLORS['bg'], 
                           font=self.default_font,
                           foreground=COLORS['text'])
        
        self.style.configure('Header.TLabel',
                           font=self.header_font,
                           foreground=COLORS['text'])
        
        # Button styles
        self.style.configure('TButton', 
                           padding=STYLES['button_padding'],
                           font=self.default_font,
                           background=COLORS['primary'])
        
        self.style.configure('Action.TButton',
                           font=self.header_font,
                           padding=STYLES['button_padding'],
                           background=COLORS['primary'])
        
        self.style.map('TButton',
                      background=[('active', COLORS['primary_dark'])],
                      foreground=[('active', 'white')])
        
        self.style.map('Action.TButton',
                      background=[('active', COLORS['primary_dark'])],
                      foreground=[('active', 'white')])
        
        # Entry style
        self.style.configure('TEntry', 
                           padding=STYLES['entry_padding'],
                           font=self.default_font)
        
        # Notebook style
        self.style.configure('TNotebook',
                           background=COLORS['bg'],
                           tabmargins=[2, 5, 2, 0])
        
        self.style.configure('TNotebook.Tab',
                           padding=[20, 10],
                           font=self.default_font)
        
        self.style.map('TNotebook.Tab',
                      background=[('selected', COLORS['primary'])],
                      foreground=[('selected', 'white')])
        
        # Create main container with padding
        self.main_container = ttk.Frame(self)
        self.main_container.pack(fill="both", expand=True, 
                               padx=STYLES['container_padding'], 
                               pady=STYLES['container_padding'])
        
        # Create and configure notebook
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill="both", expand=True)

        # Create tabs with modern styling
        self.tab_ecdsa = ttk.Frame(self.notebook, style='TFrame')
        self.tab_rsa = ttk.Frame(self.notebook, style='TFrame')
        self.tab_sign = ttk.Frame(self.notebook, style='TFrame')
        self.tab_verify = ttk.Frame(self.notebook, style='TFrame')
        self.tab_cert = ttk.Frame(self.notebook, style='TFrame')
        self.tab_x509 = ttk.Frame(self.notebook, style='TFrame')

        # Add tabs to notebook
        self.notebook.add(self.tab_ecdsa, text="ECDSA Keypair")
        self.notebook.add(self.tab_rsa, text="RSA Keypair")
        self.notebook.add(self.tab_sign, text="Sign")
        self.notebook.add(self.tab_verify, text="Verify")
        self.notebook.add(self.tab_cert, text="Certificate")
        self.notebook.add(self.tab_x509, text="X509 Ops")

        # Build tab contents
        self._build_ecdsa_tab()
        self._build_rsa_tab()
        self._build_sign_tab()
        self._build_verify_tab()
        self._build_cert_tab()
        self._build_x509_tab()

    def _create_labeled_entry(self, parent, label_text, var, browse=False, save=False, width=40):
        """Helper function to create a consistent label-entry-button group"""
        container = ttk.Frame(parent)
        container.pack(fill="x", padx=10, pady=5)
        
        label = ttk.Label(container, text=label_text)
        label.pack(side="left", padx=(0, 10))
        
        entry = ttk.Entry(container, textvariable=var, width=width)
        entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        if browse:
            browse_btn = ModernButton(container, text="Browse...", 
                                  command=lambda: self._select_file(var, save=save))
            browse_btn.pack(side="left")
        
        return container

    def _create_section_header(self, parent, text):
        """Helper function to create consistent section headers"""
        container = ttk.Frame(parent)
        container.pack(fill="x", padx=10, pady=(20, 10))
        
        header = ttk.Label(container, text=text, style='Header.TLabel')
        header.pack(side="left")
        
        separator = ttk.Separator(container, orient="horizontal")
        separator.pack(side="left", fill="x", expand=True, padx=(10, 0), pady=10)
        
        return container

    def _build_ecdsa_tab(self):
        frame = ttk.Frame(self.tab_ecdsa)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        self._create_section_header(frame, "ECDSA Key Generation")
        
        # Curve name with dropdown
        curve_container = ttk.Frame(frame)
        curve_container.pack(fill="x", padx=10, pady=5)
        ttk.Label(curve_container, text="Curve Name:").pack(side="left", padx=(0, 10))
        self.ecdsa_curve_var = tk.StringVar(value="prime256v1")
        curves = ["prime256v1", "secp384r1", "secp521r1"]
        curve_combo = ttk.Combobox(curve_container, 
                                 textvariable=self.ecdsa_curve_var,
                                 values=curves,
                                 width=30,
                                 state="readonly")
        curve_combo.pack(side="left", fill="x", expand=True)

        # File paths
        self.ecdsa_priv_var = tk.StringVar()
        self.ecdsa_pub_var = tk.StringVar()
        self._create_labeled_entry(frame, "Private Key Path:", self.ecdsa_priv_var, browse=True, save=True)
        self._create_labeled_entry(frame, "Public Key Path:", self.ecdsa_pub_var, browse=True, save=True)

        # Generate button
        btn_container = ttk.Frame(frame)
        btn_container.pack(fill="x", padx=10, pady=20)
        ModernButton(btn_container,
                  text="Generate ECDSA Keypair",
                  command=self._on_generate_ecdsa,
                  style='Action.TButton'
                  ).pack(expand=True)

    def _build_rsa_tab(self):
        frame = ttk.Frame(self.tab_rsa)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        self._create_section_header(frame, "RSA Key Generation")

        # Key size with dropdown
        size_container = ttk.Frame(frame)
        size_container.pack(fill="x", padx=10, pady=5)
        ttk.Label(size_container, text="Key Size (bits):").pack(side="left", padx=(0, 10))
        self.rsa_bits_var = tk.StringVar(value="2048")
        sizes = ["1024", "2048", "4096"]
        size_combo = ttk.Combobox(size_container,
                               textvariable=self.rsa_bits_var,
                               values=sizes,
                               width=10,
                               state="readonly")
        size_combo.pack(side="left")

        # File paths
        self.rsa_priv_var = tk.StringVar()
        self.rsa_pub_var = tk.StringVar()
        self._create_labeled_entry(frame, "Private Key Path:", self.rsa_priv_var, browse=True, save=True)
        self._create_labeled_entry(frame, "Public Key Path:", self.rsa_pub_var, browse=True, save=True)

        # Generate button
        btn_container = ttk.Frame(frame)
        btn_container.pack(fill="x", padx=10, pady=20)
        ModernButton(btn_container,
                  text="Generate RSA Keypair",
                  command=self._on_generate_rsa,
                  style='Action.TButton'
                  ).pack(expand=True)

    def _build_sign_tab(self):
        frame = ttk.Frame(self.tab_sign)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        self._create_section_header(frame, "Sign Message")

        # Algorithm selection with modern radio buttons
        algo_container = ttk.Frame(frame)
        algo_container.pack(fill="x", padx=10, pady=5)
        ttk.Label(algo_container, text="Algorithm:").pack(side="left", padx=(0, 10))
        self.sign_algo_var = tk.StringVar(value="ECDSA")
        
        radio_frame = ttk.Frame(algo_container)
        radio_frame.pack(side="left")
        
        ttk.Radiobutton(radio_frame,
                       text="ECDSA",
                       variable=self.sign_algo_var,
                       value="ECDSA"
                       ).pack(side="left", padx=10)
        
        ttk.Radiobutton(radio_frame,
                       text="RSA-PSS",
                       variable=self.sign_algo_var,
                       value="RSA-PSS"
                       ).pack(side="left", padx=10)

        # File paths
        self.sign_priv_var = tk.StringVar()
        self.sign_msg_var = tk.StringVar()
        self.sign_sig_var = tk.StringVar()
        self._create_labeled_entry(frame, "Private Key Path:", self.sign_priv_var, browse=True)
        self._create_labeled_entry(frame, "Message Path:", self.sign_msg_var, browse=True)
        self._create_labeled_entry(frame, "Signature Path:", self.sign_sig_var, browse=True, save=True)

        # Sign button
        btn_container = ttk.Frame(frame)
        btn_container.pack(fill="x", padx=10, pady=20)
        ModernButton(btn_container,
                  text="Sign Message",
                  command=self._on_sign,
                  style='Action.TButton'
                  ).pack(expand=True)

    def _build_verify_tab(self):
        frame = ttk.Frame(self.tab_verify)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        self._create_section_header(frame, "Verify Signature")

        # Algorithm selection
        algo_container = ttk.Frame(frame)
        algo_container.pack(fill="x", padx=10, pady=5)
        ttk.Label(algo_container, text="Algorithm:").pack(side="left", padx=(0, 10))
        self.verify_algo_var = tk.StringVar(value="ECDSA")
        
        radio_frame = ttk.Frame(algo_container)
        radio_frame.pack(side="left")
        
        ttk.Radiobutton(radio_frame,
                       text="ECDSA",
                       variable=self.verify_algo_var,
                       value="ECDSA"
                       ).pack(side="left", padx=10)
        
        ttk.Radiobutton(radio_frame,
                       text="RSA-PSS",
                       variable=self.verify_algo_var,
                       value="RSA-PSS"
                       ).pack(side="left", padx=10)

        # File paths
        self.verify_pub_var = tk.StringVar()
        self.verify_msg_var = tk.StringVar()
        self.verify_sig_var = tk.StringVar()
        self._create_labeled_entry(frame, "Public Key Path:", self.verify_pub_var, browse=True)
        self._create_labeled_entry(frame, "Message Path:", self.verify_msg_var, browse=True)
        self._create_labeled_entry(frame, "Signature Path:", self.verify_sig_var, browse=True)

        # Verify button
        btn_container = ttk.Frame(frame)
        btn_container.pack(fill="x", padx=10, pady=20)
        ModernButton(btn_container,
                  text="Verify Signature",
                  command=self._on_verify,
                  style='Action.TButton'
                  ).pack(expand=True)

    def _build_cert_tab(self):
        frame = ttk.Frame(self.tab_cert)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        self._create_section_header(frame, "Generate Self-Signed Certificate")

        # File paths
        self.cert_csr_var = tk.StringVar()
        self.cert_priv_var = tk.StringVar()
        self.cert_out_var = tk.StringVar()
        self._create_labeled_entry(frame, "CSR Path:", self.cert_csr_var, browse=True)
        self._create_labeled_entry(frame, "Private Key Path:", self.cert_priv_var, browse=True)
        self._create_labeled_entry(frame, "Certificate Path:", self.cert_out_var, browse=True, save=True)

        # Validity days
        days_container = ttk.Frame(frame)
        days_container.pack(fill="x", padx=10, pady=5)
        ttk.Label(days_container, text="Valid for (days):").pack(side="left", padx=(0, 10))
        self.cert_days_var = tk.StringVar(value="365")
        ttk.Entry(days_container, textvariable=self.cert_days_var, width=10).pack(side="left")

        # Generate button
        btn_container = ttk.Frame(frame)
        btn_container.pack(fill="x", padx=10, pady=20)
        ModernButton(btn_container,
                  text="Generate Self-Signed Certificate",
                  command=self._on_generate_cert,
                  style='Action.TButton'
                  ).pack(expand=True)

    def _build_x509_tab(self):
        frame = ttk.Frame(self.tab_x509)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Extract public key section
        self._create_section_header(frame, "Extract Public Key from Certificate")
        
        self.x509_cert_var = tk.StringVar()
        self.x509_pub_var = tk.StringVar()
        self._create_labeled_entry(frame, "Certificate Path:", self.x509_cert_var, browse=True)
        self._create_labeled_entry(frame, "Public Key Output:", self.x509_pub_var, browse=True, save=True)

        # Extract button
        btn_container = ttk.Frame(frame)
        btn_container.pack(fill="x", padx=10, pady=20)
        ModernButton(btn_container,
                  text="Extract Public Key",
                  command=self._on_extract_pubkey,
                  style='Action.TButton'
                  ).pack(expand=True)

        # Separator
        separator_frame = ttk.Frame(frame)
        separator_frame.pack(fill="x", padx=10, pady=20)
        ttk.Separator(separator_frame, orient="horizontal").pack(fill="x")

        # Verify with certificate section
        self._create_section_header(frame, "Verify Signature with Certificate")
        
        self.x509_msg_var = tk.StringVar()
        self.x509_sig_var = tk.StringVar()
        self._create_labeled_entry(frame, "Message Path:", self.x509_msg_var, browse=True)
        self._create_labeled_entry(frame, "Signature Path:", self.x509_sig_var, browse=True)

        # Verify button
        btn_container = ttk.Frame(frame)
        btn_container.pack(fill="x", padx=10, pady=20)
        ModernButton(btn_container,
                  text="Verify with Certificate",
                  command=self._on_verify_with_cert,
                  style='Action.TButton'
                  ).pack(expand=True)

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

    def _on_generate_ecdsa(self):
        curve = self.ecdsa_curve_var.get().strip()
        priv = self.ecdsa_priv_var.get().strip()
        pub = self.ecdsa_pub_var.get().strip()

        if not all([curve, priv, pub]):
            messagebox.showerror("Error", "All fields must be filled.")
            return

        if py_generate_ecdsa_keypair(curve, priv, pub):
            messagebox.showinfo("Success", "ECDSA keypair generated successfully.")
        else:
            messagebox.showerror("Error", "Failed to generate ECDSA keypair.")

    def _on_generate_rsa(self):
        try:
            bits = int(self.rsa_bits_var.get())
        except ValueError:
            messagebox.showerror("Error", "Key size must be a valid integer.")
            return

        priv = self.rsa_priv_var.get().strip()
        pub = self.rsa_pub_var.get().strip()

        if not all([priv, pub]):
            messagebox.showerror("Error", "All fields must be filled.")
            return

        if py_generate_rsa_keypair(bits, priv, pub):
            messagebox.showinfo("Success", "RSA keypair generated successfully.")
        else:
            messagebox.showerror("Error", "Failed to generate RSA keypair.")

    def _on_sign(self):
        algo = self.sign_algo_var.get()
        priv = self.sign_priv_var.get().strip()
        msg = self.sign_msg_var.get().strip()
        sig = self.sign_sig_var.get().strip()

        if not all([priv, msg, sig]):
            messagebox.showerror("Error", "All fields must be filled.")
            return

        if algo == "ECDSA":
            success = py_sign_ecdsa(priv, msg, sig)
        else:  # RSA-PSS
            success = py_sign_rsapss(priv, msg, sig)

        if success:
            messagebox.showinfo("Success", f"{algo} signature created successfully.")
        else:
            messagebox.showerror("Error", f"Failed to create {algo} signature.")

    def _on_verify(self):
        algo = self.verify_algo_var.get()
        pub = self.verify_pub_var.get().strip()
        msg = self.verify_msg_var.get().strip()
        sig = self.verify_sig_var.get().strip()

        if not all([pub, msg, sig]):
            messagebox.showerror("Error", "All fields must be filled.")
            return

        if algo == "ECDSA":
            success = py_verify_ecdsa(pub, msg, sig)
        else:  # RSA-PSS
            success = py_verify_rsapss(pub, msg, sig)

        if success:
            messagebox.showinfo("Success", f"{algo} signature verified successfully.")
        else:
            messagebox.showerror("Error", f"Failed to verify {algo} signature.")

    def _on_generate_cert(self):
        csr = self.cert_csr_var.get().strip()
        priv = self.cert_priv_var.get().strip()
        out = self.cert_out_var.get().strip()
        
        try:
            days = int(self.cert_days_var.get())
        except ValueError:
            messagebox.showerror("Error", "Days must be a valid integer.")
            return

        if not all([csr, priv, out]):
            messagebox.showerror("Error", "All fields must be filled.")
            return

        if py_generate_self_signed_certificate(csr, priv, out, days):
            messagebox.showinfo("Success", "Self-signed certificate generated successfully.")
        else:
            messagebox.showerror("Error", "Failed to generate self-signed certificate.")

    def _on_extract_pubkey(self):
        cert = self.x509_cert_var.get().strip()
        pub = self.x509_pub_var.get().strip()

        if not all([cert, pub]):
            messagebox.showerror("Error", "All fields must be filled.")
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
            messagebox.showerror("Error", "All fields must be filled.")
            return

        if py_verify_signature_with_cert(cert, msg, sig):
            messagebox.showinfo("Success", "Signature verified successfully with certificate.")
        else:
            messagebox.showerror("Error", "Failed to verify signature with certificate.")

if __name__ == "__main__":
    app = CryptoGUI()
    app.mainloop() 