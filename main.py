import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
import pkcs11
from pkcs11 import KeyType, Mechanism
import pkcs11.util.rsa
from cryptography import x509
from asn1crypto import csr, keys, x509 as ac_x509
from asn1crypto.keys import RSAPublicKey
from asn1crypto import pem
from pkcs11.util.x509 import decode_x509_certificate

class TokenManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Token Manager")

        # Label to display token status
        self.token_label = tk.Label(root, text="Token Not Detected")
        self.token_label.pack(pady=10)

        # Buttons for various operations
        self.detect_token_button = tk.Button(root, text="Detect Token", command=self.detect_token)
        self.detect_token_button.pack(pady=5)

        self.login_button = tk.Button(root, text="Login", command=self.login_token, state=tk.DISABLED)
        self.login_button.pack(pady=5)

        self.generate_key_button = tk.Button(root, text="Generate Key", command=self.generate_key, state=tk.DISABLED)
        self.generate_key_button.pack(pady=5)

        self.generate_csr_button = tk.Button(root, text="Generate CSR", command=self.generate_csr, state=tk.DISABLED)
        self.generate_csr_button.pack(pady=5)

        self.import_cert_button = tk.Button(root, text="Import Certificate", command=self.import_cert, state=tk.DISABLED)
        self.import_cert_button.pack(pady=5)

        self.list_objects_button = tk.Button(root, text="List Objects", command=self.list_objects, state=tk.DISABLED)
        self.list_objects_button.pack(pady=5)

        # Text widget to display objects on the token
        self.objects_text = tk.Text(root, width=80, height=15)
        self.objects_text.pack(pady=10)

        # PKCS#11 session variables
        self.pkcs11 = None
        self.token = None
        self.session = None
        self.slot = None
        self.pkcs11_module_path = None

    def detect_token(self):
        try:
            if not self.pkcs11_module_path:
                dll_path = filedialog.askopenfilename(title="Select PKCS#11 Module", filetypes=(("SO Files", "*.so"), ("DLL Files", "*.dll")))
                if dll_path:
                    self.pkcs11_module_path = dll_path
                    self.pkcs11 = pkcs11.lib(dll_path)

            # List available slots and select the first one
            slots = self.pkcs11.get_slots(token_present=True)
            if not slots:
                messagebox.showerror("Error", "No token detected")
            else:
                self.token_label.config(text="Token Detected!")
                self.slot = slots[0]
                self.token = self.slot.get_token()  # Retrieve the token from the slot
                self.login_button.config(state=tk.NORMAL)
        except pkcs11.PKCS11Error as e:
            messagebox.showerror("Error", f"Failed to detect token: {str(e)}")

    def login_token(self):
        try:
            pin = simpledialog.askstring("Login", "Enter your PIN:", show='*')
            if pin:
                # Open the token session in read/write mode and pass the user pin
                self.session = self.token.open(rw=True, user_pin=pin)
                messagebox.showinfo("Success", "Login Successful!")
                self.generate_key_button.config(state=tk.NORMAL)
                self.generate_csr_button.config(state=tk.NORMAL)
                self.import_cert_button.config(state=tk.NORMAL)
                self.list_objects_button.config(state=tk.NORMAL)
            else:
                messagebox.showerror("Error", "PIN not entered")
        except pkcs11.PKCS11Error as e:
            messagebox.showerror("Error", f"Failed to login: {str(e)}")

    def generate_key(self):
        try:
            # Get key label from the user
            key_label = simpledialog.askstring("Key Generation", "Enter key label:", initialvalue="MyPersistentRSAKey")
            if not key_label:
                messagebox.showerror("Error", "Key label not provided")
                return
            
            # Generate RSA key pair (public and private)
            pub_key, priv_key = self.session.generate_keypair(
                KeyType.RSA, 
                2048,  # Key size in bits
                mechanism=Mechanism.RSA_PKCS_KEY_PAIR_GEN,  # Mechanism used for key pair generation
                public_template={
                    pkcs11.Attribute.LABEL: key_label,
                    pkcs11.Attribute.TOKEN: True,
                    pkcs11.Attribute.PUBLIC_EXPONENT: (0x01, 0x00, 0x01),  # e = 65537
                },
                private_template={
                    pkcs11.Attribute.LABEL: key_label,
                    pkcs11.Attribute.TOKEN: True,
                    pkcs11.Attribute.SENSITIVE: True,
                    pkcs11.Attribute.PRIVATE: True,
                }
            )
            
            messagebox.showinfo("Success", f"RSA Key Pair Generated!\nLabel: {key_label}")
        except pkcs11.PKCS11Error as e:
            messagebox.showerror("Error", f"Failed to generate key: {str(e)}")

    def generate_csr(self):
        try:
            # Locate the private key on the token
            priv_key = self.session.get_key(pkcs11.ObjectClass.PRIVATE_KEY)
            if not priv_key:
                messagebox.showerror("Error", "No private key found on token.")
                return

            # Retrieve the public key from the token
            pub_key = self.session.get_key(pkcs11.ObjectClass.PUBLIC_KEY)
            if not pub_key:
                messagebox.showerror("Error", "No public key found on token.")
                return

            # Encode the public key into DER format
            pub_key_der = pkcs11.util.rsa.encode_rsa_public_key(pub_key)

            # Parse the DER-encoded RSA public key to extract modulus and exponent
            rsa_pub_key = RSAPublicKey.load(pub_key_der)

            # Construct the PublicKeyInfo structure
            public_key_info = keys.PublicKeyInfo({
                'algorithm': {
                    'algorithm': 'rsa',
                    'parameters': None
                },
                'public_key': rsa_pub_key
            })

            # Get subject details from the user
            country_name = simpledialog.askstring("CSR Subject", "Enter Country Name (e.g., US):", initialvalue="US")
            state_name = simpledialog.askstring("CSR Subject", "Enter State or Province Name (e.g., California):", initialvalue="California")
            locality_name = simpledialog.askstring("CSR Subject", "Enter Locality Name (e.g., San Francisco):", initialvalue="San Francisco")
            organization_name = simpledialog.askstring("CSR Subject", "Enter Organization Name (e.g., My Company):", initialvalue="My Company")
            common_name = simpledialog.askstring("CSR Subject", "Enter Common Name (e.g., example.com):", initialvalue="example.com")
            
            if not (country_name and state_name and locality_name and organization_name and common_name):
                messagebox.showerror("Error", "Incomplete subject details")
                return

            # Define subject for the CSR
            subject = ac_x509.Name.build({
                'country_name': country_name,
                'state_or_province_name': state_name,
                'locality_name': locality_name,
                'organization_name': organization_name,
                'common_name': common_name
            })

            # Build the CSR using asn1crypto
            cert_request = csr.CertificationRequest({
                'certification_request_info': {
                    'version': 'v1',
                    'subject': subject,
                    'subject_pk_info': public_key_info,
                    'attributes': [],
                },
                'signature_algorithm': {
                    'algorithm': 'sha256_rsa',
                },
                'signature': b'\x00'  # Placeholder for the signature
            })

            # Get the CertificationRequestInfo for signing
            to_be_signed = cert_request['certification_request_info'].dump()

            # Sign the CSR using the private key on the token
            signature = priv_key.sign(
                to_be_signed,
                mechanism=Mechanism.SHA256_RSA_PKCS
            )

            # Add the signature to the CSR
            cert_request['signature'] = signature

            # Encode the CSR in PEM format
            csr_pem = pem.armor("CERTIFICATE REQUEST", cert_request.dump())

            # Save the CSR to a file in PEM format
            file_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=(("PEM Files", "*.pem"),))
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(csr_pem.decode('utf-8'))
                messagebox.showinfo("Success", "CSR Generated and saved!")
        except pkcs11.PKCS11Error as e:
            messagebox.showerror("Error", f"Failed to generate CSR: {str(e)}")

    def import_cert(self):
        cert_file = filedialog.askopenfilename(title="Select Certificate", filetypes=(("PEM Files", "*.pem"),))
        if cert_file:
            with open(cert_file, 'rb') as f:
                cert_data = f.read()

            # Check if the certificate is PEM-encoded and convert it to DER
            if pem.detect(cert_data):
                _, _, cert_der = pem.unarmor(cert_data)  # Convert PEM to DER
            else:
                cert_der = cert_data  # Already in DER format

            # Prompt user for the label
            cert_label = simpledialog.askstring("Certificate Label", "Enter a label for the certificate:")
            if not cert_label:
                messagebox.showerror("Error", "No label entered. Import canceled.")
                return

            # Decode the certificate using python-pkcs11 utility function
            cert_obj = decode_x509_certificate(cert_der)
            cert_obj.update({
                pkcs11.Attribute.LABEL: cert_label,  # Use the user-provided label
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.CERTIFICATE,
                pkcs11.Attribute.CERTIFICATE_TYPE: pkcs11.CertificateType.X_509,
                pkcs11.Attribute.TOKEN: True
            })

            # Create certificate object on the token
            created_cert = self.session.create_object(cert_obj)
            if created_cert:
                messagebox.showinfo("Success", f"Certificate Imported to Token with label '{cert_label}'!")
            else:
                messagebox.showerror("Error", "Failed to store certificate in token.")


    from asn1crypto import x509 as ac_x509

    from asn1crypto import x509 as ac_x509

    def format_object_details(self, obj):
        """Format details of a PKCS#11 object for display."""
        try:
            obj_class = obj[pkcs11.Attribute.CLASS]
            label = obj[pkcs11.Attribute.LABEL]
            obj_type = "Unknown"

            if obj_class == pkcs11.ObjectClass.PUBLIC_KEY:
                obj_type = "Public Key Object"
                key_type = obj[pkcs11.Attribute.KEY_TYPE]
                bits = obj[pkcs11.Attribute.MODULUS_BITS] if key_type == KeyType.RSA else 'N/A'
                usage_flags = []

                # Check each usage flag
                try:
                    if obj[pkcs11.Attribute.ENCRYPT]:
                        usage_flags.append("encrypt")
                except KeyError:
                    pass
                try:
                    if obj[pkcs11.Attribute.WRAP]:
                        usage_flags.append("wrap")
                except KeyError:
                    pass
                try:
                    if obj[pkcs11.Attribute.VERIFY]:
                        usage_flags.append("verify")
                except KeyError:
                    pass

                usage = ', '.join(usage_flags)
                access = 'local' if obj[pkcs11.Attribute.TOKEN] else 'session'

                return (f"{obj_type}; Algorithm: {key_type.name}, Bits: {bits}\n"
                        f"  label:      {label}\n"
                        f"  Usage:      {usage}\n"
                        f"  Access:     {access}")

            elif obj_class == pkcs11.ObjectClass.PRIVATE_KEY:
                obj_type = "Private Key Object"
                key_type = obj[pkcs11.Attribute.KEY_TYPE]
                usage_flags = []

                # Check each usage flag
                try:
                    if obj[pkcs11.Attribute.DECRYPT]:
                        usage_flags.append("decrypt")
                except KeyError:
                    pass
                try:
                    if obj[pkcs11.Attribute.SIGN]:
                        usage_flags.append("sign")
                except KeyError:
                    pass
                try:
                    if obj[pkcs11.Attribute.UNWRAP]:
                        usage_flags.append("unwrap")
                except KeyError:
                    pass

                usage = ', '.join(usage_flags)
                access = 'sensitive, always sensitive, never extractable' if obj[pkcs11.Attribute.SENSITIVE] else 'local'

                return (f"{obj_type}; Algorithm: {key_type.name}\n"
                        f"  label:      {label}\n"
                        f"  Usage:      {usage}\n"
                        f"  Access:     {access}")

            elif obj_class == pkcs11.ObjectClass.CERTIFICATE:
                obj_type = "Certificate Object"
                cert_type = obj[pkcs11.Attribute.CERTIFICATE_TYPE]
                cert_data = obj[pkcs11.Attribute.VALUE]

                # Decode the certificate using asn1crypto
                try:
                    cert = ac_x509.Certificate.load(cert_data)
                    subject = cert['tbs_certificate']['subject']
                    
                    # Convert subject from ASN.1 structure to a human-readable format
                    subject_dn_str = ', '.join(f"{k}={v}" for k, v in subject.native.items())
                    subject_dn_formatted = f"DN: {subject_dn_str}"
                except Exception as e:
                    subject_dn_formatted = f"Error decoding DN: {str(e)}"

                return (f"{obj_type}; type = X.509 cert\n"
                        f"  label:      {label}\n"
                        f"  subject:    {subject_dn_formatted}")

            else:
                return f"Unknown Object Class: {obj_class}"
        except KeyError as e:
            return f"Missing attribute: {e}"

    # Example usage in list_objects
    def list_objects(self):
        try:
            self.objects_text.delete(1.0, tk.END)

            for obj in self.session.get_objects():
                details = self.format_object_details(obj)
                self.objects_text.insert(tk.END, details + "\n\n")
        except pkcs11.PKCS11Error as e:
            messagebox.showerror("Error", f"Failed to list objects: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = TokenManagerApp(root)
    root.mainloop()
