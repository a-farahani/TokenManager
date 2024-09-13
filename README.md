# Token Manager

A Python-based GUI application for managing PKCS#11 tokens using `tkinter`. Features include detecting tokens, logging in, generating RSA key pairs, creating Certificate Signing Requests (CSRs), importing X.509 certificates, and listing token objects.

## Features

- **Detect Token**: Locate and select PKCS#11 tokens.
- **Login**: Authenticate to the selected token.
- **Generate Key**: Create RSA key pairs on the token.
- **Generate CSR**: Create Certificate Signing Requests (CSRs) using the token's private key.
- **Import Certificate**: Import X.509 certificates into the token.
- **List Objects**: View objects stored on the token.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/a-farahani/Token-Manager.git
    ```
2. Navigate to the project directory:
    ```bash
    cd Token-Manager
    ```
3. Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. Run the application:
    ```bash
    python token_manager.py
    ```
2. Use the GUI to perform various operations with your PKCS#11 token.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please see the [CONTRIBUTING](CONTRIBUTING.md) file for details on how to contribute.

## Contact

For questions or feedback, please open an issue on the GitHub repository or contact the project maintainer.

