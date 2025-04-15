# **DataVault Pro - Secure Data Encryption Solution**

![App Logo](https://cdn-icons-png.flaticon.com/512/295/295128.png)  
🔒 A secure and user-friendly application to store and retrieve sensitive data with military-grade AES-256 encryption.

---

## **Features**
- **Military-grade AES-256 Encryption**: Protect your sensitive data with robust encryption algorithms.
- **Secure Authentication**: Master password protection ensures only authorized access.
- **Tamper-proof Storage**: All data is encrypted at rest and securely stored.
- **Intuitive Interface**: Beautiful and responsive UI for seamless user experience.
- **Error Handling**: Clear feedback for invalid inputs or failed authentication attempts.
- **Custom Animations**: Modern Lottie animations for a polished look.

---

## **Installation and Setup**

### 1. **Prerequisites**
Ensure you have the following installed on your system:
- Python 3.7 or higher
- `pip` (Python package manager)

### 2. **Clone the Repository**
```bash
git clone https://github.com/yourusername/DataVault-Pro.git
cd DataVault-Pro
```

### 3. **Set Up a Virtual Environment (Optional but Recommended)**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 4. **Install Dependencies**
Install the required libraries using the `requirements.txt` file:
```bash
pip install -r requirements.txt
```

> **Note:** If you encounter issues with `cryptography`, ensure you have the necessary system dependencies installed:
> - **Ubuntu/Debian**:
>   ```bash
>   sudo apt-get update
>   sudo apt-get install build-essential libssl-dev libffi-dev python3-dev
>   ```
> - **macOS**:
>   ```bash
>   brew install openssl
>   export LDFLAGS="-L/usr/local/opt/openssl/lib"
>   export CPPFLAGS="-I/usr/local/opt/openssl/include"
>   ```

### 5. **Run the App**
Start the Streamlit app locally:
```bash
streamlit run app.py
```

The app will open in your default web browser at `http://localhost:8501`.

---

## **Usage**

### 1. **Login**
- Use the master password (`admin123` by default) to log in.
- In production, replace the hardcoded master password with an environment variable for enhanced security.

### 2. **Dashboard**
- View app features and instructions on the dashboard.

### 3. **Store Data**
- Enter a unique label (e.g., "Bank Credentials").
- Provide sensitive data in the text area.
- Create a strong passkey (minimum 8 characters, including special characters).
- Click **"Encrypt & Store"** to securely save your data.

### 4. **Retrieve Data**
- Enter the label and passkey used during storage.
- Click **"Decrypt Data"** to retrieve and view the decrypted content.

### 5. **Logout**
- Log out securely from the sidebar menu.

---

## **Security Notes**
- **Master Password**: Replace the default `MASTER_PASS` in the code with an environment variable for production use.
- **Encryption Key**: The encryption key is stored in `secret.key`. Ensure this file is secured and not exposed publicly.
- **Stored Data**: Encrypted data is stored in `data.json`. Keep this file secure as it contains sensitive information.

---

## **File Structure**
```
DataVault-Pro/
├── app.py                # Main application file
├── secret.key            # Encryption key (generated automatically)
├── data.json             # Encrypted data storage
├── requirements.txt      # List of dependencies
├── README.md             # Documentation
└── assets/               # Optional folder for custom assets (e.g., logos)
```

---

## **Contributing**
Contributions are welcome! If you find any bugs or want to suggest improvements:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature/YourFeatureName`).
3. Commit your changes (`git commit -m "Add YourFeatureName"`).
4. Push to the branch (`git push origin feature/YourFeatureName`).
5. Open a pull request.

---

## **License**
This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## **Contact**
For questions or feedback, feel free to reach out:
- Email: wajahat345678@gmail.com
- GitHub: (https://github.com/WajahatAli3218664)

---

## **Acknowledgments**
- **Streamlit**: For providing an easy-to-use framework for building data apps.
- **Cryptography Library**: For enabling robust encryption.
- **Lottie Animations**: For enhancing the app's visual appeal.
