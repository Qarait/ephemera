# Release Asset Instructions

To create a polished release on GitHub, follow these steps to package the source code manually (if not using git archive).

## 1. Create a ZIP Archive

Run the following command (on Linux/Mac/WSL) to create a clean zip of the `ephemera` folder, excluding git history and temporary files:

```bash
# Ensure you are in the parent directory of 'ephemera'
zip -r ephemera-v1.0.0.zip ephemera -x "*.git*" -x "*__pycache__*" -x "*.DS_Store*"
```

On Windows (PowerShell):
```powershell
Compress-Archive -Path ephemera -DestinationPath ephemera-v1.0.0.zip
```
*Note: On Windows, you might need to manually ensure `.git` folder is not included if using the GUI.*

## 2. Upload to GitHub

1.  Go to your repository on GitHub.
2.  Click **Releases** > **Draft a new release**.
3.  **Tag version**: `v1.0.0`
4.  **Release title**: `v1.0.0 — Open Source Release`
5.  **Description**:
    > Initial open source release of Ephemera.
    >
    > **Highlights:**
    > *   Zero-Trust SSH CA
    > *   WebAuthn MFA
    > *   Tamper-Evident Audit Log
6.  **Attach binaries**: Upload the `ephemera-v1.0.0.zip` file you created.
7.  Click **Publish release**.
