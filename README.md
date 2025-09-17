# AWS SOC 2 Readiness Checker

This tool helps you assess your AWS environment and MongoDB Atlas for SOC 2 readiness by checking key security and compliance controls across multiple services.

## Features
- Checks IAM, CloudFront, API Gateway, NLB, ECS, ECR, S3, CloudWatch, and MongoDB Atlas
- Modular checks for each service
- Outputs results in table or JSON format
- Error handling and pagination support

## Prerequisites
- Python 3.7+
- AWS credentials configured (via environment variables, AWS CLI, or instance profile)
- MongoDB Atlas API keys (optional, for Atlas checks)

## Setup
1. **Clone or download this repository**
2. **Create and activate a Python virtual environment (optional but recommended):**
   ```powershell
   python -m venv .venv
   .venv\Scripts\activate
   ```
3. **Install dependencies:**
   ```powershell
   pip install boto3 requests tabulate
   ```

## AWS Credentials
The script uses your default AWS credentials. Set them up using one of the following methods:
- `aws configure` (recommended)
- Set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` as environment variables
- Use an EC2 instance profile or IAM role

## MongoDB Atlas Credentials (Optional)
To check MongoDB Atlas, you need:
- Atlas Public Key
- Atlas Private Key
- Atlas Project ID

You can generate API keys in the Atlas UI under Organization Access Management.


## Usage


### Basic Usage
Run all checks and print results as a table:
```powershell
python soc2_checker.py
```

### Use a Specific AWS Profile
To run checks using a specific AWS CLI profile:
```powershell
python soc2_checker.py --profile myprofile
```
Replace `myprofile` with the name of your profile from `~/.aws/credentials`.

### Export Results to JSON
```powershell
python soc2_checker.py --output report.json
```


### Export Results to Interactive HTML
Generate a visually appealing, filterable HTML report with summary tables:
```powershell
python soc2_checker.py --output report.html
```
The HTML report includes:
- Color-coded pass/fail
- Filter bar for service
- **Summary table**: Total checks, pass, fail
- **Per-service summary**: Pass/fail/total by service
- **Grouped details**: Each service's controls and results in its own table

#### Example HTML Report Section
| Total Checks | Pass | Fail |
|--------------|------|------|
| 20           | 15   | 5    |

| Service   | Pass | Fail | Total |
|-----------|------|------|-------|
| S3        | 3    | 1    | 4     |
| IAM       | 2    | 1    | 3     |
| ...       | ...  | ...  | ...   |

Each service section lists all controls, their status, and details.

### Skip MongoDB Atlas Checks
If you do not want to scan MongoDB Atlas, use:
```powershell
python soc2_checker.py --skip-atlas
```

### Include MongoDB Atlas Checks
```powershell
python soc2_checker.py --atlas-public-key <PUBLIC_KEY> --atlas-private-key <PRIVATE_KEY> --atlas-project-id <PROJECT_ID>
```

### Full Example
```powershell
python soc2_checker.py --output soc2_report.html --atlas-public-key ABC --atlas-private-key XYZ --atlas-project-id 1234567890abcdef
```

## Output
- Table format (default, printed to console)
- JSON format (if `--output` ends with `.json`)
- HTML format (if `--output` ends with `.html`): Interactive, filterable, and color-coded
- Each result includes: Service, Control, Status (Pass/Fail), Details

## Extending Checks
- Each service check is a separate function in `soc2_checker.py`.
- Add new checks by creating new functions and calling them from `main()`.

## Troubleshooting
- Ensure your AWS credentials are valid and have sufficient permissions.
- For MongoDB Atlas, ensure API keys and project ID are correct and have read access.
- If you encounter errors, check the Details column in the output for more information.

## License
MIT License
