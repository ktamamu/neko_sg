# neko_sg

[![CI](https://github.com/ktamamu/neko_sg/actions/workflows/ci.yml/badge.svg)](https://github.com/ktamamu/neko_sg/actions/workflows/ci.yml)
[![Security](https://github.com/ktamamu/neko_sg/actions/workflows/security.yml/badge.svg)](https://github.com/ktamamu/neko_sg/actions/workflows/security.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)

<div align="center">
<img src="icon.png" alt="neko" width="200">
</div>

NeKo_AWS_SG is a tool that monitors AWS security groups and detects those with inbound rules open to the global internet. The detection results are notified to Slack.

## Functions

- Scan all security groups within the AWS account (this may result in a large number of API calls to retrieve all security groups).
- Detect security groups with inbound rules open to the global internet.
- Output the detection results as a report.
- Notify the detection results to Slack.

## Prerequisites

- Python 3.11 or higher
- [uv](https://docs.astral.sh/uv/) (Python package installer and resolver)
- AWS Access Key and Secret Key
- Slack Webhook URL

## Setup

1. Clone the repository
   ```bash
   git clone https://github.com/ktamamu/neko_sg.git
   cd　neko_sg
   ```

2. Install uv (if not already installed)
   ```bash
   # On macOS and Linux
   curl -LsSf https://astral.sh/uv/install.sh | sh

   # On Windows
   powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
   ```

3. Install dependencies using uv
   ```bash
   uv sync
   ```

4. Setting Environment Variables and AWS Credentials

   a. Setting Slack Webhook URL

   Create a .env file in the root directory of the project and include the following content:

   ```
   SLACK_WEBHOOK_URL=your_slack_webhook_url
   ```

   Alternatively, you can set the environment variables directly

   ```
   export SLACK_WEBHOOK_URL=your_slack_webhook_url
   ```

   b. Setting AWS Credentials

   Configure your AWS credentials using the aws configure command:
   ```
   aws configure
   ```

   Follow the prompts to enter your AWS Access Key ID, AWS Secret Access Key, default region name, and output format.

## Usage

### Basic Scanning

Run the following command from the root directory:

```bash
# Using uv to run the script
uv run python src/main.py

# Or using the entry point
uv run neko-sg

# Explicitly use scan subcommand
uv run python src/main.py scan
```

### Managing Exclusion Rules

You can add security groups to the exclusion list using the `exclude` subcommand:

```bash
# Add a security group to exclusion rules (with auto-detection)
uv run python src/main.py exclude sg-1234567890abcdef0

# Add without auto-detection
uv run python src/main.py exclude sg-1234567890abcdef0 --no-auto-detect

# Using the entry point
uv run neko-sg exclude sg-1234567890abcdef0
```

The `exclude` command will:
- Search for the specified security group across all AWS regions
- Automatically detect the security group's current rules
- Add the security group to `config/exclusion_rules.yaml`
- Create the file if it doesn't exist
- Skip if the security group is already excluded

### Command Help

```bash
# Show all available commands
uv run python src/main.py --help

# Show help for the exclude command
uv run python src/main.py exclude --help
```

### Development

For development, you can install the optional development dependencies:

```bash
# Install with dev dependencies
uv sync --extra dev

# Run linting
uv run ruff check src/

# Run type checking
uv run mypy src/

# Run tests
uv run pytest
```

The results will be notified to the specified Slack channel.

## Setting Exclusion Rules

### Automatic Method (Recommended)

Use the `exclude` command to automatically add security groups to the exclusion list:

```bash
uv run python src/main.py exclude sg-1234567890abcdef0
```

### Manual Method

You can manually edit the `config/exclusion_rules.yaml` file to exclude specific security groups or rules:

```yaml
- security_group_id: sg-1234567890abcdef0
  description: "Excluded: WebServer-SG (HTTP/HTTPS access)"
  rules:
    - ip_address: "0.0.0.0/0"
      protocol: "tcp"
      port_range:
        from: 443
        to: 443
    - ip_address: "0.0.0.0/0"
      protocol: "tcp"
      port_range:
        from: 80
        to: 80
```

**Note**: The automatic method is recommended as it:
- Prevents syntax errors
- Automatically detects current security group rules
- Ensures proper YAML formatting
- Creates the file structure if it doesn't exist
