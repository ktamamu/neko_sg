# NeKo_AWS_SG (<u>Ne</u>twork <u>K</u>it <u>o</u>f AWS Security Group)
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

- Python 3.8 or higher
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

Run the following command from the root directory:

```bash
# Using uv to run the script
uv run python src/main.py

# Or using the entry point
uv run neko-sg
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

You can edit the exclusions.yaml file to exclude specific security groups or rules

```yaml
exclusions:
  - group_id: sg-12345678
    rules:
      - ip_protocol: tcp
        port_range:
          from: 443
          to: 443
        ip_ranges:
          - 0.0.0.0/0
```
