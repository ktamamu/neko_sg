import os
from unittest import mock
from src.config import Config

def test_config_default():
    config = Config()
    assert config.slack_webhook_url is None
    assert config.slack_bot_token is None
    assert config.slack_channel == "#alerts"
    assert config.use_slack_sdk is False
    assert config.exclusion_rules_file == "../config/exclusion_rules.yaml"
    assert config.log_level == "INFO"
    assert config.aws_timeout == 10

@mock.patch.dict(os.environ, {
    "SLACK_WEBHOOK_URL": "http://example.com/webhook",
    "SLACK_BOT_TOKEN": "xoxb-test",
    "SLACK_CHANNEL": "#general",
    "USE_SLACK_SDK": "true",
    "EXCLUSION_RULES_FILE": "/path/to/rules.yaml",
    "LOG_LEVEL": "DEBUG",
    "AWS_TIMEOUT": "20",
})
def test_config_from_env():
    config = Config.from_env()
    assert config.slack_webhook_url == "http://example.com/webhook"
    assert config.slack_bot_token == "xoxb-test"
    assert config.slack_channel == "#general"
    assert config.use_slack_sdk is True
    assert config.exclusion_rules_file == "/path/to/rules.yaml"
    assert config.log_level == "DEBUG"
    assert config.aws_timeout == 20

def test_get_exclusion_rules_path():
    config = Config(exclusion_rules_file="rules.yaml")
    assert config.get_exclusion_rules_path("/app") == "/app/rules.yaml"

    config_abs = Config(exclusion_rules_file="/absolute/rules.yaml")
    assert config_abs.get_exclusion_rules_path("/app") == "/absolute/rules.yaml"

def test_get_aws_config():
    config = Config(aws_timeout=15)
    aws_config = config.get_aws_config()
    assert aws_config.connect_timeout == 15
    assert aws_config.read_timeout == 15

