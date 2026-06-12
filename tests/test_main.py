import pytest
from unittest import mock
import sys
from src.main import scan_security_groups, main, _send_slack_notification_if_configured
from src.config import Config

@mock.patch("src.main.Config.from_env")
@mock.patch("src.main.load_exclusion_rules")
@mock.patch("src.main.find_globally_accessible_security_groups")
@mock.patch("src.main._send_slack_notification_if_configured")
def test_scan_security_groups_no_groups(mock_send, mock_find, mock_load, mock_config):
    mock_conf = mock.Mock()
    mock_conf.log_level = "INFO"
    mock_conf.get_exclusion_rules_path.return_value = "/rules.yaml"
    mock_config.return_value = mock_conf

    mock_load.return_value = []
    mock_find.return_value = []

    scan_security_groups()

    mock_find.assert_called_once_with([], mock_conf)
    mock_send.assert_not_called()

@mock.patch("src.main.Config.from_env")
@mock.patch("src.main.load_exclusion_rules")
@mock.patch("src.main.find_globally_accessible_security_groups")
@mock.patch("src.main._send_slack_notification_if_configured")
def test_scan_security_groups_with_groups(mock_send, mock_find, mock_load, mock_config):
    mock_conf = mock.Mock()
    mock_conf.log_level = "INFO"
    mock_conf.get_exclusion_rules_path.return_value = "/rules.yaml"
    mock_config.return_value = mock_conf

    mock_load.return_value = []
    groups = [{"region": "us-east-1", "group_id": "sg-123"}]
    mock_find.return_value = groups

    scan_security_groups()

    mock_find.assert_called_once_with([], mock_conf)
    mock_send.assert_called_once_with(mock_conf, groups)

@mock.patch("src.main.parse_args")
@mock.patch("src.main.scan_security_groups")
def test_main_scan(mock_scan, mock_parse_args):
    mock_args = mock.Mock()
    mock_args.command = "scan"
    mock_parse_args.return_value = mock_args

    main()
    mock_scan.assert_called_once()

@mock.patch("src.main.parse_args")
def test_main_subcommand(mock_parse_args):
    mock_args = mock.Mock()
    mock_args.command = "exclude"
    mock_func = mock.Mock(return_value=0)
    mock_args.func = mock_func
    mock_parse_args.return_value = mock_args

    with pytest.raises(SystemExit) as excinfo:
        main()
    assert excinfo.value.code == 0
    mock_func.assert_called_once_with(mock_args)

@mock.patch("src.main.send_slack_notification_sdk")
@mock.patch("src.main.send_slack_notification")
@mock.patch("src.main.format_slack_message")
def test_send_slack_notification_if_configured(mock_format, mock_send_webhook, mock_send_sdk):
    mock_format.return_value = "formatted"
    
    # 1. SDK Success
    config = Config(use_slack_sdk=True, slack_bot_token="xoxb-test", slack_channel="#alert")
    mock_send_sdk.return_value = True
    _send_slack_notification_if_configured(config, [])
    mock_send_sdk.assert_called_once_with("xoxb-test", "#alert", "formatted")
    mock_send_webhook.assert_not_called()

    mock_send_sdk.reset_mock()
    mock_send_webhook.reset_mock()

    # 2. SDK Fails, Webhook Success
    config_fallback = Config(use_slack_sdk=True, slack_bot_token="xoxb-test", slack_webhook_url="http://webhook")
    mock_send_sdk.return_value = False
    mock_send_webhook.return_value = True
    _send_slack_notification_if_configured(config_fallback, [])
    mock_send_sdk.assert_called_once()
    mock_send_webhook.assert_called_once_with("http://webhook", "formatted")

    mock_send_sdk.reset_mock()
    mock_send_webhook.reset_mock()

    # 3. None configured (should print to stdout)
    config_empty = Config()
    with mock.patch("builtins.print") as mock_print:
        _send_slack_notification_if_configured(config_empty, [])
        mock_send_sdk.assert_not_called()
        mock_send_webhook.assert_not_called()
        mock_print.assert_called_once_with("formatted")
