import pytest
from unittest import mock
import ipaddress
from src.utils import (
    _is_global_cidr,
    is_globally_accessible,
    load_exclusion_rules,
    is_excluded,
    _permission_matches_exclusion_rules,
    format_slack_message,
    send_slack_notification,
    send_slack_notification_sdk,
    get_all_regions,
    get_security_groups,
    find_globally_accessible_security_groups,
    has_unexcluded_global_access,
)
from src.config import Config

def test_is_global_cidr():
    # IPv4 Private
    assert not _is_global_cidr("10.0.0.0/8")
    assert not _is_global_cidr("172.16.0.0/12")
    assert not _is_global_cidr("192.168.0.0/16")
    assert not _is_global_cidr("127.0.0.1/32")
    # IPv4 Global
    assert _is_global_cidr("0.0.0.0/0")
    assert _is_global_cidr("8.8.8.8/32")
    
    # IPv6 Private/ULA/Loopback
    assert not _is_global_cidr("::1/128")
    assert not _is_global_cidr("fc00::/7")
    assert not _is_global_cidr("fe80::/10")
    # IPv6 Global
    assert _is_global_cidr("::/0")
    assert _is_global_cidr("2001:4860:4860::8888/128")
    
    # Invalid CIDR
    assert not _is_global_cidr("invalid-cidr")

def test_is_globally_accessible():
    # IPv4 globally accessible
    sg_ipv4_global = {
        "IpPermissions": [
            {
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": []
            }
        ]
    }
    assert is_globally_accessible(sg_ipv4_global)

    # IPv6 globally accessible
    sg_ipv6_global = {
        "IpPermissions": [
            {
                "IpRanges": [],
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}]
            }
        ]
    }
    assert is_globally_accessible(sg_ipv6_global)

    # Private only
    sg_private = {
        "IpPermissions": [
            {
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                "Ipv6Ranges": [{"CidrIpv6": "fc00::/7"}]
            }
        ]
    }
    assert not is_globally_accessible(sg_private)

def test_permission_matches_exclusion_rules():
    permission = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}]
    }

    excluded_rules_v4 = [
        {
            "ip_address": "0.0.0.0/0",
            "protocol": "tcp",
            "port_range": {"from": 22, "to": 22}
        }
    ]
    assert _permission_matches_exclusion_rules(permission, excluded_rules_v4)

    excluded_rules_v6 = [
        {
            "ip_address": "::/0",
            "protocol": "tcp",
            "port_range": {"from": 22, "to": 22}
        }
    ]
    assert _permission_matches_exclusion_rules(permission, excluded_rules_v6)

    excluded_rules_mismatch = [
        {
            "ip_address": "0.0.0.0/0",
            "protocol": "tcp",
            "port_range": {"from": 80, "to": 80}
        }
    ]
    assert not _permission_matches_exclusion_rules(permission, excluded_rules_mismatch)

def test_is_excluded():
    sg = {
        "GroupId": "sg-123",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    }

    rules = [
        {
            "security_group_id": "sg-123",
            "rules": [
                {
                    "ip_address": "0.0.0.0/0",
                    "protocol": "tcp",
                    "port_range": {"from": 80, "to": 80}
                }
            ]
        }
    ]
    assert is_excluded(sg, rules)

    rules_mismatch_id = [
        {
            "security_group_id": "sg-999",
            "rules": [
                {
                    "ip_address": "0.0.0.0/0",
                    "protocol": "tcp",
                    "port_range": {"from": 80, "to": 80}
                }
            ]
        }
    ]
    assert not is_excluded(sg, rules_mismatch_id)

def test_load_exclusion_rules():
    with mock.patch("os.path.exists", return_value=False):
        assert load_exclusion_rules("dummy.yaml") == []

    yaml_data = """
    - security_group_id: sg-123
      rules: []
    """
    with mock.patch("os.path.exists", return_value=True), \
         mock.patch("builtins.open", mock.mock_open(read_data=yaml_data)):
        rules = load_exclusion_rules("dummy.yaml")
        assert len(rules) == 1
        assert rules[0]["security_group_id"] == "sg-123"

def test_format_slack_message():
    assert format_slack_message([]) == "グローバルにアクセス可能なセキュリティグループは見つかりませんでした。"
    
    sg_list = [
        {"region": "us-east-1", "group_id": "sg-1", "group_name": "name-1"},
        {"region": "us-west-2", "group_id": "sg-2", "group_name": "name-2"},
    ]
    msg = format_slack_message(sg_list)
    assert "us-east-1" in msg
    assert "sg-2" in msg

@mock.patch("requests.post")
def test_send_slack_notification(mock_post):
    mock_post.return_value.status_code = 200
    assert send_slack_notification("http://webhook", "message")
    mock_post.assert_called_once()

    import requests
    mock_post.side_effect = requests.exceptions.RequestException("HTTP Error")
    assert not send_slack_notification("http://webhook", "message")

@mock.patch("src.utils.WebClient")
@mock.patch("src.utils.SLACK_SDK_AVAILABLE", True)
def test_send_slack_notification_sdk(mock_web_client):
    mock_client_instance = mock.Mock()
    mock_client_instance.chat_postMessage.return_value = {"ok": True}
    mock_web_client.return_value = mock_client_instance

    assert send_slack_notification_sdk("token", "#channel", "message")
    mock_client_instance.chat_postMessage.assert_called_once_with(
        channel="#channel", text="message", username="NeKo_AWS_SG", icon_emoji=":warning:"
    )

    mock_client_instance.chat_postMessage.return_value = {"ok": False, "error": "invalid_auth"}
    assert not send_slack_notification_sdk("token", "#channel", "message")

@mock.patch("boto3.session.Session")
def test_get_all_regions(mock_session_class):
    mock_session = mock.Mock()
    mock_ec2 = mock.Mock()
    mock_ec2.describe_regions.return_value = {
        "Regions": [{"RegionName": "us-east-1"}, {"RegionName": "us-west-2"}]
    }
    mock_session.client.return_value = mock_ec2
    mock_session_class.return_value = mock_session

    regions = list(get_all_regions())
    assert regions == ["us-east-1", "us-west-2"]
    mock_session.client.assert_called_with("ec2", config=None)

@mock.patch("boto3.session.Session")
def test_get_security_groups(mock_session_class):
    mock_session = mock.Mock()
    mock_ec2 = mock.Mock()
    mock_paginator = mock.Mock()
    mock_paginator.paginate.return_value = [
        {"SecurityGroups": [{"GroupId": "sg-1"}, {"GroupId": "sg-2"}]}
    ]
    mock_ec2.get_paginator.return_value = mock_paginator
    mock_session.client.return_value = mock_ec2
    mock_session_class.return_value = mock_session

    groups = list(get_security_groups("us-east-1"))
    assert len(groups) == 2
    assert groups[0]["GroupId"] == "sg-1"
    mock_session.client.assert_called_with("ec2", region_name="us-east-1", config=None)

@mock.patch("src.utils.get_all_regions")
@mock.patch("src.utils.get_security_groups")
def test_find_globally_accessible_security_groups(mock_get_groups, mock_get_regions):
    mock_get_regions.return_value = ["us-east-1"]
    mock_get_groups.return_value = [
        {
            "GroupId": "sg-1",
            "GroupName": "open-sg",
            "Description": "Open to world",
            "IpPermissions": [
                {
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": []
                }
            ]
        },
        {
            "GroupId": "sg-2",
            "GroupName": "private-sg",
            "Description": "Private",
            "IpPermissions": []
        }
    ]

    results = list(find_globally_accessible_security_groups([]))
    assert len(results) == 1
    assert results[0]["group_id"] == "sg-1"
    assert results[0]["region"] == "us-east-1"

def test_has_unexcluded_global_access():
    # 1. 除外ルールなし、グローバルアクセスあり -> True
    sg_global = {
        "GroupId": "sg-123",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": []
            }
        ]
    }
    assert has_unexcluded_global_access(sg_global, [])

    # 2. 除外ルールにマッチするルールのみ -> False
    rules = [
        {
            "security_group_id": "sg-123",
            "rules": [
                {
                    "ip_address": "0.0.0.0/0",
                    "protocol": "tcp",
                    "port_range": {"from": 80, "to": 80}
                }
            ]
        }
    ]
    assert not has_unexcluded_global_access(sg_global, rules)

    # 3. 複数のグローバルルールがあり、一部のみ除外 -> True
    sg_mixed = {
        "GroupId": "sg-123",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": []
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": []
            }
        ]
    }
    rules_ssh_only = [
        {
            "security_group_id": "sg-123",
            "rules": [
                {
                    "ip_address": "0.0.0.0/0",
                    "protocol": "tcp",
                    "port_range": {"from": 22, "to": 22}
                }
            ]
        }
    ]
    assert has_unexcluded_global_access(sg_mixed, rules_ssh_only)
