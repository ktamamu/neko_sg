import pytest
from unittest import mock
import os
import yaml
from src.cli import (
    create_exclusion_rule_entry,
    find_security_group,
    load_or_create_exclusion_rules,
    save_exclusion_rules,
    add_exclusion_command,
    parse_args,
)

def test_create_exclusion_rule_entry():
    # Basic creation without info
    entry = create_exclusion_rule_entry("sg-123")
    assert entry["security_group_id"] == "sg-123"
    assert entry["description"] == "Excluded security group: sg-123"
    assert entry["rules"] == []

    # Creation with info containing IPv4 and IPv6 rules
    sg_info = {
        "GroupName": "my-sg",
        "Description": "My security group",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}]
            }
        ]
    }
    entry_with_info = create_exclusion_rule_entry("sg-123", sg_info)
    assert "my-sg" in entry_with_info["description"]
    assert len(entry_with_info["rules"]) == 2
    assert entry_with_info["rules"][0]["ip_address"] == "0.0.0.0/0"
    assert entry_with_info["rules"][1]["ip_address"] == "::/0"

@mock.patch("src.cli.get_all_regions")
@mock.patch("src.cli.get_security_groups")
def test_find_security_group(mock_get_groups, mock_get_regions):
    mock_get_regions.return_value = ["us-east-1", "us-west-2"]
    
    def get_groups_mock(region, config=None):
        if region == "us-west-2":
            return [{"GroupId": "sg-target", "GroupName": "target-sg"}]
        return [{"GroupId": "sg-other", "GroupName": "other-sg"}]

    mock_get_groups.side_effect = get_groups_mock

    result = find_security_group("sg-target")
    assert result is not None
    assert result["GroupId"] == "sg-target"
    assert result["Region"] == "us-west-2"

    result_not_found = find_security_group("sg-nonexistent")
    assert result_not_found is None

def test_load_or_create_exclusion_rules(tmp_path):
    rules_file = tmp_path / "rules.yaml"
    
    # File doesn't exist
    assert load_or_create_exclusion_rules(str(rules_file)) == []

    # Valid YAML file
    rules_file.write_text("- security_group_id: sg-123\n  rules: []", encoding="utf-8")
    loaded = load_or_create_exclusion_rules(str(rules_file))
    assert len(loaded) == 1
    assert loaded[0]["security_group_id"] == "sg-123"

    # Empty/invalid YAML file
    rules_file.write_text("", encoding="utf-8")
    assert load_or_create_exclusion_rules(str(rules_file)) == []

def test_save_exclusion_rules(tmp_path):
    rules_file = tmp_path / "rules.yaml"
    rules = [{"security_group_id": "sg-123", "rules": []}]
    
    assert save_exclusion_rules(str(rules_file), rules)
    with open(rules_file, encoding="utf-8") as f:
        data = yaml.safe_load(f)
        assert data[0]["security_group_id"] == "sg-123"

@mock.patch("src.cli.Config.from_env")
@mock.patch("src.cli.load_or_create_exclusion_rules")
@mock.patch("src.cli.save_exclusion_rules")
@mock.patch("src.cli.find_security_group")
def test_add_exclusion_command(mock_find, mock_save, mock_load, mock_config):
    mock_conf = mock.Mock()
    mock_conf.get_exclusion_rules_path.return_value = "/rules.yaml"
    mock_config.return_value = mock_conf

    # Case: Already excluded
    mock_load.return_value = [{"security_group_id": "sg-123"}]
    assert add_exclusion_command("sg-123", auto_detect=False) == 0
    mock_save.assert_not_called()

    # Case: Add new rule
    mock_load.return_value = []
    mock_save.return_value = True
    mock_find.return_value = {"GroupId": "sg-456", "GroupName": "test", "IpPermissions": []}
    assert add_exclusion_command("sg-456", auto_detect=True) == 0
    mock_save.assert_called_once()

def test_parse_args():
    args = parse_args(["scan"])
    assert args.command == "scan"

    args = parse_args(["exclude", "sg-123"])
    assert args.command == "exclude"
    assert args.security_group_id == "sg-123"
    assert not args.no_auto_detect

    args = parse_args(["exclude", "sg-123", "--no-auto-detect"])
    assert args.no_auto_detect
