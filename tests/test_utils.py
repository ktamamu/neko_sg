'''
ユーティリティ関数のテスト
'''
import json
from unittest.mock import patch, MagicMock
import pytest
from src.utils import (
    get_all_regions,
    get_security_groups,
    is_globally_accessible,
    is_excluded,
    find_globally_accessible_security_groups,
    format_slack_message,
    send_slack_notification
)

def test_get_all_regions():
    '''
    リージョンの取得
    '''
    with patch('boto3.client') as mock_client:
        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            'Regions': [{'RegionName': 'us-east-1'}, {'RegionName': 'us-west-2'}]
        }
        mock_client.return_value = mock_ec2
        regions = list(get_all_regions())
        assert regions == ['us-east-1', 'us-west-2']

def test_get_security_groups():
    '''
    セキュリティグループの取得
    '''
    with patch('boto3.client') as mock_client:
        mock_ec2 = MagicMock()
        mock_ec2.get_paginator.return_value.paginate.return_value = [
            {'SecurityGroups': [{'GroupId': 'sg-1'}, {'GroupId': 'sg-2'}]}
        ]
        mock_client.return_value = mock_ec2
        sgs = list(get_security_groups('us-east-1'))
        assert len(sgs) == 2
        assert sgs[0]['GroupId'] == 'sg-1'
        assert sgs[1]['GroupId'] == 'sg-2'

def test_is_globally_accessible():
    '''
    グローバルなインバウンドルールの有無
    '''
    sg_global = {
        'IpPermissions': [{'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
    }
    sg_not_global = {
        'IpPermissions': [{'IpRanges': [{'CidrIp': '192.168.1.0/24'}]}]
    }
    assert is_globally_accessible(sg_global) is True
    assert is_globally_accessible(sg_not_global) is False

def test_is_excluded():
    '''
    除外ルールの有無
    '''
    sg = {
        'GroupId': 'sg-123',
        'IpPermissions': [
            {
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '203.0.113.0/24'}]
            }
        ]
    }
    exclusion_rules = [
        {
            'security_group_id': 'sg-123',
            'rules': [
                {
                    'ip_address': '203.0.113.0/24',
                    'protocol': 'tcp',
                    'port_range': {'from': '22', 'to': '22'}
                }
            ]
        }
    ]
    assert is_excluded(sg, exclusion_rules) is True
    assert is_excluded(sg, []) is False

    sg_not_excluded = {
        'GroupId': 'sg-456',
        'IpPermissions': [
            {
                'IpProtocol': 'tcp',
                'FromPort': 80,
                'ToPort': 80,
                'IpRanges': [{'CidrIp': '203.0.113.0/24'}]
            }
        ]
    }
    assert is_excluded(sg_not_excluded, exclusion_rules) is False

def test_send_slack_notification(mocker):
    '''
    Slack通知
    '''
    # モックのrequests.postを作成
    mock_post = mocker.patch('requests.post')
    mock_post.return_value.raise_for_status.return_value = None
    webhook_url = 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'
    message = 'テストメッセージ'
    timeout = 10
    send_slack_notification(webhook_url, message)
    # requests.postが正しく呼び出されたか確認
    expected_data = json.dumps({"text": message})
    mock_post.assert_called_once_with(
        webhook_url,
        data=expected_data,
        headers={'Content-Type': 'application/json'},
        timeout=timeout
    )

def test_format_slack_message():
    '''
    メッセージのフォーマット
    '''
    # テスト用のセキュリティグループデータを準備
    security_groups = [
        {
            'group_id': 'sg-123',
            'region': 'us-east-1',
            'group_name': 'sg_ssh',
            'Description': 'Allow SSH access',
            'VpcId': 'vpc-1234567890abcdef0',
            'IpPermissions': [
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '203.0.113.0/24'}]
                }
            ]
        }
    ]
    # 関数を呼び出し
    result = format_slack_message(security_groups)
    # 期待される結果を定義
    expected_result = (
        "以下のセキュリティグループにグローバルなインバウンドルールが見つかりました：\n"
        "• リージョン: us-east-1, セキュリティグループID: sg-123, 名前: sg_ssh\n"
    )
    # 結果を検証
    assert result == expected_result

@pytest.fixture
def mock_aws_services():
    '''
    AWSサービスのモック
    '''
    with patch('src.utils.boto3.client') as mock_client:
        ec2_client = MagicMock()
        ec2_client.describe_regions.return_value = {
            'Regions': [{'RegionName': 'us-east-1'}, {'RegionName': 'us-west-2'}]
        }
        ec2_client.get_paginator.return_value.paginate.return_value = [
            {
                'SecurityGroups': [
                    {
                        'GroupId': 'sg-123',
                        'GroupName': 'test-sg',
                        'Description': 'Test SG',
                        'IpPermissions': [
                            {
                                'IpProtocol': 'tcp',
                                'FromPort': 80,
                                'ToPort': 80,
                                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                            }
                        ]
                    }
                ]
            }
        ]
        mock_client.return_value = ec2_client
        yield mock_client

def test_find_globally_accessible_security_groups(mock_aws_services):
    '''
    グローバルなインバウンドルールの有無
    '''
    exclusion_rules = []  # 除外ルールなし
    result = list(find_globally_accessible_security_groups(exclusion_rules))

    assert len(result) == 2  # 2つのリージョンそれぞれで1つのSGが見つかる
    assert result[0]['region'] == 'us-east-1'
    assert result[0]['group_id'] == 'sg-123'
    assert result[0]['group_name'] == 'test-sg'
    assert result[1]['region'] == 'us-west-2'
    assert result[1]['group_id'] == 'sg-123'
    assert result[1]['group_name'] == 'test-sg'
