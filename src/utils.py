"""
ユーティリティ関数
"""

import os
import json
import ipaddress

import requests
import boto3
import yaml

def get_all_regions():
    """AWSの全リージョンを取得するジェネレータ"""
    ec2 = boto3.client('ec2')
    regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
    yield from regions

def get_security_groups(region):
    """指定されたリージョンのセキュリティグループを取得するジェネレータ"""
    ec2 = boto3.client('ec2', region_name=region)
    paginator = ec2.get_paginator('describe_security_groups')
    for page in paginator.paginate():
        yield from page['SecurityGroups']

def is_globally_accessible(sg):
    """セキュリティグループがグローバルにアクセス可能かチェック"""
    for permission in sg.get('IpPermissions', []):
        for ip_range in permission.get('IpRanges', []):
            cidr = ip_range.get('CidrIp')
            if cidr:
                try:
                    network = ipaddress.ip_network(cidr)
                    if not network.is_private:
                        return True
                except ValueError:
                    # 無効なCIDRの場合はスキップ
                    continue
    return False

def load_exclusion_rules(file_path):
    """YAMLファイルから除ルールを読み込む"""
    if not os.path.exists(file_path):
        print(f"除外ルールファイル '{file_path}' が見つかりません。除外ルールなしで続行します。")
        return []
    with open(file_path, 'r', encoding='utf-8') as file:
        return yaml.safe_load(file)

def is_excluded(sg, exclusion_rules):
    """セキュリティグループが除外ルールに該当するかチェック"""
    for rule in exclusion_rules:
        if sg['GroupId'] == rule['security_group_id']:
            for permission in sg.get('IpPermissions', []):
                for ip_range in permission.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp')
                    if cidr:
                        for excluded_rule in rule['rules']:
                            if (cidr == excluded_rule['ip_address'] and
                                permission.get('IpProtocol') == excluded_rule['protocol'] and
                                permission['FromPort'] == int(excluded_rule['port_range']['from']) and
                                permission['ToPort'] == int(excluded_rule['port_range']['to'])):
                                return True
    return False

def send_slack_notification(webhook_url, message):
    """Slackに通知を送信する関数"""
    headers = {'Content-Type': 'application/json'}
    payload = {'text': message}
    try:
        response = requests.post(webhook_url, data=json.dumps(payload), headers=headers, timeout=10)  # タイムアウトを追加
        response.raise_for_status()  # エラーがあれば例外を発生させる
        print("Slack通知が正常に送信されました。")
    except requests.exceptions.RequestException as e:
        print(f"Slack通知の送信中にエラーが発生しました: {e}")

def format_slack_message(security_groups):
    """セキュリティグループの情報をSlack通知用にフォーマットする関数"""
    if not security_groups:
        return "グローバルにアクセス可能なセキュリティグループは見つかりませんでした。"
    message = "以下のセキュリティグループにグローバルなインバウンドルールが見つかりました：\n"
    for sg in security_groups:
        message += f"• リージョン: {sg['region']}, セキュリティグループID: {sg['group_id']}, 名前: {sg['group_name']}\n"
    return message

def find_globally_accessible_security_groups(exclusion_rules):
    """全リージョンでグローバルにアクセス可能なセキュリティグループを見つけるジェネレータ（除外ルール適用）"""
    found_groups = []
    for region in get_all_regions():
        for sg in get_security_groups(region):
            if is_globally_accessible(sg) and not is_excluded(sg, exclusion_rules):
                group_info = {
                    'region': region,
                    'group_id': sg['GroupId'],
                    'group_name': sg['GroupName'],
                    'description': sg['Description']
                }
                found_groups.append(group_info)
                yield group_info
    return found_groups

# 使用例（utils.pyで直接テストする場合）
if __name__ == "__main__":
    exrules = load_exclusion_rules('exclusion_rules.yaml')
    for sgs in find_globally_accessible_security_groups(exrules):
        print(f"Region: {sgs['region']}, Group ID: {sgs['group_id']}, Name: {sgs['group_name']}")
