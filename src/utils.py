"""
ユーティリティ関数
"""

import os
import json
import ipaddress
import logging
from typing import Dict, List, Generator, Optional, Any

import requests
import boto3
import yaml
from botocore.exceptions import BotoCoreError, ClientError

# ロガーの設定
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_all_regions() -> Generator[str, None, None]:
    """AWSの全リージョンを取得するジェネレータ
    
    Yields:
        str: AWSリージョン名
        
    Raises:
        BotoCoreError: AWS API呼び出しエラー
        ClientError: AWSクライアントエラー
    """
    try:
        ec2 = boto3.client('ec2')
        regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
        yield from regions
    except (BotoCoreError, ClientError) as e:
        logger.error(f"リージョン取得エラー: {e}")
        raise

def get_security_groups(region: str) -> Generator[Dict[str, Any], None, None]:
    """指定されたリージョンのセキュリティグループを取得するジェネレータ
    
    Args:
        region: AWSリージョン名
        
    Yields:
        Dict[str, Any]: セキュリティグループの詳細情報
        
    Note:
        エラーが発生した場合は空のジェネレータを返す
    """
    try:
        ec2 = boto3.client('ec2', region_name=region)
        paginator = ec2.get_paginator('describe_security_groups')
        for page in paginator.paginate():
            yield from page['SecurityGroups']
    except (BotoCoreError, ClientError) as e:
        logger.error(f"リージョン {region} でのセキュリティグループ取得エラー: {e}")
        # エラーが発生した場合は空のジェネレータを返す
        return
        yield  # unreachable, but makes the type checker happy

def is_globally_accessible(sg: Dict[str, Any]) -> bool:
    """セキュリティグループがグローバルにアクセス可能かチェック
    
    Args:
        sg: セキュリティグループの詳細情報
        
    Returns:
        bool: グローバルにアクセス可能な場合True
    """
    for permission in sg.get('IpPermissions', []):
        for ip_range in permission.get('IpRanges', []):
            cidr = ip_range.get('CidrIp')
            if cidr and _is_global_cidr(cidr):
                return True
    return False

def _is_global_cidr(cidr: str) -> bool:
    """CIDRがグローバルアクセス可能かどうかをチェックする内部関数
    
    Args:
        cidr: チェック対象のCIDR記法のIPアドレス範囲
        
    Returns:
        bool: グローバルアクセス可能な場合True、プライベート・無効な場合False
    """
    try:
        network = ipaddress.ip_network(cidr)
        return not network.is_private
    except ValueError:
        logger.warning(f"無効なCIDR形式: {cidr}")
        return False

def load_exclusion_rules(file_path: str) -> List[Dict[str, Any]]:
    """YAMLファイルから除外ルールを読み込む
    
    Args:
        file_path: 除外ルールYAMLファイルのパス
        
    Returns:
        List[Dict[str, Any]]: 除外ルールのリスト。ファイルが存在しない場合は空リスト
        
    Note:
        ファイルが見つからない場合やYAML解析エラーの場合は空リストを返す
    """
    if not os.path.exists(file_path):
        logger.warning(f"除外ルールファイル '{file_path}' が見つかりません。除外ルールなしで続行します。")
        return []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            rules = yaml.safe_load(file)
            return rules if rules is not None else []
    except yaml.YAMLError as e:
        logger.error(f"YAMLファイル '{file_path}' の読み込みエラー: {e}")
        return []
    except IOError as e:
        logger.error(f"ファイル '{file_path}' の読み込みエラー: {e}")
        return []

def is_excluded(sg: Dict[str, Any], exclusion_rules: List[Dict[str, Any]]) -> bool:
    """セキュリティグループが除外ルールに該当するかチェック
    
    Args:
        sg: セキュリティグループの詳細情報
        exclusion_rules: 除外ルールのリスト
        
    Returns:
        bool: 除外ルールに該当する場合True
    """
    sg_id = sg['GroupId']
    
    for rule in exclusion_rules:
        if sg_id != rule.get('security_group_id'):
            continue
            
        for permission in sg.get('IpPermissions', []):
            if _permission_matches_exclusion_rules(permission, rule.get('rules', [])):
                return True
    return False

def _permission_matches_exclusion_rules(permission: Dict[str, Any], excluded_rules: List[Dict[str, Any]]) -> bool:
    """パーミッションが除外ルールにマッチするかチェックする内部関数
    
    Args:
        permission: セキュリティグループのパーミッション情報
        excluded_rules: 除外ルールのリスト
        
    Returns:
        bool: 除外ルールにマッチする場合True
    """
    for ip_range in permission.get('IpRanges', []):
        cidr = ip_range.get('CidrIp')
        if not cidr:
            continue
            
        for excluded_rule in excluded_rules:
            if _matches_excluded_rule(permission, cidr, excluded_rule):
                return True
    return False

def _matches_excluded_rule(permission: Dict[str, Any], cidr: str, excluded_rule: Dict[str, Any]) -> bool:
    """個別の除外ルールとマッチするかチェックする内部関数
    
    Args:
        permission: セキュリティグループのパーミッション情報
        cidr: CIDR記法のIPアドレス範囲
        excluded_rule: 個別の除外ルール
        
    Returns:
        bool: 除外ルールにマッチする場合True
        
    Note:
        ルール形式エラーが発生した場合はFalseを返す
    """
    try:
        return (cidr == excluded_rule.get('ip_address') and
                permission.get('IpProtocol') == excluded_rule.get('protocol') and
                permission.get('FromPort') == int(excluded_rule.get('port_range', {}).get('from', -1)) and
                permission.get('ToPort') == int(excluded_rule.get('port_range', {}).get('to', -1)))
    except (ValueError, TypeError, KeyError) as e:
        logger.warning(f"除外ルールのマッチング処理中にエラー: {e}")
        return False

def send_slack_notification(webhook_url: str, message: str) -> bool:
    """Slackに通知を送信する関数
    
    Args:
        webhook_url: Slack WebhookのURL
        message: 送信するメッセージ
        
    Returns:
        bool: 送信成功時はTrue、失敗時はFalse
        
    Raises:
        requests.exceptions.RequestException: HTTP通信エラー（内部でキャッチされる）
    """
    headers = {'Content-Type': 'application/json'}
    payload = {'text': message}
    
    try:
        response = requests.post(
            webhook_url, 
            data=json.dumps(payload), 
            headers=headers, 
            timeout=10
        )
        response.raise_for_status()
        logger.info("Slack通知が正常に送信されました。")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Slack通知の送信中にエラーが発生しました: {e}")
        return False

def format_slack_message(security_groups: List[Dict[str, str]]) -> str:
    """セキュリティグループの情報をSlack通知用にフォーマットする関数
    
    Args:
        security_groups: セキュリティグループ情報のリスト
        
    Returns:
        str: Slack通知用にフォーマットされたメッセージ
    """
    if not security_groups:
        return "グローバルにアクセス可能なセキュリティグループは見つかりませんでした。"
    
    message = "以下のセキュリティグループにグローバルなインバウンドルールが見つかりました：\n"
    for sg in security_groups:
        message += f"• リージョン: {sg['region']}, セキュリティグループID: {sg['group_id']}, 名前: {sg['group_name']}\n"
    return message

def find_globally_accessible_security_groups(exclusion_rules: List[Dict[str, Any]]) -> Generator[Dict[str, str], None, None]:
    """全リージョンでグローバルにアクセス可能なセキュリティグループを見つけるジェネレータ（除外ルール適用）
    
    Args:
        exclusion_rules: 除外ルールのリスト
        
    Yields:
        Dict[str, str]: グローバルアクセス可能なセキュリティグループの情報
            - region: リージョン名
            - group_id: セキュリティグループID
            - group_name: セキュリティグループ名
            - description: セキュリティグループの説明
    """
    for region in get_all_regions():
        logger.info(f"リージョン {region} を検索中...")
        for sg in get_security_groups(region):
            if is_globally_accessible(sg) and not is_excluded(sg, exclusion_rules):
                group_info = {
                    'region': region,
                    'group_id': sg['GroupId'],
                    'group_name': sg['GroupName'],
                    'description': sg['Description']
                }
                logger.info(f"グローバルアクセス可能なSG発見: {group_info['group_id']} in {region}")
                yield group_info

