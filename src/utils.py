"""
ユーティリティ関数
"""

import ipaddress
import json
import logging
import os
from collections.abc import Generator
from typing import Any

import boto3
import requests
import yaml
from botocore.exceptions import BotoCoreError, ClientError

try:
    from slack_sdk import WebClient
    from slack_sdk.errors import SlackApiError

    SLACK_SDK_AVAILABLE = True
except ImportError:
    SLACK_SDK_AVAILABLE = False

# ロガーの設定
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_all_regions(config: Any | None = None) -> Generator[str, None, None]:
    """AWSの全リージョンを取得するジェネレータ

    Args:
        config: アプリケーション設定

    Yields:
        str: AWSリージョン名

    Raises:
        BotoCoreError: AWS API呼び出しエラー
        ClientError: AWSクライアントエラー
    """
    try:
        aws_config = None
        if config is not None:
            aws_config = config.get_aws_config()
        elif os.getenv("AWS_TIMEOUT"):
            from src.config import Config

            aws_config = Config.from_env().get_aws_config()

        session = boto3.session.Session()
        ec2 = session.client("ec2", config=aws_config)
        regions = [region["RegionName"] for region in ec2.describe_regions()["Regions"]]
        yield from regions
    except (BotoCoreError, ClientError) as e:
        logger.error("リージョン取得エラー: %s", e)
        raise


def get_security_groups(
    region: str, config: Any | None = None
) -> Generator[dict[str, Any], None, None]:
    """指定されたリージョンのセキュリティグループを取得するジェネレータ

    Args:
        region: AWSリージョン名
        config: アプリケーション設定

    Yields:
        Dict[str, Any]: セキュリティグループの詳細情報

    Note:
        エラーが発生した場合は空のジェネレータを返す
    """
    try:
        aws_config = None
        if config is not None:
            aws_config = config.get_aws_config()
        elif os.getenv("AWS_TIMEOUT"):
            from src.config import Config

            aws_config = Config.from_env().get_aws_config()

        session = boto3.session.Session()
        ec2 = session.client("ec2", region_name=region, config=aws_config)
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            yield from page["SecurityGroups"]
    except (BotoCoreError, ClientError) as e:
        logger.error("リージョン %s でのセキュリティグループ取得エラー: %s", region, e)
        # エラーが発生した場合は空のジェネレータを返す
        return
        yield  # unreachable, but makes the type checker happy


def is_globally_accessible(sg: dict[str, Any]) -> bool:
    """セキュリティグループがグローバルにアクセス可能かチェック

    Args:
        sg: セキュリティグループの詳細情報

    Returns:
        bool: グローバルにアクセス可能な場合True
    """
    for permission in sg.get("IpPermissions", []):
        # IPv4のCIDRをチェック
        for ip_range in permission.get("IpRanges", []):
            cidr = ip_range.get("CidrIp")
            if cidr and _is_global_cidr(cidr):
                return True
        # IPv6のCIDRをチェック
        for ipv6_range in permission.get("Ipv6Ranges", []):
            cidr_ipv6 = ipv6_range.get("CidrIpv6")
            if cidr_ipv6 and _is_global_cidr(cidr_ipv6):
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
        logger.warning("無効なCIDR形式: %s", cidr)
        return False


def load_exclusion_rules(file_path: str) -> list[dict[str, Any]]:
    """YAMLファイルから除外ルールを読み込む

    Args:
        file_path: 除外ルールYAMLファイルのパス

    Returns:
        list[dict[str, Any]]: 除外ルールのリスト。ファイルが存在しない場合は空リスト

    Note:
        ファイルが見つからない場合やYAML解析エラーの場合は空リストを返す
    """
    if not os.path.exists(file_path):
        logger.warning(
            "除外ルールファイル '%s' が見つかりません。除外ルールなしで続行します。", file_path
        )
        return []

    try:
        with open(file_path, encoding="utf-8") as file:
            rules = yaml.safe_load(file)
            return rules if rules is not None else []
    except yaml.YAMLError as e:
        logger.error("YAMLファイル '%s' の読み込みエラー: %s", file_path, e)
        return []
    except OSError as e:
        logger.error("ファイル '%s' の読み込みエラー: %s", file_path, e)
        return []


def is_excluded(sg: dict[str, Any], exclusion_rules: list[dict[str, Any]]) -> bool:
    """セキュリティグループが除外ルールに該当するかチェック

    Args:
        sg: セキュリティグループの詳細情報
        exclusion_rules: 除外ルールのリスト

    Returns:
        bool: 除外ルールに該当する場合True
    """
    sg_id = sg["GroupId"]

    for rule in exclusion_rules:
        if sg_id != rule.get("security_group_id"):
            continue

        for permission in sg.get("IpPermissions", []):
            if _permission_matches_exclusion_rules(permission, rule.get("rules", [])):
                return True
    return False


def _permission_matches_exclusion_rules(
    permission: dict[str, Any], excluded_rules: list[dict[str, Any]]
) -> bool:
    """パーミッションが除外ルールにマッチするかチェックする内部関数

    Args:
        permission: セキュリティグループのパーミッション情報
        excluded_rules: 除外ルールのリスト

    Returns:
        bool: 除外ルールにマッチする場合True
    """
    # IPv4 CIDRのチェック
    for ip_range in permission.get("IpRanges", []):
        cidr = ip_range.get("CidrIp")
        if not cidr:
            continue

        for excluded_rule in excluded_rules:
            if _matches_excluded_rule(permission, cidr, excluded_rule):
                return True

    # IPv6 CIDRのチェック
    for ipv6_range in permission.get("Ipv6Ranges", []):
        cidr_ipv6 = ipv6_range.get("CidrIpv6")
        if not cidr_ipv6:
            continue

        for excluded_rule in excluded_rules:
            if _matches_excluded_rule(permission, cidr_ipv6, excluded_rule):
                return True

    return False


def _matches_excluded_rule(
    permission: dict[str, Any], cidr: str, excluded_rule: dict[str, Any]
) -> bool:
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
        return (
            cidr == excluded_rule.get("ip_address")
            and permission.get("IpProtocol") == excluded_rule.get("protocol")
            and permission.get("FromPort")
            == int(excluded_rule.get("port_range", {}).get("from", -1))
            and permission.get("ToPort") == int(excluded_rule.get("port_range", {}).get("to", -1))
        )
    except (ValueError, TypeError, KeyError) as e:
        logger.warning("除外ルールのマッチング処理中にエラー: %s", e)
        return False


def send_slack_notification(webhook_url: str, message: str) -> bool:
    """Slackに通知を送信する関数（Incoming Webhook使用）

    Args:
        webhook_url: Slack WebhookのURL
        message: 送信するメッセージ

    Returns:
        bool: 送信成功時はTrue、失敗時はFalse

    Raises:
        requests.exceptions.RequestException: HTTP通信エラー（内部でキャッチされる）
    """
    headers = {"Content-Type": "application/json"}
    payload = {"text": message}

    try:
        response = requests.post(webhook_url, data=json.dumps(payload), headers=headers, timeout=10)
        response.raise_for_status()
        logger.info("Slack通知が正常に送信されました。")
        return True
    except requests.exceptions.RequestException as e:
        logger.error("Slack通知の送信中にエラーが発生しました: %s", e)
        return False


def send_slack_notification_sdk(bot_token: str, channel: str, message: str) -> bool:
    """Slack SDKを使用してSlackに通知を送信する関数

    Args:
        bot_token: Slack Bot Token
        channel: 送信先チャンネル名（#付きまたはチャンネルID）
        message: 送信するメッセージ

    Returns:
        bool: 送信成功時はTrue、失敗時はFalse

    Note:
        slack-sdkが利用できない場合はFalseを返す
    """
    if not SLACK_SDK_AVAILABLE:
        logger.error(
            "slack-sdk が利用できません。pip install slack-sdk でインストールしてください。"
        )
        return False

    try:
        client = WebClient(token=bot_token)
        response = client.chat_postMessage(
            channel=channel, text=message, username="NeKo_AWS_SG", icon_emoji=":warning:"
        )

        if response["ok"]:
            logger.info("Slack通知が正常に送信されました（SDK使用）。")
            return True
        else:
            logger.error(
                "Slack通知の送信に失敗しました: %s", response.get("error", "Unknown error")
            )
            return False

    except SlackApiError as e:
        logger.error("Slack API エラー: %s", e.response["error"])
        return False
    except Exception as e:
        logger.error("Slack通知の送信中にエラーが発生しました: %s", e)
        return False


def format_slack_message(security_groups: list[dict[str, str]]) -> str:
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


def has_unexcluded_global_access(sg: dict[str, Any], exclusion_rules: list[dict[str, Any]]) -> bool:
    """セキュリティグループ内に、除外されていないグローバルアクセス可能なルールがあるか判定

    Args:
        sg: セキュリティグループの詳細情報
        exclusion_rules: 除外ルールのリスト

    Returns:
        bool: 除外されていないグローバルアクセス可能なルールがある場合True
    """
    sg_id = sg["GroupId"]

    # 該当するSGの除外ルールを取得
    sg_rules = []
    for rule in exclusion_rules:
        if rule.get("security_group_id") == sg_id:
            sg_rules.extend(rule.get("rules", []))

    for permission in sg.get("IpPermissions", []):
        # IPv4のチェック
        for ip_range in permission.get("IpRanges", []):
            cidr = ip_range.get("CidrIp")
            if cidr and _is_global_cidr(cidr):
                # このCIDRが除外ルールにマッチするかチェック
                excluded = False
                for excluded_rule in sg_rules:
                    if _matches_excluded_rule(permission, cidr, excluded_rule):
                        excluded = True
                        break
                if not excluded:
                    return True

        # IPv6のチェック
        for ipv6_range in permission.get("Ipv6Ranges", []):
            cidr_ipv6 = ipv6_range.get("CidrIpv6")
            if cidr_ipv6 and _is_global_cidr(cidr_ipv6):
                # このCIDRが除外ルールにマッチするかチェック
                excluded = False
                for excluded_rule in sg_rules:
                    if _matches_excluded_rule(permission, cidr_ipv6, excluded_rule):
                        excluded = True
                        break
                if not excluded:
                    return True

    return False


def find_globally_accessible_security_groups(
    exclusion_rules: list[dict[str, Any]],
    config: Any | None = None,
) -> Generator[dict[str, str], None, None]:
    """全リージョンでグローバルにアクセス可能なセキュリティグループを見つけるジェネレータ（除外ルール適用）

    Args:
        exclusion_rules: 除外ルールのリスト
        config: アプリケーション設定

    Yields:
        dict[str, str]: グローバルアクセス可能なセキュリティグループの情報
            - region: リージョン名
            - group_id: セキュリティグループID
            - group_name: セキュリティグループ名
            - description: セキュリティグループの説明
    """
    from concurrent.futures import ThreadPoolExecutor

    try:
        regions = list(get_all_regions(config))
    except Exception as e:
        logger.error("リージョン一覧の取得に失敗しました: %s", e)
        return

    def scan_region(region: str) -> list[dict[str, str]]:
        logger.info("リージョン %s を検索中...", region)
        found = []
        for sg in get_security_groups(region, config):
            if has_unexcluded_global_access(sg, exclusion_rules):
                group_info = {
                    "region": region,
                    "group_id": sg["GroupId"],
                    "group_name": sg["GroupName"],
                    "description": sg.get("Description", ""),
                }
                logger.info(
                    "グローバルアクセス可能なSG発見: %s in %s", group_info["group_id"], region
                )
                found.append(group_info)
        return found

    # ThreadPoolExecutorを使用してリージョンごとのスキャンを並列化
    max_workers = min(len(regions), 10) if regions else 1
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_region, region): region for region in regions}
        for future in futures:
            region = futures[future]
            try:
                results = future.result()
                yield from results
            except Exception as e:
                logger.error("リージョン %s のスキャン中にエラーが発生しました: %s", region, e)
