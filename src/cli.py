"""
CLIサブコマンド関連の機能
"""

import argparse
import os
import sys
from pathlib import Path

import yaml

from config import Config
from utils import get_security_groups, get_all_regions


def create_exclusion_rule_entry(sg_id: str, sg_info: dict = None) -> dict:
    """除外ルールのエントリを作成"""
    entry = {
        "security_group_id": sg_id,
        "description": f"Excluded security group: {sg_id}",
        "rules": [],
    }

    if sg_info:
        entry["description"] = (
            f"Excluded: {sg_info.get('GroupName', sg_id)} ({sg_info.get('Description', '')})"
        )

        # セキュリティグループのルールを除外ルールとして追加
        for permission in sg_info.get("IpPermissions", []):
            for ip_range in permission.get("IpRanges", []):
                cidr = ip_range.get("CidrIp")
                if cidr:
                    rule = {
                        "ip_address": cidr,
                        "protocol": permission.get("IpProtocol", "tcp"),
                        "port_range": {
                            "from": permission.get("FromPort", 0),
                            "to": permission.get("ToPort", 0),
                        },
                    }
                    entry["rules"].append(rule)

    return entry


def find_security_group(sg_id: str) -> dict | None:
    """指定されたセキュリティグループIDを全リージョンから検索"""
    print(f"セキュリティグループ {sg_id} を検索中...")

    for region in get_all_regions():
        print(f"  リージョン {region} を検索中...")
        for sg in get_security_groups(region):
            if sg["GroupId"] == sg_id:
                print(f"  見つかりました: {region}")
                sg["Region"] = region  # リージョン情報を追加
                return sg

    print(f"  セキュリティグループ {sg_id} が見つかりませんでした")
    return None


def load_or_create_exclusion_rules(file_path: str) -> list:
    """除外ルールファイルを読み込み、存在しない場合は空リストを返す"""
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                content = yaml.safe_load(file)
                return content if content is not None else []
        except yaml.YAMLError as e:
            print(f"警告: YAMLファイルの読み込みエラー: {e}")
            return []
        except OSError as e:
            print(f"警告: ファイル読み込みエラー: {e}")
            return []
    else:
        # ディレクトリが存在しない場合は作成
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        return []


def save_exclusion_rules(file_path: str, rules: list) -> bool:
    """除外ルールファイルを保存"""
    try:
        with open(file_path, "w", encoding="utf-8") as file:
            yaml.dump(rules, file, default_flow_style=False, allow_unicode=True, sort_keys=False)
        return True
    except OSError as e:
        print(f"エラー: ファイル保存エラー: {e}")
        return False


def add_exclusion_command(sg_id: str, auto_detect: bool = True) -> int:
    """除外ルール追加コマンドの実行"""
    # 設定を読み込む
    config = Config.from_env()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    exclusion_rules_file = config.get_exclusion_rules_path(script_dir)

    print(f"除外ルールファイル: {exclusion_rules_file}")

    # 既存の除外ルールを読み込み
    exclusion_rules = load_or_create_exclusion_rules(exclusion_rules_file)

    # 既に除外されているかチェック
    for rule in exclusion_rules:
        if rule.get("security_group_id") == sg_id:
            print(f"セキュリティグループ {sg_id} は既に除外ルールに含まれています。")
            return 0

    sg_info = None
    if auto_detect:
        # セキュリティグループ情報を自動取得
        sg_info = find_security_group(sg_id)
        if not sg_info:
            print(
                f"警告: セキュリティグループ {sg_id} が見つかりませんでした。基本的な除外ルールを作成します。"
            )

    # 除外ルールエントリを作成
    new_rule = create_exclusion_rule_entry(sg_id, sg_info)
    exclusion_rules.append(new_rule)

    # ファイルに保存
    if save_exclusion_rules(exclusion_rules_file, exclusion_rules):
        print(f"除外ルールを追加しました: {sg_id}")
        if sg_info:
            print(f"  名前: {sg_info.get('GroupName', 'N/A')}")
            print(f"  説明: {sg_info.get('Description', 'N/A')}")
            print(f"  リージョン: {sg_info.get('Region', 'N/A')}")
            print(f"  ルール数: {len(new_rule['rules'])}")
        return 0
    else:
        print("エラー: 除外ルールの保存に失敗しました。")
        return 1


def setup_exclude_parser(subparsers):
    """exclude サブコマンドのパーサーを設定"""
    exclude_parser = subparsers.add_parser(
        "exclude",
        help="セキュリティグループを除外ルールに追加",
        description="指定されたセキュリティグループIDを除外ルールに追加します。",
    )
    exclude_parser.add_argument(
        "security_group_id", help="除外するセキュリティグループID (例: sg-1234567890abcdef0)"
    )
    exclude_parser.add_argument(
        "--no-auto-detect", action="store_true", help="セキュリティグループの自動検索を無効にする"
    )
    exclude_parser.set_defaults(
        func=lambda args: add_exclusion_command(args.security_group_id, not args.no_auto_detect)
    )


def create_main_parser() -> argparse.ArgumentParser:
    """メインのargparseパーサーを作成"""
    parser = argparse.ArgumentParser(description="NeKo_AWS_SG - AWSセキュリティグループ監視ツール")

    subparsers = parser.add_subparsers(dest="command", help="利用可能なコマンド")

    # scan サブコマンド（デフォルトの動作）
    scan_parser = subparsers.add_parser(
        "scan",
        help="セキュリティグループをスキャン",
        description="AWSセキュリティグループをスキャンしてグローバルアクセス可能なルールを検出します。",
    )
    scan_parser.set_defaults(func=lambda args: 0)  # main()関数で処理

    # exclude サブコマンド
    setup_exclude_parser(subparsers)

    return parser


def parse_args(args=None):
    """コマンドライン引数を解析"""
    parser = create_main_parser()
    return parser.parse_args(args)
