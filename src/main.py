"""
AWSセキュリティグループのグローバルアクセス可能なインバウンドルールを検索し、Slackに通知するスクリプト
"""

import os
import logging
from typing import List, Dict, Any

from dotenv import load_dotenv
from config import Config
from utils import (
    load_exclusion_rules,
    find_globally_accessible_security_groups,
    format_slack_message,
    send_slack_notification
)

def main() -> None:
    """
    AWSセキュリティグループのグローバルアクセス可能なインバウンドルールを検索し、Slackに通知するメイン処理
    
    環境変数:
        SLACK_WEBHOOK_URL: Slack Webhook URL（オプション）
        EXCLUSION_RULES_FILE: 除外ルールファイルのパス（デフォルト: ../config/exclusion_rules.yaml）
        LOG_LEVEL: ログレベル（デフォルト: INFO）
        AWS_TIMEOUT: AWS APIタイムアウト（秒、デフォルト: 10）
        
    Raises:
        Exception: AWS APIエラー、ファイル読み込みエラーなど
    """
    # .envファイルを読み込む
    load_dotenv()
    
    # 設定を読み込む
    config = Config.from_env()
    
    # ロガーの設定
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)
    
    try:
        # スクリプトのディレクトリを取得
        script_dir = os.path.dirname(os.path.abspath(__file__))
        exclusion_rules_file = config.get_exclusion_rules_path(script_dir)

        exclusion_rules = load_exclusion_rules(exclusion_rules_file)

        logger.info("グローバルにアクセス可能なセキュリティグループを検索中...")
        found_groups = list(find_globally_accessible_security_groups(exclusion_rules))

        if not found_groups:
            logger.info("グローバルにアクセス可能なセキュリティグループは見つかりませんでした。")
        else:
            logger.info(f"検索完了。{len(found_groups)}個のセキュリティグループにグローバルなインバウンドルールが見つかりました。")
            for sg in found_groups:
                logger.info(f"リージョン: {sg['region']}, セキュリティグループID: {sg['group_id']}")
            
            # Slack通知の処理
            _send_slack_notification_if_configured(config, found_groups)
            
    except Exception as e:
        logger.error(f"実行中にエラーが発生しました: {e}")
        raise

def _send_slack_notification_if_configured(config: Config, found_groups: List[Dict[str, str]]) -> None:
    """設定されている場合のみSlack通知を送信する内部関数
    
    Args:
        config: アプリケーション設定
        found_groups: 発見されたグローバルアクセス可能なセキュリティグループのリスト
        
    Note:
        SLACK_WEBHOOK_URLが設定されていない場合は警告メッセージをログ出力
    """
    logger = logging.getLogger(__name__)
    
    if config.slack_webhook_url:
        message = format_slack_message(found_groups)
        success = send_slack_notification(config.slack_webhook_url, message)
        if not success:
            logger.warning("Slack通知の送信に失敗しました。")
    else:
        logger.warning("SLACK_WEBHOOK_URL環境変数が設定されていないため、Slack通知は送信されません。")

if __name__ == "__main__":
    main()
