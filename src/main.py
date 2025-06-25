"""
AWSセキュリティグループのグローバルアクセス可能なインバウンドルールを検索し、Slackに通知するスクリプト
"""

import logging
import os
import sys

from dotenv import load_dotenv

from cli import parse_args
from config import Config
from utils import (
    find_globally_accessible_security_groups,
    format_slack_message,
    load_exclusion_rules,
    send_slack_notification,
    send_slack_notification_sdk,
)


def scan_security_groups() -> None:
    """
    セキュリティグループをスキャンしてグローバルアクセス可能なルールを検出
    """
    # .envファイルを読み込む
    load_dotenv()

    # 設定を読み込む
    config = Config.from_env()

    # ロガーの設定
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
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
            logger.info(
                "検索完了。%d個のセキュリティグループにグローバルなインバウンドルールが見つかりました。",
                len(found_groups),
            )
            for sg in found_groups:
                logger.info(
                    "リージョン: %s, セキュリティグループID: %s", sg["region"], sg["group_id"]
                )

            # Slack通知の処理
            _send_slack_notification_if_configured(config, found_groups)

    except Exception as e:
        logger.error("実行中にエラーが発生しました: %s", e)
        raise


def main() -> None:
    """
    メイン関数 - CLIサブコマンドを処理

    環境変数:
        SLACK_WEBHOOK_URL: Slack Webhook URL（オプション）
        EXCLUSION_RULES_FILE: 除外ルールファイルのパス（デフォルト: ../config/exclusion_rules.yaml）
        LOG_LEVEL: ログレベル（デフォルト: INFO）
        AWS_TIMEOUT: AWS APIタイムアウト（秒、デフォルト: 10）

    Raises:
        Exception: AWS APIエラー、ファイル読み込みエラーなど
    """
    args = parse_args()

    # サブコマンドが指定されていない場合、またはscanの場合はスキャンを実行
    if not args.command or args.command == "scan":
        scan_security_groups()
    else:
        # サブコマンドの処理を実行
        result = args.func(args)
        sys.exit(result)


def _send_slack_notification_if_configured(
    config: Config, found_groups: list[dict[str, str]]
) -> None:
    """設定されている場合のみSlack通知を送信する内部関数

    Args:
        config: アプリケーション設定
        found_groups: 発見されたグローバルアクセス可能なセキュリティグループのリスト

    Note:
        Slack SDK使用フラグが有効な場合はSlack SDKを使用し、
        それ以外の場合は従来のIncoming Webhookを使用する
    """
    logger = logging.getLogger(__name__)

    message = format_slack_message(found_groups)
    success = False

    # Slack SDK使用が有効で、必要な設定が揃っている場合
    if config.use_slack_sdk and config.slack_bot_token:
        logger.info("Slack SDK を使用して通知を送信します。")
        success = send_slack_notification_sdk(config.slack_bot_token, config.slack_channel, message)
        if not success:
            logger.warning("Slack SDK による通知送信に失敗しました。")

    # Slack SDKが失敗した場合や使用しない場合、Webhookにフォールバック
    if not success and config.slack_webhook_url:
        logger.info("Incoming Webhook を使用して通知を送信します。")
        success = send_slack_notification(config.slack_webhook_url, message)
        if not success:
            logger.warning("Incoming Webhook による通知送信に失敗しました。")

    # 両方とも設定されていない場合
    if (
        not success
        and not config.slack_webhook_url
        and not (config.use_slack_sdk and config.slack_bot_token)
    ):
        logger.warning(
            "Slack通知の設定がされていません。以下のいずれかを設定してください:\n"
            "  - SLACK_WEBHOOK_URL (Incoming Webhook使用)\n"
            "  - SLACK_BOT_TOKEN + USE_SLACK_SDK=true (Slack SDK使用)"
        )


if __name__ == "__main__":
    main()
