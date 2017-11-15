#! -*- coding: utf-8 -*-

from __future__ import absolute_import

import json
import logging
import requests

import sentry
from django import forms
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from sentry.exceptions import PluginError
from sentry.http import is_valid_url, safe_urlopen
from sentry.plugins.bases import notify


def split_urls(value):
    if not value:
        return ()

    return filter(bool, (url.strip() for url in value.splitlines()))


def validate_urls(value, **kwargs):
    urls = split_urls(value)
    if any((not u.startswith(("http://", "https://")) or
                not is_valid_url(u)) for u in urls):
        raise PluginError("Not a valid url")

    return "\n".join(urls)


class DingTalkForm(notify.NotificationConfigurationForm):
    urls = forms.CharField(
        label=_("DingTalk robot webhook urls"),
        widget=forms.Textarea(attrs={
            "class": "span6",
            "placeholder": "https://oapi.dingtalk.com/robot/send?access_token=***"
        }),
        help_text=_("Enter DingTalk robot webhook urls (one per line).")
    )


class DingTalkPlugin(notify.NotificationPlugin):
    author = "hifiveszu"
    author_url = "https://github.com/hifiveszu/sentry-dingtalk"
    version = sentry.VERSION
    description = "Integrates DingTalk robot."
    resource_links = [
        ("Bug Tracker", "https://github.com/hifiveszu/sentry-dingtalk/issues"),
        ("Source", 'https://github.com/hifiveszu/sentry-dingtalk'),
    ]

    slug = 'dingtalk'
    title = 'dingtalk'
    conf_title = title
    conf_key = 'dingtalk'

    project_conf_form = DingTalkForm
    timeout = getattr(settings, 'SENTRY_DINGTALK_TIMEOUT', 3)
    logger = logging.getLogger('sentry.plugins.dingtalk')

    def is_configured(self, project, **kwargs):
        return bool(self.get_option('urls', project))

    def get_config(self, project, **kwargs):
        return [
            {
                'name': 'urls',
                'label': 'DingTalk robot webhook urls',
                'type': 'textarea',
                'help': 'Enter DingTalk robot webhook urls (one per line).',
                'placeholder': 'https://oapi.dingtalk.com/robot/send?access_token=***',
                'validators': [validate_urls],
                'required': True
            }
        ]

    def get_webhook_urls(self, project):
        return split_urls(self.get_option("urls", project))

    def send_webhook(self, url, payload):
        return safe_urlopen(
            url=url,
            json=payload,
            timeout=self.timeout,
            verify_ssl=False,
        )

    def notify_users(self, group, event, fail_silently=False):
        """ send DingTalk link type message
        DingTalk docs: https://open-doc.dingtalk.com/docs/doc.htm?treeId=257&articleId=105735&docType=1
        """
        project_name = group.project.name
        level = group.get_level_display().upper()
        error_count = group.times_seen
        error_message = event.get_legacy_message()
        error_link = group.get_absolute_url()
        sentry_img_url = u"https://sdkfiledl.jiguang.cn/public/4f34cb109a184038b5dae9c4933f8bac.png"
        title = u"Sentry日志告警"
        text = (
            u'{project}发生{count}次{level}级别异常, 异常信息：'
            u'{message}'.format(
                level=level,
                project=project_name,
                count=error_count,
                message=error_message)
        )

        payload = dict(
            msgtype="link",
            link=dict(
                text=text,
                title=title,
                picUrl=sentry_img_url,
                messageUrl=error_link
            )
        )
        webhook_urls = self.get_webhook_urls(group.project)
        self.send_notification(webhook_urls, payload)

    def send_notification(self, webhook_urls, payload):
        headers = {
            'Content-type': 'application/json',
            'Accept': 'text/plain'
        }
        session = requests.session()

        for url in webhook_urls:
            session.request(
                method='POST',
                url=url,
                data=json.dumps(payload),
                headers=headers)

            # TODO: If DingTalk return error, show it to console
