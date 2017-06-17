# -*- coding: utf-8 -*-
import json

from tests.common.utils import randstring
from django.core.urlresolvers import reverse
from seahub.test_utils import BaseTestCase
from seahub.share.models import UploadLinkShare

try:
    from seahub.settings import LOCAL_PRO_DEV_ENV
except ImportError:
    LOCAL_PRO_DEV_ENV = False

class UploadLinksTest(BaseTestCase):

    def setUp(self):
        self.repo_id = self.repo.id
        self.folder_path= self.folder

    def tearDown(self):
        self.remove_repo()

    def _add_upload_link(self, password=None):
        fs = UploadLinkShare.objects.create_upload_link_share(
                self.user.username, self.repo.id, self.folder_path, password, None)

        return fs.token

    def _remove_upload_link(self, token):
        link = UploadLinkShare.objects.get(token=token)
        link.delete()

    def test_get_upload_link_info_by_token(self):
        self.login_as(self.admin)
        token = self._add_upload_link()

        url = reverse('api-v2.1-admin-upload-link', args=[token])
        resp = self.client.get(url)
        self.assertEqual(200, resp.status_code)

        json_resp = json.loads(resp.content)

        assert json_resp['token'] == token

        self._remove_upload_link(token)

    def test_get_upload_link_info_with_invalid_permission(self):
        self.login_as(self.user)
        token = self._add_upload_link()

        url = reverse('api-v2.1-admin-upload-link', args=[token])
        resp = self.client.get(url)
        self.assertEqual(403, resp.status_code)

        self._remove_upload_link(token)


class UploadLinkFileServerUrlTest(BaseTestCase):

    def setUp(self):
        self.repo_id = self.repo.id
        self.folder_path= self.folder

    def tearDown(self):
        self.remove_repo()

    def _add_upload_link(self, password=None):
        fs = UploadLinkShare.objects.create_upload_link_share(
                self.user.username, self.repo.id, self.folder_path, password, None)

        return fs.token

    def _remove_upload_link(self, token):
        link = UploadLinkShare.objects.get(token=token)
        link.delete()

    def test_get_fileserver_url(self):
        self.login_as(self.admin)
        token = self._add_upload_link()

        url = reverse('api-v2.1-admin-upload-link-fileserver-url', args=[token])
        resp = self.client.get(url)
        self.assertEqual(200, resp.status_code)

        json_resp = json.loads(resp.content)

        assert '8082' in json_resp['upload']

        self._remove_upload_link(token)

    def test_get_fileserver_url_with_invalid_permission(self):
        self.login_as(self.user)
        token = self._add_upload_link()

        url = reverse('api-v2.1-admin-upload-link-fileserver-url', args=[token])
        resp = self.client.get(url)
        self.assertEqual(403, resp.status_code)

        self._remove_upload_link(token)


class UploadLinkCheckPasswordTest(BaseTestCase):

    def setUp(self):
        self.repo_id = self.repo.id
        self.folder_path= self.folder

    def tearDown(self):
        self.remove_repo()

    def _add_upload_link(self, password=None):
        fs = UploadLinkShare.objects.create_upload_link_share(
                self.user.username, self.repo.id, self.folder_path, password, None)

        return fs.token

    def _remove_upload_link(self, token):
        link = UploadLinkShare.objects.get(token=token)
        link.delete()

    def test_check_password(self):
        self.login_as(self.admin)

        password = randstring(10)
        token = self._add_upload_link(password)
        url = reverse('api-v2.1-admin-upload-link-check-password', args=[token])

        resp = self.client.post(url, {'password': password})
        self.assertEqual(200, resp.status_code)

        self._remove_upload_link(token)

    def test_check_password_with_invalid_permission(self):
        self.login_as(self.user)

        password = randstring(10)
        token = self._add_upload_link(password)
        url = reverse('api-v2.1-admin-upload-link-check-password', args=[token])

        resp = self.client.post(url, {'password': password})
        self.assertEqual(403, resp.status_code)

        self._remove_upload_link(token)

    def test_invalid_password(self):
        self.login_as(self.admin)

        password = randstring(10)
        token = self._add_upload_link(password)
        url = reverse('api-v2.1-admin-upload-link-check-password', args=[token])

        resp = self.client.post(url, {'password': 'invalid_password'})
        self.assertEqual(403, resp.status_code)

        self._remove_upload_link(token)
