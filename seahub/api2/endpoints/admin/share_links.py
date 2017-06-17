# Copyright (c) 2012-2016 Seafile Ltd.
import os
import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from django.contrib.auth.hashers import check_password

from seaserv import seafile_api

from seahub.api2.utils import api_error
from seahub.api2.endpoints.utils import get_share_link_info
from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle

from seahub.share.models import FileShare
from seahub.utils import gen_file_get_url

logger = logging.getLogger(__name__)


class AdminShareLink(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, token):
        """ Get a special share link info.

        Permission checking:
        1. only admin can perform this action.
        """

        try:
            sharelink = FileShare.objects.get(token=token)
        except FileShare.DoesNotExist:
            error_msg = 'Share link %s not found.' % token
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        link_info = get_share_link_info(sharelink)
        return Response(link_info)

class AdminShareLinkFileServerUrl(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, token):
        """ Get FileServer url of the shared file.

        Permission checking:
        1. only admin can perform this action.
        """

        try:
            sharelink = FileShare.objects.get(token=token)
        except FileShare.DoesNotExist:
            error_msg = 'Share link %s not found.' % token
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        repo_id = sharelink.repo_id
        path = sharelink.path
        obj_id = seafile_api.get_file_id_by_path(repo_id, path)
        if not obj_id:
            error_msg = 'File not found.'
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        obj_name = os.path.basename(path.rstrip('/'))

        view_token = seafile_api.get_fileserver_access_token(repo_id,
                obj_id, 'view', '', use_onetime=False)

        if not view_token:
            logger.error('FileServer access token %s invalid' % view_token)
            view_url = ''
        else:
            view_url = gen_file_get_url(view_token, obj_name)

        download_token = seafile_api.get_fileserver_access_token(repo_id,
                obj_id, 'download', '', use_onetime=True)

        if not download_token:
            logger.error('FileServer access token %s invalid' % download_token)
            download_url= ''
        else:
            download_url = gen_file_get_url(download_token, obj_name)

        result = {}
        result['view'] = view_url
        result['download'] = download_url

        return Response(result)

class AdminShareLinkCheckPassword(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def post(self, request, token):
        """ Check if password for an encrypted share link is correct.

        Permission checking:
        1. only admin can perform this action.
        """

        try:
            sharelink = FileShare.objects.get(token=token)
        except FileShare.DoesNotExist:
            error_msg = 'Share link %s not found.' % token
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if not sharelink.is_encrypted():
            error_msg = 'Share link is not encrypted.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        password = request.POST.get('password')
        if not password:
            error_msg = 'password invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if check_password(password, sharelink.password):
            return Response({'success': True})
        else:
            error_msg = 'Password is not correct.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)
