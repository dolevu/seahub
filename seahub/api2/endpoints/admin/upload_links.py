# Copyright (c) 2012-2016 Seafile Ltd.
import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from django.contrib.auth.hashers import check_password

from seaserv import seafile_api

from seahub.api2.utils import api_error
from seahub.api2.endpoints.utils import get_upload_link_info
from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle

from seahub.utils import gen_file_upload_url

from seahub.share.models import UploadLinkShare

logger = logging.getLogger(__name__)


class AdminUploadLink(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, token):
        """ Get a special upload link info.

        Permission checking:
        1. only admin can perform this action.
        """

        try:
            uploadlink = UploadLinkShare.objects.get(token=token)
        except UploadLinkShare.DoesNotExist:
            error_msg = 'Upload link %s not found.' % token
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        link_info = get_upload_link_info(uploadlink)
        return Response(link_info)


class AdminUploadLinkFileServerUrl(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, token):
        """ Get FileServer url of the shared file.

        Permission checking:
        1. only admin can perform this action.
        """

        try:
            uploadlink = UploadLinkShare.objects.get(token=token)
        except UploadLinkShare.DoesNotExist:
            error_msg = 'Upload link %s not found.' % token
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        repo_id = uploadlink.repo_id
        path = uploadlink.path
        obj_id = seafile_api.get_dir_id_by_path(repo_id, path)
        if not obj_id:
            error_msg = 'File not found.'
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        upload_token = seafile_api.get_fileserver_access_token(repo_id,
                obj_id, 'upload', '', use_onetime=True)

        if not upload_token:
            logger.error('FileServer access token %s invalid' % upload_token)
            upload_url = ''
        else:
            upload_url = gen_file_upload_url(token, 'upload-api')

        result = {}
        result['upload'] = upload_url

        return Response(result)

class AdminUploadLinkCheckPassword(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def post(self, request, token):
        """ Check if password for an encrypted upload link is correct.

        Permission checking:
        1. only admin can perform this action.
        """

        try:
            uploadlink = UploadLinkShare.objects.get(token=token)
        except UploadLinkShare.DoesNotExist:
            error_msg = 'Upload link %s not found.' % token
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if not uploadlink.is_encrypted():
            error_msg = 'Upload link is not encrypted.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        password = request.POST.get('password')
        if not password:
            error_msg = 'password invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if check_password(password, uploadlink.password):
            return Response({'success': True})
        else:
            error_msg = 'Password is not correct.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)
