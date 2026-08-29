from django.conf import settings
from django.forms import BaseForm
from basicauth.middleware import BasicAuthMiddleware as BaseBasicAuthMiddleware


class XFrameOptionsMiddleware:
    '''
        Adds the X-Frame-Options header to responses to protect against
        clickjacking. The header value is taken from the X_FRAME_OPTIONS
        setting (SAMEORIGIN or DENY). Set the setting to None to omit the
        header entirely, which allows TubeSync to be embedded in an iframe on
        another origin.

        Replaces django.middleware.clickjacking.XFrameOptionsMiddleware, which
        stopped honouring a None setting in Django 6.
    '''

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        # Don't override a header that has already been set
        if response.get('X-Frame-Options') is not None:
            return response
        # Honour the xframe_options_exempt flag set by views, if any
        if getattr(response, 'xframe_options_exempt', False):
            return response
        x_frame_options = getattr(settings, 'X_FRAME_OPTIONS', 'SAMEORIGIN')
        if x_frame_options:
            response.headers['X-Frame-Options'] = str(x_frame_options).upper()
        return response


class MaterializeDefaultFieldsMiddleware:
    '''
        Adds 'browser-default' CSS attribute class to all form fields.
    '''

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        return response

    def process_template_response(self, request, response):
        for _, v in getattr(response, 'context_data', {}).items():
            if isinstance(v, BaseForm):
                for _, field in v.fields.items():
                    field.widget.attrs.update({'class':'browser-default'})
        return response


class BasicAuthMiddleware(BaseBasicAuthMiddleware):

    def process_request(self, request):
        bypass_uris = getattr(settings, 'BASICAUTH_ALWAYS_ALLOW_URIS', [])
        if request.path in bypass_uris:
            return None
        return super().process_request(request)
