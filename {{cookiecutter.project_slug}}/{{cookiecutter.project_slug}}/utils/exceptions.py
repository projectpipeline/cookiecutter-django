from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.views import exception_handler


class ErrorCode:
    ORDER_IS_PAID_OR_ASSIGNED = 10001


class CustomAPIException(APIException):
    def __init__(self, detail=None, code=None, additional_message=None):
        super().__init__(detail=detail, code=code)
        if code:
            self.code = code
        if additional_message:
            self.additional_message = additional_message


def custom_rest_exception_handler(exc, context):
    if isinstance(exc, APIException):
        response = exception_handler(exc, context)
        errors = []
        try:
            if isinstance(exc.detail, dict):
                for k, v in exc.detail.items():
                    start_value = f"{k}," if k != 'non_field_errors' else ""
                    if isinstance(v, list):
                        errors.append(f"{start_value} {v[0].title()}".title())
                    elif isinstance(v, dict):
                        for i, j in v.items():
                            start_value = f"{i},"
                            errors.append(f"{start_value} {str(j)}".title())
                    else:
                        errors.append(f"{start_value} {v.title()}".title())

            elif isinstance(exc.detail, str):
                errors.append(exc.detail)

            else:
                errors = exc.detail
        except:
            errors = exc.detail

        response.data = {'status': 'error', 'errors': errors}
        if hasattr(exc, 'code'):
            response.data['code'] = exc.code
        if hasattr(exc, 'additional_message'):
            response.data['additional_message'] = exc.additional_message
        return response


class HttpBadRequestException(CustomAPIException):
    status_code = status.HTTP_400_BAD_REQUEST
