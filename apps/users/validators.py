import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _


class AlphaNumericSymbolValidator:
    """
    Validator to ensure a string is alphanumeric.
    """

    def validate(self, password, user=None):
        if not re.search(r"[A-Za-z]", password):
            raise ValidationError(
                _("This password must contain at least one letter."),
                code="password_no_letter",
            )

        if not re.search(r"\d", password):
            raise ValidationError(
                _("This password must contain at least one number."),
                code="password_no_number",
            )

        if not re.search(r"[^\w\s]", password):
            raise ValidationError(
                _("This password must contain at least one symbol."),
                code="password_no_symbol",
            )

    def get_help_text(self):
        return _(
            "Your password must contain at least one letter, one number, and one symbol."
        )
