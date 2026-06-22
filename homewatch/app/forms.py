"""WTForms definitions for device CRUD.

Validation here is the first line of defence: MAC format, length caps on
friendly_name (64) and notes (1000) matching the config limits. CSRF tokens are
injected automatically by FlaskForm and rendered on every form template.
"""
from flask_wtf import FlaskForm
from wtforms import BooleanField, StringField, SubmitField, TextAreaField
from wtforms.validators import Length, Optional, Regexp

# Accept colon- or hyphen-separated MAC; normalised to lowercase-colon on save.
MAC_REGEX = r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$"
MAC_MESSAGE = "Enter a valid MAC address, e.g. a4:83:e7:1b:2c:9d."


class AddDeviceForm(FlaskForm):
    mac_address = StringField(
        "MAC address",
        validators=[Regexp(MAC_REGEX, message=MAC_MESSAGE)],
    )
    friendly_name = StringField(
        "Friendly name",
        validators=[Optional(), Length(max=64)],
    )
    notes = TextAreaField(
        "Notes",
        validators=[Optional(), Length(max=1000)],
    )
    # Manually-added devices are ones the operator recognises, so default to
    # trusted — they can uncheck for a device they're cataloguing but distrust.
    trusted = BooleanField("Trusted", default=True)
    submit = SubmitField("Add device")


class EditDeviceForm(FlaskForm):
    """MAC is the device identity and is immutable — not editable here."""

    friendly_name = StringField(
        "Friendly name",
        validators=[Optional(), Length(max=64)],
    )
    notes = TextAreaField(
        "Notes",
        validators=[Optional(), Length(max=1000)],
    )
    trusted = BooleanField("Trusted")
    submit = SubmitField("Save changes")
