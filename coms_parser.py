from webargs import fields, validate

user_args = {
    # Required arguments
    "username": fields.Str(required=True),
    # Validation
    "password": fields.Str(validate=lambda p: len(p) >= 6),
    # OR use marshmallow's built-in validators
   # "password": fields.Str(validate=validate.Length(min=6)),
    # Default value when argument is missing
    "display_per_page": fields.Int(missing=10),
    # Repeated parameter, e.g. "/?nickname=Fred&nickname=Freddie"
    "nickname": fields.List(fields.Str()),
    # Delimited list, e.g. "/?languages=python,javascript"
    "languages": fields.DelimitedList(fields.Str()),
    # When value is keyed on a variable-unsafe name
    # or you want to rename a key
    "user_type": fields.Str(data_key="user-type")
}

lock_parse = {
    "id": fields.Int(required = True),
    "address": fields.Str(required = True), #validate = lambda p: len(p) >= 60),
    "nome": fields.Str(required = True), #validate = lambda p: len(p) >= 30)
}

user_parse = {
    "numtel": fields.Str(required = True),
    "cripto": fields.Str(required = True), #validate = lambda p: len(p) >= 60),
    "nome": fields.Str(required = True), #validate = lambda p: len(p) >= 30)
}

owner_parse = {
    "NUser": fields.Str(required = True),
    "ID": fields.Int(required = True),
}

autent_parse = {
    "Codigo": fields.Str(),
    "Momento": fields.DateTime(),
    "ID": fields.Int(),
    "NUser": fields.Str(),
    "Friend": fields.Str(),
    "pin": fields.Str(),
}

event_parse = {
    "ID": fields.Int(),
    "time": fields.DateTime(),
    "description": fields.Str(),
}