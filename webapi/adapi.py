from flask import Flask, jsonify
from ldap import LDAPError

from easyad import EasyAD

app = Flask(__name__)
app.config.from_pyfile("config.py")

ad = EasyAD(app.config)


def parse_ldap_error(e):
    return "An LDAP error occurred - {0}".format(e.args[0]["desc"])


def api_call(function):
    def process_api_call(*args, **kwargs):
        try:
            function(*args, **kwargs)

        except ValueError as e:
            return jsonify(dict(error=str(e))), 404
        except LDAPError as e:
            return jsonify(dict(error=parse_ldap_error(e))), 500

    return process_api_call


@app.route("/")
def index():
    return "Hello world!"


@api_call
@app.route("/user/<user_string>")
def get_user(user_string):
    return jsonify(ad.get_user(user_string, json_safe=True))


@app.route("/user/<user_string>/groups")
def user_groups(user_string):
    try:
        return jsonify(ad.get_all_user_groups(user_string, json_safe=True))
    except ValueError as e:
        return jsonify(dict(error=str(e))), 404
    except LDAPError as e:
        return jsonify(dict(error=parse_ldap_error(e))), 500


@app.route("/user/<user_string>/member-of/<group_string>")
def user_is_member_of_group(user_string, group_string):
    try:
        return jsonify(dict(member=ad.user_is_member_of_group(user_string, group_string)))
    except ValueError as e:
        return jsonify(dict(error=str(e))), 404
    except LDAPError as e:
        return jsonify(dict(error=parse_ldap_error(e))), 500


@app.route("/group/<group_string>")
def get_group(group_string):
    try:
        return jsonify(ad.get_group(group_string, json_safe=True))
    except ValueError as e:
        return jsonify(dict(error=str(e))), 404
    except LDAPError as e:
        return jsonify(dict(error=parse_ldap_error(e))), 500


@app.route("/group/<group_string>/members")
def get_group_members(group_string):
    try:
        return jsonify(ad.get_all_users_in_group(group_string, json_safe=True))
    except ValueError as e:
        return jsonify(dict(error=str(e))), 404
    except LDAPError as e:
        return jsonify(dict(error=parse_ldap_error(e))), 500


@app.route("/search/user/<user_string>")
def search_for_users(user_string):
    try:
        return jsonify(ad.search_for_users(user_string, json_safe=True))
    except ValueError as e:
        return jsonify(dict(error=str(e))), 404
    except LDAPError as e:
        return jsonify(dict(error=parse_ldap_error(e))), 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)
