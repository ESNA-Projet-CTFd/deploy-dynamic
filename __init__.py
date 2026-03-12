import traceback

from CTFd.plugins.challenges import BaseChallenge, CHALLENGE_CLASSES, get_chal_class
from CTFd.plugins.flags import get_flag_class
from CTFd.utils.user import get_ip
from CTFd.utils.uploads import delete_file
from CTFd.plugins import register_plugin_assets_directory, bypass_csrf_protection
from CTFd.schemas.tags import TagSchema
from CTFd.models import db, ma, Challenges, Teams, Users, Solves, Fails, Flags, Files, Hints, Tags, ChallengeFiles
from CTFd.utils.decorators import admins_only, authed_only, during_ctf_time_only, require_verified_emails
from CTFd.utils.decorators.visibility import check_challenge_visibility, check_score_visibility
from CTFd.utils.user import get_current_team
from CTFd.utils.user import get_current_user
from CTFd.utils.user import is_admin, authed
from CTFd.utils.config import is_teams_mode
from CTFd.api import CTFd_API_v1
from CTFd.api.v1.scoreboard import ScoreboardDetail
import CTFd.utils.scores
from CTFd.api.v1.challenges import ChallengeList, Challenge
from flask_restx import Namespace, Resource
from flask import request, Blueprint, jsonify, abort, render_template, url_for, redirect, session
# from flask_wtf import FlaskForm
from wtforms import (
    FileField,
    HiddenField,
    PasswordField,
    RadioField,
    SelectField,
    StringField,
    TextAreaField,
    SelectMultipleField,
    BooleanField,
)
# from wtforms import TextField, SubmitField, BooleanField, HiddenField, FileField, SelectMultipleField
from wtforms.validators import DataRequired, ValidationError, InputRequired
from werkzeug.utils import secure_filename
import requests
import socket as _socket
import tempfile
import http.client
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from requests.models import Response
from requests.structures import CaseInsensitiveDict
from CTFd.utils.dates import unix_time
from datetime import datetime
import json
import hashlib
import random
from CTFd.plugins import register_admin_plugin_menu_bar

from CTFd.forms import BaseForm
from CTFd.forms.fields import SubmitField
from CTFd.utils.config import get_themes

from pathlib import Path


class DockerConfig(db.Model):
    """
	Docker Config Model. This model stores the config for docker API connections.
	"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column("name", db.String(128), index=True)
    hostname = db.Column("hostname", db.String(64), index=True)
    tls_enabled = db.Column("tls_enabled", db.Boolean, default=False, index=True)
    ca_cert = db.Column("ca_cert", db.String(2200), index=True)
    client_cert = db.Column("client_cert", db.String(2000), index=True)
    client_key = db.Column("client_key", db.String(3300), index=True)
    repositories = db.Column("repositories", db.String(1024), index=True)


class DockerChallengeTracker(db.Model):
    """
	Docker Container Tracker. This model stores the users/teams active docker containers.
	"""
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column("team_id", db.String(64), index=True)
    user_id = db.Column("user_id", db.Integer, index=True)
    docker_image = db.Column("docker_image", db.String(64), index=True)
    timestamp = db.Column("timestamp", db.Integer, index=True)
    revert_time = db.Column("revert_time", db.Integer, index=True)
    instance_id = db.Column("instance_id", db.String(128), index=True)
    ports = db.Column('ports', db.String(128), index=True)
    host = db.Column('host', db.String(128), index=True)
    challenge = db.Column('challenge', db.String(256), index=True)

class DockerConfigForm(BaseForm):
    id = HiddenField()
    hostname = StringField(
        "Docker Hostname", description="The Hostname/IP and Port of your Docker API."
    )
    tls_enabled = RadioField('TLS Enabled?')
    ca_cert = FileField('CA Cert')
    client_cert = FileField('Client Cert')
    client_key = FileField('Client Key')
    repositories = SelectMultipleField('Repositories')
    submit = SubmitField('Submit')


class _UnixSocketAdapter(HTTPAdapter):
    """Requests adapter that routes HTTP traffic through a Unix domain socket."""

    def __init__(self, socket_path):
        self.socket_path = socket_path
        super().__init__()

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        parsed = urlparse(request.url)
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query

        sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        sock.connect(self.socket_path)
        conn = http.client.HTTPConnection('localhost')
        conn.sock = sock
        conn.request(request.method, path,
                     body=request.body,
                     headers=dict(request.headers))
        resp = conn.getresponse()

        response = Response()
        response.status_code = resp.status
        response.headers = CaseInsensitiveDict(dict(resp.getheaders()))
        response._content = resp.read()
        response.encoding = 'utf-8'
        response.url = request.url
        response.request = request
        return response


def _is_unix_socket(hostname):
    return bool(hostname and hostname.startswith('unix://'))


def _get_docker_session(docker):
    """Return a requests.Session configured for TCP or Unix socket."""
    s = requests.Session()
    if _is_unix_socket(docker.hostname):
        socket_path = docker.hostname[len('unix://'):]
        adapter = _UnixSocketAdapter(socket_path)
        s.mount('http://', adapter)
        s.mount('https://', adapter)
    return s


def _get_docker_base_url(docker):
    """Return the base URL for the Docker API (http://localhost for Unix sockets)."""
    if _is_unix_socket(docker.hostname):
        return 'http://localhost'
    prefix = 'https' if docker.tls_enabled else 'http'
    return f'{prefix}://{docker.hostname}'


def _get_tracker_host(docker):
    """Return the host string to store in DockerChallengeTracker."""
    if _is_unix_socket(docker.hostname):
        return 'localhost'
    return str(docker.hostname).split(':')[0]


def get_random_docker():
    """Return a random DockerConfig from all configured servers."""
    configs = DockerConfig.query.all()
    if not configs:
        return None
    return random.choice(configs)


def get_docker_by_host(host):
    """Find DockerConfig whose hostname matches the given host (IP/name without port)."""
    for c in DockerConfig.query.all():
        if not c.hostname:
            continue
        if _is_unix_socket(c.hostname) and host == 'localhost':
            return c
        if not _is_unix_socket(c.hostname) and c.hostname.split(':')[0] == host:
            return c
    return DockerConfig.query.first()


def define_docker_admin(app):
    admin_docker_config = Blueprint('admin_docker_config', __name__, template_folder='templates',
                                    static_folder='assets')

    @admin_docker_config.route("/admin/dynamic_deploy_config", methods=["GET", "POST"])
    @admins_only
    def docker_config():
        form = DockerConfigForm()
        if request.method == "POST":
            action = request.form.get('action', 'save')
            server_id = request.form.get('server_id', '').strip()

            if action == 'delete':
                if server_id:
                    DockerConfig.query.filter_by(id=int(server_id)).delete()
                    db.session.commit()
                return redirect(url_for('admin_docker_config.docker_config'))

            b = DockerConfig.query.filter_by(id=int(server_id)).first() if server_id else DockerConfig()
            try:
                ca_cert = request.files['ca_cert'].stream.read()
            except:
                ca_cert = b""
            try:
                client_cert = request.files['client_cert'].stream.read()
            except:
                client_cert = b""
            try:
                client_key = request.files['client_key'].stream.read()
            except:
                client_key = b""
            if ca_cert:
                b.ca_cert = ca_cert
            if client_cert:
                b.client_cert = client_cert
            if client_key:
                b.client_key = client_key
            b.name = request.form.get('name', '').strip()
            b.hostname = request.form['hostname']
            b.tls_enabled = request.form.get('tls_enabled') == 'True'
            if not b.tls_enabled:
                b.ca_cert = None
                b.client_cert = None
                b.client_key = None
            try:
                b.repositories = ','.join(request.form.to_dict(flat=False)['repositories'])
            except:
                b.repositories = None
            db.session.add(b)
            db.session.commit()
            new_id = b.id
            if not server_id:
                return redirect(url_for('admin_docker_config.docker_config') + f'?edit={new_id}')
            return redirect(url_for('admin_docker_config.docker_config'))

        all_servers = DockerConfig.query.all()
        edit_id = request.args.get('edit', '').strip()
        edit_server = None
        selected_repos = []
        if edit_id:
            edit_server = DockerConfig.query.filter_by(id=int(edit_id)).first()
            if edit_server:
                try:
                    repos = get_repositories(edit_server)
                except:
                    repos = []
                if len(repos) == 0:
                    form.repositories.choices = [("ERROR", "Failed to Connect to Docker")]
                else:
                    form.repositories.choices = [(d, d) for d in repos]
                selected_repos = edit_server.repositories.split(',') if edit_server.repositories else []
        else:
            form.repositories.choices = []
        return render_template("docker_config.html", servers=all_servers, form=form,
                               edit_server=edit_server, selected_repos=selected_repos)

    app.register_blueprint(admin_docker_config)


def define_docker_status(app):
    admin_docker_status = Blueprint('admin_docker_status', __name__, template_folder='templates',
                                    static_folder='assets')

    @admin_docker_status.route("/admin/docker_instances", methods=["GET", "POST"])
    @admins_only
    def docker_admin():
        docker_config = DockerConfig.query.filter_by(id=1).first()
        docker_tracker = DockerChallengeTracker.query.all()
        with db.session.no_autoflush:
            for i in docker_tracker:
                if is_teams_mode():
                    name = Teams.query.filter_by(id=i.team_id).first()
                    i.team_id = name.name if name else i.team_id
                else:
                    name = Users.query.filter_by(id=i.user_id).first()
                    i.user_id = name.name if name else i.user_id
        return render_template("admin_docker_status.html", dockers=docker_tracker)

    app.register_blueprint(admin_docker_status)


kill_container = Namespace("nuke", description='Endpoint to nuke containers')


@kill_container.route("", methods=['POST', 'GET'])
class KillContainerAPI(Resource):
    @admins_only
    def get(self):
        container = request.args.get('container')
        full = request.args.get('all')
        docker_tracker = DockerChallengeTracker.query.all()
        if full == "true":
            for c in docker_tracker:
                delete_container(get_docker_by_host(c.host), c.instance_id)
                DockerChallengeTracker.query.filter_by(instance_id=c.instance_id).delete()
                db.session.commit()

        elif container != 'null' and container in [c.instance_id for c in docker_tracker]:
            tracker_entry = DockerChallengeTracker.query.filter_by(instance_id=container).first()
            delete_container(get_docker_by_host(tracker_entry.host), container)
            DockerChallengeTracker.query.filter_by(instance_id=container).delete()
            db.session.commit()

        else:
            return False
        return True


def do_request(docker, url, headers=None, method='GET'):
    base = _get_docker_base_url(docker)
    req_session = _get_docker_session(docker)
    tls = docker.tls_enabled and not _is_unix_socket(docker.hostname)
    try:
        if tls:
            cert, verify = get_client_cert(docker)
            if method == 'GET':
                r = req_session.get(f"{base}{url}", cert=cert, verify=verify, headers=headers)
            elif method == 'DELETE':
                r = req_session.delete(f"{base}{url}", cert=cert, verify=verify, headers=headers)
            for file_path in [*cert, verify]:
                if file_path:
                    Path(file_path).unlink(missing_ok=True)
        else:
            if method == 'GET':
                r = req_session.get(f"{base}{url}", headers=headers)
            elif method == 'DELETE':
                r = req_session.delete(f"{base}{url}", headers=headers)
    except:
        traceback.print_exc()
        r = []
    return r


def get_client_cert(docker):
    # this can be done more efficiently, but works for now.
    try:
        ca = docker.ca_cert
        client = docker.client_cert
        ckey = docker.client_key
        ca_file = tempfile.NamedTemporaryFile(delete=False)
        ca_file.write(ca.encode())
        ca_file.seek(0)
        client_file = tempfile.NamedTemporaryFile(delete=False)
        client_file.write(client.encode())
        client_file.seek(0)
        key_file = tempfile.NamedTemporaryFile(delete=False)
        key_file.write(ckey.encode())
        key_file.seek(0)
        CERT = (client_file.name, key_file.name)
    except:
        traceback.print_exc()
        CERT = None
    return CERT, ca_file.name


# For the Docker Config Page. Gets the Current Repositories available on the Docker Server.
def get_repositories(docker, tags=False, repos=False):
    r = do_request(docker, '/images/json?all=1')
    result = list()
    for i in r.json():
        if not i['RepoTags'] == []:
            if not i['RepoTags'][0].split(':')[0] == '<none>':
                if repos:
                    if not i['RepoTags'][0].split(':')[0] in repos:
                        continue
                if not tags:
                    result.append(i['RepoTags'][0].split(':')[0])
                else:
                    result.append(i['RepoTags'][0])
    return list(set(result))


def get_unavailable_ports(docker):
    r = do_request(docker, '/containers/json?all=1')
    result = list()
    for i in r.json():
        if i.get('Ports'):
            for p in i['Ports']:
                if 'PublicPort' in p:
                    result.append(p['PublicPort'])
    return result


def get_required_ports(docker, image):
    r = do_request(docker, f'/images/{image}/json?all=1')
    result = r.json()['Config']['ExposedPorts'].keys()
    return result


def create_container(docker, image, team, portbl):
    base = _get_docker_base_url(docker)
    req_session = _get_docker_session(docker)
    tls = docker.tls_enabled and not _is_unix_socket(docker.hostname)
    needed_ports = get_required_ports(docker, image)
    team = hashlib.md5(team.encode("utf-8")).hexdigest()[:10]
    container_name = "%s_%s" % (image.split(':')[1], team)
    assigned_ports = dict()
    for i in needed_ports:
        while True:
            assigned_port = random.choice(range(30000, 60000))
            if assigned_port not in portbl:
                assigned_ports['%s/tcp' % assigned_port] = {}
                break
    ports = dict()
    bindings = dict()
    tmp_ports = list(assigned_ports.keys())
    for i in needed_ports:
        ports[i] = {}
        bindings[i] = [{"HostPort": tmp_ports.pop()}]
    headers = {'Content-Type': "application/json"}
    data = json.dumps({"Image": image, "ExposedPorts": ports, "HostConfig": {"PortBindings": bindings}})
    if tls:
        cert, verify = get_client_cert(docker)
        r = req_session.post(f"{base}/containers/create?name={container_name}",
                             cert=cert, verify=verify, data=data, headers=headers)
        result = r.json()
        req_session.post(f"{base}/containers/{result['Id']}/start",
                         cert=cert, verify=verify, headers=headers)
        for file_path in [*cert, verify]:
            if file_path:
                Path(file_path).unlink(missing_ok=True)
    else:
        r = req_session.post(f"{base}/containers/create?name={container_name}",
                             data=data, headers=headers)
        result = r.json()
        req_session.post(f"{base}/containers/{result['Id']}/start", headers=headers)
    return result, data


def delete_container(docker, instance_id):
    headers = {'Content-Type': "application/json"}
    do_request(docker, f'/containers/{instance_id}?force=true', headers=headers, method='DELETE')
    return True


class DockerChallengeType(BaseChallenge):
    id = "docker"
    name = "docker"
    templates = {
        'create': '/plugins/deploy-dynamic/assets/create.html',
        'update': '/plugins/deploy-dynamic/assets/update.html',
        'view': '/plugins/deploy-dynamic/assets/view.html',
    }
    scripts = {
        'create': '/plugins/deploy-dynamic/assets/create.js',
        'update': '/plugins/deploy-dynamic/assets/update.js',
        'view': '/plugins/deploy-dynamic/assets/view.js',
    }
    route = '/plugins/deploy-dynamic/assets'
    blueprint = Blueprint('deploy-dynamic', __name__, template_folder='templates', static_folder='assets')

    @staticmethod
    def update(challenge, request):
        """
		This method is used to update the information associated with a challenge. This should be kept strictly to the
		Challenges table and any child tables.

		:param challenge:
		:param request:
		:return:
		"""
        data = request.form or request.get_json()
        for attr, value in data.items():
            setattr(challenge, attr, value)

        db.session.commit()
        return challenge

    @staticmethod
    def delete(challenge):
        """
		This method is used to delete the resources used by a challenge.
		NOTE: Will need to kill all containers here

		:param challenge:
		:return:
		"""
        Fails.query.filter_by(challenge_id=challenge.id).delete()
        Solves.query.filter_by(challenge_id=challenge.id).delete()
        Flags.query.filter_by(challenge_id=challenge.id).delete()
        files = ChallengeFiles.query.filter_by(challenge_id=challenge.id).all()
        for f in files:
            delete_file(f.id)
        ChallengeFiles.query.filter_by(challenge_id=challenge.id).delete()
        Tags.query.filter_by(challenge_id=challenge.id).delete()
        Hints.query.filter_by(challenge_id=challenge.id).delete()
        DockerChallenge.query.filter_by(id=challenge.id).delete()
        Challenges.query.filter_by(id=challenge.id).delete()
        db.session.commit()

    @staticmethod
    def read(challenge):
        """
		This method is in used to access the data of a challenge in a format processable by the front end.

		:param challenge:
		:return: Challenge object, data dictionary to be returned to the user
		"""
        challenge = DockerChallenge.query.filter_by(id=challenge.id).first()
        data = {
            'id': challenge.id,
            'name': challenge.name,
            'value': challenge.value,
            'docker_image': challenge.docker_image,
            'description': challenge.description,
            'category': challenge.category,
            'state': challenge.state,
            'max_attempts': challenge.max_attempts,
            'type': challenge.type,
            'type_data': {
                'id': DockerChallengeType.id,
                'name': DockerChallengeType.name,
                'templates': DockerChallengeType.templates,
                'scripts': DockerChallengeType.scripts,
            }
        }
        return data

    @staticmethod
    def create(request):
        """
		This method is used to process the challenge creation request.

		:param request:
		:return:
		"""
        data = request.form or request.get_json()
        challenge = DockerChallenge(**data)
        db.session.add(challenge)
        db.session.commit()
        return challenge

    @staticmethod
    def attempt(challenge, request):
        """
		This method is used to check whether a given input is right or wrong. It does not make any changes and should
		return a boolean for correctness and a string to be shown to the user. It is also in charge of parsing the
		user's input from the request itself.

		:param challenge: The Challenge object from the database
		:param request: The request the user submitted
		:return: (boolean, string)
		"""

        data = request.form or request.get_json()
        print(request.get_json())
        print(data)
        submission = data["submission"].strip()
        flags = Flags.query.filter_by(challenge_id=challenge.id).all()
        for flag in flags:
            if get_flag_class(flag.type).compare(flag, submission):
                return True, "Correct"
        return False, "Incorrect"

    @staticmethod
    def solve(user, team, challenge, request):
        """
		This method is used to insert Solves into the database in order to mark a challenge as solved.

		:param team: The Team object from the database
		:param chal: The Challenge object from the database
		:param request: The request the user submitted
		:return:
		"""
        data = request.form or request.get_json()
        submission = data["submission"].strip()
        try:
            if is_teams_mode():
                docker_containers = DockerChallengeTracker.query.filter_by(
                    docker_image=challenge.docker_image).filter_by(team_id=team.id).first()
            else:
                docker_containers = DockerChallengeTracker.query.filter_by(
                    docker_image=challenge.docker_image).filter_by(user_id=user.id).first()
            delete_container(get_docker_by_host(docker_containers.host), docker_containers.instance_id)
            DockerChallengeTracker.query.filter_by(instance_id=docker_containers.instance_id).delete()
        except:
            pass
        solve = Solves(
            user_id=user.id,
            team_id=team.id if team else None,
            challenge_id=challenge.id,
            ip=get_ip(req=request),
            provided=submission,
        )
        db.session.add(solve)
        db.session.commit()
        # trying if this solces the detached instance error...
        #db.session.close()

    @staticmethod
    def fail(user, team, challenge, request):
        """
		This method is used to insert Fails into the database in order to mark an answer incorrect.

		:param team: The Team object from the database
		:param chal: The Challenge object from the database
		:param request: The request the user submitted
		:return:
		"""
        data = request.form or request.get_json()
        submission = data["submission"].strip()
        wrong = Fails(
            user_id=user.id,
            team_id=team.id if team else None,
            challenge_id=challenge.id,
            ip=get_ip(request),
            provided=submission,
        )
        db.session.add(wrong)
        db.session.commit()
        #db.session.close()


class DockerChallenge(Challenges):
    __mapper_args__ = {'polymorphic_identity': 'docker'}
    id = db.Column(None, db.ForeignKey('challenges.id'), primary_key=True)
    docker_image = db.Column(db.String(128), index=True)


# API
container_namespace = Namespace("container", description='Endpoint to interact with containers')


@container_namespace.route("", methods=['POST', 'GET'])
class ContainerAPI(Resource):
    @authed_only
    # I wish this was Post... Issues with API/CSRF and whatnot. Open to a Issue solving this.
    def get(self):
        container = request.args.get('name')
        if not container:
            return abort(403, "No container specified")
        challenge = request.args.get('challenge')
        if not challenge:
            return abort(403, "No challenge name specified")
        
        docker = get_random_docker()
        if docker is None:
            return abort(500, "No Docker server configured.")
        containers = DockerChallengeTracker.query.all()
        if container not in get_repositories(docker, tags=True):
            return abort(403,f"Container {container} not present in the repository.")
        if is_teams_mode():
            session = get_current_team()
            # First we'll delete all old docker containers (+2 hours)
            for i in containers:
                if int(session.id) == int(i.team_id) and (unix_time(datetime.utcnow()) - int(i.timestamp)) >= 7200:
                    delete_container(get_docker_by_host(i.host), i.instance_id)
                    DockerChallengeTracker.query.filter_by(instance_id=i.instance_id).delete()
                    db.session.commit()
            check = DockerChallengeTracker.query.filter_by(team_id=session.id).filter_by(docker_image=container).first()
        else:
            session = get_current_user()
            for i in containers:
                if int(session.id) == int(i.user_id) and (unix_time(datetime.utcnow()) - int(i.timestamp)) >= 7200:
                    delete_container(get_docker_by_host(i.host), i.instance_id)
                    DockerChallengeTracker.query.filter_by(instance_id=i.instance_id).delete()
                    db.session.commit()
            check = DockerChallengeTracker.query.filter_by(user_id=session.id).filter_by(docker_image=container).first()

        # If this container is already created, we don't need another one.
        if check != None and not (unix_time(datetime.utcnow()) - int(check.timestamp)) >= 30:
            return abort(403,"To prevent abuse, dockers can be reverted and stopped after 30 seconds of creation.")
        # Delete when requested
        elif check != None and request.args.get('stopcontainer'):
            delete_container(get_docker_by_host(check.host), check.instance_id)
            if is_teams_mode():
                DockerChallengeTracker.query.filter_by(team_id=session.id).filter_by(docker_image=container).delete()
            else:
                DockerChallengeTracker.query.filter_by(user_id=session.id).filter_by(docker_image=container).delete()
            db.session.commit()
            return {"result": "Container stopped"}
        # The exception would be if we are reverting a box. So we'll delete it if it exists and has been around for more than 5 minutes.
        elif check != None:
            delete_container(get_docker_by_host(check.host), check.instance_id)
            if is_teams_mode():
                DockerChallengeTracker.query.filter_by(team_id=session.id).filter_by(docker_image=container).delete()
            else:
                DockerChallengeTracker.query.filter_by(user_id=session.id).filter_by(docker_image=container).delete()
            db.session.commit()

        # Check if a container is already running for this user. We need to recheck the DB first
        containers = DockerChallengeTracker.query.all()
        for i in containers:
            if int(session.id) == int(i.user_id):
                return abort(403,f"Another container is already running for challenge:<br><i><b>{i.challenge}</b></i>.<br>Please stop this first.<br>You can only run one container.")

        portsbl = get_unavailable_ports(docker)
        create = create_container(docker, container, session.name, portsbl)
        ports = json.loads(create[1])['HostConfig']['PortBindings'].values()
        entry = DockerChallengeTracker(
            team_id=session.id if is_teams_mode() else None,
            user_id=session.id if not is_teams_mode() else None,
            docker_image=container,
            timestamp=unix_time(datetime.utcnow()),
            revert_time=unix_time(datetime.utcnow()) + 30,
            instance_id=create[0]['Id'],
            ports=','.join([p[0]['HostPort'] for p in ports]),
            host=_get_tracker_host(docker),
            challenge=challenge
        )
        db.session.add(entry)
        db.session.commit()
        #db.session.close()
        return


active_docker_namespace = Namespace("docker", description='Endpoint to retrieve User Docker Image Status')


@active_docker_namespace.route("", methods=['POST', 'GET'])
class DockerStatus(Resource):
    """
	The Purpose of this API is to retrieve a public JSON string of all docker containers
	in use by the current team/user.
	"""

    @authed_only
    def get(self):
        if is_teams_mode():
            session = get_current_team()
            tracker = DockerChallengeTracker.query.filter_by(team_id=session.id)
        else:
            session = get_current_user()
            tracker = DockerChallengeTracker.query.filter_by(user_id=session.id)
        data = list()
        for i in tracker:
            data.append({
                'id': i.id,
                'team_id': i.team_id,
                'user_id': i.user_id,
                'docker_image': i.docker_image,
                'timestamp': i.timestamp,
                'revert_time': i.revert_time,
                'instance_id': i.instance_id,
                'ports': i.ports.split(','),
                'host': i.host
            })
        return {
            'success': True,
            'data': data
        }


docker_namespace = Namespace("docker", description='Endpoint to retrieve dockerstuff')


@docker_namespace.route("", methods=['POST', 'GET'])
class DockerAPI(Resource):
    """
	This is for creating Docker Challenges. The purpose of this API is to populate the Docker Image Select form
	object in the Challenge Creation Screen.
	"""

    @admins_only
    def get(self):
        all_dockers = DockerConfig.query.all()
        images = set()
        for docker in all_dockers:
            repos = docker.repositories.split(',') if docker.repositories else None
            try:
                images.update(get_repositories(docker, tags=True, repos=repos))
            except Exception:
                pass
        if images:
            return {
                'success': True,
                'data': [{'name': i} for i in sorted(images)]
            }
        else:
            return {
                'success': False,
                'data': [{'name': 'Error in Docker Config!'}]
            }, 400



def load(app):
    app.db.create_all()
    # Add 'name' column to docker_config if it doesn't exist yet (migration)
    try:
        with app.db.engine.connect() as conn:
            conn.execute(db.text("ALTER TABLE docker_config ADD COLUMN name VARCHAR(128)"))
            conn.commit()
    except Exception:
        pass
    CHALLENGE_CLASSES['docker'] = DockerChallengeType
    @app.template_filter('datetimeformat')
    def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
        return datetime.fromtimestamp(value).strftime(format)
    register_plugin_assets_directory(app, base_path='/plugins/deploy-dynamic/assets')
    define_docker_admin(app)
    define_docker_status(app)
    CTFd_API_v1.add_namespace(docker_namespace, '/docker')
    CTFd_API_v1.add_namespace(container_namespace, '/container')
    CTFd_API_v1.add_namespace(active_docker_namespace, '/docker_instances')
    CTFd_API_v1.add_namespace(kill_container, '/nuke')
