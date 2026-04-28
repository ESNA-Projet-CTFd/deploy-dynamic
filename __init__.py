import sys
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
from docker import DockerClient
from docker.tls import TLSConfig
import tempfile
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
    public_ip = db.Column("public_ip", db.String(128), index=True)
    tls_enabled = db.Column("tls_enabled", db.Boolean, default=False, index=True)
    ca_cert = db.Column("ca_cert", db.Text)
    client_cert = db.Column("client_cert", db.Text)
    client_key = db.Column("client_key", db.Text)
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
    user_ip = db.Column('user_ip', db.String(64), index=True)

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


def get_random_docker():
    """Return a random DockerConfig from all configured servers."""
    configs = DockerConfig.query.all()
    if not configs:
        return None
    return random.choice(configs)


def get_docker_client(config):
    """Create a DockerClient from a DockerConfig. Supports unix://, tcp://, and TLS."""
    host = config.hostname or ''
    # Normalize unix socket: /var/run/docker.sock or unix://... → unix:///...
    if host.startswith('/'):
        host = f'unix://{host}'
    if host.startswith('unix://') and not host.startswith('unix:///'):
        host = 'unix:///' + host[len('unix://'):]
    if not host.startswith(('unix://', 'tcp://')):
        host = f'tcp://{host}'
    if config.tls_enabled:
        tmp = []
        def _write_tmp(content):
            f = tempfile.NamedTemporaryFile(delete=False, suffix='.pem')
            f.write(content.encode() if isinstance(content, str) else content)
            f.close()
            tmp.append(f.name)
            return f.name
        tls = TLSConfig(
            ca_cert=_write_tmp(config.ca_cert),
            client_cert=(_write_tmp(config.client_cert), _write_tmp(config.client_key)),
            verify=True,
        )
        client = DockerClient(base_url=host, tls=tls)
        client._tls_tmp_files = tmp
        return client
    return DockerClient(base_url=host)


def _close_client(client):
    client.close()
    for f in getattr(client, '_tls_tmp_files', []):
        Path(f).unlink(missing_ok=True)


IPTABLES_HELPER_IMAGE = "alpine:latest"


def _iptables_tag(instance_id):
    # iptables comments are limited to 256 chars, but keep tag short for grep safety
    return f"ctfd-{(instance_id or '')[:12]}"


def _iptables_binary(ip):
    return "ip6tables" if ip and ":" in ip else "iptables"


def _exec_on_host(config, script):
    """Run a shell script on the Docker host using a temporary privileged container with host networking."""
    client = get_docker_client(config)
    try:
        return client.containers.run(
            IPTABLES_HELPER_IMAGE,
            command=["sh", "-c", script],
            cap_add=["NET_ADMIN"],
            network_mode="host",
            remove=True,
            stdout=True,
            stderr=True,
        )
    finally:
        _close_client(client)


def apply_ip_filter(config, host_ports, allowed_ip, instance_id):
    """Insert DOCKER-USER rules so only allowed_ip can reach host_ports; everyone else is rejected.

    Picks the iptables backend (legacy/nft) actually used by Docker on the host by
    probing which one has the DOCKER-USER chain. Bails out if neither does.

    Uses an ALLOW-then-REJECT pattern (no negated source match) because `! -s` combined
    with `-m conntrack --ctorigdstport` behaves unreliably under iptables-nft: a positive
    match followed by RETURN is parsed identically by both backends.
    """
    if not allowed_ip or not host_ports:
        return
    candidates = "ip6tables-legacy ip6tables-nft ip6tables" if ":" in allowed_ip \
        else "iptables-legacy iptables-nft iptables"
    tag = _iptables_tag(instance_id)
    # Each `-I` inserts at position 1, so we add the REJECTs first and the RETURNs last —
    # the RETURNs end up on top and are evaluated before the catch-all REJECTs.
    # `--ctdir ORIGINAL` is critical: it scopes the rules to the inbound direction only.
    # Without it, the container's reply packets (REPLY direction) match the catch-all REJECT
    # because their source IP is the container's bridge IP, not the user's.
    rule_cmds = []
    for port in host_ports:
        port = int(port)
        rule_cmds.append(
            f"$IPT -I DOCKER-USER -p tcp -m conntrack --ctorigdstport {port} --ctdir ORIGINAL "
            f"-m comment --comment '{tag}' -j REJECT --reject-with tcp-reset"
        )
        rule_cmds.append(
            f"$IPT -I DOCKER-USER -p udp -m conntrack --ctorigdstport {port} --ctdir ORIGINAL "
            f"-m comment --comment '{tag}' -j REJECT"
        )
    for port in host_ports:
        port = int(port)
        rule_cmds.append(
            f"$IPT -I DOCKER-USER -p tcp -m conntrack --ctorigdstport {port} --ctdir ORIGINAL "
            f"-s {allowed_ip} -m comment --comment '{tag}' -j RETURN"
        )
        rule_cmds.append(
            f"$IPT -I DOCKER-USER -p udp -m conntrack --ctorigdstport {port} --ctdir ORIGINAL "
            f"-s {allowed_ip} -m comment --comment '{tag}' -j RETURN"
        )
    script = (
        "set -e; "
        "apk add -q --no-cache iptables 2>/dev/null || true; "
        f"IPT=; for c in {candidates}; do "
        "  if $c -L DOCKER-USER -n >/dev/null 2>&1; then IPT=$c; break; fi; "
        "done; "
        "if [ -z \"$IPT\" ]; then echo 'No iptables backend with DOCKER-USER chain' >&2; exit 1; fi; "
        "echo \"[deploy-dynamic] using $IPT\" >&2; "
        + "; ".join(rule_cmds)
    )
    print(f"[deploy-dynamic] applying iptables: ip={allowed_ip} ports={list(host_ports)} "
          f"instance={instance_id[:12]}", file=sys.stderr, flush=True)
    out = _exec_on_host(config, script)
    if out:
        try:
            print("[deploy-dynamic] iptables helper output:", out.decode(errors='replace'),
                  file=sys.stderr, flush=True)
        except Exception:
            pass


def remove_ip_filter(config, instance_id):
    """Delete DOCKER-USER rules tagged for this instance. Best-effort, idempotent.

    Tries every iptables backend (legacy/nft, v4/v6) so we clean up regardless of
    which one Docker is using on this host.
    """
    tag = _iptables_tag(instance_id)
    backends = "iptables-legacy iptables-nft iptables ip6tables-legacy ip6tables-nft ip6tables"
    script = (
        "apk add -q --no-cache iptables 2>/dev/null || true; "
        f"for c in {backends}; do "
        "  command -v $c >/dev/null 2>&1 || continue; "
        "  $c -L DOCKER-USER -n >/dev/null 2>&1 || continue; "
        f"  $c -L DOCKER-USER --line-numbers -n 2>/dev/null | grep -F '{tag}' | "
        "    awk '{print $1}' | sort -rn | "
        "    while read n; do $c -D DOCKER-USER \"$n\" 2>/dev/null || true; done; "
        "done; true"
    )
    try:
        _exec_on_host(config, script)
    except Exception:
        traceback.print_exc()


def get_docker_by_host(host):
    """Find DockerConfig whose hostname matches the stored host key."""
    for c in DockerConfig.query.all():
        if c.hostname == host:
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
            b.public_ip = request.form.get('public_ip', '').strip()
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
                except Exception:
                    traceback.print_exc()
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


# For the Docker Config Page. Gets the Current Repositories available on the Docker Server.
def get_repositories(config, tags=False, repos=False):
    client = get_docker_client(config)
    try:
        result = []
        for image in client.images.list():
            for tag in (image.tags or []):
                repo = tag.split(':')[0]
                if repo == '<none>':
                    continue
                if repos and repo not in repos:
                    continue
                result.append(tag if tags else repo)
        return list(set(result))
    finally:
        _close_client(client)


def get_unavailable_ports(config):
    client = get_docker_client(config)
    try:
        result = []
        for container in client.containers.list(all=True):
            for bindings in (container.ports or {}).values():
                for b in (bindings or []):
                    if 'HostPort' in b:
                        result.append(int(b['HostPort']))
        return result
    finally:
        _close_client(client)


def get_required_ports(config, image):
    client = get_docker_client(config)
    try:
        img = client.images.get(image)
        return list(img.attrs['Config'].get('ExposedPorts', {}).keys())
    finally:
        _close_client(client)


def create_container(config, image, team, portbl, allowed_ip=None):
    needed_ports = get_required_ports(config, image)
    team_hash = hashlib.md5(team.encode("utf-8")).hexdigest()[:10]
    container_name = "%s_%s" % (image.split(':')[1], team_hash)
    port_bindings = {}
    for port in needed_ports:
        while True:
            assigned = random.choice(range(30000, 60000))
            if assigned not in portbl:
                portbl.append(assigned)
                port_bindings[port] = assigned
                break
    client = get_docker_client(config)
    try:
        container = client.containers.create(image, name=container_name, ports=port_bindings)
        container.start()
        result = {'Id': container.id}
    finally:
        _close_client(client)
    bindings = {port: [{"HostPort": str(host_port)}] for port, host_port in port_bindings.items()}
    data = json.dumps({"Image": image, "ExposedPorts": {p: {} for p in needed_ports},
                       "HostConfig": {"PortBindings": bindings}})
    if allowed_ip:
        try:
            apply_ip_filter(config, list(port_bindings.values()), allowed_ip, result['Id'])
        except Exception:
            # If the lock-down fails, tear the container down rather than expose it to everyone.
            traceback.print_exc()
            try:
                delete_container(config, result['Id'])
            except Exception:
                traceback.print_exc()
            raise
    return result, data


def delete_container(config, instance_id):
    remove_ip_filter(config, instance_id)
    client = get_docker_client(config)
    try:
        client.containers.get(instance_id).remove(force=True)
    except Exception:
        traceback.print_exc()
    finally:
        _close_client(client)
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

        user_ip = get_ip(req=request)
        if not user_ip:
            return abort(500, "Could not determine your IP for access control. Contact an admin.")
        print(f"[deploy-dynamic] deploying container for user={session.name} captured_ip={user_ip} "
              f"remote_addr={request.remote_addr} access_route={list(request.access_route)} "
              f"xff={request.headers.get('X-Forwarded-For')}",
              file=sys.stderr, flush=True)

        portsbl = get_unavailable_ports(docker)
        try:
            create = create_container(docker, container, session.name, portsbl, allowed_ip=user_ip)
        except Exception:
            traceback.print_exc()
            return abort(500, "Failed to lock down the container. The instance was not deployed.")
        ports = json.loads(create[1])['HostConfig']['PortBindings'].values()
        entry = DockerChallengeTracker(
            team_id=session.id if is_teams_mode() else None,
            user_id=session.id if not is_teams_mode() else None,
            docker_image=container,
            timestamp=unix_time(datetime.utcnow()),
            revert_time=unix_time(datetime.utcnow()) + 30,
            instance_id=create[0]['Id'],
            ports=','.join([p[0]['HostPort'] for p in ports]),
            host=docker.public_ip or docker.hostname,
            challenge=challenge,
            user_ip=user_ip,
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
    # Widen TLS cert columns to TEXT — 4096-bit RSA certs/keys overflow the original VARCHAR sizes.
    # Idempotent: re-running on TEXT columns is a no-op on Postgres/MySQL.
    try:
        dialect = app.db.engine.dialect.name
        with app.db.engine.connect() as conn:
            if dialect == 'postgresql':
                for col in ('ca_cert', 'client_cert', 'client_key'):
                    conn.execute(db.text(f"ALTER TABLE docker_config ALTER COLUMN {col} TYPE TEXT"))
                conn.commit()
            elif dialect in ('mysql', 'mariadb'):
                for col in ('ca_cert', 'client_cert', 'client_key'):
                    conn.execute(db.text(f"ALTER TABLE docker_config MODIFY {col} TEXT"))
                conn.commit()
            # SQLite VARCHAR doesn't enforce length, no migration needed.
    except Exception:
        traceback.print_exc()
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