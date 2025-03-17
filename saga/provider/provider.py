from flask import Flask, request, jsonify, redirect, url_for
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, JWTManager
from authlib.integrations.flask_client import OAuth
from flask_pymongo import PyMongo
import saga.crypto as sc
from saga.ca.CA import get_SAGA_CA
import base64
from datetime import datetime, timezone, timedelta
import os
import saga.config


class Provider:
    def __init__(
            self,
            workdir,
            name,
            host="0.0.0.0", 
            port=5000, 
            mongo_uri="mongodb://localhost:27017/saga", 
            jwt_secret="supersecretkey"
        ):
        """
        Initializes the Provider with MongoDB, JWT, and OAuth configuration.
        """

        self.workdir = workdir if workdir[-1] == '/' else workdir+'/'
        if not os.path.exists(self.workdir):
            os.mkdir(self.workdir)
        self.name = name
        self.app = Flask(__name__)
        self.app.config["MONGO_URI"] = mongo_uri
        self.app.config["JWT_SECRET_KEY"] = jwt_secret

        # Initialize MongoDB, JWT, and Bcrypt
        self.mongo = PyMongo(self.app)
        self.jwt = JWTManager(self.app)
        self.bcrypt = Bcrypt(self.app)

        self.active_jwt_tokens = []

        # OAuth setup
        self.oauth = OAuth(self.app)
        self.google = self.oauth.register(
            name='google',
            client_id='598128652574-bh1oes4c5f5p22su48guffi65q2bobke.apps.googleusercontent.com',
            client_secret='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',
            authorize_url='https://accounts.google.com/o/oauth2/auth',
            access_token_url='https://oauth2.googleapis.com/token',
            client_kwargs={'scope': 'openid uid profile'},
        )

        # MongoDB Collections
        self.users_collection = self.mongo.db.users
        self.agents_collection = self.mongo.db.agents

        # Load CA object for certificate signing:
        self.CA = get_SAGA_CA()

        # Load TLS signing keys:
        if not (os.path.exists(self.workdir+f"{self.name}.key") and os.path.exists(self.workdir+f"{self.name}.pub") and os.path.exists(self.workdir+f"{self.name}.crt")):
            # Generate cryptographic material for signing. 
            self.SPIK, self.PIK = sc.generate_ed25519_keypair()
            self.cert = self.CA.sign(self.PIK, config=saga.config.PROVIDER_CONFIG)
            sc.save_ed25519_keys(self.workdir+f"{self.name}", self.SPIK, self.PIK)
            sc.save_x509_certificate(self.workdir+f"{self.name}", self.cert)
        else:
            self.SPIK, self.PIK = sc.load_ed25519_keys(self.workdir+f"{self.name}")
            self.cert = sc.load_x509_certificate(self.workdir+f"{self.name}.crt")
        self.ssl_context = (self.workdir+f"{self.name}.crt", self.workdir+f"{self.name}.key")

        # Register routes
        self._register_routes()

        # Web server settings
        self.host = host
        self.port = port

    def _register_routes(self):
        """Registers all Flask routes for the provider."""

        @self.app.route('/register', methods=['POST'])
        def register():
            data = request.json
            uid = data.get("uid")
            password = data.get("password")

            if self.users_collection.find_one({"uid": uid}):
                return jsonify({"message": "User already exists"}), 400

            hashed_pw = self.bcrypt.generate_password_hash(password).decode("utf-8")
            identity_key = data.get("identity_key")
            identity_key_bytes = base64.b64decode(identity_key)

            self.users_collection.insert_one({
                "uid": uid,
                "password": hashed_pw,
                "identity_key": identity_key_bytes,
                "auth_tokens": []
            })

            return jsonify({"message": "User registered successfully"}), 201

        @self.app.route('/login', methods=['POST'])
        def login():
            data = request.json
            uid = data.get("uid")
            password = data.get("password")

            user = self.users_collection.find_one({"uid": uid})
            if user and self.bcrypt.check_password_hash(user["password"], password):
                access_token = create_access_token(identity=user["uid"])
                self.users_collection.update_one({"uid": uid}, {"$push": {"auth_tokens": {
                    "token": access_token,
                    "exp": (datetime.now(timezone.utc) + timedelta(days=1)).replace(tzinfo=timezone.utc)
                }}})
                return jsonify({"access_token": access_token}), 200

            return jsonify({"message": "Invalid credentials"}), 401

        @self.app.route('/oauth_login')
        def oauth_login():
            return self.google.authorize_redirect(url_for('oauth_callback', _external=True, _scheme='https'))

        @self.app.route('/oauth_callback')
        def oauth_callback():
            token = self.google.authorize_access_token()
            user_info = self.google.get("https://www.googleapis.com/oauth2/v2/userinfo").json()
            
            uid = user_info["id"]
            user = self.users_collection.find_one({"uid": uid})

            if not user:
                self.users_collection.insert_one({"uid": uid})

            access_token = create_access_token(identity=uid)
            return jsonify({"access_token": access_token})

        @self.app.route('/register_agent', methods=['POST'])
        def register_agent():
            data = request.json
            uid = data.get("uid")
            user_jwt = data.get("jwt")

            # Validate user
            user = self.users_collection.find_one({"uid": uid})
            if not user:
                return jsonify({"message": "User not found"}), 404

            usr_record = self.users_collection.find_one({"uid": uid, "auth_tokens.token": user_jwt})
            if not usr_record:
                return jsonify({"message": "User not authenticated"}), 401

            now = datetime.now(timezone.utc)
            exp = usr_record["auth_tokens"][0]["exp"].replace(tzinfo=timezone.utc)
            if now > exp:
                return jsonify({"message": "Token expired."}), 401

            application = data.get("application")
            aid = application.get("aid")
            if not aid:
                return jsonify({"message": "Agent aid not provided"}), 400
            if self.agents_collection.find_one({"aid": aid}):
                return jsonify({"message": f'Agent "{aid}" already exists.'}), 401

            # Verify signatures
            device = application.get("device")
            ip = application.get("IP")
            port = application.get("port")

            dev_info = {
                "aid": aid, 
                "device": device, 
                "IP": ip, 
                "port": port, 
                "pik": self.PIK.public_bytes(
                    encoding=sc.serialization.Encoding.Raw,
                    format=sc.serialization.PublicFormat.Raw)
            }
            dev_info_sig_bytes = base64.b64decode(application.get("dev_info_sig"))

            user_identity_key = sc.bytesToPublicEd25519Key(user["identity_key"])

            try:
                user_identity_key.verify(
                    dev_info_sig_bytes,
                    str(dev_info).encode("utf-8")
                )
            except:
                return jsonify({"message": "Invalid device info signature"}), 401

            
            # Get the agent certificate:
            agent_cert_bytes = base64.b64decode(application.get("agent_cert"))
            agent_cert = sc.bytesToX509Certificate(agent_cert_bytes)


            public_signing_key_bytes = agent_cert.public_key().public_bytes(
                encoding=sc.serialization.Encoding.Raw,
                format=sc.serialization.PublicFormat.Raw
            ) 
            public_signing_key_sig_bytes = base64.b64decode(application.get("public_signing_key_sig"))

            agent_identity = {
                "aid": aid,
                "public_signing_key": public_signing_key_bytes,
                "pik": self.PIK.public_bytes(
                    encoding=sc.serialization.Encoding.Raw,
                    format=sc.serialization.PublicFormat.Raw)
            }

            try:
                user_identity_key.verify(
                    public_signing_key_sig_bytes,
                    str(agent_identity).encode("utf-8")
                )
            except:
                return jsonify({"message": "Invalid agent identity signature"}), 401

            agent_identity_key_bytes = base64.b64decode(application.get("identity_key"))

            spk_bytes = base64.b64decode(application.get("spk"))
            spk_sig_bytes = base64.b64decode(application.get("spk_sig"))

            try:
                user_identity_key.verify(spk_sig_bytes, spk_bytes)
            except:
                return jsonify({"message": "Invalid signed pre-key signature"}), 401

            opks = application.get("opks")
            opks_bytes = [base64.b64decode(opk) for opk in opks]

            self.agents_collection.insert_one({
                "aid": aid,
                "device": device,
                "IP": ip,
                "port": port,
                "dev_info_sig": dev_info_sig_bytes,
                "identity_key": agent_identity_key_bytes,
                "agent_cert": agent_cert_bytes,
                "public_signing_key_sig": public_signing_key_sig_bytes,
                "signed_pre_key": spk_bytes,
                "signed_pre_key_sig": spk_sig_bytes,
                "one_time_pre_keys": opks_bytes
            })

            self.users_collection.update_one({"uid": uid}, {"$pull": {"auth_tokens": {"token": user_jwt}}})
            return jsonify({"message": "Agent registered successfully"}), 201

        @self.app.route('/lookup', methods=['POST'])
        def lookup():
            data = request.json
            t_aid = data.get("t_aid", None)

            agent_metadata = self.agents_collection.find_one({"aid" : t_aid})
            user_metadata = self.users_collection.find_one({"uid" : t_aid.split(":")[0]})
            if user_metadata is None:
                return jsonify({"message":"Cannot find agent owner."}), 404
            # Include the user's identity key in the response
            user_identity_key = user_metadata.get("identity_key")
            agent_metadata.update({"user_identity_key": user_identity_key})
            # Remove the one time pre-keys from the response
            agent_metadata.pop("one_time_pre_keys", None)

            return jsonify(agent_metadata), 200
    
        @self.app.route('/access', methods=['POST'])
        def access():
            data = request.json
            t_aid = data.get("t_aid", None)

            user_metadata = self.users_collection.find_one({"uid" : t_aid.split(":")[0]})
            if user_metadata is None:
                return jsonify({"message":"Cannot find agent owner."}), 404

            agent_metadata = self.agents_collection.find_one_and_update(
                {"aid": t_aid, "one_time_pre_keys": {"$ne": []}},  # Ensure keys exist
                {"$pop": {"one_time_pre_keys": 1}},  # Remove last element
                return_document=False  # Return document *before* modification
            )

            # If agent not found or no keys left, return 404
            if agent_metadata is None:
                return jsonify({"message": "Agent not found or no keys left."}), 404

            # Include the user's identity key in the response
            user_identity_key = user_metadata.get("identity_key")
            agent_metadata.update({"user_identity_key": user_identity_key})
            # Remove the one time pre-keys from the response
            agent_metadata['one_time_pre_keys'] = [agent_metadata['one_time_pre_keys'][0]]

            return jsonify(agent_metadata), 200
    
    
    def run(self):
        """Runs the web server."""
        self.app.run(host=self.host, port=self.port, ssl_context=self.ssl_context)


# Run the provider
if __name__ == "__main__":
    provider = Provider(
        workdir="./",
        name="provider",
        host="0.0.0.0",
        port=5000,
        mongo_uri="mongodb://localhost:27017/saga",
        jwt_secret="supersecretkey"
    )
    provider.run()
