#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Native activation service tests with synthetic authenticated dependency servers.

No target, production key or whole-composition qualification is involved.
"""
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = "gate"

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def digest(value):
    return "sha256:" + hashlib.sha256(("munarium:stage2:activation:v1\0" + encoded(value)).encode()).hexdigest()

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("redirect refused")

class ActivationService(unittest.TestCase):
    def test_authenticated_barrier_and_process_recovery(self):
        openssl = shutil.which("openssl") or ("C:/Program Files/Git/usr/bin/openssl.exe" if os.name == "nt" else None)
        self.assertTrue(openssl and Path(openssl).is_file(), "OpenSSL required")
        binary = ROOT / "target/debug" / ("munarium-" + COMPONENT + (".exe" if os.name == "nt" else ""))
        self.assertTrue(binary.is_file(), "build native service first")
        with tempfile.TemporaryDirectory(prefix="munarium-activation-" + COMPONENT + "-") as folder:
            root = Path(folder)
            def run(*args):
                subprocess.run([openssl, *map(str,args)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", root/"ca.key", "-out", root/"ca.pem", "-days", "1", "-subj", "/CN=activation-test-ca",
                "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
            ext=root/"ext.cnf"
            ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n")
            fingerprints={}
            for name in ("service","dependency","council","reader","agent","unknown"):
                run("req","-newkey","rsa:2048","-nodes","-keyout",root/(name+".key"),"-out",root/(name+".csr"),"-subj","/CN="+name)
                run("x509","-req","-in",root/(name+".csr"),"-CA",root/"ca.pem","-CAkey",root/"ca.key","-CAcreateserial","-days","1","-extfile",ext,"-out",root/(name+".pem"))
                fingerprints[name]=hashlib.sha256(ssl.PEM_cert_to_DER_cert((root/(name+".pem")).read_text())).hexdigest()
            vectors=json.loads((ROOT/"contracts/stage2-v1/vectors.json").read_text())
            transition=copy.deepcopy(vectors["records"]["activation"])
            scope=copy.deepcopy(transition["scope"])
            scope["cell"]="native-"+str(time.time_ns())
            transition["scope"]=scope
            transition["transition"]["scope"]=scope
            transition["ratification"]["scope"]=scope
            transition.update(not_before=int(time.time())-10,expires_at=int(time.time())+600)
            def receipt(owner, phase="applied"):
                result=copy.deepcopy(vectors["records"]["pause"])
                for key in ("transition","prior_epoch","successor_epoch","artifact_set_digest","participant_set_digest"):
                    result[key]=transition[key]
                result.update(participant=owner, phase=phase, transition_digest=digest(transition))
                return result
            def head(owner):
                return dict(scope=scope,participant=owner,epoch=transition["successor_epoch"],artifact_set_digest=transition["artifact_set_digest"])
            policy=dict(scope=scope,coordinator="council",readers=["reader"],initial_epoch=1,initial_artifact_set_digest=transition["prior_artifact_set_digest"])
            mode=dict(ratified=True, missing=False, wrong=False, paused=True, revision=1, churn=False)
            class Dependency(BaseHTTPRequestHandler):
                def log_message(self,*args): pass
                def answer(self,body,status=200):
                    if hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()!=fingerprints["service"]:
                        self.send_error(403); return
                    raw=encoded(body).encode()
                    self.send_response(status)
                    self.send_header("Content-Type","application/json")
                    self.send_header("Content-Length",str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                def do_GET(self):
                    if mode["churn"]: mode["revision"] += 1
                    self.answer(dict(config=dict(deployment=scope["deployment"],tenant=scope["tenant"]),head=1,
                        revision=mode["revision"],artifact=dict(bindings={"stage2:"+COMPONENT:policy})))
                def do_POST(self):
                    count=int(self.headers.get("Content-Length","0"))
                    if count>262144: self.send_error(413); return
                    body=json.loads(self.rfile.read(count)); action=body["action"]
                    if self.path=="/council/v1/transitions":
                        self.answer(dict(transition=transition,transition_digest=digest(transition),ratified=mode["ratified"]));return
                    if mode["missing"] and (mode["missing"] is True or "/platform/" in self.path):
                        self.answer(dict(error="test-dependency-unavailable"),503);return
                    if self.path=="/gate/v1/actions":
                        if action["operation"]=="pause-lookup": self.answer(receipt("gate","paused"))
                        else:
                            result=head("gate");result.update(paused=mode["paused"],transition_id=transition["transition"]["id"])
                            self.answer(result)
                        return
                    owner="server" if "/platform/" in self.path else ("registry" if self.path.startswith("/registry/") else "warden")
                    result=head(owner) if action["operation"]=="head" else receipt(owner)
                    if mode["wrong"] and owner=="registry":
                        result["epoch" if action["operation"]=="head" else "successor_epoch"]=999
                    self.answer(result)
            dependency=ThreadingHTTPServer(("127.0.0.1",0),Dependency)
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(root/"dependency.pem",root/"dependency.key")
            ctx.load_verify_locations(root/"ca.pem");ctx.verify_mode=ssl.CERT_REQUIRED
            dependency.socket=ctx.wrap_socket(dependency.socket,server_side=True)
            worker=threading.Thread(target=dependency.serve_forever,daemon=True);worker.start()
            with socket.socket() as listener:
                listener.bind(("127.0.0.1",0));port=listener.getsockname()[1]
            upstream="https://localhost:"+str(dependency.server_port)
            tls=dict(listen="127.0.0.1:"+str(port),certificate_file=str(root/"service.pem"),private_key_file=str(root/"service.key"),ca_file=str(root/"ca.pem"),
                peers={fingerprints[p]:dict(service=p,tenants=[scope["tenant"]]) for p in ("council","reader","agent")})
            config=dict(tls=tls,server_endpoint=upstream,deployment=scope["deployment"])
            if COMPONENT=="gate":
                database=os.environ.get("GATE_TEST_DATABASE_URL")
                self.assertTrue(database,"isolated PostgreSQL URL required")
                (root/"database-url").write_text(database)
                config.update(registry_endpoint=upstream+"/registry",warden_endpoint=upstream+"/warden",service="gate",server_service="server",
                    registry_service="registry",provider_id="fixture",provider_token_file=str(root/"unused-token"),journal=str(root/"decisions.sqlite"),
                    evaluator=dict(python="unused",worker="unused",executable="unused",worker_digest="unused",executable_digest="unused",version="unused",capabilities={}),
                    activation=dict(database_url_file=str(root/"database-url"),council_endpoint=upstream+"/council"))
                route="/v1/actions"
                lookup="activation-lookup";head_operation="activation-head";apply_operation="apply-activation"
            else:
                (root/"signing-key").write_bytes(os.urandom(32))
                config.update(signing_key_file=str(root/"signing-key"),key_id="test-only",
                    activation=dict(database=str(root/"activation.sqlite"),service="warden",council_endpoint=upstream+"/council",gate_endpoint=upstream+"/gate",registry_endpoint=upstream+"/registry"))
                route="/v1/activation";lookup="lookup";head_operation="head";apply_operation="apply"
            (root/"config.json").write_text(encoded(config))
            child=None
            def start():
                process=subprocess.Popen([str(binary),str(root/"config.json")],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                for _ in range(250):
                    if process.poll() is not None: self.fail("service exited before readiness")
                    try:
                        with socket.create_connection(("127.0.0.1",port),timeout=0.1): return process
                    except OSError: time.sleep(0.02)
                process.kill();process.wait();self.fail("service startup timeout")
            def call(action,peer="council",tenant=None):
                ctx=ssl.create_default_context(cafile=str(root/"ca.pem"))
                ctx.load_cert_chain(root/(peer+".pem"),root/(peer+".key"))
                opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx),NoRedirect())
                request=urllib.request.Request("https://localhost:"+str(port)+route,data=encoded(dict(tenant=tenant or scope["tenant"],action=action)).encode(),headers={"Content-Type":"application/json"})
                with opener.open(request,timeout=6) as response:
                    data=response.read(262145)
                    if len(data)>262144: raise ValueError("response too large")
                    return json.loads(data)
            def refused(action,peer="council",tenant=None):
                if peer == "unknown":
                    with self.assertRaises((OSError,ValueError,urllib.error.URLError)): call(action,peer,tenant)
                else:
                    with self.assertRaises(urllib.error.HTTPError) as caught: call(action,peer,tenant)
                    self.assertIn(caught.exception.code,(400,403,409,503))
            try:
                child=start()
                apply=dict(operation=apply_operation,transition=encoded(transition))
                for peer,tenant in (("agent",None),("reader",None),("unknown",None),("council","foreign")):
                    refused(apply,peer,tenant)
                if COMPONENT=="gate":
                    refused(apply)
                    pause=dict(operation="pause",transition=encoded(transition))
                    first=call(pause);self.assertEqual(first,receipt("gate","paused"))
                    child.kill();child.wait(timeout=10);child=start()
                    self.assertEqual(call(pause),first)
                else:
                    mode["paused"]=False;refused(apply);mode["paused"]=True
                    mode["missing"]=True;refused(apply);mode["missing"]=False
                    mode["wrong"]=True;refused(apply);mode["wrong"]=False
                mode["churn"]=True;refused(apply);mode["churn"]=False
                first=call(apply)
                self.assertEqual(first,receipt(COMPONENT))
                child.kill();child.wait(timeout=10);child=start()
                self.assertEqual(call(dict(operation=lookup,transition_id=transition["transition"]["id"]),peer="reader"),first)
                self.assertEqual(call(apply),first)
                mode["ratified"]=False;refused(apply);mode["ratified"]=True
                if COMPONENT=="gate":
                    completion=dict(transition=transition,pause=receipt("gate","paused"),receipts=[receipt(p) for p in ("gate","registry","server","warden")])
                    missing=copy.deepcopy(completion);missing["receipts"].pop()
                    refused(dict(operation="resume",completion=missing))
                    resume=dict(operation="resume",completion=completion)
                    mode["missing"]="server";refused(resume);mode["missing"]=False
                    mode["wrong"]=True;refused(resume);mode["wrong"]=False
                    self.assertTrue(call(dict(operation=head_operation),peer="reader")["paused"])
                    reply=call(resume);self.assertTrue(reply["resumed"]);self.assertFalse(reply["execution_enabled"])
                    child.kill();child.wait(timeout=10);child=start()
                    self.assertEqual(call(resume),reply)
                    self.assertFalse(call(dict(operation=head_operation),peer="reader")["paused"])
                else:
                    status=call(dict(operation=head_operation),peer="reader")
                    self.assertEqual(status["epoch"],2);self.assertFalse(status["cell_resumed"])
            finally:
                if child and child.poll() is None: child.kill();child.wait(timeout=10)
                dependency.shutdown();dependency.server_close();worker.join(timeout=10)

if __name__=="__main__":
    unittest.main()
