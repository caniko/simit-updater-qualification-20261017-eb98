"""Hosted-only controlled GitHub lifecycle check for exact Simit PR 71 bytes."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def run(*args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args}: {result.stdout}\n{result.stderr}")
    return result.stdout.strip()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


evidence = Path(sys.argv[1]).resolve()
repository = os.environ["GITHUB_REPOSITORY"]
coordinate = "github.com/" + repository
revision = "30358c23a54f8cea463883d16823ef62bb769313"
result = json.loads((evidence / "result.json").read_text())
binary = Path(result[0]["outputs"]["out"]) / "bin/simit"
assert str(binary).startswith("/nix/store/")
assert (evidence / "revision").read_text().strip() == revision
assert (evidence / "tree").read_text().strip() == "3e631b999383ed532f9a0bc2cd9dc6da45072415"
binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
assert binary_hash == "1492d36db07dab391f1274c915367bdced602081eea133aa04660a39987c56e2"
save(evidence / "identity.json", {
    "sourceRepository": "caniko/simit", "sourceRevision": revision,
    "binary": str(binary), "binarySha256": binary_hash,
    "fixtureRepository": repository, "harnessRevision": os.environ["GITHUB_SHA"],
    "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
})

with tempfile.TemporaryDirectory(prefix="simit-live-authority-") as temporary:
    authority = Path(temporary)
    authority.chmod(0o700)
    credential = authority / "github-token"
    credential.write_text(os.environ.pop("GH_TOKEN"))
    credential.chmod(0o600)
    key = authority / "deploy-key"
    key.write_text(os.environ.pop("FIXTURE_SSH_KEY") + "\n")
    key.chmod(0o600)
    known_hosts = authority / "known-hosts"
    known_hosts.write_text("github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n")
    gitconfig = authority / "gitconfig"
    gitconfig.write_text(
        '[user]\n name = Can H. Tartanoglu\n email = gpg@rotas.mozmail.com\n'
        f'[url "ssh://git@github.com/{repository}.git"]\n insteadOf = https://github.com/{repository}.git\n'
    )
    env = dict(os.environ, GIT_CONFIG_GLOBAL=str(gitconfig), GIT_CONFIG_NOSYSTEM="1",
               GIT_SSH_COMMAND=f"ssh -i {key} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile={known_hosts}")
    root = Path(os.environ["RUNNER_TEMP"]) / "live-updater-state"
    projects = Path(os.environ["RUNNER_TEMP"]) / "live-projects"
    projects.mkdir()
    inventory = authority / "inventory.json"
    save(inventory, {
        "schemaVersion": 1, "root": str(projects),
        "observedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "producer": "controlled-hosted-lifecycle", "policyDigest": "b" * 64,
        "projects": [{"coordinate": coordinate, "forge": "github", "relativePath": "arbitrary/layout/project",
                      "kind": "owned-repo", "lifecycle": "active", "access": "normal",
                      "checkoutRole": "canonical", "simitCi": "auto", "mirrors": []}],
    })
    config = authority / "updates.json"
    policy = {
        "schemaVersion": 1,
        "workspaces": {"projects": {"root": str(projects), "stateDirectory": str(root),
                                     "inventory": {"file": str(inventory)}}},
        "forges": {"github": {"host": "github.com", "apiUrl": "https://api.github.com",
                               "credentialFile": str(credential), "checkAuthority": "15368",
                               "adapter": {"program": str(binary), "arguments": ["projects", "update-github-adapter"]}}},
        "profiles": {"live": {"workspace": "projects", "scopes": ["ci"], "select": {"coordinates": [coordinate]},
                              "enrollCurrent": True, "requiredChecks": [{"name": "test", "authority": "15368"}],
                              "generator": {"executable": str(binary), "sourceRevision": revision,
                                            "sourceCoordinate": coordinate, "forge": "github",
                                            "requiredChecks": [{"name": "test", "authority": "15368"}]},
                              "projectOverrides": {coordinate: {"targetBranch": "consumer"}}}},
    }
    save(config, policy)
    save(evidence / "policy.json", policy)
    save(evidence / "inventory.json", json.loads(inventory.read_text()))
    command = [str(binary), "projects", "update", "--config", str(config), "--profile", "live", "--json"]
    try:
        preview = json.loads(run(*command, "--dry-run", "--wait-seconds", "1800", env=env))
        save(evidence / "preview.json", preview)
        assert len(preview) == 1 and preview[0]["phase"] == "preview", preview
        assert ".github/workflows/ci.yaml" in preview[0]["managed"]
        pushed = subprocess.run([*command, "--push", "--wait-seconds", "1800"], text=True, capture_output=True, env=env)
        (evidence / "push.stdout").write_text(pushed.stdout)
        (evidence / "push.stderr").write_text(pushed.stderr)
        assert pushed.returncode == 0, pushed.stdout + pushed.stderr
        reports = json.loads(pushed.stdout)
        assert len(reports) == 1 and reports[0]["phase"] == "qualified", reports
        receipt = reports[0]
        checkout = next(root.glob("profile-*/repo-*/checkout"))
        assert run("git", "ls-remote", "origin", "refs/heads/consumer", cwd=checkout, env=env).split()[0] == receipt["candidate"]
        assert run("git", "ls-remote", "origin", "refs/heads/" + receipt["branch"], cwd=checkout, env=env).split()[0] == receipt["candidate"]
        assert run("git", "show", "-s", "--format=%P", receipt["candidate"], cwd=checkout, env=env) == receipt["source"]
        unchanged = json.loads(run(*command, "--push", "--wait-seconds", "1800", env=env))
        save(evidence / "unchanged.json", unchanged)
        assert unchanged[0]["phase"] == "unchanged" and unchanged[0]["candidate"] == receipt["candidate"]
        status = json.loads(run(*command, "--status", env=env))
        save(evidence / "status.json", status)
        assert status[0]["phase"] == "unchanged"
        print("PASS: genuine maintenance push -> original GitHub Actions -> same-commit landing -> adoption -> baseline -> unchanged")
    finally:
        for source in root.glob("profile-*/repo-*/*"):
            if source.is_file() and (source.suffix == ".json" or source.name == "commit.txt"):
                destination = evidence / source.parent.parent.name / source.parent.name / source.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
