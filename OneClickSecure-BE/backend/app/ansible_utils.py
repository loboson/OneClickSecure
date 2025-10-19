import subprocess
import tempfile
import json
import os

def get_os_info_with_ansible(ip, username, password):
    inventory_content = f"""[target]
{ip} ansible_user={username} ansible_password={password} ansible_become=yes ansible_become_method=sudo ansible_become_password={password} ansible_ssh_common_args='-o StrictHostKeyChecking=no'
"""
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as inv_file:
        inv_file.write(inventory_content)
        inv_path = inv_file.name

    facts_path = f"/tmp/ansible_facts/{ip}"
    try:
        result = subprocess.run(
            [
                "ansible",
                "all",
                "-i", inv_path,
                "-m", "setup",
                "-a", "filter=ansible_distribution*",
                "-o",
                "--tree", "/tmp/ansible_facts"
            ],
            capture_output=True,
            text=True,
            timeout=30
        )
        if not os.path.exists(facts_path):
            print("Ansible facts file not found:", facts_path)
            print("STDOUT:", result.stdout)
            print("STDERR:", result.stderr)
            return "Unknown"
        with open(facts_path, "r") as f:
            facts = json.load(f)
        distro = facts["ansible_facts"].get("ansible_distribution", "")
        version = facts["ansible_facts"].get("ansible_distribution_version", "")
        return f"{distro} {version}".strip()
    except Exception as e:
        print("Error getting OS info:", e)
        return "Unknown"
    finally:
        try:
            os.remove(inv_path)
        except:
            pass
        try:
            if os.path.exists(facts_path):
                os.remove(facts_path)
        except:
            pass
