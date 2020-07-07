# Ansible collection for joining hosts using realmd to domains

This module is designed to leverage pexpect module from Python and realmd package to join CentOS/Fedora/RHEL machines to either Active Directory or IPA

## Requirements 

- ansible version >= 2.9 (version that was tested with)
- pexpect >= 4.8.0  (version that was tested with)

## Installation 
To install all dependencies:

```bash
pip install -r requirements.txt
```

To install the Collection hosted in Galaxy:

```bash
ansible-galaxy collection install ogratwicklcs.realmd_ipa_ad
```

## Usage

### Playbooks

The playbook attached to the collection will install the dependencies for the Realmd package based on the IDP you will be using to join the machine to.
After the first task completes, the second task will join the server to the IDP specified.

You must provide the following variables to the playbook:

```yaml
domain_name: <full name of your domain>
username: <username that has priveleges to add server to domain>
password: <password for the admin user used for joining to domain>
provider: <ad or ipa>
nameserver: <dns server to resolve your domain>
virtualenv: <python virtual environment name that will be used to install pexpect module to>
```

### Roles
Stores the role that is used by the playbook to configure hosts to be able to discover and join the specified realm and install dependencies for realmd package.
(Tested on CentOS 8 / RHEL 8)

### Plugins

Has the code used to leverage pexpect and realmd to join Linux servers to IDP. 

```yaml
    options:
      domain:
        description:
          - "The case senstive kerberos realm that you want to add"
          - "your node to you must specify the way you will"
          - "authenticate the node to the remote server. The most"
          - "common way is to use Username and Password for a user"
          - "to has permissiosn to add VMs to domain.You can also"
          - "use a one-time-password option or no password if you"
          - "have configured your domain to allow that"
        required: true

      state:
        description:
          - Whether to join the kerberos realm
          - C(present) or remove C(absent)
          - Default is C(present)
          - If state is C(present) and node is already joined to realm
          - the node will first be removed from the realm and then
          - added back to the appropriate realm
        choices: ['absent', 'present']

      username:
        description:
          - If you are using an account to join the realm you must
          - select this option as  well specify the password for the account

      ou_location:
        description:
            - OU location you want your node to be
            - added to on your identity provider.
            - This module will not add and remove
            - the entry in the identity provider's 
            - database

      password:
        description:
          - Password for the NTML or domain user that can add
          - the specified node to the realm
          - Recommended to pass this as an environment variable or
          - through Ansible Tower / Ansible Vault

      onetimepass:
        description:
          - One time password that is configured by your domain
          - to allow nodes to join
          - This, Username / Password, or nopass option must be selected

      nopass:
        description:
          - An option yes or no for whether to run the realm join
          - with no password specifiednum
```

### EXAMPLES 
``` yaml
- name: Join to Active Directory domain
  realm_join:
    domain: realm.com
    state: present
    username: adminUsername
    password: adminPassword

- name: Leave Kerberos realm
  realm_join:
    state: absent

- name: Join with one-time-password
  realm_join:
    domain: realm.com
    state: present
    onetimepass: password
```

Tested on (CentOS/RHEL 7-8)

## License

GNU General Public License v3.0

See [LICENSE](LICENSE) to see the full text.