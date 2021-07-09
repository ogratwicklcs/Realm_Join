#!/usr/bin/python
# -*- coding: utf-8 -*-

from ansible.module_utils.basic import AnsibleModule
ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
    module: realm_join
    version_added: 2.9
    short_description: Manage realm RHEL and CentOS servers
    description:
      - Use realmd package to add and remove a node from membership
      - with kerberos realms like Active Directory or IPA
    notes:
    - Tested on RHEL and CentOS 7.7 and 8.0 with Python 2.7 and Python 3.6
    - Requires following RPM packages on the remote node if joining to Active Directory
        - krb5-workstation, samba-common-tools, sssd-ad, realmd
    - Requires following RPM packages on the remote node if joining to IPA
        - realmd, ipa-client
    - Requires Pexpect python package on the remote host

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
          - This, C(Username) / C(Password), or nopass option must be selected

      nopass:
        description:
          - An option (C(yes) or (no)) for whether to run the realm join
          - with no password specifiednum
'''

EXAMPLES = '''
- name: Join to Active Directory domain
  realm_kerb:
    domain: realm.com
    state: present
    username: adminUsername
    password: adminPassword

- name: Leave Kerberos realm
  realm_kerb:
    state: absent

- name: Join with one-time-password
  realm_kerb:
    domain: realm.com
    state: present
    onetimepass: password
'''

RETURN = '''
realm:
    description:
        - Output of realm list after module has been run successfully
        - The first entry in list is the status code of the realmd command
        - for the realm list command.
        - The second portion of the list is the output of the realm list
    returned: on success (changed/not changed)
    type: list

'''

try:
    import rpm
    rpm_lib = True
except ImportError:
    rpm_lib = False


def main():
    module = AnsibleModule(
        argument_spec=dict(
            domain=dict(type='str', required=True),
            state=dict(type='str', choices=[
                       'absent', 'present'], default="present"),
            username=dict(type='str'),
            password=dict(type='str', no_log=True),
            onetimepass=dict(type='str', no_log=True),
            ou_location=dict(type='str'),
            nopass=dict(type='str', choices=['yes', 'no'], default="no")
        ),
        required_one_of=[['nopass', 'onetimepass', 'username']],
        mutually_exclusive=[['nopass', 'onetimepass', 'username']],
        required_together=[['username', 'password']],
        supports_check_mode=True
    )
    # DEBUGGING
    # pdb.set_trace()
    # debug_output = []
    # debug_output.append(ou_loc)
    # module.exit_json(changed=False, debug_out=debug_output)
    # DEBUGGING

    pkgs_list = ["krb5-workstation",
                 "samba-common-tools", "sssd-ad", "realmd"]
    for name in pkgs_list:
        pkg_chk = rpm_installed(name)
        if not pkg_chk:
            module.fail_json(msg=("Package not found: " + name))

    check_realm = domain_check(module)  # runs function to return:
    # True = Joined Domain |  False = Not Joined
    if module.check_mode:
        chk_mode(module, check_realm)
    state_check(module, check_realm)


def state_check(module, check_realm):
    if module.params['state'] == 'present':
        discover = discover_realm(module)
        if discover:  # checks to see if domain is discoverable
            if check_realm is False:  # runs function to join realm
                join_realm(module)
            else:
                realm_query = query_realm(module)
                if realm_query != "":
                    try:
                        import re
                        re_lib = True
                    except ImportError:
                        re_lib = False
                    str_query = str(realm_query[1])
                    compile_str = str(re.compile(str_query))
                    search_result = re.search(
                        r'domain-name: ' + str(module.params['domain']), 
                        compile_str)
                    if search_result is None:  # NEEDS TESTING WITHMULTIPLE REALMS
                        leave = realm_leave(module)
                        if leave is False:
                            join_realm(module)
                        else:
                            module.fail_json(
                                msg="Failed leaving and re-joining realm",
                                return_value=query_realm(module))
                    else:
                        module.exit_json(
                            changed=False, return_value=query_realm(module))
                else:
                    module.fail_json(msg="Should not get here")
        else:
            module.fail_json(
                msg="Failed discovering realm " +
                module.params['domain'])  # + module.params['domain'])

    if module.params['state'] == 'absent':
        if check_realm:  # run the realm leave command from a function
            leave = realm_leave(module)
            if leave is True:
                module.exit_json(
                    changed=True, return_value=query_realm(module))
            else:
                module.fail_json(
                    msg="Failed leaving realm with following return values",
                    return_value=query_realm(module))
        else:
            # success since not joined to realm
            module.exit_json(changed=False, return_value=query_realm(module))


def chk_mode(module, check_realm):
    if module.params['state'] == 'present':
        discover = discover_realm(module)
        if discover:  # checks to see if domain is discoverable
            if check_realm is False:  # runs function to join realm
                module.exit_json(
                    changed=True,
                    msg="Realm will be added " +
                    module.params['domain'])
            else:
                realm_query = query_realm(module)
                if realm_query != "":
                    try:
                        import re
                        re_lib = True
                    except ImportError:
                        re_lib = False
                    str_query = str(realm_query[1])
                    compile_str = str(re.compile(str_query))
                    search_result = re.search(
                        r'domain-name: ' + str(module.params['domain']), 
                        compile_str)
                    if search_result is None:  # runs on realm mismatch
                        module.exit_json(
                            changed=True,
                            msg="Will leave and re-add the specific realm",
                            return_value=search_result)
                    else:
                        module.exit_json(
                            changed=False,
                            msg="Already joined to the specific relam",
                            return_value=query_realm(module))
                else:
                    module.exit_json(
                        changed=True,
                        msg="Will join domain " +
                        module.params['domain'])
        else:
            module.fail_json(
                msg="Failed discovering realm " +
                module.params['domain'])  # + module.params['domain'])

    if module.params['state'] == 'absent':
        if check_realm:  # run the realm leave command from a function
            module.exit_json(
                changed=True,
                msg="Leaving specificied realm " +
                module.params['domain'])
        else:
            # success since not joined to realm
            module.exit_json(changed=False,
                             msg="Node already not part of a realm")

# not sure other way of of running domain_check which required module for
# if statement


def realm_leave(module):  # False if left the realm | True if joined

    module.run_command(['realm', 'leave'])
    leave_check = domain_check(module)  # verify command was successful
    if not leave_check:
        return True
    else:
        return False


def join_realm(module):
    join_str = str("realm join")
    domain = str(module.params["domain"])
    ou = str(module.params["ou_location"])
    ou_cmd = str("--computer-ou=\'" + ou + "\'")
    # create string from different parts of the command

    if ou != "None":
        cmd = " ".join([join_str, domain, ou_cmd])
    else:
        cmd = " ".join([join_str, domain])
    pexpect_lib = False

    # if the user did not specify onetimepassword
    if module.params["onetimepass"] is None:
        # if user did not specify to run without password
        if module.params["nopass"] == "no":
            # run command using pexpect
            mod_cmd = cmd + " --user=" + \
                module.params["username"]
            try:
                import pexpect  # Need pexpect lib only for this
                pexpect_lib = True
            except ImportError:
                module.fail_json(
                    msg=("Not able to import pexpect.  Module not able to"
                         " add server to AD using username and password if"
                         " pexpect module not installed"))
        else:
            mod_cmd = cmd + " --no-password"
    else:
        mod_cmd = cmd + " --one-time-password=" + \
            module.params["onetimepass"] 

    run_command(
        mod_cmd,
        pexpect_lib,
        module.params["password"],
        module)


def run_command(mod_cmd, pexpect, password, module):
    # debug_output = []
    # debug_output.append(mod_cmd)
    # module.exit_json(changed=False, debug_out=debug_output)
    if pexpect:  # will only run when using username and password
        import pexpect
        child = pexpect.spawn(mod_cmd)
        child.expect('Password for ' + module.params["username"] + ":")
        child.sendline(password)
        child.expect(pexpect.EOF)
        # Save any potential error output from the realm process
        msg = child.before
        # Close the process so we can get its exit status
        child.close()
        rc = child.exitstatus

        if rc != 0:
            module.fail_json(
                msg="Unable to join realm",
                return_value=msg)
    else:
        module.run_command(mod_cmd)

    check_realm = domain_check(module)
    if check_realm:
        module.exit_json(changed=True, return_value=query_realm(module))
    else:
        module.fail_json(
            msg="Unable to join realm",
            return_value=query_realm(module))


def discover_realm(module):  # returns True if discovered | False if not
    check_realm = module.run_command(
        ['realm', 'discover', module.params['domain']])
    if check_realm[1] == "":
        return False
    else:
        return True


def rpm_installed(rpm_name):
    trans_set = rpm.TransactionSet()
    try:
        if trans_set.dbMatch(
                'name', rpm_name).count() in (
                1, 2):  # matches rpm name of packages needed
            return True
        else:
            return False
    except rpm.error:  # will fail if rpm not working properly
        return False


def query_realm(module):
    output_list = module.run_command(['realm', 'list'])
    return output_list


def domain_check(module):
    check_realm = module.run_command(['realm', 'list'])
    if check_realm[0] == 0:
        if check_realm[1] == "":
            return False
        else:
            return True
    else:
        module.fail_json(
            msg=(
                "Realm command returned status code for realmd was: " +
                check_realm[0]))


if __name__ == '__main__':
    main()
