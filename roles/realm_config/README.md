This role is designed for configuration of /etc/hosts to make the ansible host a fqdn entry.  It also updates the /etc/resolv.conf to search for the specified domain and update the DNS server for the one that will be able to resolve the domain.
This role will also install the needed RPM packages to join the server to AD or IPA. 
For joining to realm you will also need the PExpect package that will be installed to your virtual env. 
