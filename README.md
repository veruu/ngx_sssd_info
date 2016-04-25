Nginx module for retrieving user attributes and groups from SSSD
================================================================

**WARNING: Output to variables is not implemented yet**

This module retrives additional attributes from SSSD for current authentizated
user. Inspired by [mod_lookup_identity](https://fedorapeople.org/cgit/adelton/public_git/mod_lookup_identity.git/) module for Apache.
You can specify BASE64 encoding for values, and output to nginx variables or
headers, which can be passed further for use. Both header and variable names
can be specified.

Tried with [freeIPA](http://www.freeipa.org/page/Main_Page),
[ngx_form_auth](https://github.com/veruu/ngx_form_auth/) and basic Perl FCGI application.


Installation
------------

1. Download [the nginx source](http://www.nginx.org/en/download.html) and extract it
1. Clone this module repository into the directory
1. Make sure you have additional module you use for authentication (or use Nginx's Basic auth)
1. Follow the [nginx install documentation](http://nginx.org/en/docs/install.html) and add this module. If you are compiling more modules for access phase (eg for authentication), add this module last.

    ./configure --add-module=ngx_sssd_info


Configuration
-------------
* `sssd_info`: on | off: for enabling / disabling the module
* `sssd_info_output_to`: base64 | variables | headers: any combination of these values; specify whether the values should be BASE64 encoded and where to output them. Default value is "variables" "headers", *Use only once per whole nginx.conf*
* `sssd_info_groups`: name of a variable / header to which output user groups
* `sssd_info_group`: name of a variable / header to which output user groups one by one
* `sssd_info_group_separator`: string that divided group name outputted to `sssd_info_groups`, default is ":"
* `sssd_info_attributes`: (name of the attribute in SSSD configuration) (name of a variable / header to which output attribute)
* `sssd_info_attribute`: (name of the attribute in SSSD configuration) (name of a variable / header to which output attribute one by one)
* `sssd_info_attribute_separator` string that divided attribute values outputted to `sssd_info_attributes`, default is ":"


Example configuration with [ngx_form_auth](https://github.com/veruu/ngx_form_auth/)
------------------------------------------

    location /application/login {
        form_auth on;
        form_auth_pam_service "my_app";
        form_auth_remote_user_on;

        sssd_info on;
        sssd_info_output_to "headers";
        sssd_info_groups "mygroups";
        sssd_info_group "mygroup";
        sssd_info_attributes "mail" "mymails";
        sssd_info_attribute_separator "_";
        sssd_info_attribute "mail" "mymail";
        sssd_info_attribute "givenname" "myname";

        proxy_set_header remote-user $remote_user;
        proxy_pass http://127.0.0.1:8888/backend/login/;
    }


Debugging information and troubleshooting
-----------------------------------------

To enable debugging output, compile with the `--with-debug` option and set the
`error_log` directive in you configuratin to `debug` level.

If you have unexpected issues with authentication, make sure your PAM setup is
correct (you have the configuration file for the used service in your
`/etc/pam.d/` containing correct settings). Usual setup for using SSSD for
authentication and authorization is

    auth    required   pam_sss.so
    account required   pam_sss.so

Make sure your SSSD configuration file includes all the attributes you have in
module configuration. Important lines include

    ldap_user_extra_attrs = <all attributes you want, divided by comma>
    services = nss, sudo, pam, ssh, ifp
        Important is that `ifp` is included

    example: 
    ldap_user_extra_attrs = mail, givenname, sn

    [ifp]
    allowed_uids = <user, under which is nginx running>
    user_attributes = <all attributes you want, divided by comma and prefixed by +>

    example:
    allowed_uids = root, nobody
    user_attributes = +mail, +givenname, +sn

Restart SSSD (`sudo service sssd restart` or equivalent) after any changes in sssd.conf.

Make sure you have installed `sssd-dbus` and `dbus-devel` (or equivalent) and check
where the dbus header files are placed, in case of `dbus-devel` installation in a different
place change included directories in `config` file. Be sure the `sssd-dbus` service is running.
