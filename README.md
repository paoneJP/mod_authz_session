mod_authz_session
=================

Authorization module for access control using session data stored in 
mod_session.


## Key features

 * write ACL using session data stored in mod_session.
 * redirect to specified url when client does not satisfy required condition.


## Requirements

 * Apache HTTP Server 2.2+
 * mod_session
   * mod_session_cookie
   * mod_session_crypto


## Build and Install

Just run make and make install.

    $ cd mod_authz_session
    $ make
    $ sudo make install

Then add configuration line to ``httpd.conf`` to load this module.

    LoadModule authz_session_module /usr/lib/apache2/modules/mod_authz_session.so

If you use Debian or debian like platform, add 
``/etc/apache2/mod-available/authz_session.load`` file which contains 
``LoadModule`` line described above. Then use following command to enable 
the module.

    $ sudo a2enmod authz_session


## Directives

### AuthzSessionAuthoritative

 * Descryption
   - enables access control feature for the current directory or location.
 * Syntax
   - ``AuthzSessionAuthoritative`` ``On``|``Off``
 * Default
   - ``Off``

### AuthzSessionAuthURL

 * Descryption
   - the URL of authentication page (Session initiator page) to be redirected 
     to when client does not satisfy required condition.
 * Syntax
   - ``AuthzSessionAuthURL`` _url_
 * Default
   - none

### AuthzSessionRequire

 * Descryption
   - specifies key value pairs for permit access.
 * Syntax
   - ``AuthzSessionRequire`` _key_ _value_ [_value_] ...
 * Default
   - none

If you specify multiple values in a line, treat it as OR condition.
If you specify multiple lines for same _key_, treat it as OR condition.

If you specify multiple _keys_, treat it as AND condtion.

If you specify special ``_has_value`` to _value_, access is permitted when 
_key_ has any value.


## Example

Authenticaiton application ``/auth_app`` and restricted contents ``/sample``.

    <Location /sample>
      Session On
      SessionCookieName session path=/sample;httponly;secure
      SessionCryptoPassphrase secret
      AuthzSessionAuthoritative On
      AuthzSessionAuthURL https://this_server/auth_app
      AuthzSessionRequire auth True
      AuthzSessionRequire user _has_value
      AuthzSessionRequire level 10 20
    </Location>
    <Location /auth_app>
      Session On
      SessionCookieName session path=/sample;httponly;secure
      SessionCryptoPassphrase secret
      SessionHeader X-Replace-Sessin
    </Location>

Access is permitted if ``auth`` is ``True`` and ``user`` has any value 
and ``level`` is ``10`` or ``20``.


## License

This software is released under the MIT License, see LICENSE file.


## changelog

 * first release

