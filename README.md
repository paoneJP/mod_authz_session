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

``make install`` command also installs LoadModule configuration in distro 
specific directory.

### Debian/Ubuntu

``/etc/apache2/mods-available/authz_session.load`` is installed.
To enable this module, use following command.

    $ sudo a2enmod authz_session

### RHEL/CentOS 6.x

``/etc/httpd/conf.d/authz_session.conf-disabled`` is installed.
To enable this module, rename the file to ``authz_session.conf``.

### RHEL/CentOS 7.x

``/etc/httpd/conf.modules.d/99-authz_session.conf-disabled`` is installed.
To enable this module, rename the file to ``99-authz_session.conf``.


## Directives

### AuthzSessionAuthoritative

 * Descryption
   - enables access control feature for the current directory or location.
 * Syntax
   - ``AuthzSessionAuthoritative`` ``On``|``Off``
 * Default
   - ``Off``

### AuthzSessionAuthRedirect

 * Descryption
   - redirect to authentication page (session initiator page) specified with 
     AuthzSessionAuthURL when client does not satisfy required condition.
 * Syntax
   - ``AuthzSessionAuthRedirect`` ``On``|``Off``
 * Default
   - ``Off``

### AuthzSessionAuthURL

 * Descryption
   - URL of authentication page (session initiator page).
 * Syntax
   - ``AuthzSessionAuthURL`` _url_
 * Default
   - none

### AuthzSessionTargetURLKey

 * Descryption
   - If this directive is specified, when redirecting to authentication 
     page (session initiator page) pass the URL of requested page to 
     specified key.
 * Syntax
   - ``AuthzSessionTargetURLKey`` _key_
 * Default
   - ``target_url``

### AuthzSessionTargetURLUsePrefix

 * Descryption
   - Specify the URL prefix (scheme, hostname, port, path) of requested page. 
     If not specified, URL is automatically guessed from request parameters.
 * Syntax
   - ``AuthzSessionTargetURLUsePrefix`` _url_
 * Default
   - none (URL is automatically guessed)

### AuthzSessionRequire

 * Descryption
   - specifies key value pairs for permit access.
 * Syntax
   - ``AuthzSessionRequire`` _key_ _value_ [_value_] ...
 * Default
   - none

If you specify multiple values in a line, treat it as OR condition.
If you specify multiple lines for same _key_, treat it as OR condition.

If you specify multiple _keys_, treat it as AND condition.

If you specify special ``_has_value`` to _value_, access is permitted when 
_key_ has any value.

### AuthzSessionRequireTimeIsBefore

 * Descryption
   - Time condition for permit access.
 * Syntax
   - ``AuthzSessionRequireTimeIsBefore`` _key_
 * Default
   - none

If specified key of session data is POSIX time and if current time is before
the time, access is permitted.

If you specify multiple _keys_, treat it as AND condition.

### AuthzSessionRequireTimeIsAfter

 * Descryption
   - Time condition for permit access.
 * Syntax
   - ``AuthzSessionRequireTimeIsAfter`` _key_
 * Default
   - none

If specified key of session data is POSIX time and if current time is after
the time, access is permitted.

If you specify multiple _keys_, treat it as AND condition.

### AuthzSessionRequireTimeAllowance

 * Descryption
   - Time allowance seconds used with AuthzSessionRequireTimeIsBefore 
     and AuthzSessionTimeIsAfter directives.
 * Syntax
   - ``AuthzSessionRequireTimeAllowance`` _seconds_
 * Default
   - 0 (sec)


## Example

Authenticaiton application ``/auth_app`` and restricted contents ``/sample``.

    <Location /sample>
      Session On
      SessionCookieName session path=/sample;httponly;secure
      SessionCryptoPassphrase secret
      AuthzSessionAuthoritative On
      AuthzSessionAuthRedirect On
      AuthzSessionAuthURL https://this_server/auth_app
      AuthzSessionRequire auth True
      AuthzSessionRequire user _has_value
      AuthzSessionRequire level 10 20
      AuthzSessionRequireTimeIsBefore expires_at
      AuthzSessionRequireTimeAllowance 5
    </Location>
    <Location /auth_app>
      Session On
      SessionCookieName session path=/sample;httponly;secure
      SessionCryptoPassphrase secret
      SessionHeader X-Replace-Session
    </Location>

Access is permitted if ``auth`` is ``True`` and ``user`` has any value 
and ``level`` is ``10`` or ``20`` and current time is before ``expires_at`` + 
``5`` sec.


## License

This software is released under the MIT License, see LICENSE file.


## changelog

 * second release
   - [new] new directives.
     - AuthzSessionAuthRedirect
     - AuthzSessionTargetURLKey
     - AuthzSessionTargetURLUsePrefix
     - AuthzSessionRequireTimeIsBefore
     - AuthzSessionRequireTimeIsAfter
     - AuthzSessionRequireTimeAllowance
   - [new] multi distro support. (Debian, Ubuntu, REHL, CentOS)
   - [new] ``make install`` command installs LoadModule configuraion file.
   - [new] query string is preserved in ``target_url`` when authentication redirect occurs.

 * first release
