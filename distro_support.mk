module_name=$(patsubst mod_%,%,$(shared:%.la=%))

ifneq ($(wildcard /etc/debian_version),)
  # Debian/Ubuntu
  top_srcdir=/usr/share/apache2
  top_builddir=/usr/share/apache2
  include /usr/share/apache2/build/special.mk
  loader_file=/etc/apache2/mods-available/$(module_name).load
  loader_lines=LoadModule $(module_name)_module $(libexecdir)/mod_$(module_name).so
  ifneq ($(wildcard $(libexecdir)/apache24compat.so),)
    loader_extra_lines=LoadFile $(libexecdir)/apache24compat.so
  endif
else ifneq ($(wildcard /etc/redhat-release),)
  # RHEL/CentOS
  top_srcdir=/etc/httpd
  ifneq ($(wildcard /usr/lib64),)  # 64bit
    top_builddir=/usr/lib64/httpd
    include /usr/lib64/httpd/build/special.mk
  else
    top_builddir=/usr/lib/httpd
    include /usr/lib/httpd/build/special.mk
  endif
  ifneq ($(wildcard /etc/httpd/conf.modules.d),)  # CentOS7
    loader_file=/etc/httpd/conf.modules.d/99-$(module_name).conf-
  else
    loader_file=/etc/httpd/conf.d/$(module_name).conf-
  endif
  loader_lines=LoadModule $(module_name)_module modules/mod_$(module_name).so
  ifneq ($(wildcard $(libexecdir)/apache24compat.so),)
    loader_extra_lines=LoadFile modules/apache24compat.so
  endif
else
  $(error unsupported platform)
endif


install-loader-config:
	if [ -n "$(loader_extra_lines)" ] ; then \
	  echo -e "$(loader_extra_lines)\n$(loader_lines)" > $(loader_file) ; \
	else \
	  echo -e "$(loader_lines)" > $(loader_file) ; \
	fi
	chmod 644 $(loader_file)

install: install-modules-yes install-loader-config
