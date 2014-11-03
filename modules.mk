mod_authz_session.la: mod_authz_session.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_authz_session.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_authz_session.la
