CFLAGS=-O2 -s

tpm2-dict-setup:
	$(CC) -o tpm2-dict-setup $(CFLAGS) tpm2-dict-setup.c -ltss2-esys -ltss2-tctildr -ltss2-rc

clean:
	rm -f tpm2-dict-setup

install: tpm2-dict-setup
        # Helper scripts to enable encryption in SteamOS
	install -m755 -D steamos-enable-dirlock "$(DESTDIR)/usr/lib/steamos/steamos-enable-dirlock"
	install -m755 -D steamos-encrypt-home "$(DESTDIR)/usr/lib/steamos/steamos-encrypt-home"
	install -m755 -D steamos-decrypt-home "$(DESTDIR)/usr/lib/steamos/steamos-decrypt-home"

        # TPM2 dictionary setup tool
	install -m755 -D tpm2-dict-setup "$(DESTDIR)/usr/lib/dirlock/tpm2-dict-setup"
