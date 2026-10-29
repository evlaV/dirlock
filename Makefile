CFLAGS=-O2 -s

tpm2-dict-setup:
	$(CC) -o tpm2-dict-setup $(CFLAGS) tpm2-dict-setup.c -ltss2-esys -ltss2-tctildr -ltss2-rc

clean:
	rm -f tpm2-dict-setup

install: tpm2-dict-setup
        # The SDDM config file.
        # Copied into /etc/sddm.conf.d/ by dirlock-sddm-tracker only when needed.
	install -m644 -D sddm-theme/sddm.conf "$(DESTDIR)/usr/share/dirlock/sddm.conf"

        # The theme itself
	install -m644 -D sddm-theme/Main.qml "$(DESTDIR)/usr/share/sddm/themes/dirlock/Main.qml"
	install -m644 -D sddm-theme/ProgressIndicator.qml "$(DESTDIR)/usr/share/sddm/themes/dirlock/ProgressIndicator.qml"
	install -m644 -D sddm-theme/metadata.desktop "$(DESTDIR)/usr/share/sddm/themes/dirlock/metadata.desktop"
	install -m644 -D sddm-theme/theme.conf "$(DESTDIR)/usr/share/sddm/themes/dirlock/theme.conf"

        # The SDDM progress tracker tool
	install -m755 -D dirlock-sddm-tracker/dirlock-sddm-tracker "$(DESTDIR)/usr/lib/dirlock/dirlock-sddm-tracker"
	install -m644 -D dirlock-sddm-tracker/dirlock-sddm-tracker.service "$(DESTDIR)/usr/lib/systemd/system/dirlock-sddm-tracker.service"
	install -m644 -D dirlock-sddm-tracker/dirlock-sddm-tracker.path "$(DESTDIR)/usr/lib/systemd/system/dirlock-sddm-tracker.path"
	install -m755 -d "$(DESTDIR)/usr/lib/systemd/system/multi-user.target.wants"
	ln -s ../dirlock-sddm-tracker.path "$(DESTDIR)/usr/lib/systemd/system/multi-user.target.wants/"

        # The user progress tracker tool
	install -m755 -D dirlock-session-progress/dirlock-session-progress "$(DESTDIR)/usr/lib/dirlock/dirlock-session-progress"
	install -m644 -D dirlock-session-progress/dirlock-session-progress.service "$(DESTDIR)/usr/lib/systemd/user/dirlock-session-progress.service"

        # The wizard to let users encrypt their own homes
	install -m755 -D dirlock-convert-home/dirlock-convert-home "$(DESTDIR)/usr/lib/dirlock/dirlock-convert-home"
	install -m755 -D dirlock-convert-home/dirlock-convert-home-gui "$(DESTDIR)/usr/bin/dirlock-convert-home-gui"
	install -m644 -D dirlock-convert-home/dirlock-convert-home-gui.desktop "$(DESTDIR)/usr/share/applications/dirlock-convert-home-gui.desktop"
	install -m644 -D dirlock-convert-home/com.valvesoftware.dirlock.policy "$(DESTDIR)/usr/share/polkit-1/actions/com.valvesoftware.dirlock.policy"

        # TPM2 dictionary setup tool
	install -m755 -D tpm2-dict-setup "$(DESTDIR)/usr/lib/dirlock/tpm2-dict-setup"

        # Old helper scripts to enable encryption in SteamOS
	install -m755 -D old-setup-scripts/steamos-enable-dirlock "$(DESTDIR)/usr/lib/steamos/steamos-enable-dirlock"
	install -m755 -D old-setup-scripts/steamos-encrypt-home "$(DESTDIR)/usr/lib/steamos/steamos-encrypt-home"
	install -m755 -D old-setup-scripts/steamos-decrypt-home "$(DESTDIR)/usr/lib/steamos/steamos-decrypt-home"
