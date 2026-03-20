Name:           afw
Version:        0.1.0
Release:        1%{?dist}
Summary:        Application Firewall - eBPF process monitoring with dynamic nftables rules

License:        GPL-3.0-or-later
URL:            https://github.com/Infinit3i/AFW
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  cargo rust clang llvm bpf-linker
Requires:       nftables

%description
AFW is an eBPF-powered per-application outbound firewall for Linux.
It monitors process exec/exit via kernel tracepoints and dynamically
manages nftables rules - ports open when an app starts and close when
it exits. Default policy is drop.

%prep
%autosetup -n AFW-%{version}

%build
cargo xtask build-ebpf --release
cargo build --release -p afw

%check
cargo test --package afw

%install
install -Dm755 target/release/afw %{buildroot}%{_bindir}/afw
install -Dm644 config/afw.toml %{buildroot}%{_sysconfdir}/afw/afw.toml
install -dm755 %{buildroot}%{_sysconfdir}/afw/conf.d
for f in config/conf.d/*.toml; do
    install -Dm644 "$f" "%{buildroot}%{_sysconfdir}/afw/conf.d/$(basename $f)"
done
install -Dm644 systemd/afw.service %{buildroot}%{_unitdir}/afw.service

%post
%systemd_post afw.service

%preun
%systemd_preun afw.service

%postun
%systemd_postun_with_restart afw.service
nft delete table inet afw 2>/dev/null || true

%files
%license LICENSE
%{_bindir}/afw
%config(noreplace) %{_sysconfdir}/afw/afw.toml
%dir %{_sysconfdir}/afw/conf.d
%{_sysconfdir}/afw/conf.d/*.toml
%{_unitdir}/afw.service

%changelog
* Thu Mar 20 2026 infinit3i - 0.1.0-1
- Initial release
- eBPF-powered per-application outbound firewall
- Dynamic nftables rule management
- 119 pre-configured application profiles
- IPC authentication and input validation
