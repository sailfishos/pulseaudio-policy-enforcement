%define pulseversion %{expand:%(rpm -q --qf '[%%{version}]' pulseaudio)}
%define pulsemajorminor %{expand:%(echo '%{pulseversion}' | cut -d+ -f1)}
%define moduleversion %{pulsemajorminor}.%{expand:%(echo '%{version}' | cut -d. -f3)}

Name:       pulseaudio-policy-enforcement

Summary:    Pulseaudio module for enforcing policy decisions in the audio domain
Version:    %{pulsemajorminor}.47
Release:    0
License:    LGPLv2
URL:        https://github.com/sailfishos/pulseaudio-policy-enforcement
Source0:    %{name}-%{version}.tar.gz
BuildRequires:  libtool-ltdl-devel
BuildRequires:  meson
BuildRequires:  pkgconfig(atomic_ops)
BuildRequires:  pkgconfig(pulsecore) >= %{pulsemajorminor}
BuildRequires:  pkgconfig(libpulse) >= %{pulsemajorminor}
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(libmeego-common) >= 24

%description
This package contains a pulseaudio module that enforces (mostly audio) routing,
corking and muting policy decisions.

%prep
%autosetup -n %{name}-%{version}

%build
echo "%{moduleversion}" > .tarball-version
unset LD_AS_NEEDED
%meson
%meson_build

%install
%meson_install

%files
%{_libdir}/pulse-*/modules/module-*.so
%license COPYING
