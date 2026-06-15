# Maintainer: Seth Moore <mcapplbee@gmail.com>
pkgname=waurden-git
pkgver=0
pkgrel=1
pkgdesc='Your guardian for the AUR — LLM-powered PKGBUILD security scanner'
arch=('x86_64' 'aarch64')
url='https://github.com/sethdmoore/waurden'
license=('MIT')
makedepends=('go' 'git')
provides=('waurden')
conflicts=('waurden')
source=("$pkgname::git+https://github.com/sethdmoore/waurden.git")
sha256sums=('SKIP')

pkgver() {
    cd "$pkgname"
    if git describe --long --tags --abbrev=7 &>/dev/null; then
        git describe --long --tags --abbrev=7 | sed 's/\([^-]*-g\)/r\1/;s/-/./g'
    else
        printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short=7 HEAD)"
    fi
}

build() {
    cd "$pkgname"
    export CGO_ENABLED=0
    export GOPATH="$srcdir/go"
    go build -trimpath -ldflags='-s -w' -o waurden .
}

package() {
    cd "$pkgname"
    install -Dm755 waurden "$pkgdir/usr/bin/waurden"
}
